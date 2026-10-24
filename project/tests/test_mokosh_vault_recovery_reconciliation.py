import ast
import inspect
import os
import stat
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest import mock

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_recovery as recovery
import mokosh_vault_recovery_candidate as candidate
import mokosh_vault_recovery_publish as publisher
import mokosh_vault_recovery_reconciliation as reconciler
import mokosh_vault_recovery_storage as recovery_storage
import mokosh_vault_storage as vault_storage


OLD_PASSWORD = "Stage 2.8 old password"
NEW_PASSWORD = "Stage 2.8 explicit new password"
OTHER_PASSWORD = "Stage 2.8 other password"
THIRD_PASSWORD = "Stage 2.8 third password"
VAULT_ID = bytes(range(16))
KEY_ONE = b"K" * 32
CREATED = "2026-08-14T08:00:00Z"
RECOVERY_CREATED = "2026-08-14T09:00:00Z"
CANDIDATE_UPDATED = "2026-08-14T10:00:00Z"
THIRD_UPDATED = "2026-08-14T11:00:00Z"


def initial_keyring():
    result = keyring.VaultKeyring(
        active_key_version=1,
        keys=(
            keyring.VaultKeyRecord(
                key_version=1,
                state=keyring.KEY_STATE_ACTIVE,
                created_utc=CREATED,
                retired_utc=None,
                wrapping_key=KEY_ONE,
            ),
        ),
    )
    keyring.validate_keyring(result)
    return result


def make_session():
    encoded = vault.create_keyring_vault(
        OLD_PASSWORD,
        keyring=initial_keyring(),
        vault_id=VAULT_ID,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )
    session = vault.VaultSession(encoded)
    session.unlock(OLD_PASSWORD)
    return session


class RecoveryReconciliationTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-recovery-reconciliation-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.vault_path = self.parent / "vault"
        self.recovery_directory = self.parent / "offline-recovery"
        self.recovery_directory.mkdir(mode=0o700)
        os.chmod(self.recovery_directory, 0o700)
        self.store = vault_storage.VaultStorage.create(self.vault_path)
        self.session = make_session()
        self.source = self.store.publish(self.session)
        self.setup = recovery_storage.prepare_recovery_export(
            self.store,
            self.source,
            self.session,
            created_utc=RECOVERY_CREATED,
        )
        recovery_storage.export_recovery_record(
            self.setup,
            self.store,
            self.source,
            self.recovery_directory,
        )
        self.recovery_path = self.recovery_directory / (
            recovery_storage.recovery_record_name(self.setup.recovery_id)
        )

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.context.cleanup()

    def prepare(self, *, password=NEW_PASSWORD, time_cost=1):
        return candidate.prepare_recovery_candidate(
            self.recovery_path,
            self.setup.recovery_key,
            self.store,
            self.source,
            password,
            candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=time_cost,
            memory_kib=8192,
            parallelism=1,
        )

    def publish_target(self, *, password=NEW_PASSWORD, time_cost=1):
        prepared = self.prepare(password=password, time_cost=time_cost)
        return publisher.publish_recovery_candidate(
            prepared,
            self.recovery_path,
            self.setup.recovery_key,
            self.store,
            self.source,
            password,
            publisher.RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
        )

    def reconcile(self, **overrides):
        values = {
            "recovery_path": self.recovery_path,
            "recovery_key": self.setup.recovery_key,
            "storage": self.store,
            "source": self.source,
            "expected_target_revision": 2,
            "new_password": NEW_PASSWORD,
        }
        values.update(overrides)
        return reconciler.reconcile_recovery_publish(**values)

    def snapshot(self):
        result = {}
        for root in (self.vault_path, self.recovery_directory):
            for path in sorted(root.iterdir()):
                observed = path.stat(follow_symlinks=False)
                result[str(path)] = (
                    path.read_bytes() if path.is_file() else None,
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_mode,
                    observed.st_nlink,
                    observed.st_size,
                )
        return result


class RecoveryReconciliationRoundTripTests(RecoveryReconciliationTestCase):
    def test_target_absent_is_stably_classified(self):
        result = self.reconcile()
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.TARGET_ABSENT,
        )
        self.assertIs(
            result.recommended_action,
            reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        )
        self.assertIsNone(result.target_receipt)
        self.assertIsNone(result.target_vault_sha256)
        self.assertTrue(result.stable_observation)
        self.assertFalse(result.new_password_verified)

    def test_exact_published_target_is_stably_classified(self):
        published = self.publish_target()
        result = self.reconcile()
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        )
        self.assertEqual(result.target_receipt, published.receipt)
        self.assertEqual(result.target_vault_sha256, published.receipt.sha256)
        self.assertTrue(result.new_password_verified)
        self.assertTrue(result.keyring_verified)

    def test_post_publish_uncertain_outcome_reconciles_to_exact_target(self):
        prepared = self.prepare()
        with mock.patch.object(
            publisher,
            "_post_publish_verify",
            side_effect=RuntimeError("post-publish fault"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishUncertainError):
                publisher.publish_recovery_candidate(
                    prepared,
                    self.recovery_path,
                    self.setup.recovery_key,
                    self.store,
                    self.source,
                    NEW_PASSWORD,
                    publisher.RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
                )
        result = self.reconcile()
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        )

    def test_source_receipt_is_intentionally_nonlatest_when_target_exists(self):
        published = self.publish_target()
        self.assertNotEqual(self.store.scan().generations[-1], self.source)
        result = self.reconcile()
        self.assertEqual(result.source_receipt, self.source)
        self.assertEqual(result.target_receipt, published.receipt)

    def test_exact_target_unlocks_with_new_password_and_preserves_keyring(self):
        published = self.publish_target()
        encoded = self.store.verify_receipt(published.receipt)
        _, recovered = vault.unlock_keyring_vault(encoded, NEW_PASSWORD)
        self.assertEqual(
            keyring.encode_keyring(recovered),
            keyring.encode_keyring(initial_keyring()),
        )
        self.assertTrue(self.reconcile().keyring_verified)

    def test_result_is_fixed_nonsecret_read_only_evidence(self):
        self.publish_target()
        result = self.reconcile()
        names = {item.name for item in fields(result)}
        self.assertFalse(
            names
            & {
                "password",
                "recovery_key",
                "keyring",
                "wrapping_key",
                "path",
                "filename",
                "candidate",
                "plaintext",
            }
        )
        self.assertTrue(result.read_only)
        self.assertFalse(result.mutation_authorized)
        self.assertFalse(result.publish_performed)
        self.assertFalse(result.rollback_performed)
        self.assertFalse(result.cleanup_performed)
        self.assertFalse(result.key_deletion_performed)
        self.assertFalse(result.user_file_mutation_performed)
        rendered = repr(result)
        self.assertNotIn(NEW_PASSWORD, rendered)
        self.assertNotIn(self.setup.recovery_key.hex(), rendered)
        self.assertNotIn(KEY_ONE.hex(), rendered)

    def test_all_three_classifications_have_bounded_actions(self):
        absent = self.reconcile()
        self.assertIs(
            absent.recommended_action,
            reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        )
        self.publish_target()
        exact = self.reconcile()
        self.assertIs(
            exact.recommended_action,
            reconciler.RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY,
        )
        unknown = self.vault_path / "unexpected"
        unknown.write_bytes(b"preserve")
        conflict = self.reconcile()
        self.assertIs(
            conflict.recommended_action,
            reconciler.RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW,
        )

    def test_absent_classification_changes_no_file_or_inode(self):
        before = self.snapshot()
        self.reconcile()
        self.assertEqual(self.snapshot(), before)

    def test_exact_classification_changes_no_file_or_inode(self):
        self.publish_target()
        before = self.snapshot()
        self.reconcile()
        self.assertEqual(self.snapshot(), before)

    def test_result_counts_are_bounded_and_match_the_scan(self):
        self.publish_target()
        report = self.store.scan()
        result = self.reconcile()
        self.assertEqual(result.generation_count, len(report.generations))
        self.assertEqual(result.finding_count, len(report.findings))
        self.assertEqual(result.omitted_entries, report.omitted_entries)
        self.assertEqual(result.storage_complete, report.complete)

    def test_bytearray_recovery_root_is_accepted_but_not_retained(self):
        root = bytearray(self.setup.recovery_key)
        result = self.reconcile(recovery_key=root)
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.TARGET_ABSENT,
        )
        self.assertEqual(root, bytearray(self.setup.recovery_key))
        self.assertNotIn("recovery_key", {item.name for item in fields(result)})

    def test_old_record_is_stale_for_latest_but_valid_for_explicit_source(self):
        published = self.publish_target()
        with self.assertRaises(recovery.VaultRecoveryError):
            recovery_storage.rehearse_recovery_file(
                self.recovery_path,
                self.setup.recovery_key,
                self.store,
                published.receipt,
            )
        result = self.reconcile()
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        )


class RecoveryReconciliationConflictTests(RecoveryReconciliationTestCase):
    def assert_conflict(self, result):
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.CONFLICT,
        )
        self.assertIs(
            result.recommended_action,
            reconciler.RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW,
        )

    def test_invalid_target_bytes_are_conflict_not_absent(self):
        target = self.vault_path / vault_storage.generation_name(2)
        target.write_bytes(b"foreign target")
        os.chmod(target, 0o600)
        before = self.snapshot()
        self.assert_conflict(self.reconcile())
        self.assertEqual(self.snapshot(), before)

    def test_unknown_storage_object_is_conflict_and_preserved(self):
        unknown = self.vault_path / "unknown-object"
        unknown.write_bytes(b"do not touch")
        os.chmod(unknown, 0o600)
        before = self.snapshot()
        result = self.reconcile()
        self.assert_conflict(result)
        self.assertTrue(result.stable_observation)
        self.assertEqual(self.snapshot(), before)

    def test_linked_temporary_residue_is_conflict_and_preserved(self):
        self.publish_target()
        target = self.vault_path / vault_storage.generation_name(2)
        temporary = self.vault_path / (".mokosh-vault-" + "a" * 32 + ".tmp")
        os.link(target, temporary)
        before = self.snapshot()
        self.assert_conflict(self.reconcile())
        self.assertEqual(self.snapshot(), before)

    def test_wrong_new_password_for_present_target_is_conflict(self):
        self.publish_target()
        result = self.reconcile(new_password=OTHER_PASSWORD)
        self.assert_conflict(result)
        self.assertFalse(result.new_password_verified)

    def test_valid_target_created_with_other_password_is_conflict(self):
        self.publish_target(password=OTHER_PASSWORD)
        self.assert_conflict(self.reconcile(new_password=NEW_PASSWORD))

    def test_generation_beyond_expected_target_is_conflict(self):
        published = self.publish_target()
        target = self.store.verify_receipt(published.receipt)
        session = vault.VaultSession(target, minimum_revision=2)
        try:
            session.unlock(NEW_PASSWORD)
            session.change_password(
                THIRD_PASSWORD,
                updated_utc=THIRD_UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            self.store.publish(session, previous=published.receipt)
        finally:
            session.close()
        self.assert_conflict(self.reconcile())

    def test_incomplete_bounded_report_is_conflict(self):
        report = self.store.scan()
        incomplete = replace(report, omitted_entries=1, complete=False)
        with mock.patch.object(
            vault_storage.VaultStorage,
            "scan",
            autospec=True,
            side_effect=[incomplete, incomplete],
        ):
            result = self.reconcile()
        self.assert_conflict(result)
        self.assertFalse(result.storage_complete)
        self.assertEqual(result.omitted_entries, 1)

    def test_changed_reports_are_conflict_with_unstable_observation(self):
        clean = self.store.scan()
        incomplete = replace(clean, omitted_entries=1, complete=False)
        with mock.patch.object(
            vault_storage.VaultStorage,
            "scan",
            autospec=True,
            side_effect=[clean, incomplete],
        ):
            result = self.reconcile()
        self.assert_conflict(result)
        self.assertFalse(result.stable_observation)

    def test_target_verification_change_between_reads_is_conflict(self):
        published = self.publish_target()
        encoded = self.store.verify_receipt(published.receipt)
        observations = [
            reconciler._TargetObservation(True, published.receipt, encoded),
            reconciler._TargetObservation(False, published.receipt),
        ]
        with mock.patch.object(
            reconciler,
            "_observe_target",
            side_effect=observations,
        ):
            result = self.reconcile()
        self.assert_conflict(result)

    def test_conflict_result_does_not_expose_untrusted_target_receipt(self):
        self.publish_target(password=OTHER_PASSWORD)
        result = self.reconcile()
        self.assert_conflict(result)
        self.assertIsNone(result.target_receipt)
        self.assertIsNone(result.target_vault_sha256)


class RecoveryReconciliationInputTests(RecoveryReconciliationTestCase):
    def test_wrong_storage_and_source_types_are_refused(self):
        for values in ({"storage": object()}, {"source": object()}):
            with self.subTest(values=values):
                with self.assertRaises(
                    reconciler.VaultRecoveryReconciliationInputError
                ):
                    self.reconcile(**values)

    def test_expected_target_must_be_exact_plain_next_revision(self):
        for value in (None, True, "2", 1, 3, -1):
            with self.subTest(value=value):
                with self.assertRaises(
                    reconciler.VaultRecoveryReconciliationInputError
                ):
                    self.reconcile(expected_target_revision=value)

    def test_exhausted_source_revision_is_refused_before_sources(self):
        exhausted = replace(
            self.source,
            revision=vault.MAX_VAULT_REVISION,
        )
        with mock.patch.object(reconciler, "_verify_source") as verify:
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationInputError
            ):
                self.reconcile(
                    source=exhausted,
                    expected_target_revision=vault.MAX_VAULT_REVISION,
                )
            verify.assert_not_called()

    def test_invalid_recovery_root_is_refused_before_sources(self):
        for value in (None, "R" * 32, b"", b"R" * 31, b"R" * 33):
            with self.subTest(value=value), mock.patch.object(
                reconciler, "_verify_source"
            ) as verify:
                with self.assertRaises(
                    reconciler.VaultRecoveryReconciliationInputError
                ):
                    self.reconcile(recovery_key=value)
                verify.assert_not_called()

    def test_invalid_new_password_is_refused_before_sources_or_kdf(self):
        for value in (None, b"password", "", "x" * 1025, "\ud800"):
            with self.subTest(value=repr(value)), mock.patch.object(
                reconciler, "_verify_source"
            ) as verify, mock.patch.object(vault, "_derive_kek") as derive:
                with self.assertRaises(
                    reconciler.VaultRecoveryReconciliationInputError
                ):
                    self.reconcile(new_password=value)
                verify.assert_not_called()
                derive.assert_not_called()

    def test_invalid_kdf_policy_is_refused_before_sources(self):
        for value in (
            object(),
            vault.VaultKDFPolicy(max_time_cost=0),
            vault.VaultKDFPolicy(max_memory_kib=8191),
        ):
            with self.subTest(value=value), mock.patch.object(
                reconciler, "_verify_source"
            ) as verify:
                with self.assertRaises(
                    reconciler.VaultRecoveryReconciliationInputError
                ):
                    self.reconcile(policy=value)
                verify.assert_not_called()

    def test_invalid_input_stops_before_recovery_read_and_scan(self):
        with mock.patch.object(
            reconciler, "_read_recovery_path"
        ) as read, mock.patch.object(reconciler, "_scan") as scan:
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationInputError
            ):
                self.reconcile(expected_target_revision=3)
            read.assert_not_called()
            scan.assert_not_called()

    def test_closed_storage_is_state_error_without_mutation(self):
        before = self.snapshot()
        self.store.close()
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationStateError
        ):
            self.reconcile()
        self.assertEqual(self.snapshot(), before)


class RecoveryReconciliationSourceTests(RecoveryReconciliationTestCase):
    def test_forged_source_receipt_is_rejected(self):
        forged = replace(self.source, sha256=b"F" * 32)
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationStateError
        ):
            self.reconcile(source=forged)

    def test_wrong_exact_length_recovery_root_is_verification_error(self):
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationVerificationError
        ):
            self.reconcile(recovery_key=b"Q" * 32)

    def test_tampered_recovery_record_is_rejected_and_preserved(self):
        changed = self.recovery_path.read_bytes() + b"x"
        self.recovery_path.write_bytes(changed)
        os.chmod(self.recovery_path, 0o600)
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationVerificationError
        ):
            self.reconcile()
        self.assertEqual(self.recovery_path.read_bytes(), changed)

    def test_unsafe_recovery_permissions_are_rejected(self):
        os.chmod(self.recovery_path, 0o644)
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationVerificationError
        ):
            self.reconcile()
        self.assertEqual(stat.S_IMODE(self.recovery_path.stat().st_mode), 0o644)

    def test_hardlinked_recovery_file_is_rejected_without_cleanup(self):
        alias = self.recovery_directory / "alias.mokr"
        os.link(self.recovery_path, alias)
        with self.assertRaises(
            reconciler.VaultRecoveryReconciliationVerificationError
        ):
            self.reconcile()
        self.assertTrue(alias.exists())
        self.assertEqual(self.recovery_path.stat().st_nlink, 2)

    def test_recovery_file_change_between_reads_is_state_error(self):
        first = recovery_storage._read_recovery_path(self.recovery_path)
        changed = replace(first, file_inode=first.file_inode + 1)
        with mock.patch.object(
            reconciler,
            "_read_recovery_path",
            side_effect=[first, changed],
        ):
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationStateError
            ):
                self.reconcile()

    def test_source_change_between_reads_is_state_error(self):
        real = reconciler._verify_source
        calls = 0

        def changing(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise reconciler.VaultRecoveryReconciliationStateError(
                    "changed"
                )
            return real(*args, **kwargs)

        with mock.patch.object(
            reconciler,
            "_verify_source",
            side_effect=changing,
        ):
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationStateError
            ):
                self.reconcile()

    def test_scan_failure_is_state_error(self):
        with mock.patch.object(
            vault_storage.VaultStorage,
            "scan",
            autospec=True,
            side_effect=vault_storage.VaultStorageError("scan"),
        ):
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationStateError
            ):
                self.reconcile()

    def test_invalid_scan_report_type_is_state_error(self):
        with mock.patch.object(
            vault_storage.VaultStorage,
            "scan",
            autospec=True,
            return_value=object(),
        ):
            with self.assertRaises(
                reconciler.VaultRecoveryReconciliationStateError
            ):
                self.reconcile()


class RecoveryReconciliationFaultTests(RecoveryReconciliationTestCase):
    def test_keyboard_interrupt_is_not_converted_to_success_or_conflict(self):
        before = self.snapshot()
        with mock.patch.object(
            reconciler,
            "_scan",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.reconcile()
        self.assertEqual(self.snapshot(), before)

    def test_target_outside_caller_kdf_policy_is_conflict(self):
        self.publish_target(time_cost=2)
        narrow = vault.VaultKDFPolicy(
            max_time_cost=1,
            max_memory_kib=8192,
            max_parallelism=1,
        )
        self.assertIs(
            self.reconcile(policy=narrow).classification,
            reconciler.RecoveryPublishClassification.CONFLICT,
        )

    def test_source_recovery_and_storage_are_each_checked_twice(self):
        with mock.patch.object(
            reconciler,
            "_verify_source",
            wraps=reconciler._verify_source,
        ) as source, mock.patch.object(
            reconciler,
            "_read_recovery_path",
            wraps=reconciler._read_recovery_path,
        ) as recovery_read, mock.patch.object(
            reconciler,
            "_scan",
            wraps=reconciler._scan,
        ) as scan:
            self.reconcile()
        self.assertEqual(source.call_count, 2)
        self.assertEqual(recovery_read.call_count, 2)
        self.assertEqual(scan.call_count, 2)


class RecoveryReconciliationStaticBoundaryTests(
    RecoveryReconciliationTestCase
):
    def test_module_has_no_filesystem_mutation_or_publish_call(self):
        tree = ast.parse(inspect.getsource(reconciler))
        forbidden = {
            "open",
            "write",
            "publish",
            "unlink",
            "remove",
            "rename",
            "replace",
            "rmdir",
            "mkdir",
            "makedirs",
            "link",
            "symlink",
            "truncate",
            "fsync",
            "chmod",
            "chown",
        }
        observed = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    observed.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    observed.add(node.func.attr)
        self.assertFalse(observed & forbidden)

    def test_module_has_no_network_logging_process_or_os_import(self):
        tree = ast.parse(inspect.getsource(reconciler))
        roots = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".")[0])
        self.assertFalse(
            roots
            & {
                "os",
                "socket",
                "http",
                "urllib",
                "requests",
                "logging",
                "subprocess",
                "threading",
            }
        )

    def test_public_contract_has_no_mutation_or_candidate_handoff_parameter(self):
        signature = inspect.signature(reconciler.reconcile_recovery_publish)
        for name in (
            "output_path",
            "delete",
            "cleanup",
            "overwrite",
            "publish",
            "rollback",
            "rotate",
            "migrate",
            "prepared",
            "candidate",
        ):
            self.assertNotIn(name, signature.parameters)
        self.assertIn("source", signature.parameters)
        self.assertIn("expected_target_revision", signature.parameters)
        self.assertIn("recovery_path", signature.parameters)
        self.assertIn("new_password", signature.parameters)

    def test_result_contract_has_no_secret_path_or_mutation_payload(self):
        names = {item.name for item in fields(
            reconciler.VaultRecoveryReconciliationResult
        )}
        self.assertFalse(
            names
            & {
                "password",
                "recovery_key",
                "keyring",
                "wrapping_key",
                "path",
                "filename",
                "candidate",
                "plaintext",
                "cleanup_path",
            }
        )

    def test_reconciliation_never_adds_or_removes_a_directory_entry(self):
        before_vault = sorted(path.name for path in self.vault_path.iterdir())
        before_recovery = sorted(
            path.name for path in self.recovery_directory.iterdir()
        )
        self.reconcile()
        self.assertEqual(
            sorted(path.name for path in self.vault_path.iterdir()),
            before_vault,
        )
        self.assertEqual(
            sorted(path.name for path in self.recovery_directory.iterdir()),
            before_recovery,
        )


if __name__ == "__main__":
    unittest.main()
