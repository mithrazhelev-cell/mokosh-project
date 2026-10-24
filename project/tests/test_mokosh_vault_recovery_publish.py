import ast
import hashlib
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
import mokosh_vault_recovery_storage as recovery_storage
import mokosh_vault_storage as vault_storage


OLD_PASSWORD = "Stage 2.7 old password"
NEW_PASSWORD = "Stage 2.7 explicit new password"
WRONG_PASSWORD = "Stage 2.7 wrong password"
VAULT_ID = bytes(range(16))
KEY_ONE = b"K" * 32
CREATED = "2026-08-14T08:00:00Z"
RECOVERY_CREATED = "2026-08-14T09:00:00Z"
CANDIDATE_UPDATED = "2026-08-14T10:00:00Z"


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


def make_session(*, vault_id=VAULT_ID, keyring_value=None):
    encoded = vault.create_keyring_vault(
        OLD_PASSWORD,
        keyring=keyring_value or initial_keyring(),
        vault_id=vault_id,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )
    session = vault.VaultSession(encoded)
    session.unlock(OLD_PASSWORD)
    return session


class RecoveryPublishTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-recovery-publish-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.vault_path = self.parent / "vault"
        self.recovery_directory = self.parent / "offline-recovery"
        self.recovery_directory.mkdir(mode=0o700)
        os.chmod(self.recovery_directory, 0o700)
        self.store = vault_storage.VaultStorage.create(self.vault_path)
        self.session = make_session()
        self.receipt = self.store.publish(self.session)
        self.setup = recovery_storage.prepare_recovery_export(
            self.store,
            self.receipt,
            self.session,
            created_utc=RECOVERY_CREATED,
        )
        self.export_receipt = recovery_storage.export_recovery_record(
            self.setup,
            self.store,
            self.receipt,
            self.recovery_directory,
        )
        self.recovery_path = self.recovery_directory / (
            recovery_storage.recovery_record_name(self.setup.recovery_id)
        )

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.context.cleanup()

    def prepare(self, **overrides):
        values = {
            "recovery_path": self.recovery_path,
            "recovery_key": self.setup.recovery_key,
            "storage": self.store,
            "latest": self.receipt,
            "new_password": NEW_PASSWORD,
            "decision": candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
            "updated_utc": CANDIDATE_UPDATED,
            "time_cost": 1,
            "memory_kib": 8192,
            "parallelism": 1,
        }
        values.update(overrides)
        return candidate.prepare_recovery_candidate(**values)

    def publish(self, prepared=None, **overrides):
        values = {
            "prepared": prepared or self.prepare(),
            "recovery_path": self.recovery_path,
            "recovery_key": self.setup.recovery_key,
            "storage": self.store,
            "latest": self.receipt,
            "new_password": NEW_PASSWORD,
            "decision": publisher.RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
        }
        values.update(overrides)
        return publisher.publish_recovery_candidate(**values)

    def snapshot(self):
        result = {}
        for root in (self.vault_path, self.recovery_directory):
            for path in sorted(root.iterdir()):
                info = path.stat(follow_symlinks=False)
                result[str(path)] = (
                    path.read_bytes() if path.is_file() else None,
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_nlink,
                    info.st_size,
                )
        return result


class RecoveryPublishRoundTripTests(RecoveryPublishTestCase):
    def test_exact_next_generation_is_published_and_verified(self):
        result = self.publish()
        report = self.store.scan()
        self.assertEqual(result.source_revision, 1)
        self.assertEqual(result.target_revision, 2)
        self.assertEqual(result.receipt, report.generations[-1])
        self.assertEqual(report.generations, (self.receipt, result.receipt))
        encoded = self.store.verify_receipt(result.receipt)
        parsed, recovered = vault.unlock_keyring_vault(
            encoded,
            NEW_PASSWORD,
            minimum_revision=2,
        )
        self.assertEqual(parsed.header.vault_id, VAULT_ID)
        self.assertEqual(parsed.header.revision, 2)
        self.assertEqual(
            keyring.encode_keyring(recovered),
            keyring.encode_keyring(initial_keyring()),
        )

    def test_old_password_cannot_open_new_latest_generation(self):
        result = self.publish()
        encoded = self.store.verify_receipt(result.receipt)
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_keyring_vault(encoded, OLD_PASSWORD)
        vault.unlock_keyring_vault(encoded, NEW_PASSWORD)

    def test_source_generation_and_recovery_record_are_byte_exact_preserved(self):
        old_vault = self.store.verify_receipt(self.receipt)
        recovery_bytes = self.recovery_path.read_bytes()
        recovery_stat = self.recovery_path.stat()
        result = self.publish()
        self.assertEqual(self.store.verify_receipt(self.receipt), old_vault)
        self.assertEqual(self.recovery_path.read_bytes(), recovery_bytes)
        self.assertEqual(self.recovery_path.stat().st_ino, recovery_stat.st_ino)
        self.assertNotEqual(result.receipt.file_inode, self.receipt.file_inode)

    def test_published_generation_is_private_single_link_without_temporary(self):
        result = self.publish()
        final = self.vault_path / vault_storage.generation_name(2)
        observed = final.stat(follow_symlinks=False)
        self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        self.assertEqual(observed.st_ino, result.receipt.file_inode)
        self.assertFalse(any(path.name.endswith(".tmp") for path in self.vault_path.iterdir()))

    def test_result_contains_only_nonsecret_publish_evidence(self):
        result = self.publish()
        names = {item.name for item in fields(result)}
        self.assertFalse(
            names
            & {
                "candidate",
                "password",
                "recovery_key",
                "keyring",
                "wrapping_key",
                "path",
                "plaintext",
            }
        )
        self.assertTrue(result.source_generation_preserved)
        self.assertTrue(result.recovery_record_preserved)
        self.assertTrue(result.key_history_preserved)
        self.assertTrue(result.recovery_record_now_stale)
        self.assertFalse(result.key_deletion_performed)
        self.assertFalse(result.user_file_mutation_performed)
        rendered = repr(result)
        self.assertNotIn(NEW_PASSWORD, rendered)
        self.assertNotIn(self.setup.recovery_key.hex(), rendered)
        self.assertNotIn(KEY_ONE.hex(), rendered)

    def test_result_binds_stage26_authorization_and_all_digests(self):
        prepared = self.prepare()
        evidence = prepared.evidence
        authorization_id = prepared._authorization.authorization_id
        result = self.publish(prepared)
        self.assertEqual(result.authorization_id, authorization_id)
        self.assertEqual(result.recovery_id, evidence.recovery_id)
        self.assertEqual(result.vault_id, evidence.vault_id)
        self.assertEqual(result.source_vault_sha256, evidence.source_vault_sha256)
        self.assertEqual(result.record_sha256, evidence.record_sha256)
        self.assertEqual(result.keyring_sha256, evidence.keyring_sha256)
        self.assertEqual(result.candidate_sha256, evidence.candidate_sha256)
        self.assertEqual(result.receipt.sha256, evidence.candidate_sha256)

    def test_executor_claims_stage26_handoff_exactly_once(self):
        prepared = self.prepare()
        self.publish(prepared)
        self.assertTrue(prepared.claimed)
        with self.assertRaises(publisher.VaultRecoveryPublishInputError):
            self.publish(prepared, latest=self.store.scan().generations[-1])
        self.assertEqual(len(self.store.scan().generations), 2)

    def test_preclaimed_handoff_is_refused_without_mutation(self):
        prepared = self.prepare()
        prepared.claim_once()
        before = self.snapshot()
        with self.assertRaises(publisher.VaultRecoveryPublishInputError):
            self.publish(prepared)
        self.assertEqual(self.snapshot(), before)

    def test_old_recovery_record_is_preserved_but_stale_for_new_latest(self):
        result = self.publish()
        self.assertTrue(self.recovery_path.exists())
        with self.assertRaises(recovery.VaultRecoveryError):
            recovery_storage.rehearse_recovery_file(
                self.recovery_path,
                self.setup.recovery_key,
                self.store,
                result.receipt,
            )

    def test_bytearray_recovery_root_is_accepted_but_not_retained(self):
        root = bytearray(self.setup.recovery_key)
        result = self.publish(recovery_key=root)
        self.assertEqual(result.target_revision, 2)
        self.assertEqual(root, bytearray(self.setup.recovery_key))
        self.assertNotIn("recovery_key", {item.name for item in fields(result)})

    def test_retired_and_active_key_history_is_preserved_exactly(self):
        other_vault = self.parent / "history-vault"
        other_recovery = self.parent / "history-recovery"
        other_recovery.mkdir(mode=0o700)
        os.chmod(other_recovery, 0o700)
        store = vault_storage.VaultStorage.create(other_vault)
        session = make_session()
        try:
            first = store.publish(session)
            session.rotate_keyring(
                OLD_PASSWORD,
                rotated_utc=RECOVERY_CREATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            receipt = store.publish(session, previous=first)
            expected_keyring = session.keyring_copy()
            setup = recovery_storage.prepare_recovery_export(
                store,
                receipt,
                session,
                created_utc=CANDIDATE_UPDATED,
            )
            recovery_storage.export_recovery_record(
                setup,
                store,
                receipt,
                other_recovery,
            )
            path = other_recovery / recovery_storage.recovery_record_name(
                setup.recovery_id
            )
            prepared = candidate.prepare_recovery_candidate(
                path,
                setup.recovery_key,
                store,
                receipt,
                NEW_PASSWORD,
                candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
                updated_utc=CANDIDATE_UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            result = publisher.publish_recovery_candidate(
                prepared,
                path,
                setup.recovery_key,
                store,
                receipt,
                NEW_PASSWORD,
                publisher.RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
            )
            _, recovered = vault.unlock_keyring_vault(
                store.verify_receipt(result.receipt),
                NEW_PASSWORD,
            )
            self.assertEqual(
                keyring.encode_keyring(recovered),
                keyring.encode_keyring(expected_keyring),
            )
        finally:
            session.close()
            store.close()

    def test_explicit_exact_byte_clone_is_content_bound_not_path_authenticated(self):
        prepared = self.prepare()
        clone_path = self.parent / "explicit-clone"
        clone = vault_storage.VaultStorage.create(clone_path)
        try:
            source_name = vault_storage.generation_name(1)
            (clone_path / source_name).write_bytes(
                (self.vault_path / source_name).read_bytes()
            )
            os.chmod(clone_path / source_name, 0o600)
            clone_receipt = clone.scan().generations[-1]
            result = self.publish(
                prepared,
                storage=clone,
                latest=clone_receipt,
            )
            self.assertEqual(len(clone.scan().generations), 2)
            self.assertEqual(len(self.store.scan().generations), 1)
            self.assertEqual(result.source_vault_sha256, self.receipt.sha256)
        finally:
            clone.close()


class RecoveryPublishInputRefusalTests(RecoveryPublishTestCase):
    def test_preserve_and_non_enum_decisions_stop_before_claim_and_sources(self):
        for decision in (
            publisher.RecoveryPublishDecision.PRESERVE,
            True,
            "authorize_immutable_publish",
        ):
            prepared = self.prepare()
            with self.subTest(decision=decision), mock.patch.object(
                publisher, "_validate_latest_source"
            ) as source, mock.patch.object(
                vault, "_derive_kek"
            ) as derive:
                with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                    self.publish(prepared, decision=decision)
                source.assert_not_called()
                derive.assert_not_called()
                self.assertFalse(prepared.claimed)

    def test_wrong_prepared_type_stops_before_sources(self):
        with mock.patch.object(publisher, "_validate_latest_source") as source:
            with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                self.publish(prepared=object())
            source.assert_not_called()

    def test_invalid_recovery_root_stops_before_claim(self):
        for value in (None, "R" * 32, b"", b"R" * 31, b"R" * 33):
            prepared = self.prepare()
            with self.subTest(value=value):
                with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                    self.publish(prepared, recovery_key=value)
                self.assertFalse(prepared.claimed)

    def test_invalid_new_password_stops_before_claim_or_kdf(self):
        for value in (None, b"password", "", "x" * 1025, "\ud800"):
            prepared = self.prepare()
            with self.subTest(value=repr(value)), mock.patch.object(
                vault, "_derive_kek"
            ) as derive:
                with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                    self.publish(prepared, new_password=value)
                self.assertFalse(prepared.claimed)
                derive.assert_not_called()

    def test_invalid_policy_stops_before_claim_sources_or_kdf(self):
        for value in (
            object(),
            vault.VaultKDFPolicy(max_time_cost=0),
            vault.VaultKDFPolicy(max_memory_kib=8191),
        ):
            prepared = self.prepare()
            with self.subTest(value=value), mock.patch.object(
                publisher, "_validate_latest_source"
            ) as source, mock.patch.object(vault, "_derive_kek") as derive:
                with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                    self.publish(prepared, policy=value)
                self.assertFalse(prepared.claimed)
                source.assert_not_called()
                derive.assert_not_called()

    def test_candidate_outside_frozen_stage22_policy_is_refused_before_claim(self):
        wider = vault.VaultKDFPolicy(
            max_time_cost=10,
            max_memory_kib=256 * 1024,
            max_parallelism=8,
        )
        prepared = self.prepare(time_cost=6, policy=wider)
        with mock.patch.object(publisher, "_validate_latest_source") as source:
            with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                self.publish(prepared, policy=wider)
            source.assert_not_called()
        self.assertFalse(prepared.claimed)

    def test_wrong_storage_and_receipt_types_stop_before_claim(self):
        cases = ({"storage": object()}, {"latest": object()})
        for values in cases:
            prepared = self.prepare()
            with self.subTest(values=values):
                with self.assertRaises(publisher.VaultRecoveryPublishInputError):
                    self.publish(prepared, **values)
                self.assertFalse(prepared.claimed)

    def test_closed_storage_consumes_valid_handoff_but_does_not_publish(self):
        prepared = self.prepare()
        before = self.snapshot()
        self.store.close()
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        self.assertTrue(prepared.claimed)
        self.assertEqual(self.snapshot(), before)


class RecoveryPublishSourceRefusalTests(RecoveryPublishTestCase):
    def test_wrong_valid_password_consumes_handoff_without_publish(self):
        prepared = self.prepare()
        before = self.snapshot()
        with self.assertRaises(publisher.VaultRecoveryPublishVerificationError):
            self.publish(prepared, new_password=WRONG_PASSWORD)
        self.assertTrue(prepared.claimed)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_wrong_exact_length_recovery_root_consumes_without_publish(self):
        prepared = self.prepare()
        before = self.snapshot()
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared, recovery_key=b"Q" * 32)
        self.assertTrue(prepared.claimed)
        self.assertEqual(self.snapshot(), before)

    def test_forged_receipt_and_dirty_history_are_rejected(self):
        prepared = self.prepare()
        forged = replace(self.receipt, sha256=b"F" * 32)
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared, latest=forged)
        self.assertEqual(len(self.store.scan().generations), 1)

        prepared = self.prepare()
        unknown = self.vault_path / "unknown"
        unknown.write_bytes(b"do not touch")
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        self.assertEqual(unknown.read_bytes(), b"do not touch")

    def test_stale_nonlatest_source_receipt_is_rejected(self):
        prepared = self.prepare()
        self.session.change_password(
            OLD_PASSWORD,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        second = self.store.publish(self.session, previous=self.receipt)
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        self.assertEqual(self.store.scan().generations[-1], second)
        self.assertEqual(len(self.store.scan().generations), 2)

    def test_unsafe_recovery_permissions_and_hardlink_are_rejected(self):
        prepared = self.prepare()
        os.chmod(self.recovery_path, 0o644)
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        os.chmod(self.recovery_path, 0o600)
        self.assertEqual(len(self.store.scan().generations), 1)

        prepared = self.prepare()
        alias = self.recovery_directory / "alias.mokr"
        os.link(self.recovery_path, alias)
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_recovery_file_identity_change_between_reads_is_rejected(self):
        prepared = self.prepare()
        first = recovery_storage._read_recovery_path(self.recovery_path)
        changed = replace(first, file_inode=first.file_inode + 1)
        with mock.patch.object(
            publisher,
            "_read_recovery_path",
            side_effect=[first, changed],
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_vault_change_between_fresh_validations_is_rejected(self):
        prepared = self.prepare()
        current = self.store.verify_receipt(self.receipt)
        with mock.patch.object(
            publisher,
            "_validate_latest_source",
            side_effect=[current, publisher.VaultRecoveryPublishStateError("changed")],
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_candidate_bytes_tamper_is_rejected_before_sources(self):
        prepared = self.prepare()
        changed = bytearray(prepared._candidate)
        changed[-1] ^= 1
        object.__setattr__(prepared, "_candidate", bytes(changed))
        with mock.patch.object(publisher, "_validate_latest_source") as source:
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
            source.assert_not_called()
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_authorization_tamper_is_rejected_before_sources(self):
        prepared = self.prepare()
        bad = replace(prepared._authorization, authorization_id="AA" * 16)
        object.__setattr__(prepared, "_authorization", bad)
        with mock.patch.object(publisher, "_validate_latest_source") as source:
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
            source.assert_not_called()
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_existing_target_is_never_overwritten(self):
        prepared = self.prepare()
        target = self.vault_path / vault_storage.generation_name(2)
        target.write_bytes(b"foreign target")
        os.chmod(target, 0o600)
        before = target.read_bytes()
        with self.assertRaises(publisher.VaultRecoveryPublishStateError):
            self.publish(prepared)
        self.assertEqual(target.read_bytes(), before)


class RecoveryPublishFaultAndUncertainTests(RecoveryPublishTestCase):
    def test_first_recovery_read_fault_consumes_handoff_without_mutation(self):
        prepared = self.prepare()
        before = self.snapshot()
        with mock.patch.object(
            publisher,
            "_read_recovery_path",
            side_effect=OSError("read"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertTrue(prepared.claimed)
        self.assertEqual(self.snapshot(), before)

    def test_cancellation_before_publish_never_returns_false_success(self):
        prepared = self.prepare()
        before = self.snapshot()
        with mock.patch.object(
            publisher,
            "_validate_latest_source",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.publish(prepared)
        self.assertTrue(prepared.claimed)
        self.assertEqual(self.snapshot(), before)

    def test_prelink_publish_failure_returns_no_success_and_no_generation(self):
        prepared = self.prepare()
        with mock.patch.object(
            vault_storage.VaultStorage,
            "publish",
            side_effect=vault_storage.VaultGenerationConflictError("prelink"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_stage22_uncertain_failure_is_preserved_as_uncertain(self):
        prepared = self.prepare()
        with mock.patch.object(
            vault_storage.VaultStorage,
            "publish",
            side_effect=vault_storage.VaultPublishUncertainError("boundary"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishUncertainError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_unexpected_preconfirmation_fault_is_state_failure(self):
        prepared = self.prepare()
        with mock.patch.object(
            vault_storage.VaultStorage,
            "publish",
            side_effect=RuntimeError("fault"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 1)

    def test_fault_after_publish_is_uncertain_and_generation_is_not_deleted(self):
        prepared = self.prepare()
        with mock.patch.object(
            publisher,
            "_post_publish_verify",
            side_effect=RuntimeError("post"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishUncertainError):
                self.publish(prepared)
        report = self.store.scan()
        self.assertEqual(len(report.generations), 2)
        self.assertFalse(report.has_conflict)
        self.assertTrue(
            (self.vault_path / vault_storage.generation_name(2)).exists()
        )

    def test_recovery_change_after_publish_is_uncertain_without_rollback(self):
        prepared = self.prepare()
        real_post = publisher._post_publish_verify

        def changed_recovery(**kwargs):
            self.recovery_path.write_bytes(self.recovery_path.read_bytes() + b"x")
            os.chmod(self.recovery_path, 0o600)
            return real_post(**kwargs)

        with mock.patch.object(
            publisher,
            "_post_publish_verify",
            side_effect=changed_recovery,
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishUncertainError):
                self.publish(prepared)
        self.assertEqual(len(self.store.scan().generations), 2)
        self.assertTrue(
            (self.vault_path / vault_storage.generation_name(1)).exists()
        )
        self.assertTrue(
            (self.vault_path / vault_storage.generation_name(2)).exists()
        )

    def test_candidate_session_is_closed_after_success(self):
        original = vault.VaultSession.close
        with mock.patch.object(
            vault.VaultSession,
            "close",
            autospec=True,
            side_effect=original,
        ) as close:
            self.publish()
        self.assertGreaterEqual(close.call_count, 1)

    def test_candidate_session_is_closed_after_prepublish_failure(self):
        prepared = self.prepare()
        original = vault.VaultSession.close
        with mock.patch.object(
            vault.VaultSession,
            "close",
            autospec=True,
            side_effect=original,
        ) as close, mock.patch.object(
            vault_storage.VaultStorage,
            "publish",
            side_effect=vault_storage.VaultGenerationConflictError("prelink"),
        ):
            with self.assertRaises(publisher.VaultRecoveryPublishStateError):
                self.publish(prepared)
        self.assertGreaterEqual(close.call_count, 1)


class RecoveryPublishStaticBoundaryTests(RecoveryPublishTestCase):
    def test_module_delegates_the_only_mutation_and_has_no_direct_file_calls(self):
        source = inspect.getsource(publisher)
        tree = ast.parse(source)
        forbidden_names = {
            "open",
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
            "write",
        }
        observed = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    observed.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    observed.add(node.func.attr)
        self.assertFalse(observed & forbidden_names)
        publish_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "publish"
        ]
        self.assertEqual(len(publish_calls), 1)

    def test_module_has_no_network_logging_or_process_imports(self):
        tree = ast.parse(inspect.getsource(publisher))
        imported_roots = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imported_roots
            & {
                "socket",
                "http",
                "urllib",
                "requests",
                "logging",
                "subprocess",
                "threading",
            }
        )

    def test_public_contract_has_no_output_cleanup_or_old_password_parameter(self):
        signature = inspect.signature(publisher.publish_recovery_candidate)
        for name in (
            "output_path",
            "delete",
            "cleanup",
            "overwrite",
            "old_password",
            "current_password",
            "rotate",
            "migrate",
        ):
            self.assertNotIn(name, signature.parameters)
        self.assertIn("new_password", signature.parameters)
        self.assertIn("recovery_path", signature.parameters)
        self.assertIn("prepared", signature.parameters)

    def test_success_adds_only_one_vault_generation(self):
        before_recovery = sorted(path.name for path in self.recovery_directory.iterdir())
        before_vault = sorted(path.name for path in self.vault_path.iterdir())
        self.publish()
        after_recovery = sorted(path.name for path in self.recovery_directory.iterdir())
        after_vault = sorted(path.name for path in self.vault_path.iterdir())
        self.assertEqual(after_recovery, before_recovery)
        self.assertEqual(
            after_vault,
            before_vault + [vault_storage.generation_name(2)],
        )


if __name__ == "__main__":
    unittest.main()
