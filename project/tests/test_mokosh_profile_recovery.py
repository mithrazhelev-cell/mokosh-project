import copy
import hashlib
import os
import pickle
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mokosh_profile_recovery as recovery
import mokosh_profile_recovery_state as recovery_state
import mokosh_profile_storage as profile_storage
import mokosh_recovery_phrase_storage as phrase_storage
import mokosh_vault_format as vault
import mokosh_vault_recovery as recovery_core
import mokosh_vault_recovery_reconciliation as reconciliation
import mokosh_vault_storage as vault_storage


OLD_PASSWORD = "Stage 2.47 original password"
NEW_PASSWORD = "Stage 2.47 replacement password"
NICKNAME = "Recovery tester"
CREATED = "2026-09-13T08:00:00Z"
RECOVERY_CREATED = "2026-09-13T09:00:00Z"
UPDATED = "2026-09-13T10:00:00Z"


class ProfileRecoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-profile-recovery-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.profile_root = self.parent / "profile"
        self.record_parent = self.parent / "record-parent"
        self.record_parent.mkdir(mode=0o700)
        self.phrase_parent = self.parent / "phrase-parent"
        self.phrase_parent.mkdir(mode=0o700)
        profile_storage.create_profile(
            NICKNAME,
            OLD_PASSWORD,
            self.profile_root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )

    def tearDown(self):
        self.context.cleanup()

    def snapshot(self):
        return profile_storage.load_profile(self.profile_root)

    def begin(self):
        return recovery.begin_profile_recovery_setup(
            self.profile_root,
            OLD_PASSWORD,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            created_utc=RECOVERY_CREATED,
        )

    def paper_setup(self):
        plan = self.begin()
        words = plan.phrase_words
        plan.export_record(self.record_parent)
        plan.confirm_paper_backup(words)
        result = plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        return result, words

    def prepare_password_change(self, record_path, words):
        return recovery.prepare_profile_password_recovery_from_words(
            self.profile_root,
            record_path,
            words,
            NEW_PASSWORD,
            NEW_PASSWORD,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )


class ProfileRecoverySetupTests(ProfileRecoveryTestCase):
    def test_setup_requires_explicit_authorization_before_randomness(self):
        before = self.snapshot()
        with mock.patch.object(recovery_core.os, "urandom") as random_source:
            for decision in (
                recovery.ProfileRecoveryDecision.PRESERVE,
                "authorize",
                object(),
            ):
                with self.subTest(decision=decision):
                    with self.assertRaises(recovery.ProfileRecoveryInputError):
                        recovery.begin_profile_recovery_setup(
                            self.profile_root,
                            OLD_PASSWORD,
                            decision,
                        )
        random_source.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_wrong_current_password_creates_no_recovery_material(self):
        before = self.snapshot()
        with self.assertRaises(recovery.ProfileRecoveryAuthenticationError):
            recovery.begin_profile_recovery_setup(
                self.profile_root,
                "Stage 2.47 incorrect password",
                recovery.ProfileRecoveryDecision.AUTHORIZE,
            )
        self.assertEqual(list(self.record_parent.iterdir()), [])
        self.assertEqual(self.snapshot(), before)

    def test_paper_setup_verifies_all_words_without_vault_publish(self):
        before = self.snapshot()
        result, words = self.paper_setup()
        after = self.snapshot()
        self.assertEqual(after, before)
        self.assertEqual(result.source_revision, 1)
        self.assertEqual(result.backup_kind, recovery.ProfileRecoveryBackupKind.PAPER)
        self.assertIsNone(result.phrase_path)
        self.assertFalse(result.vault_publish_performed)
        self.assertTrue(Path(result.record_path).is_file())
        self.assertEqual(len(words), 25)
        self.assertTrue(
            recovery_state.inspect_profile_recovery_state(
                self.profile_root
            ).recovery_available
        )

    def test_setup_plan_is_nonserializable_and_hides_phrase(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        self.assertNotIn(plan.phrase_words[0], repr(plan))
        for operation in (
            lambda: copy.copy(plan),
            lambda: copy.deepcopy(plan),
            lambda: pickle.dumps(plan),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_record_must_precede_phrase_and_complete_backup(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            plan.export_phrase(self.phrase_parent)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        plan.export_record(self.record_parent)
        with self.assertRaises(recovery.ProfileRecoveryBackupError):
            plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)

    def test_wrong_paper_phrase_is_rejected_without_guessing(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        words = list(plan.phrase_words)
        plan.export_record(self.record_parent)
        words[-1] = "zoo" if words[-1] != "zoo" else "zone"
        with self.assertRaises(recovery.ProfileRecoveryBackupError):
            plan.confirm_paper_backup(words)
        self.assertFalse(plan.backup_verified)

    def test_material_cannot_be_exported_inside_profile(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            plan.export_record(self.profile_root)
        self.assertEqual(
            set(path.name for path in self.profile_root.iterdir()),
            {"profile.json", "key-vault"},
        )

    def test_same_device_phrase_export_is_refused(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        plan.export_record(self.record_parent)
        with self.assertRaises(recovery.ProfileRecoverySeparationError):
            plan.export_phrase(self.phrase_parent)
        self.assertEqual(list(self.phrase_parent.iterdir()), [])

    def test_uncertain_record_export_is_reported_without_retry(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        with mock.patch.object(
            recovery,
            "export_recovery_record",
            side_effect=recovery.RecoveryExportUncertainError("synthetic"),
        ) as export:
            with self.assertRaises(
                recovery.ProfileRecoveryExportUncertainError
            ):
                plan.export_record(self.record_parent)
        export.assert_called_once()
        self.assertEqual(len(list(self.record_parent.iterdir())), 1)
        self.assertFalse(plan.record_exported)

    def test_unsupported_record_storage_has_specific_result(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        with mock.patch.object(
            recovery,
            "create_private_recovery_directory",
            side_effect=phrase_storage.RecoveryPhraseExportUnsupportedError(
                "synthetic unsupported filesystem"
            ),
        ):
            with self.assertRaises(
                recovery.ProfileRecoveryStorageUnsupportedError
            ):
                plan.export_record(self.record_parent)
        self.assertFalse(plan.record_exported)
        self.assertEqual(list(self.record_parent.iterdir()), [])

    def test_verified_separate_sheet_flow_uses_no_manual_reentry(self):
        plan = self.begin()
        words = plan.phrase_words
        plan.export_record(self.record_parent)
        with mock.patch.object(
            phrase_storage,
            "_require_separate_device",
            return_value=None,
        ):
            plan.export_phrase(self.phrase_parent)
            result = plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        self.assertEqual(
            result.backup_kind,
            recovery.ProfileRecoveryBackupKind.SEPARATE_FILE,
        )
        self.assertIsNotNone(result.phrase_path)
        self.assertEqual(len(words), 25)
        self.assertTrue(Path(result.phrase_path).is_file())


class ProfilePasswordRecoveryTests(ProfileRecoveryTestCase):
    def test_read_only_preview_then_explicit_publish_changes_only_vault_history(self):
        setup, words = self.paper_setup()
        before = self.snapshot()
        record_before = Path(setup.record_path).read_bytes()
        prepared = self.prepare_password_change(setup.record_path, words)
        preview = prepared.preview
        middle = self.snapshot()
        self.assertEqual(middle, before)
        self.assertEqual(preview.source_revision, 1)
        self.assertEqual(preview.target_revision, 2)
        self.assertFalse(preview.publish_performed)
        result = prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        after = self.snapshot()
        self.assertEqual(after.receipt.revision, 2)
        self.assertEqual(after.descriptor, before.descriptor)
        self.assertEqual(Path(setup.record_path).read_bytes(), record_before)
        self.assertTrue(result.profile_locked_after_publish)
        self.assertTrue(result.source_generation_preserved)
        vault_dir = self.profile_root / profile_storage.PROFILE_VAULT_DIRECTORY_NAME
        with vault_storage.VaultStorage(vault_dir) as store:
            report = store.scan()
            self.assertEqual(tuple(item.revision for item in report.generations), (1, 2))
            store.verify_receipt(before.receipt)
        session = vault.VaultSession(after.vault_bytes)
        try:
            with self.assertRaises(vault.VaultError):
                session.unlock(OLD_PASSWORD)
            session.reset_failure()
            session.unlock(NEW_PASSWORD)
            self.assertIs(session.state, vault.VaultSessionState.UNLOCKED)
        finally:
            session.close()

    def test_prepare_rejects_wrong_phrase_and_password_mismatch_without_publish(self):
        setup, words = self.paper_setup()
        before = self.snapshot()
        wrong = list(words)
        wrong[-1] = "zoo" if wrong[-1] != "zoo" else "zone"
        with self.assertRaises(recovery.ProfileRecoveryInputError):
            self.prepare_password_change(setup.record_path, wrong)
        with self.assertRaises(recovery.ProfileRecoveryInputError):
            recovery.prepare_profile_password_recovery_from_words(
                self.profile_root,
                setup.record_path,
                words,
                NEW_PASSWORD,
                "Stage 2.47 different replacement",
                recovery.ProfileRecoveryDecision.AUTHORIZE,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
        self.assertEqual(self.snapshot(), before)

    def test_prepare_and_publish_each_require_explicit_decision(self):
        setup, words = self.paper_setup()
        with self.assertRaises(recovery.ProfileRecoveryInputError):
            recovery.prepare_profile_password_recovery_from_words(
                self.profile_root,
                setup.record_path,
                words,
                NEW_PASSWORD,
                NEW_PASSWORD,
                recovery.ProfileRecoveryDecision.PRESERVE,
            )
        prepared = self.prepare_password_change(setup.record_path, words)
        self.addCleanup(prepared.close)
        with self.assertRaises(recovery.ProfileRecoveryInputError):
            prepared.publish(recovery.ProfileRecoveryDecision.PRESERVE)
        self.assertEqual(self.snapshot().receipt.revision, 1)

    def test_prepared_recovery_is_one_shot_nonserializable_and_secret_free_repr(self):
        setup, words = self.paper_setup()
        prepared = self.prepare_password_change(setup.record_path, words)
        self.assertNotIn(NEW_PASSWORD, repr(prepared))
        self.assertNotIn(" ".join(words), repr(prepared))
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(TypeError):
                operation()
        prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)

    def test_old_record_becomes_stale_for_latest_profile(self):
        setup, words = self.paper_setup()
        prepared = self.prepare_password_change(setup.record_path, words)
        prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        lifecycle = recovery_state.inspect_profile_recovery_state(self.profile_root)
        self.assertTrue(lifecycle.replacement_required)
        self.assertFalse(lifecycle.recovery_available)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            recovery.prepare_profile_password_recovery_from_words(
                self.profile_root,
                setup.record_path,
                words,
                "Stage 2.47 another new password",
                "Stage 2.47 another new password",
                recovery.ProfileRecoveryDecision.AUTHORIZE,
                updated_utc="2026-09-13T11:00:00Z",
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )

    def test_setup_completion_does_not_claim_availability_if_receipt_fails(self):
        plan = self.begin()
        self.addCleanup(plan.close)
        words = plan.phrase_words
        plan.export_record(self.record_parent)
        plan.confirm_paper_backup(words)
        with mock.patch.object(
            recovery,
            "publish_current_profile_recovery_state",
            side_effect=recovery.ProfileRecoveryReceiptError("injected"),
        ):
            with self.assertRaises(recovery.ProfileRecoveryLifecyclePublishError):
                plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        self.assertFalse(
            recovery_state.inspect_profile_recovery_state(
                self.profile_root
            ).recovery_available
        )

    def test_sheet_and_record_identifier_mismatch_is_rejected(self):
        setup, words = self.paper_setup()
        other_id = b"Z" * 16
        directory = phrase_storage.create_private_recovery_directory(
            self.phrase_parent,
            phrase_storage.RecoveryMaterialKind.PHRASE,
            other_id,
            forbidden_devices=(2**62,),
        )
        phrase_storage.export_recovery_phrase_sheet(
            other_id,
            words,
            directory.path,
            forbidden_devices=(2**62,),
        )
        phrase_path = Path(directory.path) / phrase_storage.recovery_phrase_file_name(other_id)
        with mock.patch.object(
            phrase_storage,
            "_require_separate_device",
            return_value=None,
        ):
            with self.assertRaises(recovery.ProfileRecoveryStateError):
                recovery.prepare_profile_password_recovery_from_sheet(
                    self.profile_root,
                    setup.record_path,
                    phrase_path,
                    NEW_PASSWORD,
                    NEW_PASSWORD,
                    recovery.ProfileRecoveryDecision.AUTHORIZE,
                    updated_utc=UPDATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )

    def test_sheet_on_protected_device_has_specific_separation_error(self):
        setup, words = self.paper_setup()
        recovery_id = bytes.fromhex(Path(setup.record_path).stem.rsplit("-", 1)[1])
        directory = phrase_storage.create_private_recovery_directory(
            self.phrase_parent,
            phrase_storage.RecoveryMaterialKind.PHRASE,
            recovery_id,
            forbidden_devices=(2**62,),
        )
        phrase_storage.export_recovery_phrase_sheet(
            recovery_id,
            words,
            directory.path,
            forbidden_devices=(2**62,),
        )
        phrase_path = Path(directory.path) / phrase_storage.recovery_phrase_file_name(
            recovery_id
        )
        with self.assertRaises(recovery.ProfileRecoverySeparationError):
            recovery.prepare_profile_password_recovery_from_sheet(
                self.profile_root,
                setup.record_path,
                phrase_path,
                NEW_PASSWORD,
                NEW_PASSWORD,
                recovery.ProfileRecoveryDecision.AUTHORIZE,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )

    def test_uncertain_publish_conflict_is_never_retried(self):
        setup, words = self.paper_setup()
        prepared = self.prepare_password_change(setup.record_path, words)
        conflict = SimpleNamespace(
            classification=reconciliation.RecoveryPublishClassification.CONFLICT
        )
        with mock.patch.object(
            recovery,
            "publish_recovery_candidate",
            side_effect=recovery.VaultRecoveryPublishUncertainError("uncertain"),
        ) as publish, mock.patch.object(
            recovery,
            "reconcile_recovery_publish",
            return_value=conflict,
        ) as reconcile:
            with self.assertRaises(recovery.ProfileRecoveryPublishUncertainError):
                prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        publish.assert_called_once()
        reconcile.assert_called_once()
        self.assertEqual(self.snapshot().receipt.revision, 1)


if __name__ == "__main__":
    unittest.main()
