"""Adversarial state-transition tests for Stage 2.47 profile recovery.

These tests exercise only disposable low-cost profiles.  They deliberately
combine valid, stale, damaged, cross-profile, replayed, and interrupted input
and assert that every refusal leaves the current Vault generation unchanged.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mokosh_profile_gui as profile_gui
import mokosh_profile_recovery as recovery
import mokosh_profile_recovery_state as recovery_state
import mokosh_profile_storage as profile_storage
import mokosh_vault_recovery as vault_recovery


CREATED = "2026-09-14T08:00:00Z"
RECOVERY_CREATED = "2026-09-14T09:00:00Z"
UPDATED = "2026-09-14T10:00:00Z"
OLD_PASSWORD_A = "Stage 2.47 original password A"
OLD_PASSWORD_B = "Stage 2.47 original password B"
NEW_PASSWORD = "Stage 2.47 replacement password"


class ProfileRecoveryAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-profile-recovery-adversarial-"
        )
        self.root = Path(self.context.name)
        os.chmod(self.root, 0o700)
        self.profile_a = self.root / "profile-a"
        self.profile_b = self.root / "profile-b"
        self.exports_a = self.root / "exports-a"
        self.exports_b = self.root / "exports-b"
        self.attacks = self.root / "attacks"
        for path in (self.exports_a, self.exports_b, self.attacks):
            path.mkdir(mode=0o700)
        self._create_profile(self.profile_a, "Recovery A", OLD_PASSWORD_A)

    def tearDown(self):
        self.context.cleanup()

    @staticmethod
    def _create_profile(root, nickname, password):
        profile_storage.create_profile(
            nickname,
            password,
            root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )

    @staticmethod
    def _snapshot(root):
        return profile_storage.load_profile(root)

    @staticmethod
    def _setup(root, password, export_parent):
        plan = recovery.begin_profile_recovery_setup(
            root,
            password,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            created_utc=RECOVERY_CREATED,
        )
        words = plan.phrase_words
        plan.export_record(export_parent)
        plan.confirm_paper_backup(words)
        result = plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        return result, words

    @staticmethod
    def _prepare(root, record_path, words):
        return recovery.prepare_profile_password_recovery_from_words(
            root,
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

    def _private_attack_copy(self, name, payload):
        path = self.attacks / name
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        return path

    def test_damaged_truncated_appended_and_unsupported_records_fail_closed(self):
        setup, words = self._setup(
            self.profile_a, OLD_PASSWORD_A, self.exports_a
        )
        original = Path(setup.record_path).read_bytes()
        unsupported = bytearray(original)
        unsupported[len(vault_recovery.RECOVERY_MAGIC)] = 127
        variants = {
            "truncated.mokr": original[:-1],
            "appended.mokr": original + b"trailing-data",
            "unsupported.mokr": bytes(unsupported),
            "damaged.mokr": original[:-17] + bytes([original[-17] ^ 1]) + original[-16:],
        }
        before = self._snapshot(self.profile_a)
        for name, payload in variants.items():
            with self.subTest(name=name):
                path = self._private_attack_copy(name, payload)
                with self.assertRaises(recovery.ProfileRecoveryStateError):
                    self._prepare(self.profile_a, path, words)
                self.assertEqual(self._snapshot(self.profile_a), before)

    def test_cross_profile_record_phrase_and_vault_mixups_never_publish(self):
        self._create_profile(self.profile_b, "Recovery B", OLD_PASSWORD_B)
        setup_a, words_a = self._setup(
            self.profile_a, OLD_PASSWORD_A, self.exports_a
        )
        setup_b, words_b = self._setup(
            self.profile_b, OLD_PASSWORD_B, self.exports_b
        )
        before_a = self._snapshot(self.profile_a)
        before_b = self._snapshot(self.profile_b)
        attempts = (
            (self.profile_a, setup_b.record_path, words_a),
            (self.profile_a, setup_a.record_path, words_b),
            (self.profile_b, setup_a.record_path, words_a),
        )
        for root, record, words in attempts:
            with self.subTest(root=root.name, record=Path(record).name):
                with self.assertRaises(recovery.ProfileRecoveryStateError):
                    self._prepare(root, record, words)
        self.assertEqual(self._snapshot(self.profile_a), before_a)
        self.assertEqual(self._snapshot(self.profile_b), before_b)

    def test_two_prepared_candidates_allow_one_publish_and_refuse_replay(self):
        setup, words = self._setup(
            self.profile_a, OLD_PASSWORD_A, self.exports_a
        )
        first = self._prepare(self.profile_a, setup.record_path, words)
        second = self._prepare(self.profile_a, setup.record_path, words)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        after_first = self._snapshot(self.profile_a)
        self.assertEqual(after_first.receipt.revision, 2)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            second.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            first.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        self.assertEqual(self._snapshot(self.profile_a), after_first)

    def test_replacement_state_survives_restart_and_reminds_only_twice(self):
        setup, words = self._setup(
            self.profile_a, OLD_PASSWORD_A, self.exports_a
        )
        prepared = self._prepare(self.profile_a, setup.record_path, words)
        prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)

        initial = recovery_state.inspect_profile_recovery_state(self.profile_a)
        self.assertTrue(initial.replacement_required)
        reminders = []
        for _attempt in range(3):
            controller = profile_gui.ProfileApplicationController(self.profile_a)
            try:
                self.assertTrue(controller.recovery_state.replacement_required)
                result = controller.login("Recovery A", NEW_PASSWORD)
                self.assertTrue(result.unlocked)
                notice = controller.consume_recovery_login_notice()
                self.assertIsNotNone(notice)
                reminders.append(notice.show_reminder)
            finally:
                controller.close()
        self.assertEqual(reminders, [True, True, False])
        final = recovery_state.inspect_profile_recovery_state(self.profile_a)
        self.assertTrue(final.replacement_required)
        self.assertEqual(final.replacement_reminders_shown, 2)

    def test_short_state_write_after_external_exports_is_terminal_and_safe(self):
        before = self._snapshot(self.profile_a)
        plan = recovery.begin_profile_recovery_setup(
            self.profile_a,
            OLD_PASSWORD_A,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            created_utc=RECOVERY_CREATED,
        )
        words = plan.phrase_words
        plan.export_record(self.exports_a)
        record_path = plan.record_path
        self.assertIsNotNone(record_path)
        plan.confirm_paper_backup(words)
        with mock.patch.object(recovery_state.os, "write", return_value=0):
            with self.assertRaises(recovery.ProfileRecoveryLifecyclePublishError):
                plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        self.assertTrue(Path(record_path).is_file())
        self.assertEqual(self._snapshot(self.profile_a), before)
        self.assertFalse(
            recovery_state.inspect_profile_recovery_state(
                self.profile_a
            ).recovery_available
        )
        with self.assertRaises(recovery.ProfileRecoveryStateError):
            plan.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)


if __name__ == "__main__":
    unittest.main()
