import dataclasses
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mokosh_profile_recovery_state as recovery_state
import mokosh_profile_storage as profile_storage


PASSWORD = "Stage 2.47 recovery state password"
NICKNAME = "Recovery state tester"
CREATED = "2026-09-15T10:00:00Z"
RECOVERY_ID = bytes.fromhex("11" * 16)


class ProfileRecoveryStateTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="mokosh-recovery-state-")
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.root = self.parent / "profile"
        profile_storage.create_profile(
            NICKNAME,
            PASSWORD,
            self.root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.snapshot = profile_storage.load_profile(self.root)

    def tearDown(self):
        self.context.cleanup()

    def publish(self):
        return recovery_state.publish_current_profile_recovery_state(
            self.root,
            RECOVERY_ID,
            self.snapshot.receipt,
        )

    def later_snapshot(self, amount=1):
        return dataclasses.replace(
            self.snapshot,
            receipt=dataclasses.replace(
                self.snapshot.receipt,
                revision=self.snapshot.receipt.revision + amount,
            ),
        )


class RecoveryStateFormatTests(unittest.TestCase):
    def test_canonical_round_trip_contains_only_public_bounded_fields(self):
        record = recovery_state.ProfileRecoveryStateRecord(
            profile_id="11" * 16,
            vault_id="22" * 16,
            recovery_id="33" * 16,
            source_revision=7,
            replacement_reminders_shown=2,
        )
        encoded = recovery_state.encode_profile_recovery_state(record)
        self.assertEqual(recovery_state.parse_profile_recovery_state(encoded), record)
        self.assertLessEqual(
            len(encoded), recovery_state.MAX_PROFILE_RECOVERY_STATE_BYTES
        )
        self.assertEqual(
            set(json.loads(encoded)),
            {
                "format",
                "version",
                "profile_id",
                "vault_id",
                "recovery_id",
                "source_revision",
                "replacement_reminders_shown",
            },
        )
        lowered = encoded.lower()
        for forbidden in (b"password", b"phrase", b"word", b"path", b"key"):
            self.assertNotIn(forbidden, lowered)

    def test_parser_rejects_duplicates_noncanonical_values_and_bounds(self):
        record = recovery_state.ProfileRecoveryStateRecord(
            profile_id="11" * 16,
            vault_id="22" * 16,
            recovery_id="33" * 16,
            source_revision=1,
        )
        encoded = recovery_state.encode_profile_recovery_state(record)
        duplicated = encoded[:-1] + b',"version":1}'
        noncanonical = json.dumps(json.loads(encoded), indent=1).encode("ascii")
        for value in (
            b"",
            duplicated,
            noncanonical,
            b"x" * (recovery_state.MAX_PROFILE_RECOVERY_STATE_BYTES + 1),
        ):
            with self.subTest(size=len(value)):
                with self.assertRaises(recovery_state.ProfileRecoveryStateFormatError):
                    recovery_state.parse_profile_recovery_state(value)

    def test_encoder_rejects_invalid_identifiers_revisions_and_counters(self):
        base = {
            "profile_id": "11" * 16,
            "vault_id": "22" * 16,
            "recovery_id": "33" * 16,
            "source_revision": 1,
        }
        cases = (
            {"profile_id": "AA" * 16},
            {"vault_id": "22" * 15},
            {"recovery_id": "z" * 32},
            {"source_revision": 0},
            {"source_revision": True},
            {"replacement_reminders_shown": 3},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(recovery_state.ProfileRecoveryStateFormatError):
                    recovery_state.encode_profile_recovery_state(
                        recovery_state.ProfileRecoveryStateRecord(
                            **(base | changes)
                        )
                    )


class RecoveryStateLifecycleTests(ProfileRecoveryStateTestCase):
    def test_missing_state_fails_closed_without_breaking_profile(self):
        inspection = recovery_state.inspect_profile_recovery_state(self.root)
        self.assertIs(
            inspection.availability,
            recovery_state.ProfileRecoveryAvailability.MISSING,
        )
        self.assertFalse(inspection.recovery_available)
        self.assertIs(
            profile_storage.inspect_profile(self.root).state,
            profile_storage.ProfileState.READY,
        )

    def test_publish_is_private_current_and_does_not_leak_secrets(self):
        inspection = self.publish()
        self.assertTrue(inspection.recovery_available)
        state_directory = (
            self.root / profile_storage.PROFILE_RECOVERY_STATE_DIRECTORY_NAME
        )
        state_file = state_directory / recovery_state.PROFILE_RECOVERY_STATE_NAME
        self.assertEqual(stat.S_IMODE(os.lstat(state_directory).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(state_file).st_mode), 0o600)
        self.assertEqual(os.lstat(state_file).st_nlink, 1)
        persisted = state_file.read_bytes()
        self.assertNotIn(PASSWORD.encode(), persisted)
        self.assertNotIn(os.fsencode(self.root), persisted)
        self.assertNotIn("11" * 16, repr(inspection))

    def test_state_is_bound_to_profile_vault_revision_and_recovery_id(self):
        self.publish()
        current = recovery_state.inspect_profile_recovery_state(
            self.root, snapshot=self.snapshot
        )
        stale = recovery_state.inspect_profile_recovery_state(
            self.root, snapshot=self.later_snapshot()
        )
        future = recovery_state.inspect_profile_recovery_state(
            self.root,
            snapshot=dataclasses.replace(
                self.snapshot,
                receipt=dataclasses.replace(self.snapshot.receipt, revision=0),
            ),
        )
        self.assertTrue(current.recovery_available)
        self.assertTrue(stale.replacement_required)
        self.assertIs(
            future.availability,
            recovery_state.ProfileRecoveryAvailability.INVALID,
        )
        record = current._record
        self.assertIsNotNone(record)
        self.assertEqual(record.recovery_id, RECOVERY_ID.hex())

    def test_only_first_two_successful_logins_after_stale_state_remind(self):
        self.publish()
        later = self.later_snapshot()
        results = []
        with mock.patch.object(recovery_state, "load_profile", return_value=later):
            for _ in range(3):
                results.append(
                    recovery_state.note_successful_login_for_recovery(self.root)
                )
        self.assertEqual([item.show_reminder for item in results], [True, True, False])
        self.assertEqual([item.reminder_number for item in results], [1, 2, 0])
        self.assertEqual(results[-1].inspection.replacement_reminders_shown, 2)

    def test_current_state_never_shows_replacement_reminder(self):
        self.publish()
        notice = recovery_state.note_successful_login_for_recovery(self.root)
        self.assertFalse(notice.show_reminder)
        self.assertTrue(notice.inspection.recovery_available)

    def test_wrong_expected_vault_receipt_cannot_publish(self):
        wrong = dataclasses.replace(
            self.snapshot.receipt,
            revision=self.snapshot.receipt.revision + 1,
        )
        with self.assertRaises(recovery_state.ProfileRecoveryStateConflictError):
            recovery_state.publish_current_profile_recovery_state(
                self.root,
                RECOVERY_ID,
                wrong,
            )
        self.assertFalse(
            recovery_state.inspect_profile_recovery_state(self.root).recovery_available
        )

    def test_invalid_state_is_disabled_and_authenticated_setup_can_repair_it(self):
        self.publish()
        state_file = (
            self.root
            / profile_storage.PROFILE_RECOVERY_STATE_DIRECTORY_NAME
            / recovery_state.PROFILE_RECOVERY_STATE_NAME
        )
        state_file.write_bytes(b"{}")
        os.chmod(state_file, 0o600)
        self.assertIs(
            recovery_state.inspect_profile_recovery_state(self.root).availability,
            recovery_state.ProfileRecoveryAvailability.INVALID,
        )
        self.assertTrue(self.publish().recovery_available)

    def test_symlink_unknown_object_and_insecure_mode_fail_closed(self):
        self.publish()
        state_directory = (
            self.root / profile_storage.PROFILE_RECOVERY_STATE_DIRECTORY_NAME
        )
        state_file = state_directory / recovery_state.PROFILE_RECOVERY_STATE_NAME
        state_file.unlink()
        state_file.symlink_to(self.root / profile_storage.PROFILE_DESCRIPTOR_NAME)
        self.assertIs(
            recovery_state.inspect_profile_recovery_state(self.root).availability,
            recovery_state.ProfileRecoveryAvailability.INVALID,
        )
        state_file.unlink()
        (state_directory / "unexpected").write_text("keep", encoding="ascii")
        os.chmod(state_directory / "unexpected", 0o600)
        self.assertIs(
            recovery_state.inspect_profile_recovery_state(self.root).availability,
            recovery_state.ProfileRecoveryAvailability.INVALID,
        )

    def test_interrupted_known_temp_keeps_missing_or_current_state_usable(self):
        state_directory = (
            self.root / profile_storage.PROFILE_RECOVERY_STATE_DIRECTORY_NAME
        )
        state_directory.mkdir(mode=0o700)
        os.chmod(state_directory, 0o700)
        temporary = state_directory / (".recovery-state-" + "a" * 32 + ".tmp")
        temporary.write_bytes(b"")
        os.chmod(temporary, 0o600)
        missing = recovery_state.inspect_profile_recovery_state(self.root)
        self.assertIs(
            missing.availability,
            recovery_state.ProfileRecoveryAvailability.MISSING,
        )
        self.assertEqual(missing.reason, "interrupted")
        self.publish()
        self.assertTrue(
            recovery_state.inspect_profile_recovery_state(self.root).recovery_available
        )

    def test_reminder_compare_and_swap_refuses_concurrent_change(self):
        self.publish()
        later = self.later_snapshot()
        real_publish = recovery_state._publish_state

        def conflict(*args, **kwargs):
            raise recovery_state.ProfileRecoveryStateConflictError("injected")

        with mock.patch.object(recovery_state, "load_profile", return_value=later):
            with mock.patch.object(recovery_state, "_publish_state", side_effect=conflict):
                with self.assertRaises(
                    recovery_state.ProfileRecoveryStateConflictError
                ):
                    recovery_state.note_successful_login_for_recovery(self.root)
        self.assertIsNotNone(real_publish)
        unchanged = recovery_state.inspect_profile_recovery_state(
            self.root, snapshot=later
        )
        self.assertEqual(unchanged.replacement_reminders_shown, 0)


if __name__ == "__main__":
    unittest.main()
