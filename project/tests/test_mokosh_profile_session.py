import os
import tempfile
import unittest
from pathlib import Path

import mokosh_profile_session as session
import mokosh_profile_storage as storage
from mokosh_v2_key_slots import KeyVaultSlot
from mokosh_v2_operation_lifecycle import CancellationToken
from mokosh_vault_keyring import VaultKeyVersionNotFoundError


PASSWORD = "Stage 2.46 password value"
NICKNAME = "Session tester"


class FakeClock:
    def __init__(self, value):
        self.value = float(value)

    def __call__(self):
        return self.value


class SecureProfileSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = tempfile.TemporaryDirectory(prefix="mokosh-session-test-")
        cls.parent = Path(cls.context.name)
        os.chmod(cls.parent, 0o700)
        cls.root = cls.parent / "profile"
        storage.create_profile(
            NICKNAME,
            PASSWORD,
            cls.root,
            created_utc="2026-09-11T10:00:00Z",
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        cls.snapshot = storage.load_profile(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.context.cleanup()

    def make_session(self, *, timeout=900, suspend_gap=30, tolerance=5):
        monotonic = FakeClock(100)
        wall = FakeClock(1000)
        value = session.SecureProfileSession(
            self.snapshot,
            inactivity_timeout=timeout,
            suspend_gap=suspend_gap,
            clock_skew_tolerance=tolerance,
            monotonic=monotonic,
            wall_clock=wall,
        )
        self.addCleanup(value.close)
        return value, monotonic, wall

    def test_correct_login_is_explicit_and_clears_both_fields(self):
        value, _, _ = self.make_session()
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)
        result = value.unlock(NICKNAME, PASSWORD)
        self.assertEqual(result, session.LoginResult(True, True, True))
        self.assertIs(value.state, session.ProfileSessionState.UNLOCKED)
        self.assertNotIn(PASSWORD, repr(value))
        self.assertNotIn(NICKNAME, repr(value))

    def test_wrong_password_and_nickname_have_same_result(self):
        for nickname, password in (
            (NICKNAME, "Wrong password value 2.46"),
            ("Wrong nickname", PASSWORD),
            (NICKNAME, "short"),
        ):
            value, _, _ = self.make_session()
            with self.subTest(nickname=nickname):
                result = value.unlock(nickname, password)
                self.assertEqual(result, session.LoginResult(False, True, False))
                self.assertIs(value.state, session.ProfileSessionState.LOCKED)

    def test_only_finished_normal_actions_are_enabled_after_login(self):
        value, _, _ = self.make_session()
        self.assertFalse(any(value.capabilities.values()))
        value.unlock(NICKNAME, PASSWORD)
        enabled = {key for key, allowed in value.capabilities.items() if allowed}
        self.assertEqual(
            enabled,
            {
                session.ProfileCapability.LEGACY_MOK1_DECRYPT,
                session.ProfileCapability.V2_LOCAL_ENCRYPT,
                session.ProfileCapability.V2_LOCAL_DECRYPT,
                session.ProfileCapability.RECOVERY_PHRASE,
            },
        )

    def test_local_v2_lease_builds_exactly_one_active_vault_slot(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        token = CancellationToken()
        with value._begin_local_v2_operation(token) as lease:
            plan, slot = lease.encryption_plan()
            self.assertIs(lease.cancellation, token)
            self.assertEqual(len(plan.slots), 1)
            self.assertEqual(plan.slots, (slot,))
            self.assertIsInstance(slot, KeyVaultSlot)
            self.assertEqual(slot.vault_key_version, 1)
            self.assertNotIn(PASSWORD, repr(lease))
            self.assertNotIn(NICKNAME, repr(lease))
        self.assertTrue(lease.closed)

    def test_local_v2_lease_selects_only_the_exact_key_version(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        with value._begin_local_v2_operation() as lease:
            credential = lease.credential_for_version(1)
            self.assertEqual(len(credential.vault_root_key), 32)
            with self.assertRaises(VaultKeyVersionNotFoundError):
                lease.credential_for_version(2)

    def test_only_one_local_v2_operation_can_hold_keys(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        first = value._begin_local_v2_operation()
        with self.assertRaises(session.ProfileSessionError):
            value._begin_local_v2_operation()
        first.close()
        second = value._begin_local_v2_operation()
        second.close()

    def test_lock_cancels_active_operation_and_blocks_reunlock_until_drained(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        token = CancellationToken()
        lease = value._begin_local_v2_operation(token)
        value.panic_lock()
        self.assertTrue(token.cancelled)
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)
        with self.assertRaises(session.ProfileSessionError):
            value.unlock(NICKNAME, PASSWORD)
        lease.close()
        self.assertTrue(value.unlock(NICKNAME, PASSWORD).unlocked)

    def test_keyless_cleanup_lease_shares_exclusion_and_lock_drain(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        token = CancellationToken()
        lease = value._begin_local_v2_cleanup_operation(token)
        self.assertIs(lease.cancellation, token)
        self.assertFalse(hasattr(lease, "encryption_plan"))
        self.assertFalse(hasattr(lease, "credential_for_version"))
        with self.assertRaises(session.ProfileOperationBusyError):
            value._begin_local_v2_operation()

        value.panic_lock()
        self.assertTrue(token.cancelled)
        with self.assertRaises(session.ProfileOperationBusyError):
            value.unlock(NICKNAME, PASSWORD)
        lease.close()
        self.assertTrue(lease.closed)
        self.assertTrue(value.unlock(NICKNAME, PASSWORD).unlocked)

    def test_cancellation_token_subclasses_are_rejected(self):
        class TokenSubclass(CancellationToken):
            def __bool__(self):
                return False

        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        for begin in (
            value._begin_local_v2_operation,
            value._begin_local_v2_cleanup_operation,
        ):
            with self.subTest(begin=begin.__name__):
                with self.assertRaises(session.ProfileSessionError):
                    begin(TokenSubclass())

    def test_inactivity_and_close_cancel_active_operation(self):
        value, monotonic, wall = self.make_session(timeout=10, suspend_gap=100)
        value.unlock(NICKNAME, PASSWORD)
        timeout_token = CancellationToken()
        timeout_lease = value._begin_local_v2_operation(timeout_token)
        monotonic.value += 10
        wall.value += 10
        self.assertTrue(value.check().locked)
        self.assertTrue(timeout_token.cancelled)
        timeout_lease.close()

        self.assertTrue(value.unlock(NICKNAME, PASSWORD).unlocked)
        close_token = CancellationToken()
        close_lease = value._begin_local_v2_operation(close_token)
        value.close()
        self.assertTrue(close_token.cancelled)
        self.assertIs(value.state, session.ProfileSessionState.CLOSED)
        close_lease.close()

    def test_manual_and_panic_lock_are_idempotent(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        value.panic_lock()
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)
        self.assertIs(value.last_lock_reason, session.ProfileLockReason.PANIC)
        value.lock(session.ProfileLockReason.USER)
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)

    def test_inactivity_locks(self):
        value, monotonic, wall = self.make_session(timeout=10, suspend_gap=100)
        value.unlock(NICKNAME, PASSWORD)
        monotonic.value += 10
        wall.value += 10
        result = value.check()
        self.assertEqual(
            result,
            session.SessionCheckResult(True, session.ProfileLockReason.INACTIVITY),
        )
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)

    def test_activity_resets_inactivity_deadline(self):
        value, monotonic, wall = self.make_session(timeout=10, suspend_gap=100)
        value.unlock(NICKNAME, PASSWORD)
        monotonic.value += 8
        wall.value += 8
        value.touch()
        monotonic.value += 8
        wall.value += 8
        self.assertFalse(value.check().locked)

    def test_suspend_gap_locks_even_before_timeout(self):
        value, monotonic, wall = self.make_session(timeout=900, suspend_gap=30)
        value.unlock(NICKNAME, PASSWORD)
        monotonic.value += 31
        wall.value += 31
        result = value.check()
        self.assertIs(result.reason, session.ProfileLockReason.SUSPEND_OR_CLOCK)
        self.assertIs(value.state, session.ProfileSessionState.LOCKED)

    def test_backward_monotonic_and_wall_skew_lock(self):
        for change in ("monotonic", "wall"):
            value, monotonic, wall = self.make_session(suspend_gap=100)
            value.unlock(NICKNAME, PASSWORD)
            if change == "monotonic":
                monotonic.value -= 1
            else:
                wall.value -= 6
            with self.subTest(change=change):
                result = value.check()
                self.assertTrue(result.locked)
                self.assertIs(value.state, session.ProfileSessionState.LOCKED)

    def test_wall_and_monotonic_divergence_locks(self):
        value, monotonic, wall = self.make_session(suspend_gap=100, tolerance=5)
        value.unlock(NICKNAME, PASSWORD)
        monotonic.value += 1
        wall.value += 10
        self.assertIs(
            value.check().reason,
            session.ProfileLockReason.SUSPEND_OR_CLOCK,
        )

    def test_close_locks_and_prevents_reuse(self):
        value, _, _ = self.make_session()
        value.unlock(NICKNAME, PASSWORD)
        value.close()
        self.assertIs(value.state, session.ProfileSessionState.CLOSED)
        with self.assertRaises(session.ProfileSessionError):
            value.unlock(NICKNAME, PASSWORD)

    def test_registry_contains_every_capability_in_every_state(self):
        for state in session.ProfileSessionState:
            with self.subTest(state=state):
                registry = session.capability_registry(state)
                self.assertEqual(set(registry), set(session.ProfileCapability))
                self.assertFalse(registry[session.ProfileCapability.NETWORK])
                self.assertIs(
                    registry[session.ProfileCapability.RECOVERY_PHRASE],
                    state is session.ProfileSessionState.UNLOCKED,
                )


if __name__ == "__main__":
    unittest.main()
