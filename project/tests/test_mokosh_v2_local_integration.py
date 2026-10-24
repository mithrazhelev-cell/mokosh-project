import ast
import os
import tempfile
import unittest
from pathlib import Path

from mokosh_profile_gui import ProfileApplicationController
from mokosh_profile_session import (
    ProfileCapability,
    ProfileLockReason,
    ProfileSessionState,
)
from mokosh_profile_storage import create_profile
from mokosh_v2_local_service import LocalV2ErrorCode, LocalV2Service
from mokosh_v2_operation_lifecycle import OperationPhase, ProgressState


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Stage 2.48 integration password"
NICKNAME = "Local integration"


class LocalV2ProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(
            prefix="mokosh-local-integration-"
        )
        self.parent = Path(self._temporary.name)
        os.chmod(self.parent, 0o700)
        self.profile_root = self.parent / "profile"
        self.files = self.parent / "files"
        self.files.mkdir(mode=0o700)
        create_profile(
            NICKNAME,
            PASSWORD,
            self.profile_root,
            created_utc="2026-09-18T12:00:00Z",
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.controller = ProfileApplicationController(self.profile_root)

    def tearDown(self):
        self.controller.close()
        self._temporary.cleanup()

    def unlock_service(self):
        result = self.controller.login(NICKNAME, PASSWORD)
        self.assertTrue(result.unlocked)
        self.assertIsNotNone(self.controller.session)
        return LocalV2Service(self.controller.session)

    def test_controller_session_roundtrip_then_lock_removes_all_v2_capabilities(self):
        service = self.unlock_service()
        enabled = {
            capability
            for capability, allowed in self.controller.capabilities.items()
            if allowed
        }
        self.assertEqual(
            enabled,
            {
                ProfileCapability.LEGACY_MOK1_DECRYPT,
                ProfileCapability.V2_LOCAL_ENCRYPT,
                ProfileCapability.V2_LOCAL_DECRYPT,
                ProfileCapability.RECOVERY_PHRASE,
            },
        )
        source = self.files / "source.bin"
        source.write_bytes(bytes(range(251)) * 80)
        encrypted = self.files / "new.mok2"
        restored = self.files / "restored.bin"
        self.assertTrue(
            service.encrypt(source_path=source, output_path=encrypted).ok
        )
        self.assertTrue(
            service.decrypt(source_path=encrypted, output_path=restored).ok
        )
        self.assertEqual(restored.read_bytes(), source.read_bytes())
        self.assertTrue(source.exists())
        self.assertTrue(encrypted.exists())

        self.controller.lock(ProfileLockReason.USER)
        self.assertIs(self.controller.state, ProfileSessionState.LOCKED)
        self.assertFalse(any(self.controller.capabilities.values()))
        refused = service.encrypt(
            source_path=source,
            output_path=self.files / "locked.mok2",
        )
        self.assertFalse(refused.ok)
        self.assertIs(
            refused.failure.code,
            LocalV2ErrorCode.SESSION_UNAVAILABLE,
        )

    def test_controller_panic_cancels_worker_before_publication(self):
        service = self.unlock_service()
        source = self.files / "source.bin"
        source.write_bytes(b"cancel integration" * 10000)
        output = self.files / "cancelled.mok2"

        def observer(event):
            if (
                event.phase is OperationPhase.ENCRYPT
                and event.state is ProgressState.STARTED
            ):
                self.controller.lock(ProfileLockReason.PANIC)

        result = service.encrypt(
            source_path=source,
            output_path=output,
            observer=observer,
        )
        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, LocalV2ErrorCode.CANCELLED)
        self.assertFalse(output.exists())
        self.assertTrue(source.exists())
        self.assertEqual(list(self.files.glob(".mokosh-quarantine-*")), [])
        self.assertEqual(list(self.files.glob(".mokosh-operation-*")), [])

    def test_local_scope_keeps_out_of_scope_actions_disabled(self):
        self.unlock_service()
        for capability in (
            ProfileCapability.CLEAN_ORIGINALS,
            ProfileCapability.CONTACTS,
            ProfileCapability.CONTACT_CRYPTO,
            ProfileCapability.SANDBOX,
            ProfileCapability.NETWORK,
        ):
            with self.subTest(capability=capability.value):
                self.assertFalse(self.controller.capabilities[capability])


class LocalV2GUIBridgeStaticTests(unittest.TestCase):
    def test_v2_buttons_and_historical_mok1_action_are_separate(self):
        source = (ROOT / "mokosh_profile_gui.py").read_text(encoding="utf-8")
        self.assertIn(
            '("encrypt", 0, 0, self.open_local_encrypt)',
            source,
        )
        self.assertIn(
            '("decrypt", 0, 1, self.open_local_decrypt)',
            source,
        )
        self.assertIn("command=self.open_legacy_decrypt", source)
        self.assertIn('self.widgets["recovery_legacy"]', source)
        self.assertIn("ProfileCapability.V2_LOCAL_ENCRYPT", source)
        self.assertIn("ProfileCapability.V2_LOCAL_DECRYPT", source)
        self.assertIn("ProfileCapability.LEGACY_MOK1_DECRYPT", source)

    def test_local_modules_have_no_legacy_import_or_automatic_fallback(self):
        for name in ("mokosh_v2_local_service.py", "mokosh_v2_local_gui.py"):
            source = (ROOT / name).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imported = {
                node.module
                for node in tree.body
                if isinstance(node, ast.ImportFrom)
            }
            with self.subTest(name=name):
                self.assertNotIn("mokosh_legacy_mok1_recovery_gui", imported)
                self.assertNotIn("open_legacy_mok1_recovery", source)


if __name__ == "__main__":
    unittest.main()
