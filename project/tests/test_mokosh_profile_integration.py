import ast
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import mokosh_profile_gui as gui
import mokosh_profile_recovery as recovery
import mokosh_profile_session as profile_session
import mokosh_profile_storage as storage
import mokosh_vault_storage as vault_storage


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Stage 2.46 integration password"
NEW_PASSWORD = "Stage 2.47 recovered integration password"
NICKNAME = "Integration tester"


class ProtectedProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="mokosh-integration-test-")
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.root = self.parent / "profile"

    def tearDown(self):
        self.context.cleanup()

    def create(self):
        storage.create_profile(
            NICKNAME,
            PASSWORD,
            self.root,
            created_utc="2026-09-11T10:00:00Z",
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )

    def test_first_run_create_returns_locked_and_requires_explicit_login(self):
        self.assertIs(storage.inspect_profile(self.root).state, storage.ProfileState.ABSENT)
        self.create()
        controller = gui.ProfileApplicationController(self.root)
        self.addCleanup(controller.close)
        self.assertIs(controller.state, profile_session.ProfileSessionState.LOCKED)
        self.assertFalse(any(controller.capabilities.values()))
        result = controller.login(NICKNAME, PASSWORD)
        self.assertTrue(result.unlocked)
        self.assertIs(controller.state, profile_session.ProfileSessionState.UNLOCKED)

    def test_unlock_enables_only_finished_normal_actions(self):
        self.create()
        controller = gui.ProfileApplicationController(self.root)
        self.addCleanup(controller.close)
        controller.login(NICKNAME, PASSWORD)
        enabled = {item for item, allowed in controller.capabilities.items() if allowed}
        self.assertEqual(
            enabled,
            {
                profile_session.ProfileCapability.LEGACY_MOK1_DECRYPT,
                profile_session.ProfileCapability.V2_LOCAL_ENCRYPT,
                profile_session.ProfileCapability.V2_LOCAL_DECRYPT,
                profile_session.ProfileCapability.RECOVERY_PHRASE,
            },
        )

    def test_historical_login_files_are_detected_but_byte_exact(self):
        legacy = self.parent / "legacy"
        legacy.mkdir(mode=0o700)
        first = legacy / "seed_store.enc"
        second = legacy / "seed_meta.json"
        first.write_bytes(b"historical seed ciphertext")
        second.write_bytes(b"historical public metadata")
        before = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in (first, second))
        result = storage.inspect_profile(self.root, legacy_directory=legacy)
        after = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in (first, second))
        self.assertTrue(result.legacy_login_records_present)
        self.assertEqual(after, before)

    def test_profile_and_historical_login_are_separate_credentials(self):
        self.create()
        controller = gui.ProfileApplicationController(self.root)
        self.addCleanup(controller.close)
        result = controller.login("Historical nickname", "Historical password value")
        self.assertFalse(result.unlocked)
        self.assertIs(controller.state, profile_session.ProfileSessionState.LOCKED)

    def test_optional_setup_preview_publish_and_new_explicit_login(self):
        self.create()
        before = storage.load_profile(self.root)
        record_parent = self.parent / "record-parent"
        record_parent.mkdir(mode=0o700)
        setup = recovery.begin_profile_recovery_setup(
            self.root,
            PASSWORD,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            created_utc="2026-09-13T09:00:00Z",
        )
        words = setup.phrase_words
        setup.export_record(record_parent)
        setup.confirm_paper_backup(words)
        setup_result = setup.complete(recovery.ProfileRecoveryDecision.AUTHORIZE)
        record_digest = hashlib.sha256(
            Path(setup_result.record_path).read_bytes()
        ).digest()

        prepared = recovery.prepare_profile_password_recovery_from_words(
            self.root,
            setup_result.record_path,
            words,
            NEW_PASSWORD,
            NEW_PASSWORD,
            recovery.ProfileRecoveryDecision.AUTHORIZE,
            updated_utc="2026-09-13T10:00:00Z",
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.assertEqual(storage.load_profile(self.root), before)
        self.assertEqual(prepared.preview.target_revision, 2)
        prepared.publish(recovery.ProfileRecoveryDecision.AUTHORIZE)
        after = storage.load_profile(self.root)
        self.assertEqual(after.descriptor, before.descriptor)
        self.assertEqual(after.receipt.revision, 2)
        self.assertEqual(
            hashlib.sha256(Path(setup_result.record_path).read_bytes()).digest(),
            record_digest,
        )
        with vault_storage.VaultStorage(
            self.root / storage.PROFILE_VAULT_DIRECTORY_NAME
        ) as store:
            self.assertEqual(
                tuple(item.revision for item in store.scan().generations),
                (1, 2),
            )

        controller = gui.ProfileApplicationController(self.root)
        self.addCleanup(controller.close)
        refused = controller.login(NICKNAME, PASSWORD)
        self.assertFalse(refused.unlocked)
        accepted = controller.login(NICKNAME, NEW_PASSWORD)
        self.assertTrue(accepted.unlocked)
        controller.lock(profile_session.ProfileLockReason.USER)
        self.assertIs(controller.state, profile_session.ProfileSessionState.LOCKED)


class ProfileIntegrationStaticBoundaryTests(unittest.TestCase):
    def test_technical_main_signature_remains_compatible(self):
        tree = ast.parse((ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        main = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        self.assertEqual(
            tuple(item.arg for item in main.args.args),
            ("prepared_recovery_review_binding",),
        )
        self.assertEqual(
            tuple(item.arg for item in main.args.kwonlyargs),
            ("prepared_recovery_source_inspection_review_binding",),
        )

    def test_launcher_remains_byte_exact_and_uses_venv_sys_default(self):
        launcher = ROOT / "run_mokosh_gui.sh"
        self.assertEqual(
            hashlib.sha256(launcher.read_bytes()).hexdigest(),
            "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
        )
        source = launcher.read_text(encoding="utf-8")
        self.assertIn('$HOME/venv_sys', source)

    def test_legacy_store_and_security_cores_remain_byte_exact(self):
        expected = {
            "seed_manager.py": "3b5b7c3d1b47338185a2fb8b28b9a7f621ce48698e31df6cdef429aadafe818e",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "mokosh_vault_format.py": "c286a406ff267df1ad31723ffd8b9d3b068586821ea7ea281aeed74c6fd8e47d",
            "mokosh_vault_storage.py": "dd486706536a93df510e4799af28a2789f8d447f0e92d5662b0f73460a039bb6",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "mokosh_vault_recovery.py": "db64b62ffd16c6ba92b535028f140a4267b7c32c9f10bb8156e347e9dbaeff0a",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_candidate.py": "9e1c162c5f0ff25c91109e9ec351c8db632ff97c0b7a45b664ccece255e75d4b",
            "mokosh_vault_recovery_publish.py": "abcd0a99b80744eda30e18aaef90271f8fad778cba09f8ec4a2d13107511e7a4",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_normal_route_has_no_network_or_automatic_online_action(self):
        for name in (
            "mokosh_profile_storage.py",
            "mokosh_profile_session.py",
            "mokosh_profile_gui.py",
            "mokosh_legacy_mok1_recovery_gui.py",
            "mokosh_profile_recovery.py",
            "mokosh_profile_recovery_gui.py",
            "mokosh_recovery_phrase.py",
            "mokosh_recovery_phrase_storage.py",
        ):
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".", 1)[0]
                for node in tree.body
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                node.module.split(".", 1)[0]
                for node in tree.body
                if isinstance(node, ast.ImportFrom) and node.module
            }
            with self.subTest(name=name):
                self.assertTrue(
                    imported.isdisjoint({"socket", "urllib", "requests", "http", "ssl"})
                )


if __name__ == "__main__":
    unittest.main()
