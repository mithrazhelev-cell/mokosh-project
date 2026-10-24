import json
import os
import stat
import tempfile
import unittest
import unicodedata
from pathlib import Path
from unittest import mock

import mokosh_profile_storage as storage


PASSWORD = "Stage 2.46 password value"
NICKNAME = "Mokosh tester"
CREATED = "2026-09-11T10:00:00Z"


class ProfileStorageTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="mokosh-profile-test-")
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.root = self.parent / "profile"

    def tearDown(self):
        self.context.cleanup()

    def create(self, **kwargs):
        return storage.create_profile(
            NICKNAME,
            PASSWORD,
            self.root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
            **kwargs,
        )


class ProfileValidationTests(unittest.TestCase):
    def test_nickname_is_nfc_and_password_is_not_trimmed(self):
        decomposed = "Cafe\N{COMBINING ACUTE ACCENT}"
        self.assertEqual(
            storage.normalize_nickname(decomposed),
            unicodedata.normalize("NFC", decomposed),
        )
        password = "  fifteen characters and spaces  "
        self.assertEqual(storage.normalize_password(password), password)

    def test_nickname_rejects_controls_bidi_and_bounds(self):
        for value in ("", " " * 4, "x\n", "x\u202e", "x" * 65, None, True):
            with self.subTest(value=value):
                with self.assertRaises(storage.ProfileValidationError):
                    storage.normalize_nickname(value)

    def test_password_policy_is_length_only_with_unicode_support(self):
        self.assertEqual(storage.normalize_password("🔐" * 15), "🔐" * 15)
        for value in ("short", "x" * 14, "x" * 1025, None, True):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(storage.ProfileValidationError):
                    storage.normalize_password(value)

    def test_descriptor_is_canonical_and_rejects_duplicate_keys(self):
        descriptor = storage.ProfileDescriptor(
            profile_id="11" * 16,
            nickname=NICKNAME,
            created_utc=CREATED,
            vault_id="22" * 16,
        )
        encoded = storage.encode_profile_descriptor(descriptor)
        self.assertEqual(storage.parse_profile_descriptor(encoded), descriptor)
        duplicated = encoded[:-1] + b',"version":1}'
        with self.assertRaises(storage.ProfileFormatError):
            storage.parse_profile_descriptor(duplicated)
        noncanonical = json.dumps(json.loads(encoded), ensure_ascii=False).encode()
        with self.assertRaises(storage.ProfileFormatError):
            storage.parse_profile_descriptor(noncanonical)


class ProfileCreationTests(ProfileStorageTestCase):
    def test_create_publishes_private_descriptor_last_and_loads(self):
        descriptor = self.create()
        inspection = storage.inspect_profile(self.root)
        self.assertIs(inspection.state, storage.ProfileState.READY)
        self.assertEqual(inspection.descriptor, descriptor)
        self.assertEqual(
            stat.S_IMODE(os.lstat(self.root).st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(os.lstat(self.root / "profile.json").st_mode),
            0o600,
        )
        snapshot = storage.load_profile(self.root)
        self.assertEqual(snapshot.descriptor, descriptor)
        self.assertEqual(snapshot.receipt.revision, 1)
        self.assertNotIn(snapshot.vault_bytes.hex(), repr(snapshot))

    def test_existing_ready_profile_is_never_overwritten(self):
        self.create()
        before = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        with self.assertRaises(storage.ProfileConflictError):
            self.create()
        after = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_factory_failure_leaves_explicit_partial_state(self):
        def fail(*_args, **_kwargs):
            raise RuntimeError("injected")

        with self.assertRaises(RuntimeError):
            self.create(vault_factory=fail)
        self.assertIs(
            storage.inspect_profile(self.root).state,
            storage.ProfileState.PARTIAL,
        )
        with self.assertRaises(storage.ProfileConflictError):
            self.create()

    def test_empty_or_unknown_profile_state_is_not_first_run(self):
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.assertIs(storage.inspect_profile(self.root).state, storage.ProfileState.PARTIAL)
        (self.root / "unexpected.txt").write_text("keep", encoding="utf-8")
        self.assertIn(
            storage.inspect_profile(self.root).state,
            {storage.ProfileState.PARTIAL, storage.ProfileState.CONFLICT},
        )
        self.assertEqual((self.root / "unexpected.txt").read_text(), "keep")

    def test_private_recovery_state_directory_is_an_optional_profile_component(self):
        self.create()
        recovery_state = self.root / storage.PROFILE_RECOVERY_STATE_DIRECTORY_NAME
        recovery_state.mkdir(mode=0o700)
        os.chmod(recovery_state, 0o700)
        self.assertIs(
            storage.inspect_profile(self.root).state,
            storage.ProfileState.READY,
        )

    def test_symlink_and_insecure_mode_fail_closed(self):
        target = self.parent / "target"
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        self.assertIs(storage.inspect_profile(self.root).state, storage.ProfileState.CONFLICT)
        self.root.unlink()
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o755)
        self.assertIs(storage.inspect_profile(self.root).state, storage.ProfileState.CONFLICT)

    def test_descriptor_tamper_is_detected_without_repair(self):
        self.create()
        descriptor = self.root / storage.PROFILE_DESCRIPTOR_NAME
        before_vault = next((self.root / "key-vault").iterdir()).read_bytes()
        descriptor.write_bytes(b"{}")
        os.chmod(descriptor, 0o600)
        self.assertIs(storage.inspect_profile(self.root).state, storage.ProfileState.CONFLICT)
        self.assertEqual(next((self.root / "key-vault").iterdir()).read_bytes(), before_vault)

    def test_legacy_detection_uses_metadata_only_and_never_changes_files(self):
        legacy = self.parent / "legacy"
        legacy.mkdir(mode=0o700)
        first = legacy / "seed_store.enc"
        second = legacy / "seed_meta.json"
        first.write_bytes(b"legacy ciphertext")
        second.write_bytes(b"legacy metadata")
        before = (first.read_bytes(), second.read_bytes())
        inspection = storage.inspect_profile(self.root, legacy_directory=legacy)
        self.assertTrue(inspection.legacy_login_records_present)
        self.assertIs(inspection.state, storage.ProfileState.ABSENT)
        self.assertEqual((first.read_bytes(), second.read_bytes()), before)

    def test_unsupported_platform_returns_explicit_state_before_creation(self):
        with mock.patch.object(storage.sys, "platform", "win32"):
            inspection = storage.inspect_profile(self.root)
            self.assertIs(inspection.state, storage.ProfileState.UNSUPPORTED)
            with self.assertRaises(storage.ProfileUnsupportedPlatformError):
                self.create()
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
