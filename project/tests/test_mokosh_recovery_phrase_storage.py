import ast
import copy
import hashlib
import os
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mokosh_recovery_phrase as phrase
import mokosh_recovery_phrase_storage as storage


ROOT = Path(__file__).resolve().parents[1]
RECOVERY_ID = bytes(range(16))
RECOVERY_KEY = bytes(range(32))
WORDS = phrase.encode_recovery_phrase(RECOVERY_KEY)
FAKE_OTHER_DEVICE = 2**62


class RecoveryPhraseStorageTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-phrase-storage-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.directory_receipt = storage.create_private_recovery_directory(
            self.parent,
            storage.RecoveryMaterialKind.PHRASE,
            RECOVERY_ID,
            forbidden_devices=(FAKE_OTHER_DEVICE,),
        )
        self.directory = Path(self.directory_receipt.path)
        self.path = self.directory / storage.recovery_phrase_file_name(RECOVERY_ID)

    def tearDown(self):
        self.context.cleanup()

    def export(self):
        return storage.export_recovery_phrase_sheet(
            RECOVERY_ID,
            WORDS,
            self.directory,
            forbidden_devices=(FAKE_OTHER_DEVICE,),
        )

    def read(self):
        return storage.read_recovery_phrase_sheet(
            self.path,
            expected_recovery_id=RECOVERY_ID,
            forbidden_devices=(FAKE_OTHER_DEVICE,),
        )


class RecoveryPhraseEncodingTests(unittest.TestCase):
    def test_sheet_is_canonical_ascii_and_round_trips(self):
        encoded = storage.encode_recovery_phrase_sheet(RECOVERY_ID, WORDS)
        parsed = storage.parse_recovery_phrase_sheet(encoded)
        self.assertEqual(parsed.recovery_id, RECOVERY_ID)
        self.assertEqual(parsed.recovery_key, RECOVERY_KEY)
        self.assertEqual(parsed.words, WORDS)
        self.assertEqual(parsed.encoded, encoded)
        self.assertTrue(encoded.endswith(b"END\n"))
        self.assertEqual(encoded.count(b"\n"), 30)

    def test_noncanonical_or_tampered_sheet_is_rejected(self):
        valid = storage.encode_recovery_phrase_sheet(RECOVERY_ID, WORDS)
        cases = (
            valid[:-1],
            valid + b"\n",
            valid.replace(b"MOKOSH-RP1", b"BIP39-SEED", 1),
            valid.replace(b"01=cactus", b"1=cactus", 1),
            valid.replace(b"END\n", b"end\n", 1),
            b"\xff" + valid,
            b"",
        )
        for value in cases:
            with self.subTest(size=len(value)):
                with self.assertRaises(storage.RecoveryPhraseStorageError):
                    storage.parse_recovery_phrase_sheet(value)

    def test_secret_sheet_object_cannot_be_copied_or_pickled(self):
        parsed = storage.parse_recovery_phrase_sheet(
            storage.encode_recovery_phrase_sheet(RECOVERY_ID, WORDS)
        )
        self.assertNotIn(WORDS[0], repr(parsed))
        self.assertNotIn(RECOVERY_KEY.hex(), repr(parsed))
        for operation in (
            lambda: copy.copy(parsed),
            lambda: copy.deepcopy(parsed),
            lambda: pickle.dumps(parsed),
        ):
            with self.assertRaises(TypeError):
                operation()


class RecoveryPhraseDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-phrase-directory-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)

    def tearDown(self):
        self.context.cleanup()

    def test_private_directory_is_no_clobber_durable_and_exact(self):
        receipt = storage.create_private_recovery_directory(
            self.parent,
            storage.RecoveryMaterialKind.RECORD,
            RECOVERY_ID,
        )
        path = Path(receipt.path)
        self.assertTrue(path.is_dir())
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.stat().st_ino, receipt.inode)
        self.assertTrue(receipt.durable)
        with self.assertRaises(storage.RecoveryPhraseFileConflictError):
            storage.create_private_recovery_directory(
                self.parent,
                storage.RecoveryMaterialKind.RECORD,
                RECOVERY_ID,
            )

    def test_forbidden_same_device_is_rejected_before_creation(self):
        device = self.parent.stat().st_dev
        with self.assertRaises(storage.RecoveryPhraseSeparationError):
            storage.create_private_recovery_directory(
                self.parent,
                storage.RecoveryMaterialKind.PHRASE,
                RECOVERY_ID,
                forbidden_devices=(device,),
            )
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_symlink_parent_and_invalid_kind_are_rejected(self):
        link = self.parent / "link"
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(storage.UnsafeRecoveryPhraseDirectoryError):
            storage.create_private_recovery_directory(
                link,
                storage.RecoveryMaterialKind.PHRASE,
                RECOVERY_ID,
            )
        with self.assertRaises(storage.UnsafeRecoveryPhraseDirectoryError):
            storage.recovery_private_directory_name("phrase", RECOVERY_ID)

    def test_fat_and_exfat_are_rejected_before_creation(self):
        for magic in (
            storage.LINUX_MSDOS_SUPER_MAGIC,
            storage.LINUX_EXFAT_SUPER_MAGIC,
        ):
            with self.subTest(magic=magic), mock.patch.object(
                storage, "_filesystem_magic", return_value=magic
            ):
                with self.assertRaises(
                    storage.RecoveryPhraseExportUnsupportedError
                ):
                    storage.create_private_recovery_directory(
                        self.parent,
                        storage.RecoveryMaterialKind.PHRASE,
                        RECOVERY_ID,
                    )
                self.assertEqual(list(self.parent.iterdir()), [])

    def test_exact_empty_directory_can_be_rolled_back_once(self):
        receipt = storage.create_private_recovery_directory(
            self.parent,
            storage.RecoveryMaterialKind.RECORD,
            RECOVERY_ID,
        )
        path = Path(receipt.path)
        self.assertTrue(storage.remove_empty_private_recovery_directory(receipt))
        self.assertFalse(path.exists())
        with self.assertRaises(storage.UnsafeRecoveryPhraseDirectoryError):
            storage.remove_empty_private_recovery_directory(receipt)

    def test_nonempty_directory_is_never_rolled_back(self):
        receipt = storage.create_private_recovery_directory(
            self.parent,
            storage.RecoveryMaterialKind.RECORD,
            RECOVERY_ID,
        )
        path = Path(receipt.path)
        marker = path / "owned-marker"
        marker.write_bytes(b"x")
        self.assertFalse(storage.remove_empty_private_recovery_directory(receipt))
        self.assertTrue(marker.is_file())

    def test_post_create_os_failure_is_normalized_and_rolls_back(self):
        with mock.patch.object(
            storage.os,
            "fchmod",
            side_effect=OSError("synthetic directory chmod failure"),
        ):
            with self.assertRaises(
                storage.RecoveryPhraseExportUnsupportedError
            ):
                storage.create_private_recovery_directory(
                    self.parent,
                    storage.RecoveryMaterialKind.RECORD,
                    RECOVERY_ID,
                )
        self.assertEqual(list(self.parent.iterdir()), [])


class RecoveryPhraseFileTests(RecoveryPhraseStorageTestCase):
    def test_export_and_double_read_are_private_exact_and_nonsecret_receipts(self):
        receipt = self.export()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt.recovery_id, RECOVERY_ID)
        self.assertEqual(receipt.file_inode, self.path.stat().st_ino)
        self.assertEqual(receipt.sha256, hashlib.sha256(self.path.read_bytes()).digest())
        self.assertNotIn(WORDS[0], repr(receipt))
        parsed = self.read()
        self.assertEqual(parsed.recovery_key, RECOVERY_KEY)

    def test_export_never_overwrites_existing_target(self):
        self.export()
        before = self.path.read_bytes()
        with self.assertRaises(storage.RecoveryPhraseFileConflictError):
            self.export()
        self.assertEqual(self.path.read_bytes(), before)

    def test_export_refuses_same_device_and_leaves_directory_empty(self):
        device = self.directory.stat().st_dev
        with self.assertRaises(storage.RecoveryPhraseSeparationError):
            storage.export_recovery_phrase_sheet(
                RECOVERY_ID,
                WORDS,
                self.directory,
                forbidden_devices=(device,),
            )
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_read_refuses_wrong_id_mode_hardlink_and_filename(self):
        self.export()
        with self.assertRaises(storage.RecoveryPhraseSourceChangedError):
            storage.read_recovery_phrase_sheet(
                self.path,
                expected_recovery_id=b"X" * 16,
                forbidden_devices=(FAKE_OTHER_DEVICE,),
            )
        os.chmod(self.path, 0o644)
        with self.assertRaises(storage.RecoveryPhraseFileConflictError):
            self.read()
        os.chmod(self.path, 0o600)
        link = self.directory / "hardlink"
        os.link(self.path, link)
        with self.assertRaises(storage.RecoveryPhraseFileConflictError):
            self.read()
        link.unlink()
        wrong = self.directory / "phrase.txt"
        self.path.rename(wrong)
        with self.assertRaises(storage.RecoveryPhraseFileConflictError):
            storage.read_recovery_phrase_sheet(
                wrong,
                forbidden_devices=(FAKE_OTHER_DEVICE,),
            )

    def test_read_refuses_content_tamper_and_same_device(self):
        self.export()
        encoded = bytearray(self.path.read_bytes())
        encoded[-5] ^= 1
        self.path.write_bytes(encoded)
        os.chmod(self.path, 0o600)
        with self.assertRaises(storage.RecoveryPhraseStorageError):
            self.read()
        self.path.write_bytes(
            storage.encode_recovery_phrase_sheet(RECOVERY_ID, WORDS)
        )
        os.chmod(self.path, 0o600)
        with self.assertRaises(storage.RecoveryPhraseSeparationError):
            storage.read_recovery_phrase_sheet(
                self.path,
                forbidden_devices=(self.directory.stat().st_dev,),
            )

    def test_write_failure_cleans_only_owned_new_file(self):
        real_fsync = os.fsync
        calls = 0

        def fail_file_sync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic file sync failure")
            return real_fsync(descriptor)

        with mock.patch.object(storage.os, "fsync", side_effect=fail_file_sync):
            with self.assertRaises(
                storage.RecoveryPhraseExportUnsupportedError
            ):
                self.export()
        self.assertFalse(self.path.exists())

    def test_read_os_failure_is_normalized_without_mutation(self):
        self.export()
        before = self.path.read_bytes()
        real_fstat = os.fstat
        calls = 0

        def fail_middle_fstat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("synthetic read verification failure")
            return real_fstat(descriptor)

        with mock.patch.object(storage.os, "fstat", side_effect=fail_middle_fstat):
            with self.assertRaises(storage.RecoveryPhraseSourceChangedError):
                self.read()
        self.assertEqual(self.path.read_bytes(), before)

    def test_nonprivate_directory_is_rejected_without_file_mutation(self):
        os.chmod(self.directory, 0o755)
        with self.assertRaises(storage.UnsafeRecoveryPhraseDirectoryError):
            self.export()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_module_has_no_network_clipboard_logging_or_automatic_home_path(self):
        tree = ast.parse(
            (ROOT / "mokosh_recovery_phrase_storage.py").read_text()
        )
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
        self.assertTrue(
            imported.isdisjoint(
                {"socket", "urllib", "requests", "tkinter", "logging", "shutil"}
            )
        )


if __name__ == "__main__":
    unittest.main()
