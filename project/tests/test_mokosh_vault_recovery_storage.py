import ast
import copy
import hashlib
import inspect
import os
import pickle
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_recovery as recovery
import mokosh_vault_recovery_storage as recovery_storage
import mokosh_vault_storage as vault_storage


PASSWORD = "Stage 2.5 correct password"
NEW_PASSWORD = "Stage 2.5 new password"
VAULT_ID = bytes(range(16))
OTHER_VAULT_ID = bytes(range(16, 32))
KEY_ONE = b"K" * 32
KEY_TWO = b"L" * 32
RECOVERY_KEY = b"R" * 32
RECOVERY_ID = b"I" * 16
RECOVERY_NONCE = b"N" * 12
CREATED = "2026-08-13T08:00:00Z"
RECOVERY_CREATED = "2026-08-13T09:00:00Z"
UPDATED = "2026-08-13T10:00:00Z"


def initial_keyring(*, material=KEY_ONE):
    record = keyring.VaultKeyRecord(
        key_version=1,
        state=keyring.KEY_STATE_ACTIVE,
        created_utc=CREATED,
        retired_utc=None,
        wrapping_key=material,
    )
    result = keyring.VaultKeyring(active_key_version=1, keys=(record,))
    keyring.validate_keyring(result)
    return result


def make_session(*, vault_id=VAULT_ID, material=KEY_ONE, password=PASSWORD):
    encoded = vault.create_keyring_vault(
        password,
        keyring=initial_keyring(material=material),
        vault_id=vault_id,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )
    session = vault.VaultSession(encoded)
    session.unlock(password)
    return session


class RecoveryStorageTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-recovery-storage-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.vault_path = self.parent / "vault"
        self.export_path = self.parent / "offline-recovery"
        self.export_path.mkdir(mode=0o700)
        os.chmod(self.export_path, 0o700)
        self.store = vault_storage.VaultStorage.create(self.vault_path)
        self.session = make_session()
        self.receipt = self.store.publish(self.session)

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.context.cleanup()

    def prepare(self):
        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
        ):
            return recovery_storage.prepare_recovery_export(
                self.store,
                self.receipt,
                self.session,
                created_utc=RECOVERY_CREATED,
            )

    def export(self, setup=None, directory=None):
        return recovery_storage.export_recovery_record(
            setup or self.prepare(),
            self.store,
            self.receipt,
            directory or self.export_path,
        )

    def exported_path(self, recovery_id=RECOVERY_ID):
        return self.export_path / recovery_storage.recovery_record_name(
            recovery_id
        )


class RecoveryPreparationTests(RecoveryStorageTestCase):
    def test_prepare_requires_exact_latest_durable_vault(self):
        setup = self.prepare()
        self.assertEqual(setup.recovery_key, RECOVERY_KEY)
        self.assertEqual(setup.vault_id, self.receipt.vault_id)
        self.assertEqual(setup.source_revision, self.receipt.revision)
        self.assertEqual(setup.source_vault_sha256, self.receipt.sha256)
        recovery.rehearse_recovery(
            setup.record,
            setup.recovery_key,
            self.store.verify_receipt(self.receipt),
        )

    def test_prepare_is_in_memory_and_does_not_touch_export_directory(self):
        before_vault = {
            entry.name: (
                entry.stat(follow_symlinks=False).st_ino,
                entry.stat(follow_symlinks=False).st_size,
            )
            for entry in os.scandir(self.vault_path)
        }
        self.assertEqual(list(os.scandir(self.export_path)), [])
        self.prepare()
        after_vault = {
            entry.name: (
                entry.stat(follow_symlinks=False).st_ino,
                entry.stat(follow_symlinks=False).st_size,
            )
            for entry in os.scandir(self.vault_path)
        }
        self.assertEqual(after_vault, before_vault)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_prepare_rejects_dirty_incomplete_or_forged_history(self):
        unknown = self.vault_path / "unknown"
        unknown.write_bytes(b"do not touch")
        with self.assertRaises(recovery_storage.VaultRecoveryStorageStateError):
            self.prepare()
        self.assertEqual(unknown.read_bytes(), b"do not touch")
        unknown.unlink()

        forged = replace(self.receipt, sha256=b"F" * 32)
        with self.assertRaises(recovery_storage.VaultRecoveryStorageStateError):
            recovery_storage.prepare_recovery_export(
                self.store,
                forged,
                self.session,
                created_utc=RECOVERY_CREATED,
            )

        incomplete = replace(self.store.scan(), complete=False)
        with mock.patch.object(
            vault_storage.VaultStorage,
            "scan",
            return_value=incomplete,
        ):
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                self.prepare()

    def test_prepare_rejects_nonlatest_receipt_and_stale_session(self):
        first = self.receipt
        self.session.change_password(
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        second = self.store.publish(self.session, previous=first)
        self.receipt = second
        with self.assertRaises(recovery_storage.VaultRecoveryStorageStateError):
            recovery_storage.prepare_recovery_export(
                self.store,
                first,
                self.session,
                created_utc=UPDATED,
            )

        other = make_session(vault_id=OTHER_VAULT_ID, material=KEY_TWO)
        try:
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                recovery_storage.prepare_recovery_export(
                    self.store, second, other, created_utc=UPDATED
                )
        finally:
            other.close()

    def test_prepare_rejects_locked_or_wrong_type_session(self):
        self.session.lock()
        for candidate in (self.session, object()):
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(
                    recovery_storage.VaultRecoveryStorageStateError
                ):
                    recovery_storage.prepare_recovery_export(
                        self.store,
                        self.receipt,
                        candidate,
                        created_utc=RECOVERY_CREATED,
                    )

    def test_storage_change_during_prepare_returns_no_setup(self):
        real_create = recovery.create_recovery_record

        def create_then_dirty(*args, **kwargs):
            result = real_create(*args, **kwargs)
            (self.vault_path / "late-object").write_bytes(b"conflict")
            return result

        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
        ), mock.patch.object(
            recovery_storage,
            "create_recovery_record",
            side_effect=create_then_dirty,
        ):
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                recovery_storage.prepare_recovery_export(
                    self.store,
                    self.receipt,
                    self.session,
                    created_utc=RECOVERY_CREATED,
                )

    def test_prepare_rejects_wrong_or_closed_storage_without_randomness(self):
        with mock.patch.object(recovery.os, "urandom") as random_source:
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                recovery_storage.prepare_recovery_export(
                    object(),
                    self.receipt,
                    self.session,
                    created_utc=RECOVERY_CREATED,
                )
            random_source.assert_not_called()

        self.store.close()
        with mock.patch.object(recovery.os, "urandom") as random_source:
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                recovery_storage.prepare_recovery_export(
                    self.store,
                    self.receipt,
                    self.session,
                    created_utc=RECOVERY_CREATED,
                )
            random_source.assert_not_called()

    def test_prepare_fault_does_not_mutate_session_or_vault_history(self):
        original = self.session.encoded
        before = self.store.scan()
        with mock.patch.object(
            recovery_storage,
            "create_recovery_record",
            side_effect=RuntimeError("setup fault"),
        ):
            with self.assertRaises(RuntimeError):
                recovery_storage.prepare_recovery_export(
                    self.store,
                    self.receipt,
                    self.session,
                    created_utc=RECOVERY_CREATED,
                )
        self.assertEqual(self.session.encoded, original)
        self.assertEqual(self.store.scan(), before)


class RecoveryExportTests(RecoveryStorageTestCase):
    def test_export_is_private_exact_durable_and_no_clobber(self):
        setup = self.prepare()
        receipt = self.export(setup)
        target = self.exported_path()
        observed = os.lstat(target)
        self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        self.assertEqual(target.read_bytes(), setup.record)
        self.assertEqual(receipt.recovery_id, RECOVERY_ID)
        self.assertEqual(receipt.vault_id, VAULT_ID)
        self.assertEqual(receipt.source_revision, 1)
        self.assertEqual(receipt.source_vault_sha256, self.receipt.sha256)
        self.assertEqual(
            receipt.record_sha256, hashlib.sha256(setup.record).digest()
        )
        self.assertTrue(receipt.durable)

        before = target.read_bytes()
        with self.assertRaises(recovery_storage.RecoveryFileConflictError):
            self.export(setup)
        self.assertEqual(target.read_bytes(), before)

    def test_export_writes_only_record_and_never_recovery_key(self):
        setup = self.prepare()
        receipt = self.export(setup)
        entries = list(os.scandir(self.export_path))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, recovery_storage.recovery_record_name(RECOVERY_ID))
        self.assertEqual(Path(entries[0].path).read_bytes(), setup.record)
        self.assertNotIn(RECOVERY_KEY.hex(), entries[0].name)
        self.assertNotIn("recovery_key", receipt.__dataclass_fields__)
        self.assertNotIn("path", receipt.__dataclass_fields__)
        self.assertNotIn("filename", receipt.__dataclass_fields__)

    def test_export_receipt_cannot_be_copied_or_pickled(self):
        receipt = self.export()
        with self.assertRaises(TypeError):
            copy.copy(receipt)
        with self.assertRaises(TypeError):
            copy.deepcopy(receipt)
        with self.assertRaises(TypeError):
            pickle.dumps(receipt)

    def test_canonical_filename_is_exact_and_bounded(self):
        self.assertEqual(
            recovery_storage.recovery_record_name(bytes(range(16))),
            "mokosh-vault-recovery-000102030405060708090a0b0c0d0e0f.mokr",
        )
        for value in (None, "id", b"", b"I" * 15, b"I" * 17):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(recovery_storage.RecoveryFileConflictError):
                    recovery_storage.recovery_record_name(value)

    def test_export_rejects_unsafe_symlink_or_vault_directory(self):
        setup = self.prepare()
        os.chmod(self.export_path, 0o755)
        with self.assertRaises(recovery_storage.UnsafeRecoveryDirectoryError):
            self.export(setup)
        os.chmod(self.export_path, 0o700)

        alias = self.parent / "offline-alias"
        alias.symlink_to(self.export_path, target_is_directory=True)
        with self.assertRaises(recovery_storage.UnsafeRecoveryDirectoryError):
            self.export(setup, alias)
        with self.assertRaises(recovery_storage.UnsafeRecoveryDirectoryError):
            self.export(setup, self.vault_path)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_export_rejects_malformed_setup_or_wrong_recovery_key(self):
        setup = self.prepare()
        variants = (
            object(),
            replace(setup, recovery_key=b"W" * 32),
            replace(setup, record=bytearray(setup.record)),
            replace(setup, recovery_key=bytearray(setup.recovery_key)),
            replace(setup, vault_id=OTHER_VAULT_ID),
            replace(setup, source_revision=2),
            replace(setup, source_vault_sha256=b"S" * 32),
        )
        for changed in variants:
            with self.subTest(changed=type(changed).__name__):
                with self.assertRaises(recovery.VaultRecoveryError):
                    self.export(changed)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_export_rejects_record_made_stale_before_write(self):
        setup = self.prepare()
        first = self.receipt
        self.session.change_password(
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.receipt = self.store.publish(self.session, previous=first)
        with self.assertRaises(recovery.VaultRecoveryStaleError):
            self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_write_or_file_sync_failure_cleans_only_owned_file(self):
        setup = self.prepare()
        with mock.patch.object(
            recovery_storage, "_write_all", side_effect=OSError("write fault")
        ):
            with self.assertRaises(OSError):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

        real_fsync = recovery_storage.os.fsync

        def fail_regular_file(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("file fsync fault")
            return real_fsync(descriptor)

        with mock.patch.object(
            recovery_storage.os, "fsync", side_effect=fail_regular_file
        ):
            with self.assertRaises(OSError):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_foreign_hardlink_during_failure_is_preserved_as_uncertain(self):
        setup = self.prepare()
        alias = self.export_path / "foreign-alias"

        def link_then_fail(descriptor, data):
            target = self.exported_path()
            os.link(target, alias)
            raise OSError("fault after foreign hardlink")

        with mock.patch.object(
            recovery_storage, "_write_all", side_effect=link_then_fail
        ):
            with self.assertRaises(
                recovery_storage.RecoveryExportUncertainError
            ):
                self.export(setup)
        self.assertTrue(self.exported_path().exists())
        self.assertTrue(alias.exists())
        self.assertEqual(os.lstat(self.exported_path()).st_nlink, 2)

    def test_failure_after_directory_sync_preserves_durable_record_as_uncertain(self):
        setup = self.prepare()
        current = self.store.verify_receipt(self.receipt)
        calls = 0

        def latest_then_fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise recovery_storage.VaultRecoveryStorageStateError(
                    "Vault changed after export"
                )
            return current

        with mock.patch.object(
            recovery_storage,
            "_verified_latest_vault",
            side_effect=latest_then_fail,
        ):
            with self.assertRaises(
                recovery_storage.RecoveryExportUncertainError
            ):
                self.export(setup)
        self.assertEqual(self.exported_path().read_bytes(), setup.record)

    def test_file_change_during_publish_sync_is_uncertain_and_preserved(self):
        setup = self.prepare()
        real_sync = recovery_storage._sync_directory
        calls = 0

        def change_before_publish_sync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                target = self.exported_path()
                changed = bytearray(target.read_bytes())
                changed[-1] ^= 1
                target.write_bytes(changed)
                os.chmod(target, 0o600)
            return real_sync(descriptor)

        with mock.patch.object(
            recovery_storage,
            "_sync_directory",
            side_effect=change_before_publish_sync,
        ):
            with self.assertRaises(
                recovery_storage.RecoveryExportUncertainError
            ):
                self.export(setup)
        self.assertTrue(self.exported_path().exists())
        self.assertNotEqual(self.exported_path().read_bytes(), setup.record)

    def test_directory_sync_failure_never_reports_success(self):
        setup = self.prepare()
        real_sync = recovery_storage._sync_directory
        calls = 0

        def fail_publish_sync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise recovery_storage.RecoveryExportUnsupportedError(
                    "directory fsync fault"
                )
            return real_sync(descriptor)

        with mock.patch.object(
            recovery_storage,
            "_sync_directory",
            side_effect=fail_publish_sync,
        ):
            with self.assertRaises(
                recovery_storage.RecoveryExportUnsupportedError
            ):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_cleanup_sync_failure_is_uncertain_even_after_local_unlink(self):
        setup = self.prepare()
        real_sync = recovery_storage._sync_directory
        calls = 0

        def fail_cleanup_sync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise recovery_storage.RecoveryExportUnsupportedError(
                    "cleanup directory fsync fault"
                )
            return real_sync(descriptor)

        with mock.patch.object(
            recovery_storage,
            "_write_all",
            side_effect=OSError("write fault"),
        ), mock.patch.object(
            recovery_storage,
            "_sync_directory",
            side_effect=fail_cleanup_sync,
        ):
            with self.assertRaises(
                recovery_storage.RecoveryExportUncertainError
            ):
                self.export(setup)
        self.assertFalse(self.exported_path().exists())

    def test_fchmod_failure_cleans_the_exclusively_created_file(self):
        setup = self.prepare()
        with mock.patch.object(
            recovery_storage.os,
            "fchmod",
            side_effect=OSError("fchmod fault"),
        ):
            with self.assertRaises(OSError):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_target_created_in_race_is_never_opened_or_changed(self):
        setup = self.prepare()
        target = self.exported_path()
        real_open = recovery_storage.os.open
        raced = False

        def create_before_exclusive_open(path, flags, *args, **kwargs):
            nonlocal raced
            if (
                not raced
                and path == target.name
                and flags & os.O_CREAT
            ):
                raced = True
                target.write_bytes(b"foreign record")
                os.chmod(target, 0o600)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(
            recovery_storage.os,
            "open",
            side_effect=create_before_exclusive_open,
        ):
            with self.assertRaises(recovery_storage.RecoveryFileConflictError):
                self.export(setup)
        self.assertEqual(target.read_bytes(), b"foreign record")

    def test_keyboard_interrupt_before_durable_sync_cleans_and_propagates(self):
        setup = self.prepare()
        with mock.patch.object(
            recovery_storage,
            "_write_all",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])

    def test_export_directory_replacement_is_detected_without_foreign_deletion(self):
        setup = self.prepare()
        moved = self.parent / "moved-offline-recovery"
        real_write = recovery_storage._write_all

        def write_then_replace_directory(descriptor, data):
            real_write(descriptor, data)
            self.export_path.rename(moved)
            self.export_path.mkdir(mode=0o700)
            os.chmod(self.export_path, 0o700)

        with mock.patch.object(
            recovery_storage,
            "_write_all",
            side_effect=write_then_replace_directory,
        ):
            with self.assertRaises(
                recovery_storage.UnsafeRecoveryDirectoryError
            ):
                self.export(setup)
        self.assertEqual(list(os.scandir(self.export_path)), [])
        self.assertEqual(list(os.scandir(moved)), [])


class RecoveryImportTests(RecoveryStorageTestCase):
    def test_read_only_file_rehearsal_returns_nonsecret_evidence(self):
        setup = self.prepare()
        export_receipt = self.export(setup)
        result = recovery_storage.rehearse_recovery_file(
            self.exported_path(),
            setup.recovery_key,
            self.store,
            self.receipt,
        )
        self.assertEqual(result.recovery_id, RECOVERY_ID)
        self.assertEqual(result.vault_id, VAULT_ID)
        self.assertEqual(result.source_revision, 1)
        self.assertEqual(result.record_sha256, export_receipt.record_sha256)
        self.assertEqual(result.active_key_version, 1)
        self.assertEqual(result.key_count, 1)
        fields = set(result.__dataclass_fields__)
        self.assertFalse(
            fields
            & {
                "path",
                "filename",
                "record",
                "recovery_key",
                "keyring",
                "wrapping_key",
                "password",
                "plaintext",
            }
        )
        self.assertNotIn(RECOVERY_KEY.hex(), repr(result))
        self.assertNotIn(KEY_ONE.hex(), repr(result))

    def test_rehearsal_is_exactly_read_only_for_both_directories(self):
        setup = self.prepare()
        self.export(setup)

        def snapshot(path):
            return {
                entry.name: (
                    entry.stat(follow_symlinks=False).st_dev,
                    entry.stat(follow_symlinks=False).st_ino,
                    entry.stat(follow_symlinks=False).st_mode,
                    entry.stat(follow_symlinks=False).st_nlink,
                    entry.stat(follow_symlinks=False).st_size,
                    hashlib.sha256(Path(entry.path).read_bytes()).digest(),
                )
                for entry in os.scandir(path)
            }

        before_vault = snapshot(self.vault_path)
        before_export = snapshot(self.export_path)
        recovery_storage.rehearse_recovery_file(
            self.exported_path(),
            setup.recovery_key,
            self.store,
            self.receipt,
        )
        self.assertEqual(snapshot(self.vault_path), before_vault)
        self.assertEqual(snapshot(self.export_path), before_export)

    def test_import_rejects_wrong_root_tamper_and_truncation(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        with self.assertRaises(recovery.VaultRecoveryAuthenticationError):
            recovery_storage.rehearse_recovery_file(
                target, b"W" * 32, self.store, self.receipt
            )

        original = target.read_bytes()
        for changed in (original[:-1], original[:-1] + bytes([original[-1] ^ 1])):
            target.write_bytes(changed)
            os.chmod(target, 0o600)
            with self.assertRaises(recovery.VaultRecoveryError):
                recovery_storage.rehearse_recovery_file(
                    target, setup.recovery_key, self.store, self.receipt
                )
        target.write_bytes(original)
        os.chmod(target, 0o600)

    def test_import_rejects_symlink_hardlink_and_insecure_mode(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()

        os.chmod(target, 0o644)
        with self.assertRaises(recovery_storage.RecoveryFileConflictError):
            recovery_storage.rehearse_recovery_file(
                target, setup.recovery_key, self.store, self.receipt
            )
        os.chmod(target, 0o600)

        alias = self.export_path / "hardlink"
        os.link(target, alias)
        with self.assertRaises(recovery_storage.RecoveryFileConflictError):
            recovery_storage.rehearse_recovery_file(
                target, setup.recovery_key, self.store, self.receipt
            )
        alias.unlink()

        held = self.export_path / "held-record"
        target.rename(held)
        target.symlink_to(held.name)
        with self.assertRaises(recovery_storage.UnsafeRecoveryDirectoryError):
            recovery_storage.rehearse_recovery_file(
                target, setup.recovery_key, self.store, self.receipt
            )

    def test_import_rejects_noncanonical_filename_and_oversized_input(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        wrong_name = self.export_path / recovery_storage.recovery_record_name(
            b"J" * 16
        )
        target.rename(wrong_name)
        with self.assertRaises(recovery_storage.RecoveryFileConflictError):
            recovery_storage.rehearse_recovery_file(
                wrong_name, setup.recovery_key, self.store, self.receipt
            )

        wrong_name.unlink()
        oversized = self.export_path / recovery_storage.recovery_record_name(
            b"O" * 16
        )
        oversized.write_bytes(b"X" * (recovery_storage.MAX_RECOVERY_FILE_BYTES + 1))
        os.chmod(oversized, 0o600)
        with self.assertRaises(recovery_storage.RecoveryStorageLimitError):
            recovery_storage.rehearse_recovery_file(
                oversized, setup.recovery_key, self.store, self.receipt
            )

    def test_read_race_to_fifo_uses_nonblocking_open_and_rejects(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        held = self.export_path / "held-regular-record"
        real_open = os.open
        swapped = False

        def open_after_fifo_swap(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == target.name and not flags & os.O_DIRECTORY and not swapped:
                swapped = True
                target.rename(held)
                os.mkfifo(target, 0o600)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(
            recovery_storage.os,
            "open",
            side_effect=open_after_fifo_swap,
        ):
            with self.assertRaises(
                recovery_storage.RecoverySourceChangedError
            ):
                recovery_storage._read_recovery_path(target)
        self.assertTrue(swapped)

    def test_read_rejects_stable_fifo_before_content_open(self):
        target = self.exported_path()
        os.mkfifo(target, 0o600)
        real_open = os.open

        def reject_fifo_content_open(path, flags, *args, **kwargs):
            if path == target.name and not flags & os.O_DIRECTORY:
                raise AssertionError("FIFO reached content-capable open")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(
            recovery_storage.os,
            "open",
            side_effect=reject_fifo_content_open,
        ):
            with self.assertRaises(
                recovery_storage.RecoveryFileConflictError
            ):
                recovery_storage._read_recovery_path(target)

    def test_read_rejects_ancestor_rename_and_symlink_after_path_check(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        moved = self.parent / "moved-offline-recovery"
        real_path_text = recovery_storage._path_text
        swapped = False

        def validate_then_swap(value, field_name):
            nonlocal swapped
            result = real_path_text(value, field_name)
            if not swapped:
                swapped = True
                self.export_path.rename(moved)
                self.export_path.symlink_to(moved.name, target_is_directory=True)
            return result

        with mock.patch.object(
            recovery_storage,
            "_path_text",
            side_effect=validate_then_swap,
        ):
            with self.assertRaises(
                recovery_storage.UnsafeRecoveryDirectoryError
            ):
                recovery_storage._read_recovery_path(target)
        self.assertTrue(swapped)

    def test_read_closes_file_and_full_directory_chain_on_baseexception(self):
        setup = self.prepare()
        self.export(setup)
        real_open = os.open
        real_close = os.close
        retained: set[int] = set()

        def tracked_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            retained.add(descriptor)
            return descriptor

        def tracked_close(descriptor):
            retained.discard(descriptor)
            return real_close(descriptor)

        with (
            mock.patch.object(
                recovery_storage.os,
                "open",
                side_effect=tracked_open,
            ),
            mock.patch.object(
                recovery_storage.os,
                "close",
                side_effect=tracked_close,
            ),
            mock.patch.object(
                recovery_storage,
                "_read_exact_descriptor",
                side_effect=KeyboardInterrupt,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                recovery_storage._read_recovery_path(self.exported_path())
        self.assertEqual(retained, set())

    def test_read_requests_no_filesystem_mutation(self):
        setup = self.prepare()
        self.export(setup)
        forbidden = {
            name: mock.Mock(side_effect=AssertionError(name))
            for name in (
                "write",
                "fchmod",
                "fsync",
                "truncate",
                "ftruncate",
                "unlink",
                "remove",
                "rename",
                "replace",
                "utime",
            )
        }
        with mock.patch.multiple(recovery_storage.os, **forbidden):
            imported = recovery_storage._read_recovery_path(
                self.exported_path()
            )
        self.assertEqual(imported.record, setup.record)
        for operation in forbidden.values():
            operation.assert_not_called()

    def test_read_detects_file_replacement_during_structural_parse(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        held = self.export_path / "parsed-original"
        real_parse = recovery_storage.parse_recovery_record

        def parse_then_replace(encoded):
            parsed = real_parse(encoded)
            target.rename(held)
            target.write_bytes(encoded)
            os.chmod(target, 0o600)
            return parsed

        with mock.patch.object(
            recovery_storage,
            "parse_recovery_record",
            side_effect=parse_then_replace,
        ):
            with self.assertRaises(
                recovery_storage.RecoverySourceChangedError
            ):
                recovery_storage._read_recovery_path(target)

    def test_import_rejects_stale_rollback_mixed_or_dirty_current_vault(self):
        setup = self.prepare()
        self.export(setup)
        first = self.receipt
        self.session.change_password(
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        second = self.store.publish(self.session, previous=first)
        self.receipt = second
        with self.assertRaises(recovery.VaultRecoveryStaleError):
            recovery_storage.rehearse_recovery_file(
                self.exported_path(), setup.recovery_key, self.store, second
            )

        unknown = self.vault_path / "unknown"
        unknown.write_bytes(b"conflict")
        with self.assertRaises(recovery_storage.VaultRecoveryStorageStateError):
            recovery_storage.rehearse_recovery_file(
                self.exported_path(), setup.recovery_key, self.store, second
            )

    def test_file_change_during_bounded_read_is_rejected(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        real_read = recovery_storage._read_exact_descriptor
        changed = False

        def read_then_change(descriptor, expected_size):
            nonlocal changed
            result = real_read(descriptor, expected_size)
            if not changed:
                changed = True
                data = bytearray(target.read_bytes())
                data[-1] ^= 1
                target.write_bytes(data)
                os.chmod(target, 0o600)
            return result

        with mock.patch.object(
            recovery_storage,
            "_read_exact_descriptor",
            side_effect=read_then_change,
        ):
            with self.assertRaises(recovery_storage.RecoverySourceChangedError):
                recovery_storage.rehearse_recovery_file(
                    target, setup.recovery_key, self.store, self.receipt
                )

    def test_file_replacement_between_double_reads_is_rejected(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        real_read_path = recovery_storage._read_recovery_path
        calls = 0

        def read_then_replace(path):
            nonlocal calls
            result = real_read_path(path)
            calls += 1
            if calls == 1:
                held = self.export_path / "old"
                target.rename(held)
                target.write_bytes(setup.record)
                os.chmod(target, 0o600)
            return result

        with mock.patch.object(
            recovery_storage,
            "_read_recovery_path",
            side_effect=read_then_replace,
        ):
            with self.assertRaises(recovery_storage.RecoverySourceChangedError):
                recovery_storage.rehearse_recovery_file(
                    target, setup.recovery_key, self.store, self.receipt
                )

    def test_import_rejects_mixed_vault_and_rolled_back_current_vault(self):
        other_session = make_session(vault_id=OTHER_VAULT_ID, material=KEY_TWO)
        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
            ):
                other_setup = recovery.create_recovery_record(
                    other_session,
                    created_utc=RECOVERY_CREATED,
                )
        finally:
            other_session.close()
        target = self.exported_path()
        target.write_bytes(other_setup.record)
        os.chmod(target, 0o600)
        with self.assertRaises(recovery.VaultRecoveryMixedVaultError):
            recovery_storage.rehearse_recovery_file(
                target,
                other_setup.recovery_key,
                self.store,
                self.receipt,
            )

        target.unlink()
        newer_session = make_session()
        try:
            newer_session.change_password(
                NEW_PASSWORD,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
            ):
                newer_setup = recovery.create_recovery_record(
                    newer_session,
                    created_utc=UPDATED,
                )
        finally:
            newer_session.close()
        target.write_bytes(newer_setup.record)
        os.chmod(target, 0o600)
        with self.assertRaises(recovery.VaultRecoveryRollbackError):
            recovery_storage.rehearse_recovery_file(
                target,
                newer_setup.recovery_key,
                self.store,
                self.receipt,
            )

    def test_import_rejects_unsafe_directory_and_nonregular_target(self):
        setup = self.prepare()
        self.export(setup)
        target = self.exported_path()
        os.chmod(self.export_path, 0o755)
        with self.assertRaises(recovery_storage.UnsafeRecoveryDirectoryError):
            recovery_storage.rehearse_recovery_file(
                target, setup.recovery_key, self.store, self.receipt
            )
        os.chmod(self.export_path, 0o700)
        target.unlink()
        target.mkdir(mode=0o700)
        with self.assertRaises(recovery_storage.RecoveryFileConflictError):
            recovery_storage.rehearse_recovery_file(
                target, setup.recovery_key, self.store, self.receipt
            )

    def test_vault_change_during_file_rehearsal_is_rejected(self):
        setup = self.prepare()
        self.export(setup)
        real_read_path = recovery_storage._read_recovery_path
        calls = 0

        def read_then_dirty(path):
            nonlocal calls
            result = real_read_path(path)
            calls += 1
            if calls == 1:
                (self.vault_path / "late-conflict").write_bytes(b"conflict")
            return result

        with mock.patch.object(
            recovery_storage,
            "_read_recovery_path",
            side_effect=read_then_dirty,
        ):
            with self.assertRaises(
                recovery_storage.VaultRecoveryStorageStateError
            ):
                recovery_storage.rehearse_recovery_file(
                    self.exported_path(),
                    setup.recovery_key,
                    self.store,
                    self.receipt,
                )

    def test_import_recovery_key_type_and_length_remain_exact(self):
        setup = self.prepare()
        self.export(setup)
        for value in (None, "secret", b"", b"R" * 31, b"R" * 33):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(recovery.VaultRecoveryFormatError):
                    recovery_storage.rehearse_recovery_file(
                        self.exported_path(), value, self.store, self.receipt
                    )


class RecoveryStorageScopeTests(unittest.TestCase):
    def test_module_has_no_network_gui_logging_replace_rename_or_key_export(self):
        source = inspect.getsource(recovery_storage)
        tree = ast.parse(source)
        forbidden = {
            "replace",
            "rename",
            "renames",
            "remove",
            "socket",
            "urlopen",
            "print",
            "publish",
        }
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in forbidden:
                found.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden:
                found.add(node.func.attr)
        self.assertEqual(found, set())
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("export_recovery_key", source)
        self.assertNotIn("write_recovery_key", source)
        self.assertFalse(imports & {"socket", "logging", "tkinter"})

    def test_public_results_never_expose_paths_or_secrets(self):
        for value in (
            recovery_storage.VaultRecoveryExportReceipt,
            recovery_storage.VaultRecoveryFileRehearsal,
        ):
            fields = set(value.__dataclass_fields__)
            for forbidden in {
                "path",
                "filename",
                "record",
                "recovery_key",
                "keyring",
                "wrapping_key",
                "password",
                "plaintext",
            }:
                self.assertNotIn(forbidden, fields)

    def test_import_api_is_read_only_at_source_level(self):
        source = inspect.getsource(recovery_storage.rehearse_recovery_file)
        tree = ast.parse(source)
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(called & {"write", "unlink", "link", "chmod", "mkdir"})

    def test_descriptor_flags_require_no_follow_cloexec_and_exclusive_create(self):
        self.assertTrue(recovery_storage._directory_flags() & os.O_RDONLY == os.O_RDONLY)
        self.assertTrue(recovery_storage._directory_flags() & os.O_NOFOLLOW)
        self.assertTrue(recovery_storage._file_flags() & os.O_NOFOLLOW)
        self.assertTrue(recovery_storage._directory_flags() & os.O_CLOEXEC)
        self.assertTrue(recovery_storage._file_flags() & os.O_CLOEXEC)
        self.assertTrue(recovery_storage._create_flags() & os.O_CREAT)
        self.assertTrue(recovery_storage._create_flags() & os.O_EXCL)

    def test_missing_security_flag_is_never_silently_downgraded(self):
        with mock.patch.object(recovery_storage.os, "O_NOFOLLOW", 0):
            with self.assertRaises(
                recovery_storage.RecoveryExportUnsupportedError
            ):
                recovery_storage._file_flags()


if __name__ == "__main__":
    unittest.main()
