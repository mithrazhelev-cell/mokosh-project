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

import mokosh_vault_storage as storage
from mokosh_vault_format import (
    VaultSession,
    VaultSessionState,
    create_vault,
)


PASSWORD = "Stage 2.2 correct password"
NEW_PASSWORD = "Stage 2.2 new password"
ROOT_KEY = bytes(range(32))
VAULT_ID = bytes(range(16))
CREATED = "2026-08-11T10:00:00Z"
UPDATED = "2026-08-11T11:00:00Z"


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


def make_session(*, password=PASSWORD, vault_id=VAULT_ID, root_key=ROOT_KEY):
    encoded = create_vault(
        password,
        root_key=root_key,
        vault_id=vault_id,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )
    clock = FakeClock()
    session = VaultSession(encoded, inactivity_timeout=10, clock=clock)
    session.unlock(password)
    return session, clock


def advance_session(session):
    session.change_password(
        NEW_PASSWORD,
        updated_utc=UPDATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.parent_context = tempfile.TemporaryDirectory(
            prefix="mokosh-vault-storage-test-"
        )
        self.parent = Path(self.parent_context.name)
        os.chmod(self.parent, 0o700)
        self.path = self.parent / "vault"
        self.store = storage.VaultStorage.create(self.path)
        self.sessions = []

    def tearDown(self):
        for session in self.sessions:
            session.close()
        self.store.close()
        self.parent_context.cleanup()

    def session(self, **kwargs):
        session, clock = make_session(**kwargs)
        self.sessions.append(session)
        return session, clock

    def initial_publish(self):
        session, clock = self.session()
        receipt = self.store.publish(session)
        return session, clock, receipt


class VaultStorageCreationTests(StorageTestCase):
    def test_created_directory_is_private_and_exact(self):
        observed = os.lstat(self.path)
        self.assertTrue(stat.S_ISDIR(observed.st_mode))
        self.assertEqual(stat.S_IMODE(observed.st_mode), 0o700)
        self.assertEqual(self.store.directory_identity.inode, observed.st_ino)

    def test_existing_directory_is_never_reused_by_create(self):
        with self.assertRaises(storage.UnsafeVaultDirectoryError):
            storage.VaultStorage.create(self.path)

    def test_insecure_directory_mode_is_rejected(self):
        other = self.parent / "insecure"
        other.mkdir(mode=0o700)
        os.chmod(other, 0o755)
        with self.assertRaises(storage.UnsafeVaultDirectoryError):
            storage.VaultStorage(other)

    def test_symlink_directory_is_rejected(self):
        alias = self.parent / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(storage.UnsafeVaultDirectoryError):
            storage.VaultStorage(alias)

    def test_group_writable_parent_is_rejected_for_creation(self):
        insecure_parent = self.parent / "shared"
        insecure_parent.mkdir(mode=0o700)
        os.chmod(insecure_parent, 0o770)
        with self.assertRaises(storage.UnsafeVaultDirectoryError):
            storage.VaultStorage.create(insecure_parent / "vault")

    def test_replaced_directory_identity_is_rejected(self):
        moved = self.parent / "moved"
        self.path.rename(moved)
        self.path.mkdir(mode=0o700)
        with self.assertRaises(storage.UnsafeVaultDirectoryError):
            self.store.scan()

    def test_storage_cannot_be_copied_pickled_or_used_after_close(self):
        self.assertNotIn(str(self.path), repr(self.store))
        with self.assertRaises(TypeError):
            copy.copy(self.store)
        with self.assertRaises(TypeError):
            copy.deepcopy(self.store)
        with self.assertRaises(TypeError):
            pickle.dumps(self.store)
        self.store.close()
        with self.assertRaises(storage.VaultStorageError):
            self.store.scan()

    def test_generation_name_is_canonical_and_bounded(self):
        self.assertEqual(storage.generation_name(1), "vault-r00000000000000000001.mokv")
        for value in (0, -1, True, 10**20):
            with self.subTest(value=value):
                with self.assertRaises(storage.VaultGenerationConflictError):
                    storage.generation_name(value)


class VaultStoragePublishTests(StorageTestCase):
    def test_initial_publish_is_durable_private_and_no_clobber(self):
        session, _, receipt = self.initial_publish()
        final = self.path / storage.generation_name(1)
        observed = os.lstat(final)
        self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        self.assertTrue(receipt.durable)
        self.assertEqual(receipt.sha256, hashlib.sha256(session.encoded).digest())
        self.assertEqual(self.store.verify_receipt(receipt), session.encoded)
        self.assertEqual(
            [item.name for item in os.scandir(self.path)],
            [storage.generation_name(1)],
        )

    def test_update_creates_new_immutable_generation_and_keeps_old(self):
        session, _, first = self.initial_publish()
        first_stat = os.lstat(self.path / storage.generation_name(1))
        first_bytes = self.store.verify_receipt(first)
        advance_session(session)
        second = self.store.publish(session, previous=first)
        self.assertEqual(second.revision, 2)
        self.assertEqual(os.lstat(self.path / storage.generation_name(1)).st_ino, first_stat.st_ino)
        self.assertEqual(self.store.verify_receipt(first), first_bytes)
        self.assertEqual(self.store.verify_receipt(second), session.encoded)
        self.assertEqual(
            sorted(item.name for item in os.scandir(self.path)),
            [storage.generation_name(1), storage.generation_name(2)],
        )

    def test_publish_requires_unlocked_unexpired_session(self):
        session, clock = self.session()
        session.lock()
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session)
        session.unlock(PASSWORD)
        clock.value = 111.0
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session)
        self.assertIs(session.state, VaultSessionState.LOCKED)

    def test_initial_publish_requires_revision_one_and_empty_history(self):
        session, _ = self.session()
        advance_session(session)
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session)
        original, _, _ = self.initial_publish()
        other, _ = self.session(root_key=b"Z" * 32, vault_id=b"Y" * 16)
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(other)

    def test_update_requires_exact_latest_receipt_and_contiguous_revision(self):
        session, _, first = self.initial_publish()
        advance_session(session)
        forged = replace(first, sha256=b"x" * 32)
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session, previous=forged)
        wrong_revision = replace(first, revision=2)
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session, previous=wrong_revision)

    def test_update_rejects_different_vault_identifier(self):
        _, _, first = self.initial_publish()
        other, _ = self.session(vault_id=b"Q" * 16, root_key=b"R" * 32)
        advance_session(other)
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(other, previous=first)

    def test_target_collision_is_never_overwritten(self):
        session, _ = self.session()
        target = self.path / storage.generation_name(1)
        target.write_bytes(b"existing")
        os.chmod(target, 0o600)
        before = target.read_bytes()
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session)
        self.assertEqual(target.read_bytes(), before)

    def test_unknown_object_blocks_publish_without_modification(self):
        session, _ = self.session()
        unknown = self.path / "notes.txt"
        unknown.write_text("do not touch", encoding="utf-8")
        before = unknown.stat()
        with self.assertRaises(storage.VaultGenerationConflictError):
            self.store.publish(session)
        after = unknown.stat()
        self.assertEqual((before.st_ino, before.st_size), (after.st_ino, after.st_size))
        self.assertEqual(unknown.read_text(encoding="utf-8"), "do not touch")

    def test_receipt_is_bound_to_directory_inode_file_inode_and_digest(self):
        _, _, receipt = self.initial_publish()
        variants = (
            replace(receipt, directory_inode=receipt.directory_inode + 1),
            replace(receipt, file_inode=receipt.file_inode + 1),
            replace(receipt, sha256=b"x" * 32),
            replace(receipt, durable=False),
            replace(receipt, durable=1),
            replace(receipt, vault_id="x" * 16),
        )
        for changed in variants:
            with self.subTest(changed=changed):
                with self.assertRaises(storage.VaultGenerationConflictError):
                    self.store.verify_receipt(changed)


class VaultStorageReconciliationTests(StorageTestCase):
    def test_empty_and_valid_history_reports_are_complete(self):
        empty = self.store.scan()
        self.assertTrue(empty.complete)
        self.assertFalse(empty.has_conflict)
        self.assertEqual(empty.generations, ())
        _, _, receipt = self.initial_publish()
        report = self.store.scan()
        self.assertTrue(report.complete)
        self.assertFalse(report.has_conflict)
        self.assertEqual(report.generations, (receipt,))

    def test_scan_is_read_only(self):
        self.initial_publish()
        before = {
            entry.name: (entry.stat(follow_symlinks=False).st_ino, entry.stat(follow_symlinks=False).st_size)
            for entry in os.scandir(self.path)
        }
        self.store.scan()
        after = {
            entry.name: (entry.stat(follow_symlinks=False).st_ino, entry.stat(follow_symlinks=False).st_size)
            for entry in os.scandir(self.path)
        }
        self.assertEqual(after, before)

    def test_unlinked_and_linked_temporaries_are_classified_not_changed(self):
        unlinked = self.path / (".mokosh-vault-" + "a" * 32 + ".tmp")
        linked = self.path / (".mokosh-vault-" + "b" * 32 + ".tmp")
        unlinked.write_bytes(b"candidate")
        linked.write_bytes(b"candidate")
        os.chmod(unlinked, 0o600)
        os.chmod(linked, 0o600)
        os.link(linked, self.path / "linked-alias")
        report = self.store.scan()
        kinds = {finding.kind for finding in report.findings}
        self.assertIn(storage.VaultObjectKind.TEMPORARY_UNLINKED, kinds)
        self.assertIn(storage.VaultObjectKind.TEMPORARY_LINKED, kinds)
        self.assertIn(storage.VaultObjectKind.UNKNOWN, kinds)
        self.assertTrue(report.has_conflict)
        self.assertTrue(unlinked.exists())
        self.assertTrue(linked.exists())

    def test_invalid_generation_and_unknown_symlink_are_classified(self):
        invalid = self.path / storage.generation_name(1)
        invalid.write_bytes(b"not a vault")
        os.chmod(invalid, 0o600)
        (self.path / "alias").symlink_to(invalid.name)
        report = self.store.scan()
        kinds = [finding.kind for finding in report.findings]
        self.assertIn(storage.VaultObjectKind.GENERATION_INVALID, kinds)
        self.assertIn(storage.VaultObjectKind.UNKNOWN, kinds)
        self.assertEqual(invalid.read_bytes(), b"not a vault")

    def test_scan_limit_has_exact_omitted_count(self):
        for index in range(5):
            (self.path / f"unknown-{index}").write_bytes(b"x")
        report = self.store.scan(maximum_entries=2)
        self.assertFalse(report.complete)
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(report.omitted_entries, 3)
        with self.assertRaises(storage.VaultStorageLimitError):
            self.store.scan(maximum_entries=0)

    def test_findings_do_not_expose_basenames_or_paths(self):
        secret_name = "private-owner-note.txt"
        (self.path / secret_name).write_bytes(b"x")
        report = self.store.scan()
        rendered = repr(report)
        self.assertNotIn(secret_name, rendered)
        self.assertNotIn(str(self.path), rendered)

    def test_gap_or_mixed_vault_history_is_a_conflict(self):
        session, _ = self.session()
        advance_session(session)
        gap = self.path / storage.generation_name(2)
        gap.write_bytes(session.encoded)
        os.chmod(gap, 0o600)
        report = self.store.scan()
        self.assertTrue(report.has_conflict)

        gap.unlink()
        first, _ = self.session()
        first_path = self.path / storage.generation_name(1)
        first_path.write_bytes(first.encoded)
        os.chmod(first_path, 0o600)
        other, _ = self.session(vault_id=b"Q" * 16, root_key=b"R" * 32)
        advance_session(other)
        second_path = self.path / storage.generation_name(2)
        second_path.write_bytes(other.encoded)
        os.chmod(second_path, 0o600)
        self.assertTrue(self.store.scan().has_conflict)


class VaultStorageFaultInjectionTests(StorageTestCase):
    def assert_no_generation_or_temp(self):
        self.assertEqual(list(os.scandir(self.path)), [])

    def test_write_failure_removes_only_owned_unpublished_temporary(self):
        session, _ = self.session()
        with mock.patch.object(storage, "_write_all", side_effect=OSError("fault")):
            with self.assertRaises(OSError):
                self.store.publish(session)
        self.assert_no_generation_or_temp()

    def test_abort_does_not_unlink_temporary_after_foreign_hardlink(self):
        session, _ = self.session()
        alias = self.path / "foreign-alias"

        def link_then_fail(descriptor, data):
            with os.scandir(self.path) as entries:
                temporary = next(
                    entry.name for entry in entries if entry.name.endswith(".tmp")
                )
            os.link(self.path / temporary, alias)
            raise OSError("fault after unexpected link")

        with mock.patch.object(storage, "_write_all", side_effect=link_then_fail):
            with self.assertRaises(OSError):
                self.store.publish(session)
        names = sorted(entry.name for entry in os.scandir(self.path))
        self.assertEqual(len(names), 2)
        self.assertIn("foreign-alias", names)
        self.assertTrue(any(name.endswith(".tmp") for name in names))

    def test_file_fsync_failure_aborts_before_publish(self):
        session, _ = self.session()
        real_fsync = storage.os.fsync

        def fail_file_only(descriptor):
            if descriptor == self.store._descriptor:
                return real_fsync(descriptor)
            raise OSError("file fsync fault")

        with mock.patch.object(storage.os, "fsync", side_effect=fail_file_only):
            with self.assertRaises(OSError):
                self.store.publish(session)
        self.assert_no_generation_or_temp()

    def test_link_failure_aborts_without_generation(self):
        session, _ = self.session()
        with mock.patch.object(storage.os, "link", side_effect=OSError("link fault")):
            with self.assertRaises(storage.VaultPublishUnsupportedError):
                self.store.publish(session)
        self.assert_no_generation_or_temp()

    def test_directory_sync_failure_after_link_is_uncertain_and_preserved(self):
        session, _ = self.session()
        real_sync = storage._sync_directory
        calls = 0

        def fail_second(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise storage.VaultPublishUnsupportedError("fault")
            return real_sync(descriptor)

        with mock.patch.object(storage, "_sync_directory", side_effect=fail_second):
            with self.assertRaises(storage.VaultPublishUncertainError):
                self.store.publish(session)
        names = sorted(entry.name for entry in os.scandir(self.path))
        self.assertEqual(len(names), 2)
        self.assertIn(storage.generation_name(1), names)
        report = self.store.scan()
        self.assertTrue(report.has_conflict)

    def test_unlink_failure_after_link_is_uncertain_and_preserved(self):
        session, _ = self.session()
        real_unlink = storage.os.unlink

        def fail_temp(name, *args, **kwargs):
            if str(name).endswith(".tmp"):
                raise OSError("unlink fault")
            return real_unlink(name, *args, **kwargs)

        with mock.patch.object(storage.os, "unlink", side_effect=fail_temp):
            with self.assertRaises(storage.VaultPublishUncertainError):
                self.store.publish(session)
        names = sorted(entry.name for entry in os.scandir(self.path))
        self.assertEqual(len(names), 2)
        self.assertIn(storage.generation_name(1), names)

    def test_final_sync_failure_never_reports_success(self):
        session, _ = self.session()
        real_sync = storage._sync_directory
        calls = 0

        def fail_third(descriptor):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise storage.VaultPublishUnsupportedError("fault")
            return real_sync(descriptor)

        with mock.patch.object(storage, "_sync_directory", side_effect=fail_third):
            with self.assertRaises(storage.VaultPublishUncertainError):
                self.store.publish(session)
        self.assertTrue((self.path / storage.generation_name(1)).exists())

    def test_keyboard_interrupt_before_link_cleans_unpublished_temp_and_propagates(self):
        session, _ = self.session()
        with mock.patch.object(storage.os, "link", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.store.publish(session)
        self.assert_no_generation_or_temp()


class VaultStorageContractTests(unittest.TestCase):
    def test_module_has_no_replace_rename_network_gui_or_secret_logging(self):
        source = inspect.getsource(storage)
        tree = ast.parse(source)
        forbidden = {"replace", "rename", "renames", "socket", "urlopen", "print"}
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in forbidden:
                found.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden:
                found.add(node.func.attr)
        self.assertEqual(found, set())

    def test_report_and_receipt_schemas_have_no_path_or_filename(self):
        report_fields = set(storage.VaultStorageReport.__dataclass_fields__)
        receipt_fields = set(storage.VaultGenerationReceipt.__dataclass_fields__)
        for forbidden in {"path", "name", "filename", "password", "root_key"}:
            self.assertNotIn(forbidden, report_fields)
            self.assertNotIn(forbidden, receipt_fields)


if __name__ == "__main__":
    unittest.main()
