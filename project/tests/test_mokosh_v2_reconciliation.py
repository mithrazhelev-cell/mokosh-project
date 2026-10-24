import inspect
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mokosh_v2_filesystem import ExclusiveFileQuarantineSink
from mokosh_v2_operation_journal import (
    JOURNAL_NAME_PREFIX,
    TEMP_NAME_PREFIX,
    build_operation_journal,
    encode_operation_journal,
    journal_name_for,
    operation_id_from_temporary_name,
    temporary_name_for,
)
from mokosh_v2_reconciliation import (
    ReconciliationDirectoryChanged,
    ReconciliationStatus,
    UnsafeReconciliationDirectory,
    scan_quarantine_directory,
)


class PrivateDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)
        os.chmod(self.directory, 0o700)

    def tearDown(self):
        self._temporary.cleanup()

    def abandon(self, sink):
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False


class ReconciliationDiscoveryTests(PrivateDirectoryTestCase):
    def test_active_record_is_only_a_read_only_inode_match(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        sink.write(b"in progress")
        report = scan_quarantine_directory(self.directory)
        self.assertFalse(report.mutation_permitted)
        self.assertEqual(report.directory_device, self.directory.stat().st_dev)
        self.assertEqual(report.directory_inode, self.directory.stat().st_ino)
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.status, ReconciliationStatus.RECORDED_INODE_MATCH)
        self.assertFalse(finding.mutation_permitted)
        self.assertEqual(finding.journal_name, Path(sink.journal_path).name)
        self.assertEqual(finding.temporary_name, Path(sink.temp_path).name)
        sink.abort()

    def test_normal_commit_and_abort_leave_no_reconciliation_artifacts(self):
        first = ExclusiveFileQuarantineSink(self.directory / "committed.mok")
        first.write(b"complete")
        first.commit()
        second = ExclusiveFileQuarantineSink(self.directory / "aborted.mok")
        second.write(b"cancel")
        second.abort()
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(report.findings, ())
        self.assertFalse((self.directory / "aborted.mok").exists())

    def test_missing_temporary_is_reported_without_modification(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temp = Path(sink.temp_path)
        journal = Path(sink.journal_path)
        temp.unlink()
        self.abandon(sink)
        before = journal.read_bytes()
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            [item.status for item in report.findings],
            [ReconciliationStatus.TEMPORARY_MISSING],
        )
        self.assertEqual(journal.read_bytes(), before)

    def test_replaced_temporary_is_mismatch_and_not_removed(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temp = Path(sink.temp_path)
        moved = self.directory / "original-inode"
        temp.rename(moved)
        temp.write_bytes(b"foreign")
        os.chmod(temp, 0o600)
        self.abandon(sink)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.TEMPORARY_IDENTITY_MISMATCH,
        )
        self.assertEqual(temp.read_bytes(), b"foreign")
        self.assertTrue(moved.exists())

    def test_added_hardlink_is_reported_and_neither_link_is_removed(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temp = Path(sink.temp_path)
        other = self.directory / "second-link"
        os.link(temp, other)
        self.abandon(sink)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED,
        )
        self.assertTrue(temp.exists())
        self.assertTrue(other.exists())

    def test_publish_crash_window_is_link_count_changed_not_cleanup_permission(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temp = Path(sink.temp_path)
        published = self.directory / "result.mok"
        os.link(temp, published)
        self.abandon(sink)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED,
        )
        self.assertFalse(report.findings[0].mutation_permitted)
        self.assertTrue(temp.exists())
        self.assertTrue(published.exists())

    def test_tampered_and_noncanonical_journals_are_invalid(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        journal = Path(sink.journal_path)
        journal.write_bytes(journal.read_bytes() + b"\n")
        self.abandon(sink)
        report = scan_quarantine_directory(self.directory)
        statuses = {item.status for item in report.findings}
        self.assertIn(ReconciliationStatus.INVALID_JOURNAL, statuses)
        self.assertIn(ReconciliationStatus.UNRECORDED_TEMPORARY, statuses)
        self.assertTrue(journal.exists())

    def test_symlink_or_public_journal_is_unsafe_and_untouched(self):
        operation_id = "a" * 32
        journal = self.directory / journal_name_for(operation_id)
        target = self.directory / "target"
        target.write_bytes(b"foreign")
        journal.symlink_to(target)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.UNSAFE_JOURNAL,
        )
        self.assertTrue(journal.is_symlink())
        journal.unlink()
        journal.write_bytes(b"{}")
        os.chmod(journal, 0o644)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.UNSAFE_JOURNAL,
        )

    def test_unrecorded_canonical_and_malformed_temporaries_are_reported(self):
        names = (
            temporary_name_for("b" * 32),
            TEMP_NAME_PREFIX + "not-canonical",
        )
        for name in names:
            path = self.directory / name
            path.write_bytes(b"unknown")
            os.chmod(path, 0o600)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            [item.status for item in report.findings],
            [
                ReconciliationStatus.UNRECORDED_TEMPORARY,
                ReconciliationStatus.UNRECORDED_TEMPORARY,
            ],
        )
        self.assertTrue(all((self.directory / name).exists() for name in names))

    def test_prefix_alone_never_grants_mutation_permission(self):
        operation_id = "c" * 32
        temp = self.directory / temporary_name_for(operation_id)
        temp.write_bytes(b"attacker-created")
        os.chmod(temp, 0o600)
        report = scan_quarantine_directory(self.directory)
        self.assertFalse(report.mutation_permitted)
        self.assertFalse(report.findings[0].mutation_permitted)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.UNRECORDED_TEMPORARY,
        )

    def test_valid_looking_forged_pair_still_does_not_authorize_cleanup(self):
        operation_id = "d" * 32
        temp = self.directory / temporary_name_for(operation_id)
        temp.write_bytes(b"forged but structurally consistent")
        os.chmod(temp, 0o600)
        parent_stat = self.directory.stat()
        temp_stat = temp.stat()
        record = build_operation_journal(
            operation_id=operation_id,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
            temp_device=temp_stat.st_dev,
            temp_inode=temp_stat.st_ino,
            owner_uid=temp_stat.st_uid,
            owner_gid=temp_stat.st_gid,
        )
        journal = self.directory / journal_name_for(operation_id)
        journal.write_bytes(encode_operation_journal(record))
        os.chmod(journal, 0o600)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.RECORDED_INODE_MATCH,
        )
        self.assertFalse(report.findings[0].mutation_permitted)
        self.assertTrue(temp.exists())
        self.assertTrue(journal.exists())

    def test_wrong_parent_binding_is_invalid(self):
        operation_id = "e" * 32
        temp = self.directory / temporary_name_for(operation_id)
        temp.write_bytes(b"data")
        os.chmod(temp, 0o600)
        temp_stat = temp.stat()
        record = build_operation_journal(
            operation_id=operation_id,
            parent_device=self.directory.stat().st_dev,
            parent_inode=self.directory.stat().st_ino + 1,
            temp_device=temp_stat.st_dev,
            temp_inode=temp_stat.st_ino,
            owner_uid=temp_stat.st_uid,
            owner_gid=temp_stat.st_gid,
        )
        journal = self.directory / journal_name_for(operation_id)
        journal.write_bytes(encode_operation_journal(record))
        os.chmod(journal, 0o600)
        report = scan_quarantine_directory(self.directory)
        self.assertIn(
            ReconciliationStatus.INVALID_JOURNAL,
            {item.status for item in report.findings},
        )

    def test_invalid_journal_prefix_name_is_reported_not_opened_as_trusted(self):
        journal = self.directory / (JOURNAL_NAME_PREFIX + "bad.json")
        journal.write_bytes(b"{}")
        os.chmod(journal, 0o600)
        report = scan_quarantine_directory(self.directory)
        self.assertEqual(
            report.findings[0].status,
            ReconciliationStatus.INVALID_JOURNAL,
        )

    def test_symlink_public_and_non_directory_targets_are_rejected(self):
        public = self.directory / "public"
        public.mkdir(mode=0o700)
        os.chmod(public, 0o777)
        real = self.directory / "real"
        real.mkdir(mode=0o700)
        link = self.directory / "link"
        link.symlink_to(real, target_is_directory=True)
        file_path = self.directory / "file"
        file_path.write_bytes(b"x")
        for value in (public, link, file_path, self.directory / "missing"):
            with self.subTest(value=value):
                with self.assertRaises(UnsafeReconciliationDirectory):
                    scan_quarantine_directory(value)

    def test_directory_change_during_scan_is_rejected(self):
        real_listdir = os.listdir

        def changing_listdir(descriptor):
            names = real_listdir(descriptor)
            (self.directory / "late-file").write_bytes(b"change")
            return names

        with patch("mokosh_v2_reconciliation.os.listdir", side_effect=changing_listdir):
            with self.assertRaises(ReconciliationDirectoryChanged):
                scan_quarantine_directory(self.directory)

    def test_scan_does_not_change_file_names_content_modes_or_links(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        sink.write(b"in progress")

        def snapshot():
            values = {}
            for path in self.directory.iterdir():
                item = path.lstat()
                values[path.name] = (
                    path.read_bytes() if path.is_file() else None,
                    stat.S_IMODE(item.st_mode),
                    item.st_ino,
                    item.st_nlink,
                    item.st_size,
                    item.st_mtime_ns,
                )
            return values

        before = snapshot()
        scan_quarantine_directory(self.directory)
        self.assertEqual(snapshot(), before)
        sink.abort()


class ReconciliationScopeTests(unittest.TestCase):
    def test_reconciliation_has_no_mutation_gui_network_logging_or_crypto(self):
        import mokosh_v2_reconciliation

        source = inspect.getsource(mokosh_v2_reconciliation)
        for forbidden in (
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
            "os.link",
            "os.write",
            "tkinter",
            "socket",
            "requests",
            "logging",
            "AESGCM",
            "decrypt_stream",
            "private_key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
