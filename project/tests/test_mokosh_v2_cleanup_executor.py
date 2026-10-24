import inspect
import os
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

from mokosh_v2_cleanup_authorization import (
    CleanupUserDecision,
    PreparedCleanupAuthorization,
    prepare_cleanup_authorization,
)
from mokosh_v2_cleanup_executor import (
    CleanupExecutionError,
    CleanupExecutionResult,
    CleanupExecutionStatus,
    execute_cleanup,
)
from mokosh_v2_filesystem import ExclusiveFileQuarantineSink
from mokosh_v2_operation_journal import operation_id_from_temporary_name
from mokosh_v2_operation_lease import (
    LeaseProbeStatus,
    OperationLeaseBackend,
    OperationLeaseProbe,
)
from mokosh_v2_reconciliation import scan_quarantine_directory
from mokosh_v2_reconciliation_evidence import build_reconciliation_evidence


class PrivateDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)
        os.chmod(self.directory, 0o700)

    def tearDown(self):
        self._temporary.cleanup()

    @staticmethod
    def operation_id(sink):
        return operation_id_from_temporary_name(Path(sink.temp_path).name)

    @staticmethod
    def abandon(sink):
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False

    def prepared_pair(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "published.mok")
        sink.write(b"quarantine payload")
        operation_id = self.operation_id(sink)
        evidence = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        self.abandon(sink)
        prepared = prepare_cleanup_authorization(
            self.directory,
            evidence,
            operation_id,
            CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        return sink, operation_id, prepared


class CleanupExecutorSuccessTests(PrivateDirectoryTestCase):
    def test_exact_pair_is_removed_after_fresh_validation(self):
        unrelated = self.directory / "unrelated.txt"
        unrelated.write_bytes(b"preserve")
        sink, operation_id, prepared = self.prepared_pair()
        result = execute_cleanup(self.directory, prepared)
        self.assertEqual(result.status, CleanupExecutionStatus.COMPLETED)
        self.assertEqual(result.operation_id, operation_id)
        self.assertTrue(result.temporary_removed)
        self.assertTrue(result.journal_removed)
        self.assertFalse(result.rescan_required)
        self.assertFalse(result.original_touched)
        self.assertFalse(result.output_touched)
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertFalse(Path(sink.journal_path).exists())
        self.assertEqual(unrelated.read_bytes(), b"preserve")

    def test_authorization_is_consumed_by_success(self):
        _, _, prepared = self.prepared_pair()
        execute_cleanup(self.directory, prepared)
        self.assertTrue(prepared.claimed)
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)

    def test_only_canonical_temp_then_journal_are_unlinked(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_unlink = os.unlink
        calls = []

        def tracked(name, *, dir_fd=None):
            calls.append(name)
            return real_unlink(name, dir_fd=dir_fd)

        with patch.object(module.os, "unlink", side_effect=tracked):
            execute_cleanup(self.directory, prepared)
        self.assertEqual(
            calls,
            [Path(sink.temp_path).name, Path(sink.journal_path).name],
        )

    def test_lease_is_held_during_both_unlinks(self):
        _, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_unlink = os.unlink
        observed = []
        lease_ref = []

        def tracked(name, *, dir_fd=None):
            observed.append(lease_ref[0].fileno() >= 0)
            return real_unlink(name, dir_fd=dir_fd)

        real_probe = module.probe_operation_lease

        def probe(descriptor):
            result = real_probe(descriptor)
            lease_ref.append(result.lease)
            return result

        with patch.object(module, "probe_operation_lease", side_effect=probe), patch.object(
            module.os, "unlink", side_effect=tracked
        ):
            execute_cleanup(self.directory, prepared)
        self.assertEqual(observed, [True, True])

    def test_success_performs_preflight_and_two_post_unlink_syncs(self):
        _, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_sync = module._strict_directory_sync
        calls = []

        def tracked(descriptor):
            calls.append(descriptor)
            return real_sync(descriptor)

        with patch.object(module, "_strict_directory_sync", side_effect=tracked):
            execute_cleanup(self.directory, prepared)
        self.assertEqual(len(calls), 3)


class CleanupExecutorRefusalTests(PrivateDirectoryTestCase):
    def test_non_prepared_values_are_rejected_without_mutation(self):
        for value in (None, {}, b"claim", True):
            with self.subTest(value=value), self.assertRaises(CleanupExecutionError):
                execute_cleanup(self.directory, value)

    def test_preflight_fsync_failure_refuses_before_unlink(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        with patch.object(
            module,
            "_strict_directory_sync",
            side_effect=CleanupExecutionError("forced"),
        ), patch.object(module.os, "unlink") as unlink, self.assertRaises(
            CleanupExecutionError
        ):
            execute_cleanup(self.directory, prepared)
        unlink.assert_not_called()
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())
        self.assertTrue(prepared.claimed)

    def test_changed_directory_contents_invalidate_evidence(self):
        sink, _, prepared = self.prepared_pair()
        (self.directory / "new-entry").write_bytes(b"change")
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

    def test_replaced_temporary_inode_is_never_removed(self):
        sink, _, prepared = self.prepared_pair()
        temp = Path(sink.temp_path)
        moved = self.directory / "original-temp"
        temp.rename(moved)
        temp.write_bytes(b"foreign")
        os.chmod(temp, 0o600)
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertEqual(temp.read_bytes(), b"foreign")
        self.assertTrue(moved.exists())
        self.assertTrue(Path(sink.journal_path).exists())

    def test_replaced_journal_inode_is_never_removed(self):
        sink, _, prepared = self.prepared_pair()
        journal = Path(sink.journal_path)
        original = self.directory / "original-journal"
        journal.rename(original)
        journal.write_bytes(original.read_bytes())
        os.chmod(journal, 0o600)
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(journal.exists())
        self.assertTrue(original.exists())
        self.assertTrue(Path(sink.temp_path).exists())

    def test_wrong_directory_is_rejected_and_authorization_consumed(self):
        sink, _, prepared = self.prepared_pair()
        with tempfile.TemporaryDirectory() as other:
            os.chmod(other, 0o700)
            with self.assertRaises(CleanupExecutionError):
                execute_cleanup(other, prepared)
        self.assertTrue(prepared.claimed)
        self.assertTrue(Path(sink.temp_path).exists())

    def test_active_writer_probe_is_rejected(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        def active(descriptor):
            os.close(descriptor)
            return OperationLeaseProbe(
                LeaseProbeStatus.HELD_BY_OTHER,
                OperationLeaseBackend.POSIX_FLOCK,
                None,
            )

        with patch.object(module, "probe_operation_lease", side_effect=active), self.assertRaises(
            CleanupExecutionError
        ):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

    def test_unsupported_lease_is_rejected(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        def unsupported(descriptor):
            os.close(descriptor)
            return OperationLeaseProbe(LeaseProbeStatus.UNSUPPORTED, None, None)

        with patch.object(
            module,
            "probe_operation_lease",
            side_effect=unsupported,
        ), self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(Path(sink.temp_path).exists())

    def test_backend_mismatch_is_rejected(self):
        sink, _, prepared = self.prepared_pair()
        original = prepared._claim
        other = (
            OperationLeaseBackend.WINDOWS_MSVCRT
            if original.lease_backend is OperationLeaseBackend.POSIX_FLOCK
            else OperationLeaseBackend.POSIX_FLOCK
        )
        prepared._claim = replace(original, lease_backend=other)
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(Path(sink.temp_path).exists())

    def test_authorization_is_burned_even_when_executor_rescan_fails(self):
        _, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        with patch.object(
            module,
            "_validate_fresh_evidence",
            side_effect=CleanupExecutionError("forced"),
        ), self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(prepared.claimed)
        with self.assertRaises(CleanupExecutionError):
            execute_cleanup(self.directory, prepared)


class CleanupExecutorPartialResultTests(PrivateDirectoryTestCase):
    def test_failure_after_temporary_unlink_retains_journal(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_sync = module._strict_directory_sync
        count = 0

        def fail_second(descriptor):
            nonlocal count
            count += 1
            if count == 2:
                raise CleanupExecutionError("forced")
            return real_sync(descriptor)

        with patch.object(module, "_strict_directory_sync", side_effect=fail_second):
            result = execute_cleanup(self.directory, prepared)
        self.assertEqual(
            result.status,
            CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED,
        )
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())
        self.assertTrue(result.rescan_required)

    def test_journal_unlink_failure_returns_rescan_result(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_unlink = os.unlink
        count = 0

        def fail_second(name, *, dir_fd=None):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("forced")
            return real_unlink(name, dir_fd=dir_fd)

        with patch.object(module.os, "unlink", side_effect=fail_second):
            result = execute_cleanup(self.directory, prepared)
        self.assertEqual(
            result.status,
            CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED,
        )
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

    def test_final_sync_failure_reports_pair_removed_uncertain(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        real_sync = module._strict_directory_sync
        count = 0

        def fail_third(descriptor):
            nonlocal count
            count += 1
            if count == 3:
                raise CleanupExecutionError("forced")
            return real_sync(descriptor)

        with patch.object(module, "_strict_directory_sync", side_effect=fail_third):
            result = execute_cleanup(self.directory, prepared)
        self.assertEqual(
            result.status,
            CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN,
        )
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertFalse(Path(sink.journal_path).exists())
        self.assertTrue(result.rescan_required)

    def test_keyboard_interrupt_before_mutation_propagates_without_unlink(self):
        sink, _, prepared = self.prepared_pair()
        import mokosh_v2_cleanup_executor as module

        with patch.object(
            module,
            "_validate_fresh_evidence",
            side_effect=KeyboardInterrupt,
        ), self.assertRaises(KeyboardInterrupt):
            execute_cleanup(self.directory, prepared)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())


class CleanupExecutorContractTests(unittest.TestCase):
    def test_result_schema_contains_no_paths_names_or_sensitive_metadata(self):
        names = {field.name for field in fields(CleanupExecutionResult)}
        for forbidden in (
            "path",
            "directory_path",
            "journal_name",
            "temporary_name",
            "source_name",
            "output_name",
            "size",
            "timestamp",
            "key",
            "content",
        ):
            self.assertNotIn(forbidden, names)

    def test_module_has_exactly_two_unlink_sites_and_no_broad_mutation_api(self):
        import mokosh_v2_cleanup_executor

        source = inspect.getsource(mokosh_v2_cleanup_executor)
        self.assertEqual(source.count("os.unlink("), 2)
        for forbidden in (
            "os.remove(",
            "os.rename(",
            "os.replace(",
            "os.link(",
            "shutil",
            "glob(",
            "rmtree",
            "decrypt",
            "private_key",
            "socket",
            "requests",
            "tkinter",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_result_policy_rejects_false_safety_flags(self):
        valid = CleanupExecutionResult(
            "a" * 32,
            "b" * 32,
            CleanupExecutionStatus.COMPLETED,
            True,
            True,
            False,
        )
        for change in (
            {"temporary_removed": False},
            {"journal_removed": False},
            {"rescan_required": True},
            {"original_touched": True},
            {"output_touched": True},
            {"status": "completed"},
        ):
            with self.subTest(change=change), self.assertRaises(CleanupExecutionError):
                replace(valid, **change)


if __name__ == "__main__":
    unittest.main()
