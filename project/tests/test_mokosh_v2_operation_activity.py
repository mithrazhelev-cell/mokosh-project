import inspect
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mokosh_v2_filesystem import ExclusiveFileQuarantineSink
from mokosh_v2_operation_activity import (
    OperationActivityAssessment,
    OperationActivityError,
    OperationActivityStatus,
    assess_operation_activity,
)
from mokosh_v2_operation_journal import (
    build_operation_journal,
    encode_operation_journal,
    journal_name_for,
    operation_id_from_temporary_name,
    temporary_name_for,
)
from mokosh_v2_operation_lease import (
    LeaseProbeStatus,
    OperationLeaseBackend,
    OperationLeaseProbe,
)


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


class OperationActivityIntegrationTests(PrivateDirectoryTestCase):
    def test_active_sink_is_observed_without_mutation_permission(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        result = assess_operation_activity(self.directory, self.operation_id(sink))
        self.assertEqual(result.status, OperationActivityStatus.ACTIVE)
        self.assertTrue(result.exact_identity_verified)
        self.assertTrue(result.active_writer_observed)
        self.assertFalse(result.cooperating_writer_absent)
        self.assertFalse(result.abandonment_proven)
        self.assertFalse(result.mutation_permitted)
        sink.abort()

    def test_released_lease_is_only_a_candidate(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        self.abandon(sink)
        result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(
            result.status,
            OperationActivityStatus.RELEASED_CANDIDATE,
        )
        self.assertTrue(result.exact_identity_verified)
        self.assertFalse(result.active_writer_observed)
        self.assertTrue(result.cooperating_writer_absent)
        self.assertTrue(result.user_decision_required)
        self.assertTrue(result.rescan_required)
        self.assertFalse(result.abandonment_proven)
        self.assertFalse(result.mutation_permitted)

    def test_normal_commit_and_abort_close_writer_lease(self):
        committed = ExclusiveFileQuarantineSink(self.directory / "committed.mok")
        commit_lease = committed._journal_lease
        committed.write(b"complete")
        committed.commit()
        self.assertTrue(commit_lease.closed)
        aborted = ExclusiveFileQuarantineSink(self.directory / "aborted.mok")
        abort_lease = aborted._journal_lease
        aborted.abort()
        self.assertTrue(abort_lease.closed)

    def test_replaced_temporary_is_identity_conflict(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        temporary = Path(sink.temp_path)
        temporary.rename(self.directory / "original")
        temporary.write_bytes(b"foreign")
        os.chmod(temporary, 0o600)
        result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(result.status, OperationActivityStatus.IDENTITY_CONFLICT)
        self.assertFalse(result.exact_identity_verified)
        self.assertTrue(temporary.exists())
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False

    def test_changed_link_count_is_identity_conflict(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        os.link(sink.temp_path, self.directory / "second-link")
        result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(result.status, OperationActivityStatus.IDENTITY_CONFLICT)
        self.assertFalse(result.mutation_permitted)
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False

    def test_missing_or_tampered_journal_is_identity_conflict(self):
        for action in ("missing", "tampered"):
            with self.subTest(action=action):
                sink = ExclusiveFileQuarantineSink(
                    self.directory / f"{action}.mok"
                )
                operation_id = self.operation_id(sink)
                journal = Path(sink.journal_path)
                if action == "missing":
                    journal.unlink()
                else:
                    journal.write_bytes(journal.read_bytes() + b"\n")
                result = assess_operation_activity(self.directory, operation_id)
                self.assertEqual(
                    result.status,
                    OperationActivityStatus.IDENTITY_CONFLICT,
                )
                sink._journal_lease.close()
                os.close(sink._descriptor)
                os.close(sink._parent_descriptor)
                sink._active = False

    def test_unsupported_backend_is_explicit_and_fail_closed(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        self.abandon(sink)
        import mokosh_v2_operation_lease

        with patch.object(
            mokosh_v2_operation_lease,
            "_load_backend",
            side_effect=mokosh_v2_operation_lease.OperationLeaseUnsupported(
                "forced"
            ),
        ):
            result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(
            result.status,
            OperationActivityStatus.LEASE_UNSUPPORTED,
        )
        self.assertTrue(result.exact_identity_verified)
        self.assertFalse(result.cooperating_writer_absent)
        self.assertFalse(result.mutation_permitted)

    def test_probe_error_is_identity_conflict(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        self.abandon(sink)
        result_value = OperationLeaseProbe(
            LeaseProbeStatus.ERROR,
            OperationLeaseBackend.POSIX_FLOCK,
            None,
        )

        def error_probe(descriptor):
            os.close(descriptor)
            return result_value

        with patch(
            "mokosh_v2_operation_activity.probe_operation_lease",
            side_effect=error_probe,
        ):
            result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(result.status, OperationActivityStatus.IDENTITY_CONFLICT)

    def test_change_during_acquired_probe_is_conflict_and_files_remain(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        self.abandon(sink)
        temporary = Path(sink.temp_path)
        real_probe = __import__(
            "mokosh_v2_operation_lease"
        ).probe_operation_lease

        def changing_probe(descriptor):
            result = real_probe(descriptor)
            os.chmod(temporary, 0o400)
            return result

        with patch(
            "mokosh_v2_operation_activity.probe_operation_lease",
            side_effect=changing_probe,
        ):
            result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(result.status, OperationActivityStatus.IDENTITY_CONFLICT)
        self.assertTrue(temporary.exists())
        self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o400)

    def test_assessment_does_not_change_names_content_modes_or_links(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")

        def snapshot():
            return {
                path.name: (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                    path.stat().st_ino,
                    path.stat().st_nlink,
                    path.stat().st_size,
                    path.stat().st_mtime_ns,
                )
                for path in self.directory.iterdir()
            }

        before = snapshot()
        assess_operation_activity(self.directory, self.operation_id(sink))
        self.assertEqual(snapshot(), before)
        sink.abort()

    def test_valid_forged_pair_can_only_be_released_candidate(self):
        operation_id = "d" * 32
        temporary = self.directory / temporary_name_for(operation_id)
        temporary.write_bytes(b"forged")
        os.chmod(temporary, 0o600)
        parent = self.directory.stat()
        temp_stat = temporary.stat()
        record = build_operation_journal(
            operation_id=operation_id,
            parent_device=parent.st_dev,
            parent_inode=parent.st_ino,
            temp_device=temp_stat.st_dev,
            temp_inode=temp_stat.st_ino,
            owner_uid=temp_stat.st_uid,
            owner_gid=temp_stat.st_gid,
        )
        journal = self.directory / journal_name_for(operation_id)
        journal.write_bytes(encode_operation_journal(record))
        os.chmod(journal, 0o600)
        result = assess_operation_activity(self.directory, operation_id)
        self.assertEqual(
            result.status,
            OperationActivityStatus.RELEASED_CANDIDATE,
        )
        self.assertFalse(result.abandonment_proven)
        self.assertFalse(result.mutation_permitted)
        self.assertTrue(temporary.exists())
        self.assertTrue(journal.exists())


class OperationActivityContractTests(unittest.TestCase):
    def test_invalid_operation_identifiers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            for value in ("", "0" * 31, "A" * 32, True, None):
                with self.subTest(value=value):
                    with self.assertRaises(OperationActivityError):
                        assess_operation_activity(directory, value)

    def test_assessment_invariants_reject_false_safety_claims(self):
        base = dict(
            operation_id="0" * 32,
            status=OperationActivityStatus.RELEASED_CANDIDATE,
            backend=OperationLeaseBackend.POSIX_FLOCK,
            exact_identity_verified=True,
            active_writer_observed=False,
            cooperating_writer_absent=True,
        )
        OperationActivityAssessment(**base)
        for change in (
            {"exact_identity_verified": False},
            {"active_writer_observed": True},
            {"abandonment_proven": True},
            {"mutation_permitted": True},
            {"rescan_required": False},
            {"user_decision_required": False},
        ):
            with self.subTest(change=change):
                with self.assertRaises(OperationActivityError):
                    OperationActivityAssessment(**(base | change))

    def test_result_schema_contains_no_paths_or_file_names(self):
        fields = set(OperationActivityAssessment.__dataclass_fields__)
        for forbidden in (
            "path",
            "directory_path",
            "journal_name",
            "temporary_name",
            "output_name",
            "source_name",
        ):
            self.assertNotIn(forbidden, fields)

    def test_module_has_no_cleanup_publish_crypto_network_gui_or_trust(self):
        import mokosh_v2_operation_activity

        source = inspect.getsource(mokosh_v2_operation_activity)
        for forbidden in (
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
            "os.link",
            "os.write",
            "AESGCM",
            "decrypt",
            "private_key",
            "socket",
            "requests",
            "tkinter",
            "trust",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
