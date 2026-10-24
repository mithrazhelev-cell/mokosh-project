import copy
import inspect
import os
import pickle
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mokosh_v2_cleanup_authorization import (
    AUTHORIZATION_FORMAT,
    AUTHORIZATION_VERSION,
    CleanupAuthorizationClaim,
    CleanupAuthorizationError,
    CleanupUserDecision,
    PreparedCleanupAuthorization,
    prepare_cleanup_authorization,
)
from mokosh_v2_filesystem import ExclusiveFileQuarantineSink
from mokosh_v2_operation_activity import (
    OperationActivityAssessment,
    OperationActivityStatus,
)
from mokosh_v2_operation_journal import (
    operation_id_from_temporary_name,
)
from mokosh_v2_operation_lease import OperationLeaseBackend
from mokosh_v2_reconciliation import (
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
    scan_quarantine_directory,
)
from mokosh_v2_reconciliation_evidence import (
    build_reconciliation_evidence,
    reconciliation_evidence_sha256,
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

    def reviewed_pair(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        operation_id = self.operation_id(sink)
        evidence = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        return sink, operation_id, evidence

class CleanupAuthorizationSuccessTests(PrivateDirectoryTestCase):
    def test_released_candidate_prepares_exact_non_mutating_claim(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        with patch("mokosh_v2_cleanup_authorization.os.urandom", return_value=b"A" * 16):
            prepared = prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )
        self.assertFalse(prepared.claimed)
        claim = prepared.claim_once()
        self.assertTrue(prepared.claimed)
        self.assertEqual(claim.format, AUTHORIZATION_FORMAT)
        self.assertEqual(claim.version, AUTHORIZATION_VERSION)
        self.assertEqual(claim.authorization_id, "41" * 16)
        self.assertEqual(claim.operation_id, operation_id)
        self.assertEqual(claim.directory_device, evidence.directory_device)
        self.assertEqual(claim.directory_inode, evidence.directory_inode)
        self.assertEqual(
            claim.evidence_sha256,
            reconciliation_evidence_sha256(evidence),
        )
        self.assertEqual(claim.evidence_sequence, evidence.items[0].sequence)
        expected_backend = (
            OperationLeaseBackend.POSIX_FLOCK
            if os.name == "posix"
            else OperationLeaseBackend.WINDOWS_MSVCRT
        )
        self.assertEqual(claim.lease_backend, expected_backend)
        self.assertTrue(claim.user_confirmed)
        self.assertTrue(claim.reviewed_evidence_matched)
        self.assertTrue(claim.fresh_rescan_verified)
        self.assertTrue(claim.released_candidate_observed)
        self.assertTrue(claim.executor_rescan_required)
        self.assertTrue(claim.single_use_claim)
        self.assertFalse(claim.abandonment_proven)
        self.assertFalse(claim.mutation_permitted)

    def test_prepared_authorization_can_be_claimed_only_once(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        prepared = prepare_cleanup_authorization(
            self.directory,
            evidence,
            operation_id,
            CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        first = prepared.claim_once()
        self.assertIsInstance(first, CleanupAuthorizationClaim)
        with self.assertRaises(CleanupAuthorizationError):
            prepared.claim_once()

    def test_prepared_authorization_cannot_be_copied_or_serialized(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        prepared = prepare_cleanup_authorization(
            self.directory,
            evidence,
            operation_id,
            CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        for action in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(action=action):
                with self.assertRaises(CleanupAuthorizationError):
                    action()

    def test_preparation_performs_two_fresh_scans_around_activity(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        events = []
        import mokosh_v2_cleanup_authorization as module

        real_fresh = module._fresh_evidence
        real_activity = module.assess_operation_activity

        def fresh(directory):
            events.append("scan")
            return real_fresh(directory)

        def activity(directory, exact_id):
            events.append("activity")
            return real_activity(directory, exact_id)

        with patch.object(module, "_fresh_evidence", side_effect=fresh), patch.object(
            module,
            "assess_operation_activity",
            side_effect=activity,
        ):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )
        self.assertEqual(events, ["scan", "activity", "scan"])

    def test_preparation_does_not_change_directory_contents_or_metadata(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)

        def snapshot():
            return {
                path.name: (
                    path.read_bytes(),
                    path.stat().st_dev,
                    path.stat().st_ino,
                    path.stat().st_mode,
                    path.stat().st_nlink,
                    path.stat().st_size,
                    path.stat().st_mtime_ns,
                )
                for path in self.directory.iterdir()
            }

        before = snapshot()
        prepare_cleanup_authorization(
            self.directory,
            evidence,
            operation_id,
            CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertEqual(snapshot(), before)

    def test_forged_pair_never_becomes_abandonment_proof_or_mutation(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        claim = prepare_cleanup_authorization(
            self.directory,
            evidence,
            operation_id,
            CleanupUserDecision.AUTHORIZE_CLEANUP,
        ).claim_once()
        self.assertFalse(claim.abandonment_proven)
        self.assertFalse(claim.mutation_permitted)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())


class CleanupAuthorizationRefusalTests(PrivateDirectoryTestCase):
    def test_preserve_and_non_enum_decisions_are_rejected_before_rescan(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        import mokosh_v2_cleanup_authorization as module

        for decision in (CleanupUserDecision.PRESERVE, True, "authorize_cleanup"):
            with self.subTest(decision=decision), patch.object(
                module,
                "_fresh_evidence",
            ) as fresh:
                with self.assertRaises(CleanupAuthorizationError):
                    prepare_cleanup_authorization(
                        self.directory,
                        evidence,
                        operation_id,
                        decision,
                    )
                fresh.assert_not_called()

    def test_active_writer_is_rejected(self):
        sink, operation_id, evidence = self.reviewed_pair()
        with patch("mokosh_v2_cleanup_authorization.os.urandom") as random_source, \
                self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )
        random_source.assert_not_called()
        sink.abort()

    def test_unsupported_and_identity_conflict_are_rejected(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        variants = (
            OperationActivityAssessment(
                operation_id,
                OperationActivityStatus.LEASE_UNSUPPORTED,
                OperationLeaseBackend.POSIX_FLOCK,
                True,
                False,
                False,
            ),
            OperationActivityAssessment(
                operation_id,
                OperationActivityStatus.IDENTITY_CONFLICT,
                OperationLeaseBackend.POSIX_FLOCK,
                False,
                False,
                False,
            ),
        )
        for activity in variants:
            with self.subTest(status=activity.status), patch(
                "mokosh_v2_cleanup_authorization.assess_operation_activity",
                return_value=activity,
            ):
                with self.assertRaises(CleanupAuthorizationError):
                    prepare_cleanup_authorization(
                        self.directory,
                        evidence,
                        operation_id,
                        CleanupUserDecision.AUTHORIZE_CLEANUP,
                    )

    def test_reviewed_evidence_must_contain_exact_unique_inode_match(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        wrong_id = "f" * 32
        with self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                wrong_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

        source = scan_quarantine_directory(self.directory)
        duplicate_source = ReconciliationReport(
            (source.findings[0], source.findings[0]),
            source.scanned_entries,
            source.directory_device,
            source.directory_inode,
        )
        duplicate = build_reconciliation_evidence(duplicate_source)
        with self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                duplicate,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

    def test_incomplete_reviewed_evidence_is_rejected(self):
        first = ExclusiveFileQuarantineSink(self.directory / "first.mok")
        second = ExclusiveFileQuarantineSink(self.directory / "second.mok")
        operation_id = self.operation_id(first)
        incomplete = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory),
            max_items=1,
        )
        self.abandon(first)
        self.abandon(second)
        self.assertFalse(incomplete.complete)
        with self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                incomplete,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

    def test_non_matching_classification_is_rejected(self):
        sink, operation_id, _ = self.reviewed_pair()
        Path(sink.temp_path).unlink()
        self.abandon(sink)
        missing = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        with self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                missing,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

    def test_first_fresh_scan_must_exactly_match_reviewed_bytes(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        unrelated = self.directory / "unrelated"
        unrelated.write_bytes(b"x")
        with self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

    def test_change_between_activity_and_second_scan_is_rejected(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        import mokosh_v2_cleanup_authorization as module

        real_activity = module.assess_operation_activity

        def changing_activity(directory, exact_id):
            result = real_activity(directory, exact_id)
            (self.directory / "changed-after-activity").write_bytes(b"x")
            return result

        with patch.object(
            module,
            "assess_operation_activity",
            side_effect=changing_activity,
        ):
            with self.assertRaises(CleanupAuthorizationError):
                prepare_cleanup_authorization(
                    self.directory,
                    evidence,
                    operation_id,
                    CleanupUserDecision.AUTHORIZE_CLEANUP,
                )

    def test_invalid_random_source_is_rejected_only_after_all_checks(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        for source in (lambda size: b"short", lambda size: bytearray(size)):
            with self.subTest(source=source):
                with patch(
                    "mokosh_v2_cleanup_authorization.os.urandom",
                    side_effect=source,
                ), self.assertRaises(CleanupAuthorizationError):
                    prepare_cleanup_authorization(
                        self.directory,
                        evidence,
                        operation_id,
                        CleanupUserDecision.AUTHORIZE_CLEANUP,
                    )

    def test_random_source_error_is_wrapped_but_cancellation_propagates(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)

        def failed(size):
            raise RuntimeError("forced")

        with patch(
            "mokosh_v2_cleanup_authorization.os.urandom",
            side_effect=failed,
        ), self.assertRaises(CleanupAuthorizationError):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

        def interrupted(size):
            raise KeyboardInterrupt()

        with patch(
            "mokosh_v2_cleanup_authorization.os.urandom",
            side_effect=interrupted,
        ), self.assertRaises(KeyboardInterrupt):
            prepare_cleanup_authorization(
                self.directory,
                evidence,
                operation_id,
                CleanupUserDecision.AUTHORIZE_CLEANUP,
            )

    def test_invalid_operation_id_and_report_type_are_rejected(self):
        sink, operation_id, evidence = self.reviewed_pair()
        self.abandon(sink)
        for invalid_id in ("", "A" * 32, True, None):
            with self.subTest(invalid_id=invalid_id):
                with self.assertRaises(CleanupAuthorizationError):
                    prepare_cleanup_authorization(
                        self.directory,
                        evidence,
                        invalid_id,
                        CleanupUserDecision.AUTHORIZE_CLEANUP,
                    )
        for invalid_report in (None, {}, b"report"):
            with self.subTest(invalid_report=invalid_report):
                with self.assertRaises(CleanupAuthorizationError):
                    prepare_cleanup_authorization(
                        self.directory,
                        invalid_report,
                        operation_id,
                        CleanupUserDecision.AUTHORIZE_CLEANUP,
                    )


class CleanupAuthorizationContractTests(unittest.TestCase):
    @staticmethod
    def valid_claim():
        return CleanupAuthorizationClaim(
            AUTHORIZATION_FORMAT,
            AUTHORIZATION_VERSION,
            "a" * 32,
            "b" * 32,
            11,
            22,
            "c" * 64,
            0,
            OperationLeaseBackend.POSIX_FLOCK,
        )

    def test_claim_invariants_reject_false_safety_statements(self):
        claim = self.valid_claim()
        for change in (
            {"format": "other"},
            {"version": 2},
            {"authorization_id": "A" * 32},
            {"evidence_sha256": "x" * 64},
            {"evidence_sequence": True},
            {"lease_backend": "posix_flock"},
            {"user_confirmed": False},
            {"fresh_rescan_verified": False},
            {"executor_rescan_required": False},
            {"single_use_claim": False},
            {"abandonment_proven": True},
            {"mutation_permitted": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(CleanupAuthorizationError):
                    replace(claim, **change)

    def test_prepared_type_rejects_non_claim(self):
        for value in (None, {}, "claim"):
            with self.subTest(value=value):
                with self.assertRaises(CleanupAuthorizationError):
                    PreparedCleanupAuthorization(value)

    def test_claim_schema_has_no_paths_names_time_or_process_identity(self):
        fields = set(CleanupAuthorizationClaim.__dataclass_fields__)
        for forbidden in (
            "path",
            "directory_path",
            "journal_name",
            "temporary_name",
            "source_name",
            "output_name",
            "timestamp",
            "created_utc",
            "expires_utc",
            "pid",
            "process_id",
        ):
            self.assertNotIn(forbidden, fields)

    def test_module_has_no_filesystem_mutation_crypto_network_gui_or_codec(self):
        import mokosh_v2_cleanup_authorization

        source = inspect.getsource(mokosh_v2_cleanup_authorization)
        for forbidden in (
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
            "os.link",
            "os.write",
            "shutil",
            "AESGCM",
            "decrypt",
            "private_key",
            "socket",
            "requests",
            "tkinter",
            "json.dumps",
            "pickle.dumps",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
