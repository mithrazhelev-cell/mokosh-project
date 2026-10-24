import inspect
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from mokosh_v2_filesystem import ExclusiveFileQuarantineSink
from mokosh_v2_operation_journal import TEMP_NAME_PREFIX
from mokosh_v2_reconciliation import (
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
    scan_quarantine_directory,
)
from mokosh_v2_reconciliation_evidence import (
    EVIDENCE_FORMAT,
    EVIDENCE_VERSION,
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_ITEMS,
    EvidenceClassification,
    RecommendedNextStep,
    ReconciliationEvidenceError,
    build_reconciliation_evidence,
    decode_reconciliation_evidence,
    encode_reconciliation_evidence,
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
    def abandon(sink):
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False


class EvidenceConstructionTests(PrivateDirectoryTestCase):
    def test_empty_snapshot_is_complete_and_directory_bound(self):
        source = scan_quarantine_directory(self.directory)
        report = build_reconciliation_evidence(source)
        self.assertEqual(report.format, EVIDENCE_FORMAT)
        self.assertEqual(report.version, EVIDENCE_VERSION)
        self.assertEqual(report.directory_device, self.directory.stat().st_dev)
        self.assertEqual(report.directory_inode, self.directory.stat().st_ino)
        self.assertEqual(report.items, ())
        self.assertTrue(report.complete)
        self.assertFalse(report.mutation_permitted)

    def test_inode_match_is_only_a_review_candidate(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        item = report.items[0]
        self.assertEqual(item.classification, EvidenceClassification.INODE_MATCH)
        self.assertEqual(
            item.recommended_next_step,
            RecommendedNextStep.REVIEW_MATCHED_PAIR,
        )
        self.assertTrue(item.identity_prerequisite_met)
        self.assertTrue(item.user_decision_required)
        self.assertTrue(item.rescan_required)
        self.assertFalse(item.mutation_permitted)
        sink.abort()

    def test_missing_temporary_never_meets_identity_prerequisite(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        Path(sink.temp_path).unlink()
        self.abandon(sink)
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        item = report.items[0]
        self.assertEqual(
            item.classification,
            EvidenceClassification.TEMPORARY_MISSING,
        )
        self.assertFalse(item.identity_prerequisite_met)
        self.assertFalse(item.mutation_permitted)

    def test_identity_conflict_is_preserved(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temporary = Path(sink.temp_path)
        temporary.rename(self.directory / "old")
        temporary.write_bytes(b"foreign")
        os.chmod(temporary, 0o600)
        self.abandon(sink)
        item = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        ).items[0]
        self.assertEqual(
            item.classification,
            EvidenceClassification.IDENTITY_CONFLICT,
        )
        self.assertEqual(
            item.recommended_next_step,
            RecommendedNextStep.PRESERVE_IDENTITY_CONFLICT,
        )

    def test_link_count_conflict_is_publish_window_review(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        temporary = Path(sink.temp_path)
        os.link(temporary, self.directory / "possible-published-output")
        self.abandon(sink)
        item = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        ).items[0]
        self.assertEqual(
            item.classification,
            EvidenceClassification.LINK_COUNT_CONFLICT,
        )
        self.assertEqual(
            item.recommended_next_step,
            RecommendedNextStep.REVIEW_PUBLISH_WINDOW,
        )
        self.assertFalse(item.identity_prerequisite_met)

    def test_invalid_journal_and_unrecorded_temporary_are_distinct(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        journal = Path(sink.journal_path)
        journal.write_bytes(journal.read_bytes() + b"\n")
        self.abandon(sink)
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        self.assertEqual(
            {item.classification for item in report.items},
            {
                EvidenceClassification.INVALID_RECORD,
                EvidenceClassification.UNRECORDED_TEMPORARY,
            },
        )
        self.assertTrue(all(not item.mutation_permitted for item in report.items))

    def test_unrecorded_malformed_name_does_not_invent_operation_id(self):
        temporary = self.directory / (TEMP_NAME_PREFIX + "malformed")
        temporary.write_bytes(b"unknown")
        os.chmod(temporary, 0o600)
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        self.assertIsNone(report.items[0].operation_id)
        self.assertEqual(
            report.items[0].classification,
            EvidenceClassification.UNRECORDED_TEMPORARY,
        )

    def test_encoded_report_omits_names_paths_and_sensitive_metadata(self):
        sink = ExclusiveFileQuarantineSink(
            self.directory / "very-sensitive-client-name.mok"
        )
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        encoded = encode_reconciliation_evidence(report).lower()
        for forbidden in (
            b"very-sensitive-client-name",
            str(self.directory).encode().lower(),
            b"journal_name",
            b"temporary_name",
            b"password",
            b"private_key",
            b"content_hash",
            b"exception",
        ):
            self.assertNotIn(forbidden, encoded)
        sink.abort()

    def test_valid_looking_pair_still_never_authorizes_mutation(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        report = build_reconciliation_evidence(
            scan_quarantine_directory(self.directory)
        )
        self.assertTrue(report.items[0].identity_prerequisite_met)
        self.assertFalse(report.items[0].mutation_permitted)
        self.assertFalse(report.mutation_permitted)
        sink.abort()

    def test_source_files_are_unchanged_by_evidence_building(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")

        def snapshot():
            return {
                path.name: (
                    path.read_bytes(),
                    path.stat().st_ino,
                    path.stat().st_nlink,
                    path.stat().st_mode,
                    path.stat().st_mtime_ns,
                )
                for path in self.directory.iterdir()
            }

        before = snapshot()
        build_reconciliation_evidence(scan_quarantine_directory(self.directory))
        self.assertEqual(snapshot(), before)
        sink.abort()


class EvidenceBoundsAndCodecTests(unittest.TestCase):
    @staticmethod
    def source_with_findings(count):
        findings = tuple(
            ReconciliationFinding(
                ReconciliationStatus.UNRECORDED_TEMPORARY,
                f"{index:032x}",
                None,
                TEMP_NAME_PREFIX + f"{index:032x}",
            )
            for index in range(count)
        )
        return ReconciliationReport(findings, count, 11, 22)

    def test_report_is_bounded_and_omission_is_explicit(self):
        report = build_reconciliation_evidence(
            self.source_with_findings(5),
            max_items=2,
        )
        self.assertEqual(report.source_findings, 5)
        self.assertEqual(report.included_findings, 2)
        self.assertEqual(report.omitted_findings, 3)
        self.assertFalse(report.complete)
        self.assertEqual(len(report.items), 2)
        counts = dict(report.classification_counts)
        self.assertEqual(counts[EvidenceClassification.UNRECORDED_TEMPORARY], 5)

    def test_maximum_item_boundary_is_supported(self):
        report = build_reconciliation_evidence(
            self.source_with_findings(MAX_EVIDENCE_ITEMS)
        )
        self.assertTrue(report.complete)
        self.assertEqual(len(report.items), MAX_EVIDENCE_ITEMS)
        self.assertLessEqual(
            len(encode_reconciliation_evidence(report)),
            MAX_EVIDENCE_BYTES,
        )

    def test_invalid_item_limits_are_rejected(self):
        source = self.source_with_findings(1)
        for value in (0, -1, MAX_EVIDENCE_ITEMS + 1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ReconciliationEvidenceError):
                    build_reconciliation_evidence(source, max_items=value)

    def test_codec_roundtrip_is_canonical_and_deterministic(self):
        report = build_reconciliation_evidence(self.source_with_findings(3))
        encoded = encode_reconciliation_evidence(report)
        self.assertEqual(decode_reconciliation_evidence(encoded), report)
        self.assertEqual(encode_reconciliation_evidence(report), encoded)
        self.assertEqual(
            encoded,
            json.dumps(
                json.loads(encoded),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
        )

    def test_digest_is_exact_sha256_and_directory_bound(self):
        first = build_reconciliation_evidence(self.source_with_findings(1))
        second = build_reconciliation_evidence(
            replace(self.source_with_findings(1), directory_inode=23)
        )
        import hashlib

        self.assertEqual(
            reconciliation_evidence_sha256(first),
            hashlib.sha256(encode_reconciliation_evidence(first)).hexdigest(),
        )
        self.assertNotEqual(
            reconciliation_evidence_sha256(first),
            reconciliation_evidence_sha256(second),
        )

    def test_duplicate_unknown_missing_and_noncanonical_json_are_rejected(self):
        encoded = encode_reconciliation_evidence(
            build_reconciliation_evidence(self.source_with_findings(1))
        )
        decoded = json.loads(encoded)
        variants = [
            b'{"format":"a","format":"b"}',
            b" " + encoded,
            encoded + b"\n",
        ]
        changed = dict(decoded)
        changed["unknown"] = 1
        variants.append(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        )
        changed = dict(decoded)
        changed.pop("directory_inode")
        variants.append(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        )
        for value in variants:
            with self.subTest(value=value[:40]):
                with self.assertRaises(ReconciliationEvidenceError):
                    decode_reconciliation_evidence(value)

    def test_tampered_policy_flags_are_rejected(self):
        encoded = encode_reconciliation_evidence(
            build_reconciliation_evidence(self.source_with_findings(1))
        )
        decoded = json.loads(encoded)
        variants = []
        for field, value in (
            ("mutation_permitted", True),
            ("complete", False),
            ("included_findings", True),
        ):
            changed = json.loads(json.dumps(decoded))
            changed[field] = value
            variants.append(changed)
        for field in (
            "mutation_permitted",
            "user_decision_required",
            "rescan_required",
            "identity_prerequisite_met",
        ):
            changed = json.loads(json.dumps(decoded))
            changed["items"][0][field] = not changed["items"][0][field]
            variants.append(changed)
        for value in variants:
            with self.subTest(value=value):
                data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaises(ReconciliationEvidenceError):
                    decode_reconciliation_evidence(data)

    def test_non_bytes_empty_oversized_and_non_ascii_are_rejected(self):
        values = (
            "text",
            b"",
            b"{" + b"x" * MAX_EVIDENCE_BYTES + b"}",
            "ж".encode("utf-8"),
        )
        for value in values:
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ReconciliationEvidenceError):
                    decode_reconciliation_evidence(value)

    def test_inconsistent_source_finding_is_rejected(self):
        source = self.source_with_findings(1)
        bad = replace(
            source.findings[0],
            operation_id="f" * 32,
        )
        with self.assertRaises(ReconciliationEvidenceError):
            build_reconciliation_evidence(replace(source, findings=(bad,)))

    def test_non_report_input_is_rejected(self):
        for value in (None, {}, (), "report"):
            with self.subTest(value=value):
                with self.assertRaises(ReconciliationEvidenceError):
                    build_reconciliation_evidence(value)


class EvidenceScopeTests(unittest.TestCase):
    def test_module_has_no_filesystem_network_gui_crypto_or_mutation_calls(self):
        import mokosh_v2_reconciliation_evidence

        source = inspect.getsource(mokosh_v2_reconciliation_evidence)
        for forbidden in (
            "os.open",
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
            "os.link",
            "os.write",
            "pathlib",
            "tkinter",
            "socket",
            "requests",
            "logging",
            "AESGCM",
            "decrypt",
            "private_key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
