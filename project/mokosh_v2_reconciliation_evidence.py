"""Bounded, non-secret evidence and action planning for reconciliation.

Stage 1.20 converts a read-only Stage 1.19 snapshot into a deterministic
report.  The report deliberately omits directory paths, file names, content
metadata, keys, credentials, contacts, and exception text.  It can describe a
future review step, but it never authorizes or performs mutation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_v2_format import V2FormatError
from mokosh_v2_operation_journal import (
    MAX_UINT64,
    OperationJournalError,
    journal_name_for,
    temporary_name_for,
    validate_operation_id,
)
from mokosh_v2_reconciliation import (
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
)


EVIDENCE_FORMAT = "MOKOSH-RECON-EVIDENCE"
EVIDENCE_VERSION = 1
MAX_EVIDENCE_ITEMS = 256
MAX_EVIDENCE_BYTES = 131_072


class ReconciliationEvidenceError(V2FormatError):
    """The evidence report is malformed, ambiguous, or unsupported."""


class EvidenceClassification(str, Enum):
    INODE_MATCH = "inode_match"
    TEMPORARY_MISSING = "temporary_missing"
    IDENTITY_CONFLICT = "identity_conflict"
    LINK_COUNT_CONFLICT = "link_count_conflict"
    INVALID_RECORD = "invalid_record"
    UNSAFE_RECORD = "unsafe_record"
    UNRECORDED_TEMPORARY = "unrecorded_temporary"


class RecommendedNextStep(str, Enum):
    REVIEW_MATCHED_PAIR = "review_matched_pair"
    REVIEW_MISSING_TEMPORARY = "review_missing_temporary"
    PRESERVE_IDENTITY_CONFLICT = "preserve_identity_conflict"
    REVIEW_PUBLISH_WINDOW = "review_publish_window"
    PRESERVE_INVALID_RECORD = "preserve_invalid_record"
    PRESERVE_UNSAFE_RECORD = "preserve_unsafe_record"
    PRESERVE_UNRECORDED_TEMPORARY = "preserve_unrecorded_temporary"


_STATUS_POLICY = {
    ReconciliationStatus.RECORDED_INODE_MATCH: (
        EvidenceClassification.INODE_MATCH,
        RecommendedNextStep.REVIEW_MATCHED_PAIR,
        True,
    ),
    ReconciliationStatus.TEMPORARY_MISSING: (
        EvidenceClassification.TEMPORARY_MISSING,
        RecommendedNextStep.REVIEW_MISSING_TEMPORARY,
        False,
    ),
    ReconciliationStatus.TEMPORARY_IDENTITY_MISMATCH: (
        EvidenceClassification.IDENTITY_CONFLICT,
        RecommendedNextStep.PRESERVE_IDENTITY_CONFLICT,
        False,
    ),
    ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED: (
        EvidenceClassification.LINK_COUNT_CONFLICT,
        RecommendedNextStep.REVIEW_PUBLISH_WINDOW,
        False,
    ),
    ReconciliationStatus.INVALID_JOURNAL: (
        EvidenceClassification.INVALID_RECORD,
        RecommendedNextStep.PRESERVE_INVALID_RECORD,
        False,
    ),
    ReconciliationStatus.UNSAFE_JOURNAL: (
        EvidenceClassification.UNSAFE_RECORD,
        RecommendedNextStep.PRESERVE_UNSAFE_RECORD,
        False,
    ),
    ReconciliationStatus.UNRECORDED_TEMPORARY: (
        EvidenceClassification.UNRECORDED_TEMPORARY,
        RecommendedNextStep.PRESERVE_UNRECORDED_TEMPORARY,
        False,
    ),
}

_CLASSIFICATIONS = tuple(EvidenceClassification)
_TOP_FIELDS = frozenset(
    {
        "format",
        "version",
        "directory_device",
        "directory_inode",
        "scanned_entries",
        "source_findings",
        "included_findings",
        "omitted_findings",
        "complete",
        "classification_counts",
        "items",
        "mutation_permitted",
    }
)
_ITEM_FIELDS = frozenset(
    {
        "sequence",
        "classification",
        "operation_id",
        "identity_prerequisite_met",
        "recommended_next_step",
        "user_decision_required",
        "rescan_required",
        "mutation_permitted",
    }
)


@dataclass(frozen=True, slots=True)
class ReconciliationEvidenceItem:
    sequence: int
    classification: EvidenceClassification
    operation_id: str | None
    identity_prerequisite_met: bool
    recommended_next_step: RecommendedNextStep
    user_decision_required: bool = True
    rescan_required: bool = True
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        _validate_item(self)


@dataclass(frozen=True, slots=True)
class ReconciliationEvidenceReport:
    format: str
    version: int
    directory_device: int
    directory_inode: int
    scanned_entries: int
    source_findings: int
    included_findings: int
    omitted_findings: int
    complete: bool
    classification_counts: tuple[tuple[EvidenceClassification, int], ...]
    items: tuple[ReconciliationEvidenceItem, ...]
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        _validate_report(self)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReconciliationEvidenceError("duplicate evidence field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReconciliationEvidenceError(
        f"non-standard JSON constant is forbidden: {value}"
    )


def _require_uint(value: Any, field: str, maximum: int = MAX_UINT64) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ReconciliationEvidenceError(
            f"{field} must be a bounded unsigned integer"
        )
    return value


def _validate_optional_operation_id(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return validate_operation_id(value)
    except OperationJournalError as exc:
        raise ReconciliationEvidenceError("operation_id is invalid") from exc


def _validate_item(value: Any) -> ReconciliationEvidenceItem:
    if not isinstance(value, ReconciliationEvidenceItem):
        raise ReconciliationEvidenceError("evidence item type is invalid")
    _require_uint(value.sequence, "sequence", MAX_EVIDENCE_ITEMS - 1)
    if not isinstance(value.classification, EvidenceClassification):
        raise ReconciliationEvidenceError("evidence classification is invalid")
    _validate_optional_operation_id(value.operation_id)
    if type(value.identity_prerequisite_met) is not bool:
        raise ReconciliationEvidenceError("identity prerequisite must be boolean")
    if not isinstance(value.recommended_next_step, RecommendedNextStep):
        raise ReconciliationEvidenceError("recommended next step is invalid")
    expected = {
        classification: (next_step, prerequisite)
        for classification, next_step, prerequisite in _STATUS_POLICY.values()
    }[value.classification]
    if (value.recommended_next_step, value.identity_prerequisite_met) != expected:
        raise ReconciliationEvidenceError("evidence item policy is inconsistent")
    if value.user_decision_required is not True:
        raise ReconciliationEvidenceError("user decision must remain required")
    if value.rescan_required is not True:
        raise ReconciliationEvidenceError("rescan must remain required")
    if value.mutation_permitted is not False:
        raise ReconciliationEvidenceError("Stage 1.20 never permits mutation")
    return value


def _validate_report(value: Any) -> ReconciliationEvidenceReport:
    if not isinstance(value, ReconciliationEvidenceReport):
        raise ReconciliationEvidenceError("evidence report type is invalid")
    if value.format != EVIDENCE_FORMAT:
        raise ReconciliationEvidenceError("evidence format is unsupported")
    if type(value.version) is not int or value.version != EVIDENCE_VERSION:
        raise ReconciliationEvidenceError("evidence version is unsupported")
    _require_uint(value.directory_device, "directory_device")
    _require_uint(value.directory_inode, "directory_inode")
    _require_uint(value.scanned_entries, "scanned_entries")
    _require_uint(value.source_findings, "source_findings")
    _require_uint(
        value.included_findings,
        "included_findings",
        MAX_EVIDENCE_ITEMS,
    )
    _require_uint(value.omitted_findings, "omitted_findings")
    if value.source_findings != value.included_findings + value.omitted_findings:
        raise ReconciliationEvidenceError("evidence finding counts do not add up")
    if value.included_findings != len(value.items):
        raise ReconciliationEvidenceError("included finding count is inconsistent")
    if type(value.complete) is not bool or value.complete != (value.omitted_findings == 0):
        raise ReconciliationEvidenceError("complete flag is inconsistent")
    if value.mutation_permitted is not False:
        raise ReconciliationEvidenceError("Stage 1.20 never permits mutation")
    expected_keys = tuple(_CLASSIFICATIONS)
    if not isinstance(value.classification_counts, tuple):
        raise ReconciliationEvidenceError("classification counts must be immutable")
    if tuple(item[0] for item in value.classification_counts) != expected_keys:
        raise ReconciliationEvidenceError("classification count keys are not exact")
    total = 0
    for classification, count in value.classification_counts:
        if not isinstance(classification, EvidenceClassification):
            raise ReconciliationEvidenceError("classification count key is invalid")
        total += _require_uint(count, "classification count")
    if total != value.source_findings:
        raise ReconciliationEvidenceError("classification counts do not add up")
    if not isinstance(value.items, tuple):
        raise ReconciliationEvidenceError("evidence items must be immutable")
    for sequence, item in enumerate(value.items):
        _validate_item(item)
        if item.sequence != sequence:
            raise ReconciliationEvidenceError("evidence sequence is not contiguous")
    return value


def _validate_finding(value: Any) -> ReconciliationFinding:
    if not isinstance(value, ReconciliationFinding):
        raise ReconciliationEvidenceError("reconciliation finding type is invalid")
    if not isinstance(value.status, ReconciliationStatus):
        raise ReconciliationEvidenceError("reconciliation status is invalid")
    if value.mutation_permitted is not False:
        raise ReconciliationEvidenceError("source finding unexpectedly permits mutation")
    operation_id = _validate_optional_operation_id(value.operation_id)
    canonical_statuses = {
        ReconciliationStatus.RECORDED_INODE_MATCH,
        ReconciliationStatus.TEMPORARY_MISSING,
        ReconciliationStatus.TEMPORARY_IDENTITY_MISMATCH,
        ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED,
        ReconciliationStatus.UNSAFE_JOURNAL,
    }
    if value.status in canonical_statuses:
        if operation_id is None:
            raise ReconciliationEvidenceError("bound finding lacks operation_id")
        if value.journal_name != journal_name_for(operation_id):
            raise ReconciliationEvidenceError("journal name is not canonically bound")
        if value.temporary_name != temporary_name_for(operation_id):
            raise ReconciliationEvidenceError("temporary name is not canonically bound")
    if value.status is ReconciliationStatus.UNRECORDED_TEMPORARY:
        if value.journal_name is not None or value.temporary_name is None:
            raise ReconciliationEvidenceError("unrecorded temporary is inconsistent")
        if operation_id is not None and value.temporary_name != temporary_name_for(
            operation_id
        ):
            raise ReconciliationEvidenceError("unrecorded temporary id is inconsistent")
    return value


def _validate_source_report(value: Any) -> ReconciliationReport:
    if not isinstance(value, ReconciliationReport):
        raise ReconciliationEvidenceError("source report type is invalid")
    if value.mutation_permitted is not False:
        raise ReconciliationEvidenceError("source report unexpectedly permits mutation")
    _require_uint(value.scanned_entries, "scanned_entries")
    _require_uint(value.directory_device, "directory_device")
    _require_uint(value.directory_inode, "directory_inode")
    if not isinstance(value.findings, tuple):
        raise ReconciliationEvidenceError("source findings must be immutable")
    for finding in value.findings:
        _validate_finding(finding)
    return value


def build_reconciliation_evidence(
    source: ReconciliationReport,
    *,
    max_items: int = MAX_EVIDENCE_ITEMS,
) -> ReconciliationEvidenceReport:
    """Build a bounded deterministic plan without granting any action."""

    report = _validate_source_report(source)
    if type(max_items) is not int or not 1 <= max_items <= MAX_EVIDENCE_ITEMS:
        raise ReconciliationEvidenceError("max_items is outside the evidence policy")

    counts = {classification: 0 for classification in _CLASSIFICATIONS}
    planned: list[
        tuple[
            EvidenceClassification,
            str | None,
            RecommendedNextStep,
            bool,
        ]
    ] = []
    for finding in report.findings:
        classification, next_step, prerequisite = _STATUS_POLICY[finding.status]
        counts[classification] += 1
        planned.append(
            (classification, finding.operation_id, next_step, prerequisite)
        )
    planned.sort(key=lambda item: (item[0].value, item[1] or ""))
    included = planned[:max_items]
    items = tuple(
        ReconciliationEvidenceItem(
            sequence=sequence,
            classification=classification,
            operation_id=operation_id,
            identity_prerequisite_met=prerequisite,
            recommended_next_step=next_step,
        )
        for sequence, (classification, operation_id, next_step, prerequisite)
        in enumerate(included)
    )
    result = ReconciliationEvidenceReport(
        format=EVIDENCE_FORMAT,
        version=EVIDENCE_VERSION,
        directory_device=report.directory_device,
        directory_inode=report.directory_inode,
        scanned_entries=report.scanned_entries,
        source_findings=len(planned),
        included_findings=len(items),
        omitted_findings=len(planned) - len(items),
        complete=len(planned) == len(items),
        classification_counts=tuple(
            (classification, counts[classification])
            for classification in _CLASSIFICATIONS
        ),
        items=items,
    )
    encode_reconciliation_evidence(result)
    return result


def _report_object(report: ReconciliationEvidenceReport) -> dict[str, Any]:
    return {
        "format": report.format,
        "version": report.version,
        "directory_device": report.directory_device,
        "directory_inode": report.directory_inode,
        "scanned_entries": report.scanned_entries,
        "source_findings": report.source_findings,
        "included_findings": report.included_findings,
        "omitted_findings": report.omitted_findings,
        "complete": report.complete,
        "classification_counts": {
            classification.value: count
            for classification, count in report.classification_counts
        },
        "items": [
            {
                "sequence": item.sequence,
                "classification": item.classification.value,
                "operation_id": item.operation_id,
                "identity_prerequisite_met": item.identity_prerequisite_met,
                "recommended_next_step": item.recommended_next_step.value,
                "user_decision_required": item.user_decision_required,
                "rescan_required": item.rescan_required,
                "mutation_permitted": item.mutation_permitted,
            }
            for item in report.items
        ],
        "mutation_permitted": report.mutation_permitted,
    }


def encode_reconciliation_evidence(value: ReconciliationEvidenceReport) -> bytes:
    report = _validate_report(value)
    encoded = json.dumps(
        _report_object(report),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ReconciliationEvidenceError("evidence report exceeds its size limit")
    return encoded


def decode_reconciliation_evidence(data: Any) -> ReconciliationEvidenceReport:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ReconciliationEvidenceError("evidence report must be bytes")
    exact = bytes(data)
    if not exact or len(exact) > MAX_EVIDENCE_BYTES:
        raise ReconciliationEvidenceError("evidence report size is invalid")
    try:
        decoded = json.loads(
            exact.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconciliationEvidenceError("evidence report is not strict JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) != _TOP_FIELDS:
        raise ReconciliationEvidenceError("evidence report fields are not exact")
    raw_counts = decoded["classification_counts"]
    if not isinstance(raw_counts, dict) or set(raw_counts) != {
        item.value for item in _CLASSIFICATIONS
    }:
        raise ReconciliationEvidenceError("classification count fields are not exact")
    raw_items = decoded["items"]
    if not isinstance(raw_items, list) or len(raw_items) > MAX_EVIDENCE_ITEMS:
        raise ReconciliationEvidenceError("evidence item collection is invalid")
    items: list[ReconciliationEvidenceItem] = []
    for raw in raw_items:
        if not isinstance(raw, dict) or set(raw) != _ITEM_FIELDS:
            raise ReconciliationEvidenceError("evidence item fields are not exact")
        try:
            classification = EvidenceClassification(raw["classification"])
            next_step = RecommendedNextStep(raw["recommended_next_step"])
        except (TypeError, ValueError) as exc:
            raise ReconciliationEvidenceError("evidence item enum is invalid") from exc
        items.append(
            ReconciliationEvidenceItem(
                sequence=raw["sequence"],
                classification=classification,
                operation_id=raw["operation_id"],
                identity_prerequisite_met=raw["identity_prerequisite_met"],
                recommended_next_step=next_step,
                user_decision_required=raw["user_decision_required"],
                rescan_required=raw["rescan_required"],
                mutation_permitted=raw["mutation_permitted"],
            )
        )
    report = ReconciliationEvidenceReport(
        format=decoded["format"],
        version=decoded["version"],
        directory_device=decoded["directory_device"],
        directory_inode=decoded["directory_inode"],
        scanned_entries=decoded["scanned_entries"],
        source_findings=decoded["source_findings"],
        included_findings=decoded["included_findings"],
        omitted_findings=decoded["omitted_findings"],
        complete=decoded["complete"],
        classification_counts=tuple(
            (classification, raw_counts[classification.value])
            for classification in _CLASSIFICATIONS
        ),
        items=tuple(items),
        mutation_permitted=decoded["mutation_permitted"],
    )
    if encode_reconciliation_evidence(report) != exact:
        raise ReconciliationEvidenceError("evidence encoding is not canonical")
    return report


def reconciliation_evidence_sha256(
    value: ReconciliationEvidenceReport,
) -> str:
    """Return the digest of the exact canonical non-secret report bytes."""

    return hashlib.sha256(encode_reconciliation_evidence(value)).hexdigest()
