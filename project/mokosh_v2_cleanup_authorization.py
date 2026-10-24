"""One-shot, non-mutating cleanup authorization preparation.

Stage 1.22 binds an explicit user decision to a complete reviewed evidence
report, two matching fresh read-only scans, and a released-candidate lease
observation.  The resulting in-memory claim is not proof of abandonment and
never grants filesystem mutation.  A future executor must perform another
exact rescan before considering any action.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_v2_operation_activity import (
    OperationActivityAssessment,
    OperationActivityStatus,
    assess_operation_activity,
)
from mokosh_v2_operation_journal import (
    MAX_UINT64,
    OperationJournalError,
    validate_operation_id,
)
from mokosh_v2_operation_lease import OperationLeaseBackend
from mokosh_v2_reconciliation import scan_quarantine_directory
from mokosh_v2_reconciliation_evidence import (
    MAX_EVIDENCE_ITEMS,
    EvidenceClassification,
    ReconciliationEvidenceError,
    ReconciliationEvidenceReport,
    build_reconciliation_evidence,
    encode_reconciliation_evidence,
    reconciliation_evidence_sha256,
)


AUTHORIZATION_FORMAT = "MOKOSH-CLEANUP-AUTHORIZATION"
AUTHORIZATION_VERSION = 1
AUTHORIZATION_ID_BYTES = 16


class CleanupAuthorizationError(ValueError):
    """A cleanup authorization cannot satisfy the fail-closed contract."""


class CleanupUserDecision(str, Enum):
    PRESERVE = "preserve"
    AUTHORIZE_CLEANUP = "authorize_cleanup"


@dataclass(frozen=True, slots=True)
class CleanupAuthorizationClaim:
    format: str
    version: int
    authorization_id: str
    operation_id: str
    directory_device: int
    directory_inode: int
    evidence_sha256: str
    evidence_sequence: int
    lease_backend: OperationLeaseBackend
    user_confirmed: bool = True
    reviewed_evidence_matched: bool = True
    fresh_rescan_verified: bool = True
    released_candidate_observed: bool = True
    executor_rescan_required: bool = True
    single_use_claim: bool = True
    abandonment_proven: bool = False
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        _validate_claim(self)


class PreparedCleanupAuthorization:
    """One in-memory authorization that can issue exactly one claim."""

    __slots__ = ("_claim", "_claimed")

    def __init__(self, claim: CleanupAuthorizationClaim) -> None:
        self._claim = _validate_claim(claim)
        self._claimed = False

    @property
    def claimed(self) -> bool:
        return self._claimed

    def claim_once(self) -> CleanupAuthorizationClaim:
        if self._claimed:
            raise CleanupAuthorizationError("cleanup authorization was already claimed")
        self._claimed = True
        return self._claim

    def __copy__(self) -> PreparedCleanupAuthorization:
        raise CleanupAuthorizationError("cleanup authorization cannot be copied")

    def __deepcopy__(self, memo: Any) -> PreparedCleanupAuthorization:
        raise CleanupAuthorizationError("cleanup authorization cannot be copied")

    def __reduce__(self) -> Any:
        raise CleanupAuthorizationError("cleanup authorization cannot be serialized")


def _require_uint(value: Any, field: str, maximum: int = MAX_UINT64) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CleanupAuthorizationError(f"{field} must be a bounded integer")
    return value


def _require_lower_hex(value: Any, field: str, length: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CleanupAuthorizationError(f"{field} must be lowercase hexadecimal")
    return value


def _validate_operation_id(value: Any) -> str:
    try:
        return validate_operation_id(value)
    except OperationJournalError as exc:
        raise CleanupAuthorizationError("operation_id is invalid") from exc


def _validate_claim(value: Any) -> CleanupAuthorizationClaim:
    if not isinstance(value, CleanupAuthorizationClaim):
        raise CleanupAuthorizationError("cleanup authorization claim type is invalid")
    if value.format != AUTHORIZATION_FORMAT:
        raise CleanupAuthorizationError("cleanup authorization format is unsupported")
    if type(value.version) is not int or value.version != AUTHORIZATION_VERSION:
        raise CleanupAuthorizationError("cleanup authorization version is unsupported")
    _require_lower_hex(value.authorization_id, "authorization_id", 32)
    _validate_operation_id(value.operation_id)
    _require_uint(value.directory_device, "directory_device")
    _require_uint(value.directory_inode, "directory_inode")
    _require_lower_hex(value.evidence_sha256, "evidence_sha256", 64)
    _require_uint(
        value.evidence_sequence,
        "evidence_sequence",
        MAX_EVIDENCE_ITEMS - 1,
    )
    if not isinstance(value.lease_backend, OperationLeaseBackend):
        raise CleanupAuthorizationError("lease backend is invalid")
    required_true = (
        value.user_confirmed,
        value.reviewed_evidence_matched,
        value.fresh_rescan_verified,
        value.released_candidate_observed,
        value.executor_rescan_required,
        value.single_use_claim,
    )
    if any(item is not True for item in required_true):
        raise CleanupAuthorizationError("cleanup authorization policy is incomplete")
    if value.abandonment_proven is not False:
        raise CleanupAuthorizationError("authorization cannot prove abandonment")
    if value.mutation_permitted is not False:
        raise CleanupAuthorizationError("Stage 1.22 never permits mutation")
    return value


def _validate_reviewed_report(
    report: Any,
    operation_id: str,
) -> tuple[bytes, int]:
    if not isinstance(report, ReconciliationEvidenceReport):
        raise CleanupAuthorizationError("reviewed evidence report type is invalid")
    try:
        encoded = encode_reconciliation_evidence(report)
    except ReconciliationEvidenceError as exc:
        raise CleanupAuthorizationError("reviewed evidence report is invalid") from exc
    if not report.complete or report.omitted_findings != 0:
        raise CleanupAuthorizationError("reviewed evidence report must be complete")
    matches = tuple(
        item for item in report.items if item.operation_id == operation_id
    )
    if len(matches) != 1:
        raise CleanupAuthorizationError("operation is not uniquely reviewed")
    item = matches[0]
    if (
        item.classification is not EvidenceClassification.INODE_MATCH
        or item.identity_prerequisite_met is not True
        or item.user_decision_required is not True
        or item.rescan_required is not True
        or item.mutation_permitted is not False
    ):
        raise CleanupAuthorizationError("reviewed operation is not eligible")
    return encoded, item.sequence


def _fresh_evidence(directory: Any) -> ReconciliationEvidenceReport:
    try:
        return build_reconciliation_evidence(
            scan_quarantine_directory(directory),
            max_items=MAX_EVIDENCE_ITEMS,
        )
    except (OSError, ReconciliationEvidenceError) as exc:
        raise CleanupAuthorizationError("fresh reconciliation scan failed") from exc


def _validate_activity(
    activity: Any,
    operation_id: str,
) -> OperationLeaseBackend:
    if not isinstance(activity, OperationActivityAssessment):
        raise CleanupAuthorizationError("activity assessment type is invalid")
    if (
        activity.operation_id != operation_id
        or activity.status is not OperationActivityStatus.RELEASED_CANDIDATE
        or activity.backend is None
        or activity.exact_identity_verified is not True
        or activity.active_writer_observed is not False
        or activity.cooperating_writer_absent is not True
        or activity.user_decision_required is not True
        or activity.rescan_required is not True
        or activity.abandonment_proven is not False
        or activity.mutation_permitted is not False
    ):
        raise CleanupAuthorizationError("operation is not a released candidate")
    return activity.backend


def _new_authorization_id() -> str:
    try:
        value = os.urandom(AUTHORIZATION_ID_BYTES)
    except Exception as exc:
        raise CleanupAuthorizationError("random source failed") from exc
    if not isinstance(value, bytes) or len(value) != AUTHORIZATION_ID_BYTES:
        raise CleanupAuthorizationError("random source returned invalid bytes")
    return value.hex()


def prepare_cleanup_authorization(
    directory: Any,
    reviewed_evidence: ReconciliationEvidenceReport,
    operation_id: Any,
    decision: CleanupUserDecision,
) -> PreparedCleanupAuthorization:
    """Prepare one non-mutating claim after two exact fresh rescans."""

    exact_id = _validate_operation_id(operation_id)
    if not isinstance(decision, CleanupUserDecision):
        raise CleanupAuthorizationError("cleanup decision type is invalid")
    if decision is not CleanupUserDecision.AUTHORIZE_CLEANUP:
        raise CleanupAuthorizationError("cleanup was not explicitly authorized")

    reviewed_bytes, sequence = _validate_reviewed_report(
        reviewed_evidence,
        exact_id,
    )
    first_fresh = _fresh_evidence(directory)
    first_bytes = encode_reconciliation_evidence(first_fresh)
    if first_bytes != reviewed_bytes:
        raise CleanupAuthorizationError("fresh evidence differs from reviewed evidence")

    try:
        activity = assess_operation_activity(directory, exact_id)
    except OSError as exc:
        raise CleanupAuthorizationError("activity assessment failed") from exc
    backend = _validate_activity(activity, exact_id)

    second_fresh = _fresh_evidence(directory)
    second_bytes = encode_reconciliation_evidence(second_fresh)
    if second_bytes != reviewed_bytes or second_bytes != first_bytes:
        raise CleanupAuthorizationError("evidence changed during authorization")

    authorization_id = _new_authorization_id()
    claim = CleanupAuthorizationClaim(
        format=AUTHORIZATION_FORMAT,
        version=AUTHORIZATION_VERSION,
        authorization_id=authorization_id,
        operation_id=exact_id,
        directory_device=second_fresh.directory_device,
        directory_inode=second_fresh.directory_inode,
        evidence_sha256=reconciliation_evidence_sha256(second_fresh),
        evidence_sequence=sequence,
        lease_backend=backend,
    )
    return PreparedCleanupAuthorization(claim)
