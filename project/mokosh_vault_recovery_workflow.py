"""Strict non-mutating workflow state for reviewed Vault recovery results.

Stage 2.9 binds one exact Stage 2.8 reconciliation result to one explicit
user review decision.  It produces only bounded non-secret routing state for
a future adapter.  A route is never a mutation authorization: every later
candidate, normal-unlock, recovery-setup, publish, or cleanup operation keeps
its own prerequisites and explicit decision.

The module performs no filesystem access, password processing, Vault unlock,
candidate creation, recovery setup, publish, retry, repair, cleanup, key
deletion, user-file mutation, GUI work, network access, telemetry, logging,
clock access, randomness, update discovery, download, or installation.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_vault_format import MAX_VAULT_REVISION
from mokosh_vault_recovery import (
    RECOVERY_ID_LEN,
    RECOVERY_SHA256_LEN,
    RECOVERY_VAULT_ID_LEN,
    VaultRecoveryError,
)
from mokosh_vault_recovery_reconciliation import (
    RecoveryPublishClassification,
    RecoveryReconciliationAction,
    VaultRecoveryReconciliationResult,
)
from mokosh_vault_storage import (
    MAX_GENERATION_BYTES,
    MAX_STORAGE_ENTRIES,
    VaultGenerationReceipt,
    VaultStorageError,
    _validate_receipt,
)


RECOVERY_WORKFLOW_FORMAT = "MOKOSH_VAULT_RECOVERY_WORKFLOW"
RECOVERY_WORKFLOW_VERSION = 1
RECOVERY_WORKFLOW_RESULT_SHA256_LEN = 32
MAX_UINT64 = (1 << 64) - 1

_RESULT_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-WORKFLOW\x00RECONCILIATION-RESULT-V1\x00"
)


class VaultRecoveryWorkflowError(VaultRecoveryError):
    """Base class for strict Stage 2.9 workflow failures."""


class VaultRecoveryWorkflowResultError(VaultRecoveryWorkflowError):
    """The reviewed reconciliation result is malformed or contradictory."""


class VaultRecoveryWorkflowMismatchError(VaultRecoveryWorkflowError):
    """The transition supplied a different reviewed result."""


class VaultRecoveryWorkflowTransitionError(VaultRecoveryWorkflowError):
    """The explicit review decision is invalid for the exact result."""


class VaultRecoveryWorkflowReplayError(VaultRecoveryWorkflowTransitionError):
    """The process-local workflow was already transitioned once."""


class RecoveryWorkflowDecision(str, Enum):
    PRESERVE_AND_STOP = "preserve_and_stop"
    ACKNOWLEDGE_TARGET_ABSENT = "acknowledge_target_absent"
    ACKNOWLEDGE_EXACT_TARGET = "acknowledge_exact_target"
    ACKNOWLEDGE_CONFLICT = "acknowledge_conflict"


class RecoveryWorkflowState(str, Enum):
    AWAITING_USER_REVIEW = "awaiting_user_review"
    FRESH_CANDIDATE_DECISION_REQUIRED = (
        "fresh_candidate_decision_required"
    )
    NORMAL_UNLOCK_REQUIRED = "normal_unlock_required"
    MANUAL_REVIEW_STOP = "manual_review_stop"
    PRESERVED_STOP = "preserved_stop"


class RecoveryWorkflowGate(str, Enum):
    STAGE_2_6_NEW_CANDIDATE_DECISION = (
        "stage_2_6_new_candidate_decision"
    )
    NORMAL_VAULT_UNLOCK = "normal_vault_unlock"
    STAGE_2_5_NEW_RECOVERY_SETUP_DECISION = (
        "stage_2_5_new_recovery_setup_decision"
    )
    MANUAL_REVIEW_ONLY = "manual_review_only"


@dataclass(frozen=True, slots=True)
class VaultRecoveryWorkflowEvidence:
    """Fixed non-secret binding to one validated Stage 2.8 result."""

    reconciliation_result_sha256: bytes
    classification: RecoveryPublishClassification
    recommended_action: RecoveryReconciliationAction
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    source_vault_sha256: bytes
    record_sha256: bytes
    keyring_sha256: bytes
    target_vault_sha256: bytes | None
    storage_complete: bool
    stable_observation: bool
    format: str = RECOVERY_WORKFLOW_FORMAT
    version: int = RECOVERY_WORKFLOW_VERSION

    def __post_init__(self) -> None:
        _validate_workflow_evidence(self)


@dataclass(frozen=True, slots=True)
class VaultRecoveryWorkflowState:
    """One reviewed route; explicitly not authority for a later operation."""

    evidence: VaultRecoveryWorkflowEvidence
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    required_gates: tuple[RecoveryWorkflowGate, ...]
    transition_sequence: int = 1
    reviewed_result_validated: bool = True
    user_decision_recorded: bool = True
    read_only: bool = True
    terminal_stop: bool = False
    downstream_reverification_required: bool = True
    secrets_retained: bool = False
    mutation_authorized: bool = False
    candidate_creation_authorized: bool = False
    normal_unlock_authorized: bool = False
    recovery_setup_authorized: bool = False
    publish_authorized: bool = False
    retry_authorized: bool = False
    repair_authorized: bool = False
    cleanup_authorized: bool = False
    key_deletion_authorized: bool = False
    user_file_mutation_authorized: bool = False
    format: str = RECOVERY_WORKFLOW_FORMAT
    version: int = RECOVERY_WORKFLOW_VERSION

    def __post_init__(self) -> None:
        _validate_workflow_state(self)


class PreparedVaultRecoveryWorkflow:
    """Process-local exact-result binding with one successful transition."""

    __slots__ = ("_evidence", "_final_state", "_transitioned")

    def __init__(self, evidence: VaultRecoveryWorkflowEvidence) -> None:
        self._evidence = _validate_workflow_evidence(evidence)
        self._final_state: VaultRecoveryWorkflowState | None = None
        self._transitioned = False

    @property
    def evidence(self) -> VaultRecoveryWorkflowEvidence:
        return self._evidence

    @property
    def transitioned(self) -> bool:
        return self._transitioned

    @property
    def current_state(self) -> RecoveryWorkflowState:
        if self._final_state is None:
            return RecoveryWorkflowState.AWAITING_USER_REVIEW
        return self._final_state.state

    def review_once(
        self,
        reviewed_result: VaultRecoveryReconciliationResult,
        decision: RecoveryWorkflowDecision,
    ) -> VaultRecoveryWorkflowState:
        """Record one exact explicit review route without granting authority."""

        if self._transitioned:
            raise VaultRecoveryWorkflowReplayError(
                "recovery workflow was already transitioned"
            )
        if type(decision) is not RecoveryWorkflowDecision:
            raise VaultRecoveryWorkflowTransitionError(
                "decision must be an exact RecoveryWorkflowDecision"
            )

        observed = _workflow_evidence_from_result(reviewed_result)
        if (
            not hmac.compare_digest(
                observed.reconciliation_result_sha256,
                self._evidence.reconciliation_result_sha256,
            )
            or observed != self._evidence
        ):
            raise VaultRecoveryWorkflowMismatchError(
                "reviewed reconciliation result differs from prepared evidence"
            )

        final_state = _state_for_decision(self._evidence, decision)
        self._final_state = final_state
        self._transitioned = True
        return final_state

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryWorkflow("
            f"classification={self._evidence.classification.value!r}, "
            f"transitioned={self._transitioned})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryWorkflowReplayError(
            "prepared recovery workflow cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryWorkflowReplayError(
            "prepared recovery workflow cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryWorkflowReplayError(
            "prepared recovery workflow cannot be serialized"
        )


def _exact_bytes(value: Any, field_name: str, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise VaultRecoveryWorkflowResultError(
            f"{field_name} must be exact {length}-byte data"
        )
    return value


def _bounded_uint(value: Any, field_name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise VaultRecoveryWorkflowResultError(
            f"{field_name} must be a bounded non-negative integer"
        )
    return value


def _validate_bounded_receipt(
    value: Any,
    field_name: str,
) -> VaultGenerationReceipt:
    if type(value) is not VaultGenerationReceipt:
        raise VaultRecoveryWorkflowResultError(
            f"{field_name} must be an exact VaultGenerationReceipt"
        )
    try:
        _validate_receipt(value)
    except VaultStorageError as exc:
        raise VaultRecoveryWorkflowResultError(
            f"{field_name} is invalid"
        ) from exc
    for name in (
        "directory_device",
        "directory_inode",
        "file_device",
        "file_inode",
    ):
        _bounded_uint(getattr(value, name), f"{field_name}.{name}", MAX_UINT64)
    _bounded_uint(
        value.revision,
        f"{field_name}.revision",
        MAX_VAULT_REVISION,
    )
    encoded_size = _bounded_uint(
        value.encoded_size,
        f"{field_name}.encoded_size",
        MAX_GENERATION_BYTES,
    )
    if encoded_size == 0:
        raise VaultRecoveryWorkflowResultError(
            f"{field_name}.encoded_size must be positive"
        )
    return value


def _validate_fixed_result_flags(value: VaultRecoveryReconciliationResult) -> None:
    bool_fields = (
        "storage_complete",
        "stable_observation",
        "source_verified",
        "recovery_record_verified",
        "new_password_verified",
        "keyring_verified",
        "read_only",
        "mutation_authorized",
        "publish_performed",
        "rollback_performed",
        "cleanup_performed",
        "key_deletion_performed",
        "user_file_mutation_performed",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryWorkflowResultError(
            "reconciliation safety flags must be exact booleans"
        )
    if (
        value.source_verified is not True
        or value.recovery_record_verified is not True
        or value.read_only is not True
    ):
        raise VaultRecoveryWorkflowResultError(
            "reviewed result lacks mandatory read-only verification"
        )
    forbidden_true = (
        value.mutation_authorized,
        value.publish_performed,
        value.rollback_performed,
        value.cleanup_performed,
        value.key_deletion_performed,
        value.user_file_mutation_performed,
    )
    if any(item is not False for item in forbidden_true):
        raise VaultRecoveryWorkflowResultError(
            "reviewed result contains forbidden mutation authority or outcome"
        )


def _validate_result_common(
    value: Any,
) -> tuple[VaultGenerationReceipt, VaultGenerationReceipt | None]:
    if type(value) is not VaultRecoveryReconciliationResult:
        raise VaultRecoveryWorkflowResultError(
            "reviewed_result must be an exact Stage 2.8 result"
        )
    if type(value.classification) is not RecoveryPublishClassification:
        raise VaultRecoveryWorkflowResultError(
            "reconciliation classification is invalid"
        )
    if type(value.recommended_action) is not RecoveryReconciliationAction:
        raise VaultRecoveryWorkflowResultError(
            "reconciliation action is invalid"
        )

    _exact_bytes(value.recovery_id, "recovery_id", RECOVERY_ID_LEN)
    _exact_bytes(value.vault_id, "vault_id", RECOVERY_VAULT_ID_LEN)
    _exact_bytes(
        value.source_vault_sha256,
        "source_vault_sha256",
        RECOVERY_SHA256_LEN,
    )
    _exact_bytes(value.record_sha256, "record_sha256", RECOVERY_SHA256_LEN)
    _exact_bytes(value.keyring_sha256, "keyring_sha256", RECOVERY_SHA256_LEN)

    source_revision = _bounded_uint(
        value.source_revision,
        "source_revision",
        MAX_VAULT_REVISION,
    )
    target_revision = _bounded_uint(
        value.target_revision,
        "target_revision",
        MAX_VAULT_REVISION,
    )
    if (
        source_revision < 1
        or source_revision >= MAX_VAULT_REVISION
        or target_revision != source_revision + 1
    ):
        raise VaultRecoveryWorkflowResultError(
            "target_revision must be the exact next Vault revision"
        )

    generation_count = _bounded_uint(
        value.generation_count,
        "generation_count",
        MAX_STORAGE_ENTRIES,
    )
    finding_count = _bounded_uint(
        value.finding_count,
        "finding_count",
        MAX_STORAGE_ENTRIES,
    )
    omitted_entries = _bounded_uint(
        value.omitted_entries,
        "omitted_entries",
        MAX_UINT64,
    )
    if generation_count > finding_count:
        raise VaultRecoveryWorkflowResultError(
            "generation_count cannot exceed finding_count"
        )

    _validate_fixed_result_flags(value)
    if value.storage_complete != (omitted_entries == 0):
        raise VaultRecoveryWorkflowResultError(
            "storage completeness differs from omitted entry count"
        )

    source = _validate_bounded_receipt(value.source_receipt, "source_receipt")
    if (
        source.revision != source_revision
        or not hmac.compare_digest(source.vault_id, value.vault_id)
        or not hmac.compare_digest(source.sha256, value.source_vault_sha256)
    ):
        raise VaultRecoveryWorkflowResultError(
            "source receipt differs from reconciliation evidence"
        )

    target = value.target_receipt
    if target is not None:
        target = _validate_bounded_receipt(target, "target_receipt")
    return source, target


def _validate_result_classification(
    value: VaultRecoveryReconciliationResult,
    source: VaultGenerationReceipt,
    target: VaultGenerationReceipt | None,
) -> None:
    classification = value.classification
    if classification is RecoveryPublishClassification.TARGET_ABSENT:
        if (
            value.recommended_action
            is not RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE
            or target is not None
            or value.target_vault_sha256 is not None
            or value.storage_complete is not True
            or value.stable_observation is not True
            or value.new_password_verified is not False
            or value.keyring_verified is not False
            or value.generation_count != value.source_revision
            or value.finding_count != value.generation_count
        ):
            raise VaultRecoveryWorkflowResultError(
                "target-absent result invariants are contradictory"
            )
        return

    if classification is RecoveryPublishClassification.TARGET_EXACT_DURABLE:
        if target is None:
            raise VaultRecoveryWorkflowResultError(
                "exact-target result lacks a target receipt"
            )
        target_digest = _exact_bytes(
            value.target_vault_sha256,
            "target_vault_sha256",
            RECOVERY_SHA256_LEN,
        )
        if (
            value.recommended_action
            is not RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY
            or value.storage_complete is not True
            or value.stable_observation is not True
            or value.new_password_verified is not True
            or value.keyring_verified is not True
            or value.generation_count != value.target_revision
            or value.finding_count != value.generation_count
            or target.directory_device != source.directory_device
            or target.directory_inode != source.directory_inode
            or target.revision != value.target_revision
            or not hmac.compare_digest(target.vault_id, value.vault_id)
            or not hmac.compare_digest(target.sha256, target_digest)
        ):
            raise VaultRecoveryWorkflowResultError(
                "exact-target result invariants are contradictory"
            )
        return

    if classification is RecoveryPublishClassification.CONFLICT:
        if (
            value.recommended_action
            is not RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW
            or target is not None
            or value.target_vault_sha256 is not None
            or value.new_password_verified is not False
            or value.keyring_verified is not False
        ):
            raise VaultRecoveryWorkflowResultError(
                "conflict result invariants are contradictory"
            )
        return

    raise VaultRecoveryWorkflowResultError(
        "reconciliation classification is unsupported"
    )


def _receipt_transcript(value: VaultGenerationReceipt) -> bytes:
    return struct.pack(
        ">QQ16sQ32sQQQ?",
        value.directory_device,
        value.directory_inode,
        value.vault_id,
        value.revision,
        value.sha256,
        value.file_device,
        value.file_inode,
        value.encoded_size,
        value.durable,
    )


def _result_transcript(value: VaultRecoveryReconciliationResult) -> bytes:
    classification_code = {
        RecoveryPublishClassification.TARGET_ABSENT: 1,
        RecoveryPublishClassification.TARGET_EXACT_DURABLE: 2,
        RecoveryPublishClassification.CONFLICT: 3,
    }[value.classification]
    action_code = {
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE: 1,
        RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY: 2,
        RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW: 3,
    }[value.recommended_action]
    target = value.target_receipt
    parts = [
        _RESULT_DIGEST_DOMAIN,
        struct.pack(">BB", classification_code, action_code),
        value.recovery_id,
        value.vault_id,
        struct.pack(">QQ", value.source_revision, value.target_revision),
        value.source_vault_sha256,
        value.record_sha256,
        value.keyring_sha256,
        _receipt_transcript(value.source_receipt),
        struct.pack(">B", target is not None),
    ]
    if target is not None:
        parts.append(_receipt_transcript(target))
        parts.append(value.target_vault_sha256)
    parts.extend(
        (
            struct.pack(
                ">QQQ",
                value.generation_count,
                value.finding_count,
                value.omitted_entries,
            ),
            struct.pack(
                ">13?",
                value.storage_complete,
                value.stable_observation,
                value.source_verified,
                value.recovery_record_verified,
                value.new_password_verified,
                value.keyring_verified,
                value.read_only,
                value.mutation_authorized,
                value.publish_performed,
                value.rollback_performed,
                value.cleanup_performed,
                value.key_deletion_performed,
                value.user_file_mutation_performed,
            ),
        )
    )
    return b"".join(parts)


def _workflow_evidence_from_result(
    value: Any,
) -> VaultRecoveryWorkflowEvidence:
    source, target = _validate_result_common(value)
    _validate_result_classification(value, source, target)
    digest = hashlib.sha256(_result_transcript(value)).digest()
    return VaultRecoveryWorkflowEvidence(
        reconciliation_result_sha256=digest,
        classification=value.classification,
        recommended_action=value.recommended_action,
        recovery_id=value.recovery_id,
        vault_id=value.vault_id,
        source_revision=value.source_revision,
        target_revision=value.target_revision,
        source_vault_sha256=value.source_vault_sha256,
        record_sha256=value.record_sha256,
        keyring_sha256=value.keyring_sha256,
        target_vault_sha256=value.target_vault_sha256,
        storage_complete=value.storage_complete,
        stable_observation=value.stable_observation,
    )


def _validate_workflow_evidence(
    value: Any,
) -> VaultRecoveryWorkflowEvidence:
    if type(value) is not VaultRecoveryWorkflowEvidence:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence type is invalid"
        )
    if (
        value.format != RECOVERY_WORKFLOW_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_WORKFLOW_VERSION
    ):
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence format or version is unsupported"
        )
    _exact_bytes(
        value.reconciliation_result_sha256,
        "reconciliation_result_sha256",
        RECOVERY_WORKFLOW_RESULT_SHA256_LEN,
    )
    _exact_bytes(value.recovery_id, "recovery_id", RECOVERY_ID_LEN)
    _exact_bytes(value.vault_id, "vault_id", RECOVERY_VAULT_ID_LEN)
    _exact_bytes(
        value.source_vault_sha256,
        "source_vault_sha256",
        RECOVERY_SHA256_LEN,
    )
    _exact_bytes(value.record_sha256, "record_sha256", RECOVERY_SHA256_LEN)
    _exact_bytes(value.keyring_sha256, "keyring_sha256", RECOVERY_SHA256_LEN)
    source_revision = _bounded_uint(
        value.source_revision,
        "source_revision",
        MAX_VAULT_REVISION,
    )
    target_revision = _bounded_uint(
        value.target_revision,
        "target_revision",
        MAX_VAULT_REVISION,
    )
    if source_revision < 1 or target_revision != source_revision + 1:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence revisions are not exact next revisions"
        )
    if type(value.classification) is not RecoveryPublishClassification:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence classification is invalid"
        )
    if type(value.recommended_action) is not RecoveryReconciliationAction:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence action is invalid"
        )
    expected_action = {
        RecoveryPublishClassification.TARGET_ABSENT: (
            RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE
        ),
        RecoveryPublishClassification.TARGET_EXACT_DURABLE: (
            RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY
        ),
        RecoveryPublishClassification.CONFLICT: (
            RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW
        ),
    }[value.classification]
    if value.recommended_action is not expected_action:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence action differs from its classification"
        )
    if type(value.storage_complete) is not bool or type(value.stable_observation) is not bool:
        raise VaultRecoveryWorkflowResultError(
            "workflow evidence observation flags must be booleans"
        )
    if value.classification is RecoveryPublishClassification.TARGET_EXACT_DURABLE:
        _exact_bytes(
            value.target_vault_sha256,
            "target_vault_sha256",
            RECOVERY_SHA256_LEN,
        )
        if value.storage_complete is not True or value.stable_observation is not True:
            raise VaultRecoveryWorkflowResultError(
                "exact target workflow evidence must be complete and stable"
            )
    elif value.target_vault_sha256 is not None:
        raise VaultRecoveryWorkflowResultError(
            "non-exact workflow evidence cannot expose a target digest"
        )
    if (
        value.classification is RecoveryPublishClassification.TARGET_ABSENT
        and (value.storage_complete is not True or value.stable_observation is not True)
    ):
        raise VaultRecoveryWorkflowResultError(
            "target-absent workflow evidence must be complete and stable"
        )
    return value


def _state_for_decision(
    evidence: VaultRecoveryWorkflowEvidence,
    decision: RecoveryWorkflowDecision,
) -> VaultRecoveryWorkflowState:
    state, gates, terminal, reverification = _route_for_decision(
        evidence,
        decision,
    )
    return VaultRecoveryWorkflowState(
        evidence=evidence,
        decision=decision,
        state=state,
        required_gates=gates,
        terminal_stop=terminal,
        downstream_reverification_required=reverification,
    )


def _validate_workflow_state(value: Any) -> VaultRecoveryWorkflowState:
    if type(value) is not VaultRecoveryWorkflowState:
        raise VaultRecoveryWorkflowTransitionError(
            "workflow state type is invalid"
        )
    evidence = _validate_workflow_evidence(value.evidence)
    if (
        value.format != RECOVERY_WORKFLOW_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_WORKFLOW_VERSION
        or type(value.transition_sequence) is not int
        or value.transition_sequence != 1
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
        or type(value.required_gates) is not tuple
        or any(type(item) is not RecoveryWorkflowGate for item in value.required_gates)
    ):
        raise VaultRecoveryWorkflowTransitionError(
            "workflow state schema is invalid"
        )
    bool_fields = (
        "reviewed_result_validated",
        "user_decision_recorded",
        "read_only",
        "terminal_stop",
        "downstream_reverification_required",
        "secrets_retained",
        "mutation_authorized",
        "candidate_creation_authorized",
        "normal_unlock_authorized",
        "recovery_setup_authorized",
        "publish_authorized",
        "retry_authorized",
        "repair_authorized",
        "cleanup_authorized",
        "key_deletion_authorized",
        "user_file_mutation_authorized",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryWorkflowTransitionError(
            "workflow policy flags must be exact booleans"
        )
    if (
        value.reviewed_result_validated is not True
        or value.user_decision_recorded is not True
        or value.read_only is not True
        or value.secrets_retained is not False
    ):
        raise VaultRecoveryWorkflowTransitionError(
            "workflow state lacks mandatory non-secret review policy"
        )
    forbidden_authority = (
        value.mutation_authorized,
        value.candidate_creation_authorized,
        value.normal_unlock_authorized,
        value.recovery_setup_authorized,
        value.publish_authorized,
        value.retry_authorized,
        value.repair_authorized,
        value.cleanup_authorized,
        value.key_deletion_authorized,
        value.user_file_mutation_authorized,
    )
    if any(item is not False for item in forbidden_authority):
        raise VaultRecoveryWorkflowTransitionError(
            "workflow route cannot grant operation authority"
        )

    expected = _route_for_decision(evidence, value.decision)
    if (
        value.state is not expected[0]
        or value.required_gates != expected[1]
        or value.terminal_stop is not expected[2]
        or value.downstream_reverification_required is not expected[3]
    ):
        raise VaultRecoveryWorkflowTransitionError(
            "workflow state differs from the exact decision route"
        )
    return value


def _route_for_decision(
    evidence: VaultRecoveryWorkflowEvidence,
    decision: RecoveryWorkflowDecision,
) -> tuple[
    RecoveryWorkflowState,
    tuple[RecoveryWorkflowGate, ...],
    bool,
    bool,
]:
    if decision is RecoveryWorkflowDecision.PRESERVE_AND_STOP:
        return RecoveryWorkflowState.PRESERVED_STOP, (), True, False
    if (
        decision is RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT
        and evidence.classification
        is RecoveryPublishClassification.TARGET_ABSENT
    ):
        return (
            RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
            (RecoveryWorkflowGate.STAGE_2_6_NEW_CANDIDATE_DECISION,),
            False,
            True,
        )
    if (
        decision is RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET
        and evidence.classification
        is RecoveryPublishClassification.TARGET_EXACT_DURABLE
    ):
        return (
            RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
            (
                RecoveryWorkflowGate.NORMAL_VAULT_UNLOCK,
                RecoveryWorkflowGate.STAGE_2_5_NEW_RECOVERY_SETUP_DECISION,
            ),
            False,
            True,
        )
    if (
        decision is RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT
        and evidence.classification is RecoveryPublishClassification.CONFLICT
    ):
        return (
            RecoveryWorkflowState.MANUAL_REVIEW_STOP,
            (RecoveryWorkflowGate.MANUAL_REVIEW_ONLY,),
            True,
            False,
        )
    raise VaultRecoveryWorkflowTransitionError(
        "decision is incompatible with the reviewed classification"
    )


def prepare_recovery_workflow(
    reviewed_result: VaultRecoveryReconciliationResult,
) -> PreparedVaultRecoveryWorkflow:
    """Bind one exact reviewed Stage 2.8 result for one later review route."""

    return PreparedVaultRecoveryWorkflow(
        _workflow_evidence_from_result(reviewed_result)
    )
