"""Fixed non-secret presentation model for a validated recovery workflow.

Stage 2.10 accepts one exact Stage 2.9 ``VaultRecoveryWorkflowState`` and
transforms it into bounded localization keys plus ordered confirmation
requirements.  It does not render localized prose and it never treats a route
or gate as an operation that has been performed or authorized.

The module performs no filesystem access, Vault unlock, recovery rehearsal,
candidate creation, recovery setup, publish, retry, repair, cleanup, callback,
executor, mutation, GUI work, network access, telemetry, logging, clock access,
randomness, update discovery, download, or installation.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from typing import Any

from mokosh_vault_recovery_reconciliation import (
    RecoveryPublishClassification,
    RecoveryReconciliationAction,
)
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowGate,
    RecoveryWorkflowState,
    VaultRecoveryWorkflowError,
    VaultRecoveryWorkflowState,
    _validate_workflow_state,
)


RECOVERY_PRESENTATION_FORMAT = "MOKOSH_VAULT_RECOVERY_PRESENTATION"
RECOVERY_PRESENTATION_VERSION = 1
RECOVERY_PRESENTATION_STATE_SHA256_LEN = 32
MAX_PRESENTATION_MESSAGE_KEYS = 12
MAX_PRESENTATION_GATE_KEYS = 2
MAX_PRESENTATION_CONFIRMATIONS = 4

_STATE_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-PRESENTATION\x00WORKFLOW-STATE-V1\x00"
)


class VaultRecoveryPresentationError(ValueError):
    """Base class for strict Stage 2.10 presentation failures."""


class VaultRecoveryPresentationStateError(VaultRecoveryPresentationError):
    """The supplied Stage 2.9 state is malformed or contradictory."""


class VaultRecoveryPresentationFormatError(VaultRecoveryPresentationError):
    """A presentation object violates the fixed Stage 2.10 schema."""


class RecoveryPresentationMessageKey(str, Enum):
    """Fixed localization keys; these values are not rendered user prose."""

    WORKFLOW_RESULT_REVIEWED = "recovery.workflow.result_reviewed"

    CLASSIFICATION_TARGET_ABSENT = "recovery.classification.target_absent"
    CLASSIFICATION_TARGET_EXACT = "recovery.classification.target_exact"
    CLASSIFICATION_CONFLICT = "recovery.classification.conflict"

    DECISION_PRESERVE_AND_STOP = "recovery.decision.preserve_and_stop"
    DECISION_TARGET_ABSENT_ACKNOWLEDGED = (
        "recovery.decision.target_absent_acknowledged"
    )
    DECISION_EXACT_TARGET_ACKNOWLEDGED = (
        "recovery.decision.exact_target_acknowledged"
    )
    DECISION_CONFLICT_ACKNOWLEDGED = (
        "recovery.decision.conflict_acknowledged"
    )

    ROUTE_FRESH_CANDIDATE_DECISION_REQUIRED = (
        "recovery.route.fresh_candidate_decision_required"
    )
    ROUTE_NORMAL_UNLOCK_REQUIRED = "recovery.route.normal_unlock_required"
    ROUTE_MANUAL_REVIEW_STOP = "recovery.route.manual_review_stop"
    ROUTE_PRESERVED_STOP = "recovery.route.preserved_stop"

    GATE_FRESH_STAGE_2_6_DECISION_REQUIRED = (
        "recovery.gate.fresh_stage_2_6_decision_required"
    )
    GATE_NORMAL_VAULT_UNLOCK_REQUIRED = (
        "recovery.gate.normal_vault_unlock_required"
    )
    GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED = (
        "recovery.gate.new_stage_2_5_setup_decision_required"
    )
    GATE_MANUAL_REVIEW_ONLY = "recovery.gate.manual_review_only"

    DOWNSTREAM_REVERIFICATION_REQUIRED = (
        "recovery.safety.downstream_reverification_required"
    )
    FRESH_INPUTS_REQUIRED = "recovery.safety.fresh_inputs_required"
    OLD_RECOVERY_RECORD_REMAINS_STALE = (
        "recovery.safety.old_recovery_record_remains_stale"
    )
    TERMINAL_STOP = "recovery.safety.terminal_stop"
    RECOVERY_PROBLEM_NOT_RESOLVED = (
        "recovery.safety.recovery_problem_not_resolved"
    )
    NO_OPERATION_PERFORMED = "recovery.safety.no_operation_performed"
    NO_OPERATION_AUTHORIZED = "recovery.safety.no_operation_authorized"
    NO_AUTOMATIC_RETRY_REPAIR_OR_CLEANUP = (
        "recovery.safety.no_automatic_retry_repair_or_cleanup"
    )


class RecoveryPresentationConfirmationKey(str, Enum):
    """Ordered acknowledgements a future adapter must present separately."""

    ACKNOWLEDGE_NO_OPERATION_PERFORMED = (
        "recovery.confirm.no_operation_performed"
    )
    ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED = (
        "recovery.confirm.downstream_reverification_required"
    )
    ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED = (
        "recovery.confirm.fresh_stage_2_6_decision_required"
    )
    ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED = (
        "recovery.confirm.normal_unlock_required"
    )
    ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED = (
        "recovery.confirm.new_stage_2_5_setup_decision_required"
    )
    ACKNOWLEDGE_MANUAL_REVIEW_STOP = (
        "recovery.confirm.manual_review_stop"
    )
    ACKNOWLEDGE_NO_AUTOMATIC_REPAIR = (
        "recovery.confirm.no_automatic_repair"
    )
    ACKNOWLEDGE_PRESERVED_STOP = "recovery.confirm.preserved_stop"
    ACKNOWLEDGE_RECOVERY_NOT_RESOLVED = (
        "recovery.confirm.recovery_not_resolved"
    )


@_dataclass(frozen=True, slots=True)
class VaultRecoveryWorkflowPresentation:
    """Bounded view-model data with no text, callback, executor, or authority."""

    workflow_state_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    message_keys: tuple[RecoveryPresentationMessageKey, ...]
    gate_message_keys: tuple[RecoveryPresentationMessageKey, ...]
    confirmation_requirements: tuple[RecoveryPresentationConfirmationKey, ...]
    terminal_stop: bool
    downstream_reverification_required: bool
    workflow_state_validated: bool = True
    fixed_message_keys_only: bool = True
    raw_text_included: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_PRESENTATION_FORMAT
    version: int = RECOVERY_PRESENTATION_VERSION

    def __post_init__(self) -> None:
        _validate_presentation(self)


def _state_transcript(value: VaultRecoveryWorkflowState) -> bytes:
    evidence = value.evidence
    classification_code = {
        RecoveryPublishClassification.TARGET_ABSENT: 1,
        RecoveryPublishClassification.TARGET_EXACT_DURABLE: 2,
        RecoveryPublishClassification.CONFLICT: 3,
    }[evidence.classification]
    action_code = {
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE: 1,
        RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY: 2,
        RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW: 3,
    }[evidence.recommended_action]
    decision_code = {
        RecoveryWorkflowDecision.PRESERVE_AND_STOP: 1,
        RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT: 2,
        RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET: 3,
        RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT: 4,
    }[value.decision]
    state_code = {
        RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED: 1,
        RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED: 2,
        RecoveryWorkflowState.MANUAL_REVIEW_STOP: 3,
        RecoveryWorkflowState.PRESERVED_STOP: 4,
    }[value.state]
    gate_codes = {
        RecoveryWorkflowGate.STAGE_2_6_NEW_CANDIDATE_DECISION: 1,
        RecoveryWorkflowGate.NORMAL_VAULT_UNLOCK: 2,
        RecoveryWorkflowGate.STAGE_2_5_NEW_RECOVERY_SETUP_DECISION: 3,
        RecoveryWorkflowGate.MANUAL_REVIEW_ONLY: 4,
    }
    target_digest = evidence.target_vault_sha256
    state_flags = (
        evidence.storage_complete,
        evidence.stable_observation,
        value.reviewed_result_validated,
        value.user_decision_recorded,
        value.read_only,
        value.terminal_stop,
        value.downstream_reverification_required,
        value.secrets_retained,
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
    parts = [
        _STATE_DIGEST_DOMAIN,
        evidence.reconciliation_result_sha256,
        struct.pack(">BBBB", classification_code, action_code, decision_code, state_code),
        evidence.recovery_id,
        evidence.vault_id,
        struct.pack(">QQ", evidence.source_revision, evidence.target_revision),
        evidence.source_vault_sha256,
        evidence.record_sha256,
        evidence.keyring_sha256,
        struct.pack(">B", target_digest is not None),
        target_digest if target_digest is not None else b"\x00" * 32,
        struct.pack(">18?", *state_flags),
        struct.pack(">B", len(value.required_gates)),
        bytes(gate_codes[item] for item in value.required_gates),
    ]
    return b"".join(parts)


def _validate_source_state(value: Any) -> VaultRecoveryWorkflowState:
    if type(value) is not VaultRecoveryWorkflowState:
        raise VaultRecoveryPresentationStateError(
            "workflow_state must be an exact VaultRecoveryWorkflowState"
        )
    try:
        return _validate_workflow_state(value)
    except VaultRecoveryWorkflowError as exc:
        raise VaultRecoveryPresentationStateError(
            "workflow_state violates the Stage 2.9 contract"
        ) from exc


def _classification_message(
    value: RecoveryPublishClassification,
) -> RecoveryPresentationMessageKey:
    return {
        RecoveryPublishClassification.TARGET_ABSENT: (
            RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_ABSENT
        ),
        RecoveryPublishClassification.TARGET_EXACT_DURABLE: (
            RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_EXACT
        ),
        RecoveryPublishClassification.CONFLICT: (
            RecoveryPresentationMessageKey.CLASSIFICATION_CONFLICT
        ),
    }[value]


def _presentation_components(
    classification: RecoveryPublishClassification,
    decision: RecoveryWorkflowDecision,
    state: RecoveryWorkflowState,
    terminal_stop: bool,
    downstream_reverification_required: bool,
) -> tuple[
    tuple[RecoveryPresentationMessageKey, ...],
    tuple[RecoveryPresentationMessageKey, ...],
    tuple[RecoveryPresentationConfirmationKey, ...],
]:
    classification_key = _classification_message(classification)
    common = (
        RecoveryPresentationMessageKey.WORKFLOW_RESULT_REVIEWED,
        classification_key,
    )
    safety = (
        RecoveryPresentationMessageKey.NO_OPERATION_PERFORMED,
        RecoveryPresentationMessageKey.NO_OPERATION_AUTHORIZED,
    )
    first_confirmation = (
        RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_OPERATION_PERFORMED,
    )

    if decision is RecoveryWorkflowDecision.PRESERVE_AND_STOP:
        if (
            state is not RecoveryWorkflowState.PRESERVED_STOP
            or terminal_stop is not True
            or downstream_reverification_required is not False
        ):
            raise VaultRecoveryPresentationFormatError(
                "preserved presentation route is contradictory"
            )
        messages = common + (
            RecoveryPresentationMessageKey.DECISION_PRESERVE_AND_STOP,
            RecoveryPresentationMessageKey.ROUTE_PRESERVED_STOP,
        ) + safety + (
            RecoveryPresentationMessageKey.TERMINAL_STOP,
            RecoveryPresentationMessageKey.RECOVERY_PROBLEM_NOT_RESOLVED,
        )
        confirmations = first_confirmation + (
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_PRESERVED_STOP,
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_RECOVERY_NOT_RESOLVED,
        )
        return messages, (), confirmations

    if (
        classification is RecoveryPublishClassification.TARGET_ABSENT
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT
    ):
        if (
            state is not RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED
            or terminal_stop is not False
            or downstream_reverification_required is not True
        ):
            raise VaultRecoveryPresentationFormatError(
                "target-absent presentation route is contradictory"
            )
        gates = (
            RecoveryPresentationMessageKey.GATE_FRESH_STAGE_2_6_DECISION_REQUIRED,
        )
        messages = common + (
            RecoveryPresentationMessageKey.DECISION_TARGET_ABSENT_ACKNOWLEDGED,
            RecoveryPresentationMessageKey.ROUTE_FRESH_CANDIDATE_DECISION_REQUIRED,
        ) + safety + (
            RecoveryPresentationMessageKey.DOWNSTREAM_REVERIFICATION_REQUIRED,
            gates[0],
            RecoveryPresentationMessageKey.FRESH_INPUTS_REQUIRED,
        )
        confirmations = first_confirmation + (
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED,
        )
        return messages, gates, confirmations

    if (
        classification is RecoveryPublishClassification.TARGET_EXACT_DURABLE
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET
    ):
        if (
            state is not RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED
            or terminal_stop is not False
            or downstream_reverification_required is not True
        ):
            raise VaultRecoveryPresentationFormatError(
                "exact-target presentation route is contradictory"
            )
        gates = (
            RecoveryPresentationMessageKey.GATE_NORMAL_VAULT_UNLOCK_REQUIRED,
            RecoveryPresentationMessageKey.GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
        )
        messages = common + (
            RecoveryPresentationMessageKey.DECISION_EXACT_TARGET_ACKNOWLEDGED,
            RecoveryPresentationMessageKey.ROUTE_NORMAL_UNLOCK_REQUIRED,
        ) + safety + (
            RecoveryPresentationMessageKey.DOWNSTREAM_REVERIFICATION_REQUIRED,
            gates[0],
            gates[1],
            RecoveryPresentationMessageKey.OLD_RECOVERY_RECORD_REMAINS_STALE,
        )
        confirmations = first_confirmation + (
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED,
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
        )
        return messages, gates, confirmations

    if (
        classification is RecoveryPublishClassification.CONFLICT
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT
    ):
        if (
            state is not RecoveryWorkflowState.MANUAL_REVIEW_STOP
            or terminal_stop is not True
            or downstream_reverification_required is not False
        ):
            raise VaultRecoveryPresentationFormatError(
                "conflict presentation route is contradictory"
            )
        gates = (RecoveryPresentationMessageKey.GATE_MANUAL_REVIEW_ONLY,)
        messages = common + (
            RecoveryPresentationMessageKey.DECISION_CONFLICT_ACKNOWLEDGED,
            RecoveryPresentationMessageKey.ROUTE_MANUAL_REVIEW_STOP,
        ) + safety + (
            RecoveryPresentationMessageKey.TERMINAL_STOP,
            gates[0],
            RecoveryPresentationMessageKey.NO_AUTOMATIC_RETRY_REPAIR_OR_CLEANUP,
        )
        confirmations = first_confirmation + (
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP,
            RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
        )
        return messages, gates, confirmations

    raise VaultRecoveryPresentationFormatError(
        "presentation classification, decision, and route are incompatible"
    )


def _validate_exact_enum_tuple(
    value: Any,
    enum_type: type[Enum],
    field_name: str,
    maximum: int,
) -> tuple[Any, ...]:
    if (
        type(value) is not tuple
        or not 1 <= len(value) <= maximum
        or any(type(item) is not enum_type for item in value)
        or len(set(value)) != len(value)
    ):
        raise VaultRecoveryPresentationFormatError(
            f"{field_name} must be a bounded unique exact-enum tuple"
        )
    return value


def _validate_presentation(
    value: Any,
) -> VaultRecoveryWorkflowPresentation:
    if type(value) is not VaultRecoveryWorkflowPresentation:
        raise VaultRecoveryPresentationFormatError(
            "presentation type is invalid"
        )
    if (
        value.format != RECOVERY_PRESENTATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_PRESENTATION_VERSION
        or type(value.workflow_state_sha256) is not bytes
        or len(value.workflow_state_sha256)
        != RECOVERY_PRESENTATION_STATE_SHA256_LEN
        or type(value.classification) is not RecoveryPublishClassification
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
    ):
        raise VaultRecoveryPresentationFormatError(
            "presentation schema is invalid"
        )

    messages = _validate_exact_enum_tuple(
        value.message_keys,
        RecoveryPresentationMessageKey,
        "message_keys",
        MAX_PRESENTATION_MESSAGE_KEYS,
    )
    gates = value.gate_message_keys
    if (
        type(gates) is not tuple
        or len(gates) > MAX_PRESENTATION_GATE_KEYS
        or any(type(item) is not RecoveryPresentationMessageKey for item in gates)
        or len(set(gates)) != len(gates)
    ):
        raise VaultRecoveryPresentationFormatError(
            "gate_message_keys must be a bounded unique exact-enum tuple"
        )
    confirmations = _validate_exact_enum_tuple(
        value.confirmation_requirements,
        RecoveryPresentationConfirmationKey,
        "confirmation_requirements",
        MAX_PRESENTATION_CONFIRMATIONS,
    )

    bool_fields = (
        "terminal_stop",
        "downstream_reverification_required",
        "workflow_state_validated",
        "fixed_message_keys_only",
        "raw_text_included",
        "operation_performed",
        "operation_authorized",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryPresentationFormatError(
            "presentation safety flags must be exact booleans"
        )
    if (
        value.workflow_state_validated is not True
        or value.fixed_message_keys_only is not True
        or value.raw_text_included is not False
        or value.operation_performed is not False
        or value.operation_authorized is not False
        or value.secrets_retained is not False
    ):
        raise VaultRecoveryPresentationFormatError(
            "presentation contains forbidden text, authority, or executable state"
        )

    expected = _presentation_components(
        value.classification,
        value.decision,
        value.state,
        value.terminal_stop,
        value.downstream_reverification_required,
    )
    if messages != expected[0] or gates != expected[1] or confirmations != expected[2]:
        raise VaultRecoveryPresentationFormatError(
            "presentation keys differ from the exact workflow route"
        )
    if any(item not in messages for item in gates):
        raise VaultRecoveryPresentationFormatError(
            "every gate message must be visibly present in message_keys"
        )
    return value


def prepare_recovery_workflow_presentation(
    workflow_state: VaultRecoveryWorkflowState,
) -> VaultRecoveryWorkflowPresentation:
    """Create fixed presentation keys from one exact validated Stage 2.9 state."""

    validated = _validate_source_state(workflow_state)
    messages, gates, confirmations = _presentation_components(
        validated.evidence.classification,
        validated.decision,
        validated.state,
        validated.terminal_stop,
        validated.downstream_reverification_required,
    )
    return VaultRecoveryWorkflowPresentation(
        workflow_state_sha256=hashlib.sha256(_state_transcript(validated)).digest(),
        classification=validated.evidence.classification,
        decision=validated.decision,
        state=validated.state,
        message_keys=messages,
        gate_message_keys=gates,
        confirmation_requirements=confirmations,
        terminal_stop=validated.terminal_stop,
        downstream_reverification_required=(
            validated.downstream_reverification_required
        ),
    )
