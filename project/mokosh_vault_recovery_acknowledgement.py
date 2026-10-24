"""One-shot non-mutating acknowledgement of a recovery presentation.

Stage 2.11 binds one exact validated Stage 2.10 presentation and accepts only
its complete ordered tuple of fixed confirmation keys.  A successful
acknowledgement returns bounded non-secret state.  It never invokes a gate and
never grants operation authority.

The module performs no filesystem access, Vault unlock, recovery rehearsal,
candidate creation, recovery setup, publish, retry, repair, cleanup, callback,
executor, mutation, GUI work, network access, telemetry, logging, clock access,
randomness, update discovery, download, or installation.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from typing import Any

from mokosh_vault_recovery_presentation import (
    MAX_PRESENTATION_CONFIRMATIONS,
    RecoveryPresentationConfirmationKey,
    RecoveryPresentationMessageKey,
    VaultRecoveryPresentationError,
    VaultRecoveryWorkflowPresentation,
    _validate_presentation,
)
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowState,
)


RECOVERY_ACKNOWLEDGEMENT_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_PRESENTATION_ACKNOWLEDGEMENT"
)
RECOVERY_ACKNOWLEDGEMENT_VERSION = 1
RECOVERY_ACKNOWLEDGEMENT_PRESENTATION_SHA256_LEN = 32
RECOVERY_ACKNOWLEDGEMENT_SEQUENCE = 1

_PRESENTATION_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-ACKNOWLEDGEMENT\x00PRESENTATION-V1\x00"
)


class VaultRecoveryAcknowledgementError(ValueError):
    """Base class for strict Stage 2.11 acknowledgement failures."""


class VaultRecoveryAcknowledgementPresentationError(
    VaultRecoveryAcknowledgementError
):
    """The supplied Stage 2.10 presentation is malformed or unsupported."""


class VaultRecoveryAcknowledgementConfirmationError(
    VaultRecoveryAcknowledgementError
):
    """Confirmation keys are malformed, incomplete, or out of order."""


class VaultRecoveryAcknowledgementMismatchError(
    VaultRecoveryAcknowledgementError
):
    """The acknowledged presentation differs from the prepared binding."""


class VaultRecoveryAcknowledgementReplayError(
    VaultRecoveryAcknowledgementError
):
    """A prepared acknowledgement was already consumed or cannot be copied."""


class VaultRecoveryAcknowledgementFormatError(
    VaultRecoveryAcknowledgementError
):
    """An acknowledgement receipt violates the fixed Stage 2.11 schema."""


class RecoveryPresentationAcknowledgementState(str, Enum):
    """Process-local state; neither member is operation authorization."""

    AWAITING_CONFIRMATIONS = "awaiting_confirmations"
    ACKNOWLEDGED = "acknowledged"


@_dataclass(frozen=True, slots=True)
class VaultRecoveryPresentationAcknowledgementReceipt:
    """Bounded acknowledgement evidence with no secret or operation authority."""

    presentation_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    acknowledgement_state: RecoveryPresentationAcknowledgementState
    acknowledged_confirmations: tuple[RecoveryPresentationConfirmationKey, ...]
    confirmation_count: int
    terminal_stop: bool
    downstream_reverification_required: bool
    acknowledgement_sequence: int = RECOVERY_ACKNOWLEDGEMENT_SEQUENCE
    presentation_validated: bool = True
    confirmation_order_validated: bool = True
    all_confirmations_acknowledged: bool = True
    one_shot: bool = True
    read_only: bool = True
    operation_performed: bool = False
    operation_authorized: bool = False
    gate_invoked: bool = False
    automatic_transition: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_ACKNOWLEDGEMENT_FORMAT
    version: int = RECOVERY_ACKNOWLEDGEMENT_VERSION

    def __post_init__(self) -> None:
        _validate_acknowledgement_receipt(self)


@_dataclass(frozen=True, slots=True)
class _AcknowledgementBinding:
    presentation_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    required_confirmations: tuple[RecoveryPresentationConfirmationKey, ...]
    terminal_stop: bool
    downstream_reverification_required: bool


class PreparedVaultRecoveryPresentationAcknowledgement:
    """Process-local binding that permits exactly one successful acknowledgement."""

    __slots__ = ("_binding", "_receipt", "_acknowledged", "_lock")

    def __init__(self, binding: _AcknowledgementBinding) -> None:
        if type(binding) is not _AcknowledgementBinding:
            raise VaultRecoveryAcknowledgementFormatError(
                "acknowledgement binding type is invalid"
            )
        self._binding = binding
        self._receipt: VaultRecoveryPresentationAcknowledgementReceipt | None = None
        self._acknowledged = False
        self._lock = _Lock()

    @property
    def required_confirmations(
        self,
    ) -> tuple[RecoveryPresentationConfirmationKey, ...]:
        return self._binding.required_confirmations

    @property
    def acknowledged(self) -> bool:
        return self._acknowledged

    @property
    def current_state(self) -> RecoveryPresentationAcknowledgementState:
        if self._acknowledged:
            return RecoveryPresentationAcknowledgementState.ACKNOWLEDGED
        return RecoveryPresentationAcknowledgementState.AWAITING_CONFIRMATIONS

    @property
    def receipt(self) -> VaultRecoveryPresentationAcknowledgementReceipt | None:
        return self._receipt

    def acknowledge_once(
        self,
        presentation: VaultRecoveryWorkflowPresentation,
        confirmations: tuple[RecoveryPresentationConfirmationKey, ...],
    ) -> VaultRecoveryPresentationAcknowledgementReceipt:
        """Record one exact ordered acknowledgement without invoking a gate."""

        with self._lock:
            if self._acknowledged:
                raise VaultRecoveryAcknowledgementReplayError(
                    "recovery presentation was already acknowledged"
                )

            observed = _binding_from_presentation(presentation)
            if (
                not hmac.compare_digest(
                    observed.presentation_sha256,
                    self._binding.presentation_sha256,
                )
                or observed != self._binding
            ):
                raise VaultRecoveryAcknowledgementMismatchError(
                    "presentation differs from the prepared acknowledgement"
                )

            validated_confirmations = _validate_confirmation_input(confirmations)
            if validated_confirmations != self._binding.required_confirmations:
                raise VaultRecoveryAcknowledgementConfirmationError(
                    "confirmations must exactly match the required ordered keys"
                )

            receipt = VaultRecoveryPresentationAcknowledgementReceipt(
                presentation_sha256=self._binding.presentation_sha256,
                classification=self._binding.classification,
                decision=self._binding.decision,
                state=self._binding.state,
                acknowledgement_state=(
                    RecoveryPresentationAcknowledgementState.ACKNOWLEDGED
                ),
                acknowledged_confirmations=validated_confirmations,
                confirmation_count=len(validated_confirmations),
                terminal_stop=self._binding.terminal_stop,
                downstream_reverification_required=(
                    self._binding.downstream_reverification_required
                ),
            )
            self._receipt = receipt
            self._acknowledged = True
            return receipt

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryPresentationAcknowledgement("
            f"classification={self._binding.classification.value!r}, "
            f"state={self.current_state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryAcknowledgementReplayError(
            "prepared acknowledgement cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryAcknowledgementReplayError(
            "prepared acknowledgement cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryAcknowledgementReplayError(
            "prepared acknowledgement cannot be serialized"
        )


def _pack_enum(value: Enum) -> bytes:
    encoded = value.value.encode("ascii")
    return struct.pack(">H", len(encoded)) + encoded


def _pack_enum_tuple(value: tuple[Enum, ...]) -> bytes:
    return struct.pack(">B", len(value)) + b"".join(_pack_enum(item) for item in value)


def _presentation_transcript(value: VaultRecoveryWorkflowPresentation) -> bytes:
    flags = (
        value.terminal_stop,
        value.downstream_reverification_required,
        value.workflow_state_validated,
        value.fixed_message_keys_only,
        value.raw_text_included,
        value.operation_performed,
        value.operation_authorized,
        value.secrets_retained,
    )
    return b"".join(
        (
            _PRESENTATION_DIGEST_DOMAIN,
            value.workflow_state_sha256,
            _pack_enum(value.classification),
            _pack_enum(value.decision),
            _pack_enum(value.state),
            _pack_enum_tuple(value.message_keys),
            _pack_enum_tuple(value.gate_message_keys),
            _pack_enum_tuple(value.confirmation_requirements),
            struct.pack(">8?", *flags),
            struct.pack(">I", value.version),
        )
    )


def _validate_source_presentation(
    value: Any,
) -> VaultRecoveryWorkflowPresentation:
    if type(value) is not VaultRecoveryWorkflowPresentation:
        raise VaultRecoveryAcknowledgementPresentationError(
            "presentation must be an exact VaultRecoveryWorkflowPresentation"
        )
    try:
        return _validate_presentation(value)
    except VaultRecoveryPresentationError as exc:
        raise VaultRecoveryAcknowledgementPresentationError(
            "presentation violates the Stage 2.10 contract"
        ) from exc


def _binding_from_presentation(
    value: Any,
) -> _AcknowledgementBinding:
    validated = _validate_source_presentation(value)
    return _AcknowledgementBinding(
        presentation_sha256=hashlib.sha256(
            _presentation_transcript(validated)
        ).digest(),
        classification=validated.classification,
        decision=validated.decision,
        state=validated.state,
        required_confirmations=validated.confirmation_requirements,
        terminal_stop=validated.terminal_stop,
        downstream_reverification_required=(
            validated.downstream_reverification_required
        ),
    )


def _validate_confirmation_input(
    value: Any,
) -> tuple[RecoveryPresentationConfirmationKey, ...]:
    if (
        type(value) is not tuple
        or not 1 <= len(value) <= MAX_PRESENTATION_CONFIRMATIONS
        or any(type(item) is not RecoveryPresentationConfirmationKey for item in value)
        or len(set(value)) != len(value)
    ):
        raise VaultRecoveryAcknowledgementConfirmationError(
            "confirmations must be a bounded unique exact-enum tuple"
        )
    return value


def _route_confirmation_policy(
    classification: RecoveryPublishClassification,
    decision: RecoveryWorkflowDecision,
    state: RecoveryWorkflowState,
) -> tuple[tuple[RecoveryPresentationConfirmationKey, ...], bool, bool]:
    first = (
        RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_OPERATION_PERFORMED,
    )
    if decision is RecoveryWorkflowDecision.PRESERVE_AND_STOP:
        if state is not RecoveryWorkflowState.PRESERVED_STOP:
            raise VaultRecoveryAcknowledgementFormatError(
                "preserve acknowledgement route is invalid"
            )
        return (
            first
            + (
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_PRESERVED_STOP,
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_RECOVERY_NOT_RESOLVED,
            ),
            True,
            False,
        )
    if (
        classification is RecoveryPublishClassification.TARGET_ABSENT
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT
        and state is RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED
    ):
        return (
            first
            + (
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED,
            ),
            False,
            True,
        )
    if (
        classification is RecoveryPublishClassification.TARGET_EXACT_DURABLE
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET
        and state is RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED
    ):
        return (
            first
            + (
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED,
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
            ),
            False,
            True,
        )
    if (
        classification is RecoveryPublishClassification.CONFLICT
        and decision is RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT
        and state is RecoveryWorkflowState.MANUAL_REVIEW_STOP
    ):
        return (
            first
            + (
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP,
                RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
            ),
            True,
            False,
        )
    raise VaultRecoveryAcknowledgementFormatError(
        "acknowledgement classification, decision, and state are incompatible"
    )


def _validate_acknowledgement_receipt(
    value: Any,
) -> VaultRecoveryPresentationAcknowledgementReceipt:
    if type(value) is not VaultRecoveryPresentationAcknowledgementReceipt:
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement receipt type is invalid"
        )
    if (
        value.format != RECOVERY_ACKNOWLEDGEMENT_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_ACKNOWLEDGEMENT_VERSION
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_ACKNOWLEDGEMENT_PRESENTATION_SHA256_LEN
        or type(value.classification) is not RecoveryPublishClassification
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
        or type(value.acknowledgement_state)
        is not RecoveryPresentationAcknowledgementState
        or value.acknowledgement_state
        is not RecoveryPresentationAcknowledgementState.ACKNOWLEDGED
        or type(value.acknowledgement_sequence) is not int
        or value.acknowledgement_sequence != RECOVERY_ACKNOWLEDGEMENT_SEQUENCE
        or type(value.confirmation_count) is not int
    ):
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement receipt schema is invalid"
        )

    try:
        confirmations = _validate_confirmation_input(
            value.acknowledged_confirmations
        )
    except VaultRecoveryAcknowledgementConfirmationError as exc:
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement receipt confirmations are invalid"
        ) from exc
    if value.confirmation_count != len(confirmations):
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement confirmation_count is invalid"
        )

    bool_fields = (
        "terminal_stop",
        "downstream_reverification_required",
        "presentation_validated",
        "confirmation_order_validated",
        "all_confirmations_acknowledged",
        "one_shot",
        "read_only",
        "operation_performed",
        "operation_authorized",
        "gate_invoked",
        "automatic_transition",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement safety flags must be exact booleans"
        )
    if (
        value.presentation_validated is not True
        or value.confirmation_order_validated is not True
        or value.all_confirmations_acknowledged is not True
        or value.one_shot is not True
        or value.read_only is not True
        or value.operation_performed is not False
        or value.operation_authorized is not False
        or value.gate_invoked is not False
        or value.automatic_transition is not False
        or value.secrets_retained is not False
    ):
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement cannot contain authority or executable state"
        )

    expected_confirmations, expected_terminal, expected_reverification = (
        _route_confirmation_policy(
            value.classification,
            value.decision,
            value.state,
        )
    )
    if (
        confirmations != expected_confirmations
        or value.terminal_stop is not expected_terminal
        or value.downstream_reverification_required
        is not expected_reverification
    ):
        raise VaultRecoveryAcknowledgementFormatError(
            "acknowledgement differs from the exact presentation route"
        )
    return value


def prepare_recovery_presentation_acknowledgement(
    presentation: VaultRecoveryWorkflowPresentation,
) -> PreparedVaultRecoveryPresentationAcknowledgement:
    """Bind one exact Stage 2.10 presentation for one later acknowledgement."""

    return PreparedVaultRecoveryPresentationAcknowledgement(
        _binding_from_presentation(presentation)
    )
