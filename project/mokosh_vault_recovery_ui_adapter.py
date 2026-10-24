"""Bounded non-mutating UI adapter model for Vault recovery review.

Stage 2.12 turns one exact validated Stage 2.10 presentation into fixed,
ordered UI items and delegates one exact visible confirmation sequence to the
Stage 2.11 acknowledgement lifecycle.  It is a deterministic adapter contract,
not a GUI toolkit implementation and not an operation dispatcher.

The module performs no filesystem access, Vault unlock, recovery rehearsal,
candidate creation, recovery setup, publish, retry, repair, cleanup, callback,
executor, mutation, GUI work, network access, telemetry, logging, clock access,
randomness, update discovery, download, or installation.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from typing import Any

from mokosh_vault_recovery_acknowledgement import (
    PreparedVaultRecoveryPresentationAcknowledgement,
    RecoveryPresentationAcknowledgementState,
    VaultRecoveryAcknowledgementError,
    VaultRecoveryPresentationAcknowledgementReceipt,
    _binding_from_presentation,
    _route_confirmation_policy,
    _validate_acknowledgement_receipt,
    prepare_recovery_presentation_acknowledgement as _prepare_acknowledgement,
)
from mokosh_vault_recovery_presentation import (
    MAX_PRESENTATION_CONFIRMATIONS,
    MAX_PRESENTATION_MESSAGE_KEYS,
    RecoveryPresentationConfirmationKey,
    RecoveryPresentationMessageKey,
    VaultRecoveryPresentationError,
    VaultRecoveryWorkflowPresentation,
    _presentation_components,
    _validate_presentation,
)
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowState,
)


RECOVERY_UI_ADAPTER_FORMAT = "MOKOSH_VAULT_RECOVERY_UI_ADAPTER"
RECOVERY_UI_ADAPTER_VERSION = 1
RECOVERY_UI_ADAPTER_PRESENTATION_SHA256_LEN = 32
RECOVERY_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE = 1


class VaultRecoveryUIAdapterError(ValueError):
    """Base class for strict Stage 2.12 adapter failures."""


class VaultRecoveryUIAdapterPresentationError(VaultRecoveryUIAdapterError):
    """The supplied Stage 2.10 presentation is malformed or unsupported."""


class VaultRecoveryUIAdapterInteractionError(VaultRecoveryUIAdapterError):
    """Visible confirmation events are incomplete, hidden, or out of order."""


class VaultRecoveryUIAdapterMismatchError(VaultRecoveryUIAdapterError):
    """The submitted presentation differs from the prepared UI binding."""


class VaultRecoveryUIAdapterReplayError(VaultRecoveryUIAdapterError):
    """The prepared adapter was already consumed or cannot be copied."""


class VaultRecoveryUIAdapterFormatError(VaultRecoveryUIAdapterError):
    """A view, control, event, binding, or receipt violates the fixed schema."""


class RecoveryUIAdapterState(str, Enum):
    """Process-local UI state; neither member grants operation authority."""

    AWAITING_USER_CONFIRMATIONS = "awaiting_user_confirmations"
    ACKNOWLEDGED = "acknowledged"


@_dataclass(frozen=True, slots=True)
class RecoveryUIMessageItem:
    """One fixed localization key at one stable visible ordinal."""

    ordinal: int
    message_key: RecoveryPresentationMessageKey
    is_gate_message: bool
    visible: bool = True
    accessible_label_key_bound: bool = True

    def __post_init__(self) -> None:
        _validate_message_item(self)


@_dataclass(frozen=True, slots=True)
class RecoveryUIConfirmationControl:
    """One required, separately selectable, initially unselected control."""

    ordinal: int
    confirmation_key: RecoveryPresentationConfirmationKey
    visible: bool = True
    required: bool = True
    individually_selectable: bool = True
    default_selected: bool = False
    accessible_label_key_bound: bool = True

    def __post_init__(self) -> None:
        _validate_confirmation_control(self)


@_dataclass(frozen=True, slots=True)
class RecoveryUIConfirmationEvent:
    """Adapter-reported selection for one exact visible confirmation control.

    ``user_initiated`` is a bounded adapter assertion.  It is not biometric
    proof, authentication, a legal consent record, or operation authority.
    """

    ordinal: int
    confirmation_key: RecoveryPresentationConfirmationKey
    visible: bool
    user_selected: bool
    user_initiated: bool

    def __post_init__(self) -> None:
        _validate_confirmation_event_shape(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryUIAdapterView:
    """Fixed view-model data without rendered prose or operation controls."""

    presentation_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    message_items: tuple[RecoveryUIMessageItem, ...]
    confirmation_controls: tuple[RecoveryUIConfirmationControl, ...]
    terminal_stop: bool
    downstream_reverification_required: bool
    adapter_state: RecoveryUIAdapterState = (
        RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
    )
    presentation_validated: bool = True
    fixed_localization_keys_only: bool = True
    all_required_messages_visible: bool = True
    all_confirmation_controls_visible: bool = True
    confirmations_individually_selectable: bool = True
    confirmation_order_fixed: bool = True
    auto_accept_available: bool = False
    operation_controls_included: bool = False
    raw_text_included: bool = False
    operation_authorized: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_UI_ADAPTER_FORMAT
    version: int = RECOVERY_UI_ADAPTER_VERSION

    def __post_init__(self) -> None:
        _validate_adapter_view(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryUIAdapterReceipt:
    """Bounded no-authority evidence of one accepted visible UI sequence."""

    presentation_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    adapter_state: RecoveryUIAdapterState
    acknowledged_confirmations: tuple[RecoveryPresentationConfirmationKey, ...]
    confirmation_count: int
    terminal_stop: bool
    downstream_reverification_required: bool
    acknowledgement_sequence: int = RECOVERY_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE
    presentation_revalidated: bool = True
    ui_view_revalidated: bool = True
    all_required_messages_visible: bool = True
    all_confirmation_controls_visible: bool = True
    confirmation_order_validated: bool = True
    all_confirmations_user_selected: bool = True
    user_initiated_events_reported: bool = True
    stage_2_11_acknowledgement_validated: bool = True
    read_only: bool = True
    auto_accept_used: bool = False
    hidden_confirmation_used: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    gate_invoked: bool = False
    automatic_transition: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_UI_ADAPTER_FORMAT
    version: int = RECOVERY_UI_ADAPTER_VERSION

    def __post_init__(self) -> None:
        _validate_adapter_receipt(self)


@_dataclass(frozen=True, slots=True)
class _UIAdapterBinding:
    presentation_sha256: bytes = _field(repr=False)
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    message_keys: tuple[RecoveryPresentationMessageKey, ...]
    gate_message_keys: tuple[RecoveryPresentationMessageKey, ...]
    required_confirmations: tuple[RecoveryPresentationConfirmationKey, ...]
    terminal_stop: bool
    downstream_reverification_required: bool


class PreparedVaultRecoveryUIAdapter:
    """Process-local adapter allowing exactly one successful UI acknowledgement."""

    __slots__ = (
        "_binding",
        "_view",
        "_acknowledgement",
        "_receipt",
        "_acknowledged",
        "_lock",
    )

    def __init__(
        self,
        binding: _UIAdapterBinding,
        view: VaultRecoveryUIAdapterView,
        acknowledgement: PreparedVaultRecoveryPresentationAcknowledgement,
    ) -> None:
        if (
            type(binding) is not _UIAdapterBinding
            or type(view) is not VaultRecoveryUIAdapterView
            or type(acknowledgement)
            is not PreparedVaultRecoveryPresentationAcknowledgement
        ):
            raise VaultRecoveryUIAdapterFormatError(
                "prepared UI adapter inputs are invalid"
            )
        _validate_adapter_view(view)
        if not _view_matches_binding(view, binding):
            raise VaultRecoveryUIAdapterFormatError(
                "prepared UI view differs from its presentation binding"
            )
        if acknowledgement.required_confirmations != binding.required_confirmations:
            raise VaultRecoveryUIAdapterFormatError(
                "Stage 2.11 acknowledgement differs from the UI binding"
            )
        self._binding = binding
        self._view = view
        self._acknowledgement = acknowledgement
        self._receipt: VaultRecoveryUIAdapterReceipt | None = None
        self._acknowledged = False
        self._lock = _Lock()

    @property
    def view(self) -> VaultRecoveryUIAdapterView:
        return self._view

    @property
    def required_confirmations(
        self,
    ) -> tuple[RecoveryPresentationConfirmationKey, ...]:
        return self._binding.required_confirmations

    @property
    def acknowledged(self) -> bool:
        return self._acknowledged

    @property
    def current_state(self) -> RecoveryUIAdapterState:
        if self._acknowledged:
            return RecoveryUIAdapterState.ACKNOWLEDGED
        return RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS

    @property
    def receipt(self) -> VaultRecoveryUIAdapterReceipt | None:
        return self._receipt

    def acknowledge_visible_once(
        self,
        presentation: VaultRecoveryWorkflowPresentation,
        events: tuple[RecoveryUIConfirmationEvent, ...],
    ) -> VaultRecoveryUIAdapterReceipt:
        """Accept one exact visible ordered UI sequence without invoking a gate."""

        with self._lock:
            if self._acknowledged:
                raise VaultRecoveryUIAdapterReplayError(
                    "recovery UI adapter was already acknowledged"
                )

            observed = _binding_from_source_presentation(presentation)
            if (
                not hmac.compare_digest(
                    observed.presentation_sha256,
                    self._binding.presentation_sha256,
                )
                or observed != self._binding
            ):
                raise VaultRecoveryUIAdapterMismatchError(
                    "presentation differs from the prepared UI adapter"
                )

            _validate_adapter_view(self._view)
            if not _view_matches_binding(self._view, self._binding):
                raise VaultRecoveryUIAdapterMismatchError(
                    "UI view differs from the prepared presentation binding"
                )

            validated_events = _validate_interaction_events(
                events,
                self._binding.required_confirmations,
            )
            confirmations = tuple(
                item.confirmation_key for item in validated_events
            )

            try:
                acknowledgement_receipt = self._acknowledgement.acknowledge_once(
                    presentation,
                    confirmations,
                )
                _validate_acknowledgement_receipt(acknowledgement_receipt)
            except VaultRecoveryAcknowledgementError as exc:
                raise VaultRecoveryUIAdapterMismatchError(
                    "Stage 2.11 acknowledgement rejected the UI binding"
                ) from exc

            if not _acknowledgement_matches_binding(
                acknowledgement_receipt,
                self._binding,
            ):
                raise VaultRecoveryUIAdapterMismatchError(
                    "Stage 2.11 receipt differs from the UI binding"
                )

            receipt = VaultRecoveryUIAdapterReceipt(
                presentation_sha256=self._binding.presentation_sha256,
                classification=self._binding.classification,
                decision=self._binding.decision,
                state=self._binding.state,
                adapter_state=RecoveryUIAdapterState.ACKNOWLEDGED,
                acknowledged_confirmations=confirmations,
                confirmation_count=len(confirmations),
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
            "PreparedVaultRecoveryUIAdapter("
            f"classification={self._binding.classification.value!r}, "
            f"state={self.current_state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryUIAdapterReplayError(
            "prepared recovery UI adapter cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryUIAdapterReplayError(
            "prepared recovery UI adapter cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryUIAdapterReplayError(
            "prepared recovery UI adapter cannot be serialized"
        )


def _validate_source_presentation(
    value: Any,
) -> VaultRecoveryWorkflowPresentation:
    if type(value) is not VaultRecoveryWorkflowPresentation:
        raise VaultRecoveryUIAdapterPresentationError(
            "presentation must be an exact VaultRecoveryWorkflowPresentation"
        )
    try:
        return _validate_presentation(value)
    except VaultRecoveryPresentationError as exc:
        raise VaultRecoveryUIAdapterPresentationError(
            "presentation violates the Stage 2.10 contract"
        ) from exc


def _binding_from_source_presentation(value: Any) -> _UIAdapterBinding:
    validated = _validate_source_presentation(value)
    try:
        acknowledgement_binding = _binding_from_presentation(validated)
    except VaultRecoveryAcknowledgementError as exc:
        raise VaultRecoveryUIAdapterPresentationError(
            "presentation violates the Stage 2.11 binding contract"
        ) from exc
    return _UIAdapterBinding(
        presentation_sha256=acknowledgement_binding.presentation_sha256,
        classification=validated.classification,
        decision=validated.decision,
        state=validated.state,
        message_keys=validated.message_keys,
        gate_message_keys=validated.gate_message_keys,
        required_confirmations=validated.confirmation_requirements,
        terminal_stop=validated.terminal_stop,
        downstream_reverification_required=(
            validated.downstream_reverification_required
        ),
    )


def _validate_message_item(value: Any) -> RecoveryUIMessageItem:
    if type(value) is not RecoveryUIMessageItem:
        raise VaultRecoveryUIAdapterFormatError("UI message item type is invalid")
    if (
        type(value.ordinal) is not int
        or not 1 <= value.ordinal <= MAX_PRESENTATION_MESSAGE_KEYS
        or type(value.message_key) is not RecoveryPresentationMessageKey
        or type(value.is_gate_message) is not bool
        or type(value.visible) is not bool
        or type(value.accessible_label_key_bound) is not bool
        or value.visible is not True
        or value.accessible_label_key_bound is not True
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI message item schema or visibility is invalid"
        )
    return value


def _validate_confirmation_control(
    value: Any,
) -> RecoveryUIConfirmationControl:
    if type(value) is not RecoveryUIConfirmationControl:
        raise VaultRecoveryUIAdapterFormatError(
            "UI confirmation control type is invalid"
        )
    bool_fields = (
        "visible",
        "required",
        "individually_selectable",
        "default_selected",
        "accessible_label_key_bound",
    )
    if (
        type(value.ordinal) is not int
        or not 1 <= value.ordinal <= MAX_PRESENTATION_CONFIRMATIONS
        or type(value.confirmation_key) is not RecoveryPresentationConfirmationKey
        or any(type(getattr(value, name)) is not bool for name in bool_fields)
        or value.visible is not True
        or value.required is not True
        or value.individually_selectable is not True
        or value.default_selected is not False
        or value.accessible_label_key_bound is not True
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI confirmation control schema is invalid"
        )
    return value


def _validate_confirmation_event_shape(
    value: Any,
) -> RecoveryUIConfirmationEvent:
    if type(value) is not RecoveryUIConfirmationEvent:
        raise VaultRecoveryUIAdapterInteractionError(
            "UI confirmation event type is invalid"
        )
    if (
        type(value.ordinal) is not int
        or not 1 <= value.ordinal <= MAX_PRESENTATION_CONFIRMATIONS
        or type(value.confirmation_key) is not RecoveryPresentationConfirmationKey
        or type(value.visible) is not bool
        or type(value.user_selected) is not bool
        or type(value.user_initiated) is not bool
    ):
        raise VaultRecoveryUIAdapterInteractionError(
            "UI confirmation event schema is invalid"
        )
    return value


def _message_items(
    message_keys: tuple[RecoveryPresentationMessageKey, ...],
    gate_keys: tuple[RecoveryPresentationMessageKey, ...],
) -> tuple[RecoveryUIMessageItem, ...]:
    return tuple(
        RecoveryUIMessageItem(
            ordinal=index,
            message_key=key,
            is_gate_message=key in gate_keys,
        )
        for index, key in enumerate(message_keys, start=1)
    )


def _confirmation_controls(
    keys: tuple[RecoveryPresentationConfirmationKey, ...],
) -> tuple[RecoveryUIConfirmationControl, ...]:
    return tuple(
        RecoveryUIConfirmationControl(ordinal=index, confirmation_key=key)
        for index, key in enumerate(keys, start=1)
    )


def _expected_route(
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
    try:
        return _presentation_components(
            classification,
            decision,
            state,
            terminal_stop,
            downstream_reverification_required,
        )
    except VaultRecoveryPresentationError as exc:
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter route is invalid"
        ) from exc


def _validate_adapter_view(value: Any) -> VaultRecoveryUIAdapterView:
    if type(value) is not VaultRecoveryUIAdapterView:
        raise VaultRecoveryUIAdapterFormatError("UI adapter view type is invalid")
    if (
        value.format != RECOVERY_UI_ADAPTER_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_UI_ADAPTER_VERSION
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.classification) is not RecoveryPublishClassification
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
        or type(value.adapter_state) is not RecoveryUIAdapterState
        or value.adapter_state
        is not RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
    ):
        raise VaultRecoveryUIAdapterFormatError("UI adapter view schema is invalid")

    if (
        type(value.message_items) is not tuple
        or not 1 <= len(value.message_items) <= MAX_PRESENTATION_MESSAGE_KEYS
        or any(type(item) is not RecoveryUIMessageItem for item in value.message_items)
        or type(value.confirmation_controls) is not tuple
        or not 1
        <= len(value.confirmation_controls)
        <= MAX_PRESENTATION_CONFIRMATIONS
        or any(
            type(item) is not RecoveryUIConfirmationControl
            for item in value.confirmation_controls
        )
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter view items are invalid"
        )
    for item in value.message_items:
        _validate_message_item(item)
    for item in value.confirmation_controls:
        _validate_confirmation_control(item)

    bool_fields = (
        "terminal_stop",
        "downstream_reverification_required",
        "presentation_validated",
        "fixed_localization_keys_only",
        "all_required_messages_visible",
        "all_confirmation_controls_visible",
        "confirmations_individually_selectable",
        "confirmation_order_fixed",
        "auto_accept_available",
        "operation_controls_included",
        "raw_text_included",
        "operation_authorized",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter view safety flags must be exact booleans"
        )
    if (
        value.presentation_validated is not True
        or value.fixed_localization_keys_only is not True
        or value.all_required_messages_visible is not True
        or value.all_confirmation_controls_visible is not True
        or value.confirmations_individually_selectable is not True
        or value.confirmation_order_fixed is not True
        or value.auto_accept_available is not False
        or value.operation_controls_included is not False
        or value.raw_text_included is not False
        or value.operation_authorized is not False
        or value.secrets_retained is not False
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter view contains hidden, automatic, or authoritative state"
        )

    expected_messages, expected_gates, expected_confirmations = _expected_route(
        value.classification,
        value.decision,
        value.state,
        value.terminal_stop,
        value.downstream_reverification_required,
    )
    observed_messages = tuple(item.message_key for item in value.message_items)
    observed_gates = tuple(
        item.message_key for item in value.message_items if item.is_gate_message
    )
    observed_confirmations = tuple(
        item.confirmation_key for item in value.confirmation_controls
    )
    if (
        observed_messages != expected_messages
        or observed_gates != expected_gates
        or observed_confirmations != expected_confirmations
        or tuple(item.ordinal for item in value.message_items)
        != tuple(range(1, len(value.message_items) + 1))
        or tuple(item.ordinal for item in value.confirmation_controls)
        != tuple(range(1, len(value.confirmation_controls) + 1))
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter items differ from the exact ordered route"
        )
    return value


def _view_matches_binding(
    view: VaultRecoveryUIAdapterView,
    binding: _UIAdapterBinding,
) -> bool:
    return (
        hmac.compare_digest(
            view.presentation_sha256,
            binding.presentation_sha256,
        )
        and view.classification is binding.classification
        and view.decision is binding.decision
        and view.state is binding.state
        and tuple(item.message_key for item in view.message_items)
        == binding.message_keys
        and tuple(
            item.message_key for item in view.message_items if item.is_gate_message
        )
        == binding.gate_message_keys
        and tuple(
            item.confirmation_key for item in view.confirmation_controls
        )
        == binding.required_confirmations
        and view.terminal_stop is binding.terminal_stop
        and view.downstream_reverification_required
        is binding.downstream_reverification_required
    )


def _validate_interaction_events(
    value: Any,
    expected: tuple[RecoveryPresentationConfirmationKey, ...],
) -> tuple[RecoveryUIConfirmationEvent, ...]:
    if (
        type(value) is not tuple
        or len(value) != len(expected)
        or not 1 <= len(value) <= MAX_PRESENTATION_CONFIRMATIONS
        or any(type(item) is not RecoveryUIConfirmationEvent for item in value)
    ):
        raise VaultRecoveryUIAdapterInteractionError(
            "UI confirmation events must be one exact bounded tuple"
        )
    for index, (event, required_key) in enumerate(
        zip(value, expected, strict=True),
        start=1,
    ):
        _validate_confirmation_event_shape(event)
        if (
            event.ordinal != index
            or event.confirmation_key is not required_key
            or event.visible is not True
            or event.user_selected is not True
            or event.user_initiated is not True
        ):
            raise VaultRecoveryUIAdapterInteractionError(
                "every required confirmation must be visible and selected in order"
            )
    return value


def _acknowledgement_matches_binding(
    receipt: VaultRecoveryPresentationAcknowledgementReceipt,
    binding: _UIAdapterBinding,
) -> bool:
    return (
        type(receipt) is VaultRecoveryPresentationAcknowledgementReceipt
        and hmac.compare_digest(
            receipt.presentation_sha256,
            binding.presentation_sha256,
        )
        and receipt.classification is binding.classification
        and receipt.decision is binding.decision
        and receipt.state is binding.state
        and receipt.acknowledgement_state
        is RecoveryPresentationAcknowledgementState.ACKNOWLEDGED
        and receipt.acknowledged_confirmations == binding.required_confirmations
        and receipt.confirmation_count == len(binding.required_confirmations)
        and receipt.terminal_stop is binding.terminal_stop
        and receipt.downstream_reverification_required
        is binding.downstream_reverification_required
        and receipt.operation_performed is False
        and receipt.operation_authorized is False
        and receipt.gate_invoked is False
        and receipt.automatic_transition is False
        and receipt.secrets_retained is False
    )


def _validate_adapter_receipt(
    value: Any,
) -> VaultRecoveryUIAdapterReceipt:
    if type(value) is not VaultRecoveryUIAdapterReceipt:
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt type is invalid"
        )
    if (
        value.format != RECOVERY_UI_ADAPTER_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_UI_ADAPTER_VERSION
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.classification) is not RecoveryPublishClassification
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
        or type(value.adapter_state) is not RecoveryUIAdapterState
        or value.adapter_state is not RecoveryUIAdapterState.ACKNOWLEDGED
        or type(value.confirmation_count) is not int
        or type(value.acknowledgement_sequence) is not int
        or value.acknowledgement_sequence
        != RECOVERY_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt schema is invalid"
        )
    if (
        type(value.acknowledged_confirmations) is not tuple
        or not 1
        <= len(value.acknowledged_confirmations)
        <= MAX_PRESENTATION_CONFIRMATIONS
        or any(
            type(item) is not RecoveryPresentationConfirmationKey
            for item in value.acknowledged_confirmations
        )
        or len(set(value.acknowledged_confirmations))
        != len(value.acknowledged_confirmations)
        or value.confirmation_count != len(value.acknowledged_confirmations)
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt confirmations are invalid"
        )

    bool_fields = (
        "terminal_stop",
        "downstream_reverification_required",
        "presentation_revalidated",
        "ui_view_revalidated",
        "all_required_messages_visible",
        "all_confirmation_controls_visible",
        "confirmation_order_validated",
        "all_confirmations_user_selected",
        "user_initiated_events_reported",
        "stage_2_11_acknowledgement_validated",
        "read_only",
        "auto_accept_used",
        "hidden_confirmation_used",
        "operation_performed",
        "operation_authorized",
        "gate_invoked",
        "automatic_transition",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt safety flags must be exact booleans"
        )
    required_true = (
        value.presentation_revalidated,
        value.ui_view_revalidated,
        value.all_required_messages_visible,
        value.all_confirmation_controls_visible,
        value.confirmation_order_validated,
        value.all_confirmations_user_selected,
        value.user_initiated_events_reported,
        value.stage_2_11_acknowledgement_validated,
        value.read_only,
    )
    required_false = (
        value.auto_accept_used,
        value.hidden_confirmation_used,
        value.operation_performed,
        value.operation_authorized,
        value.gate_invoked,
        value.automatic_transition,
        value.secrets_retained,
    )
    if any(item is not True for item in required_true) or any(
        item is not False for item in required_false
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt contains hidden, automatic, or authoritative state"
        )

    try:
        expected, terminal, reverification = _route_confirmation_policy(
            value.classification,
            value.decision,
            value.state,
        )
    except VaultRecoveryAcknowledgementError as exc:
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt route is invalid"
        ) from exc
    if (
        value.acknowledged_confirmations != expected
        or value.terminal_stop is not terminal
        or value.downstream_reverification_required is not reverification
    ):
        raise VaultRecoveryUIAdapterFormatError(
            "UI adapter receipt differs from the exact route"
        )
    return value


def prepare_recovery_ui_adapter(
    presentation: VaultRecoveryWorkflowPresentation,
) -> PreparedVaultRecoveryUIAdapter:
    """Create one fixed UI view and a private Stage 2.11 acknowledgement."""

    binding = _binding_from_source_presentation(presentation)
    acknowledgement = _prepare_acknowledgement(presentation)
    view = VaultRecoveryUIAdapterView(
        presentation_sha256=binding.presentation_sha256,
        classification=binding.classification,
        decision=binding.decision,
        state=binding.state,
        message_items=_message_items(
            binding.message_keys,
            binding.gate_message_keys,
        ),
        confirmation_controls=_confirmation_controls(
            binding.required_confirmations
        ),
        terminal_stop=binding.terminal_stop,
        downstream_reverification_required=(
            binding.downstream_reverification_required
        ),
    )
    return PreparedVaultRecoveryUIAdapter(binding, view, acknowledgement)
