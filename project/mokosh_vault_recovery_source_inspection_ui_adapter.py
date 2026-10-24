"""Bounded UI adapter core for exact Stage 2.33 inspection presentation.

The adapter creates fixed ordered message items and default-unselected
confirmation controls, then delegates one exact adapter-reported interaction
sequence to a private Stage 2.34 acknowledgement.  It is a pure view-model and
interaction contract, not a GUI toolkit, renderer, consent mechanism, source
reader, recovery operation, or authorization dispatcher.

Visibility, selection, and user-initiation values are adapter assertions.  They
do not prove physical rendering, accessibility conformance, human
understanding, user identity, informed consent, or operation authority.
"""

from __future__ import annotations

import hmac as _hmac
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_acknowledgement import (
    PreparedVaultRecoverySourceInspectionAcknowledgement,
    RecoverySourceInspectionAcknowledgementState,
    VaultRecoverySourceInspectionAcknowledgementError,
    VaultRecoverySourceInspectionAcknowledgementReceipt,
    _binding_from_presentation as _acknowledgement_binding_from_presentation,
    _validate_acknowledgement_binding,
    _validate_source_inspection_acknowledgement_receipt,
    prepare_recovery_source_inspection_acknowledgement as _prepare_acknowledgement,
)
from mokosh_vault_recovery_source_inspection_presentation import (
    RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT,
    RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT,
    RecoverySourceInspectionPresentationConfirmationKey,
    RecoverySourceInspectionPresentationMessageKey,
    VaultRecoverySourceInspectionPresentation,
    _validate_source_inspection_presentation,
)


RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_UI_ADAPTER"
)
RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION = 1
RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN = 32
RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE = 1

_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)
_MESSAGE_KEYS = (
    RecoverySourceInspectionPresentationMessageKey.INSPECTION_COMPLETED,
    RecoverySourceInspectionPresentationMessageKey.HEADER_STRUCTURALLY_VALIDATED,
    RecoverySourceInspectionPresentationMessageKey.CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED,
    RecoverySourceInspectionPresentationMessageKey.RECOVERY_SECRET_NOT_RECEIVED,
    RecoverySourceInspectionPresentationMessageKey.FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationMessageKey.NO_RECOVERY_PERFORMED,
    RecoverySourceInspectionPresentationMessageKey.NO_OPERATION_AUTHORIZED,
)
_REQUIRED_CONFIRMATIONS = (
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
)
_TERMINAL_FAILURE = object()


class VaultRecoverySourceInspectionUIAdapterError(ValueError):
    """Base class for strict Stage 2.35 adapter failures."""


class VaultRecoverySourceInspectionUIAdapterPresentationError(
    VaultRecoverySourceInspectionUIAdapterError
):
    """The supplied exact Stage 2.33 presentation is invalid."""


class VaultRecoverySourceInspectionUIAdapterInteractionError(
    VaultRecoverySourceInspectionUIAdapterError
):
    """The adapter-reported interaction tuple is invalid."""


class VaultRecoverySourceInspectionUIAdapterMismatchError(
    VaultRecoverySourceInspectionUIAdapterError
):
    """A presentation, view, or private acknowledgement binding differs."""


class VaultRecoverySourceInspectionUIAdapterReplayError(
    VaultRecoverySourceInspectionUIAdapterError
):
    """The adapter is terminal or cannot be duplicated."""


class VaultRecoverySourceInspectionUIAdapterFormatError(
    VaultRecoverySourceInspectionUIAdapterError
):
    """An adapter object violates the frozen Stage 2.35 schema."""


class RecoverySourceInspectionUIAdapterState(str, Enum):
    """Process-local adapter state; no member grants operation authority."""

    AWAITING_USER_CONFIRMATIONS = "awaiting_user_confirmations"
    ACKNOWLEDGED = "acknowledged"
    FAILED_CLOSED = "failed_closed"


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionUIMessageItem:
    """One fixed localization key at one stable required ordinal."""

    ordinal: int
    message_key: RecoverySourceInspectionPresentationMessageKey
    visible: bool = True
    accessible_label_key_bound: bool = True

    def __post_init__(self) -> None:
        _validate_message_item(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionUIConfirmationControl:
    """One separate required and initially unselected confirmation control."""

    ordinal: int
    confirmation_key: RecoverySourceInspectionPresentationConfirmationKey
    visible: bool = True
    required: bool = True
    individually_selectable: bool = True
    default_selected: bool = False
    select_all_available: bool = False
    accessible_label_key_bound: bool = True

    def __post_init__(self) -> None:
        _validate_confirmation_control(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionUIConfirmationEvent:
    """One adapter assertion for an exact confirmation control."""

    ordinal: int
    confirmation_key: RecoverySourceInspectionPresentationConfirmationKey
    visible: bool
    user_selected: bool
    user_initiated: bool

    def __post_init__(self) -> None:
        _validate_confirmation_event_shape(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionUIAdapterView:
    """Fixed key-only view model without rendered prose or capabilities."""

    presentation_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    message_items: tuple[RecoverySourceInspectionUIMessageItem, ...]
    confirmation_controls: tuple[
        RecoverySourceInspectionUIConfirmationControl, ...
    ]
    adapter_state: RecoverySourceInspectionUIAdapterState = (
        RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
    )
    presentation_validated: bool = True
    fixed_localization_keys_only: bool = True
    all_required_messages_visible: bool = True
    all_confirmation_controls_visible: bool = True
    confirmations_individually_selectable: bool = True
    confirmation_order_fixed: bool = True
    all_controls_default_unselected: bool = True
    process_local: bool = True
    physical_gui_rendering_proven: bool = False
    accessibility_conformance_proven: bool = False
    auto_accept_available: bool = False
    select_all_available: bool = False
    remembered_selection_used: bool = False
    raw_text_included: bool = False
    operation_controls_included: bool = False
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    operation_authorized: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION

    def __post_init__(self) -> None:
        _validate_adapter_view(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter view cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter view cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter view cannot be serialized"
        )


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionUIAdapterReceipt:
    """Bounded no-authority evidence of one accepted adapter event tuple."""

    presentation_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    adapter_state: RecoverySourceInspectionUIAdapterState
    acknowledged_confirmations: tuple[
        RecoverySourceInspectionPresentationConfirmationKey, ...
    ]
    confirmation_count: int
    acknowledgement_sequence: int = (
        RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE
    )
    presentation_revalidated: bool = True
    ui_view_revalidated: bool = True
    all_required_messages_visible_reported: bool = True
    all_confirmation_controls_visible_reported: bool = True
    confirmation_order_validated: bool = True
    all_confirmations_user_selected_reported: bool = True
    user_initiated_events_reported: bool = True
    stage2_34_acknowledgement_validated: bool = True
    read_only: bool = True
    process_local: bool = True
    ui_event_claims_are_adapter_assertions: bool = True
    actual_gui_rendering_proven: bool = False
    accessibility_conformance_proven: bool = False
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    digital_signature_created: bool = False
    source_provenance_proven: bool = False
    cryptographic_authenticity_established: bool = False
    source_freshness_established: bool = False
    recovery_secret_received: bool = False
    recovery_performed: bool = False
    rehearsal_performed: bool = False
    stage2_8_used: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    gate_invoked: bool = False
    automatic_transition: bool = False
    filesystem_access_performed: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    logging_used: bool = False
    gui_used: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION

    def __post_init__(self) -> None:
        _validate_adapter_receipt(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter receipt cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter receipt cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "source inspection UI adapter receipt cannot be serialized"
        )


@_dataclass(frozen=True, slots=True)
class _UIAdapterBinding:
    presentation_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    message_keys: tuple[RecoverySourceInspectionPresentationMessageKey, ...]
    required_confirmations: tuple[
        RecoverySourceInspectionPresentationConfirmationKey, ...
    ]


class PreparedVaultRecoverySourceInspectionUIAdapter:
    """One exact view and one terminal private acknowledgement lifecycle."""

    __slots__ = (
        "_binding",
        "_view",
        "_acknowledgement",
        "_terminal",
        "_lock",
    )

    def __init__(
        self,
        binding: _UIAdapterBinding,
        view: VaultRecoverySourceInspectionUIAdapterView,
        acknowledgement: PreparedVaultRecoverySourceInspectionAcknowledgement,
    ) -> None:
        _validate_adapter_binding(binding)
        if type(view) is not VaultRecoverySourceInspectionUIAdapterView:
            raise VaultRecoverySourceInspectionUIAdapterFormatError(
                "source inspection UI adapter view type is invalid"
            )
        _validate_adapter_view(view)
        if not _view_matches_binding(view, binding):
            raise VaultRecoverySourceInspectionUIAdapterFormatError(
                "source inspection UI view differs from its binding"
            )
        if type(acknowledgement) is not PreparedVaultRecoverySourceInspectionAcknowledgement:
            raise VaultRecoverySourceInspectionUIAdapterFormatError(
                "private Stage 2.34 acknowledgement type is invalid"
            )
        try:
            private_binding = acknowledgement._binding
            _validate_acknowledgement_binding(private_binding)
        except Exception:
            raise VaultRecoverySourceInspectionUIAdapterFormatError(
                "private Stage 2.34 acknowledgement binding is invalid"
            ) from None
        if (
            not _hmac.compare_digest(
                private_binding.presentation_sha256,
                binding.presentation_sha256,
            )
            or private_binding.locale is not binding.locale
            or private_binding.required_confirmations
            != binding.required_confirmations
            or acknowledgement.required_confirmations
            != binding.required_confirmations
            or acknowledgement.current_state
            is not RecoverySourceInspectionAcknowledgementState.AWAITING_CONFIRMATIONS
            or acknowledgement.acknowledged is not False
            or acknowledgement.receipt is not None
        ):
            raise VaultRecoverySourceInspectionUIAdapterFormatError(
                "private Stage 2.34 acknowledgement differs from the UI binding"
            )
        self._binding = binding
        self._view = view
        self._acknowledgement = acknowledgement
        self._terminal: (
            object | VaultRecoverySourceInspectionUIAdapterReceipt | None
        ) = None
        self._lock = _Lock()

    @property
    def view(self) -> VaultRecoverySourceInspectionUIAdapterView:
        return self._view

    @property
    def required_confirmations(
        self,
    ) -> tuple[RecoverySourceInspectionPresentationConfirmationKey, ...]:
        return self._binding.required_confirmations

    @property
    def terminal(self) -> bool:
        return self._terminal is not None

    @property
    def acknowledged(self) -> bool:
        return type(self._terminal) is VaultRecoverySourceInspectionUIAdapterReceipt

    @property
    def current_state(self) -> RecoverySourceInspectionUIAdapterState:
        if self._terminal is None:
            return RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
        if self._terminal is _TERMINAL_FAILURE:
            return RecoverySourceInspectionUIAdapterState.FAILED_CLOSED
        if type(self._terminal) is VaultRecoverySourceInspectionUIAdapterReceipt:
            return RecoverySourceInspectionUIAdapterState.ACKNOWLEDGED
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter terminal marker is invalid"
        )

    @property
    def receipt(self) -> VaultRecoverySourceInspectionUIAdapterReceipt | None:
        if type(self._terminal) is VaultRecoverySourceInspectionUIAdapterReceipt:
            return self._terminal
        return None

    def acknowledge_visible_once(
        self,
        presentation: VaultRecoverySourceInspectionPresentation,
        events: tuple[RecoverySourceInspectionUIConfirmationEvent, ...],
    ) -> VaultRecoverySourceInspectionUIAdapterReceipt:
        """Delegate one exact adapter event tuple without granting authority."""

        with self._lock:
            if self._terminal is not None:
                raise VaultRecoverySourceInspectionUIAdapterReplayError(
                    "source inspection UI adapter is terminal"
                )

            observed = _binding_from_source_presentation(presentation)
            if not _bindings_match(observed, self._binding):
                raise VaultRecoverySourceInspectionUIAdapterMismatchError(
                    "presentation differs from the prepared UI adapter"
                )

            _validate_adapter_view(self._view)
            if not _view_matches_binding(self._view, self._binding):
                raise VaultRecoverySourceInspectionUIAdapterMismatchError(
                    "UI view differs from the prepared presentation binding"
                )

            validated_events = _validate_interaction_events(
                events,
                self._binding.required_confirmations,
            )
            confirmations = tuple(
                event.confirmation_key for event in validated_events
            )

            # From this point, every outcome is terminal fail-closed.  This
            # prevents a consumed private acknowledgement from coexisting with
            # an outer adapter that appears fresh after interruption.
            self._terminal = _TERMINAL_FAILURE
            try:
                acknowledgement_receipt = self._acknowledgement.acknowledge_once(
                    presentation,
                    confirmations,
                )
                _validate_source_inspection_acknowledgement_receipt(
                    acknowledgement_receipt
                )
            except VaultRecoverySourceInspectionAcknowledgementError as exc:
                raise VaultRecoverySourceInspectionUIAdapterMismatchError(
                    "private Stage 2.34 acknowledgement rejected the UI binding"
                ) from exc

            if (
                self._acknowledgement.current_state
                is not RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED
                or self._acknowledgement.acknowledged is not True
                or self._acknowledgement.receipt is not acknowledgement_receipt
                or not _acknowledgement_matches_binding(
                    acknowledgement_receipt,
                    self._binding,
                )
            ):
                raise VaultRecoverySourceInspectionUIAdapterMismatchError(
                    "private Stage 2.34 terminal receipt differs from the UI binding"
                )

            receipt = VaultRecoverySourceInspectionUIAdapterReceipt(
                presentation_sha256=self._binding.presentation_sha256,
                locale=self._binding.locale,
                adapter_state=RecoverySourceInspectionUIAdapterState.ACKNOWLEDGED,
                acknowledged_confirmations=confirmations,
                confirmation_count=len(confirmations),
            )
            self._terminal = receipt
            return receipt

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionUIAdapter("
            f"locale={self._binding.locale.value!r}, "
            f"state={self.current_state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "prepared source inspection UI adapter cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "prepared source inspection UI adapter cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionUIAdapterReplayError(
            "prepared source inspection UI adapter cannot be serialized"
        )


def _validate_source_presentation(
    value: _Any,
) -> VaultRecoverySourceInspectionPresentation:
    if type(value) is not VaultRecoverySourceInspectionPresentation:
        raise VaultRecoverySourceInspectionUIAdapterPresentationError(
            "presentation type is invalid"
        )
    try:
        _validate_source_inspection_presentation(value)
    except Exception:
        raise VaultRecoverySourceInspectionUIAdapterPresentationError(
            "presentation violates the Stage 2.33 contract"
        ) from None
    return value


def _binding_from_source_presentation(value: _Any) -> _UIAdapterBinding:
    exact = _validate_source_presentation(value)
    try:
        acknowledgement_binding = _acknowledgement_binding_from_presentation(
            exact
        )
    except VaultRecoverySourceInspectionAcknowledgementError:
        raise VaultRecoverySourceInspectionUIAdapterPresentationError(
            "presentation violates the Stage 2.34 binding contract"
        ) from None
    binding = _UIAdapterBinding(
        presentation_sha256=acknowledgement_binding.presentation_sha256,
        locale=exact.locale,
        message_keys=exact.message_keys,
        required_confirmations=exact.confirmation_requirements,
    )
    _validate_adapter_binding(binding)
    return binding


def _validate_adapter_binding(value: _Any) -> None:
    if (
        type(value) is not _UIAdapterBinding
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.message_keys) is not tuple
        or value.message_keys != _MESSAGE_KEYS
        or any(
            type(item) is not RecoverySourceInspectionPresentationMessageKey
            for item in value.message_keys
        )
        or type(value.required_confirmations) is not tuple
        or value.required_confirmations != _REQUIRED_CONFIRMATIONS
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value.required_confirmations
        )
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter binding is invalid"
        )


def _bindings_match(first: _UIAdapterBinding, second: _UIAdapterBinding) -> bool:
    return (
        type(first) is _UIAdapterBinding
        and type(second) is _UIAdapterBinding
        and _hmac.compare_digest(
            first.presentation_sha256,
            second.presentation_sha256,
        )
        and first.locale is second.locale
        and first.message_keys == second.message_keys
        and first.required_confirmations == second.required_confirmations
    )


def _validate_message_item(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionUIMessageItem
        or type(value.ordinal) is not int
        or not 1
        <= value.ordinal
        <= RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or type(value.message_key)
        is not RecoverySourceInspectionPresentationMessageKey
        or value.visible is not True
        or value.accessible_label_key_bound is not True
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI message item is invalid"
        )


def _validate_confirmation_control(value: _Any) -> None:
    required_true = (
        value.visible,
        value.required,
        value.individually_selectable,
        value.accessible_label_key_bound,
    ) if type(value) is RecoverySourceInspectionUIConfirmationControl else ()
    required_false = (
        value.default_selected,
        value.select_all_available,
    ) if type(value) is RecoverySourceInspectionUIConfirmationControl else ()
    if (
        type(value) is not RecoverySourceInspectionUIConfirmationControl
        or type(value.ordinal) is not int
        or not 1
        <= value.ordinal
        <= RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or type(value.confirmation_key)
        is not RecoverySourceInspectionPresentationConfirmationKey
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI confirmation control is invalid"
        )


def _validate_confirmation_event_shape(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionUIConfirmationEvent
        or type(value.ordinal) is not int
        or not 1
        <= value.ordinal
        <= RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or type(value.confirmation_key)
        is not RecoverySourceInspectionPresentationConfirmationKey
        or type(value.visible) is not bool
        or type(value.user_selected) is not bool
        or type(value.user_initiated) is not bool
    ):
        raise VaultRecoverySourceInspectionUIAdapterInteractionError(
            "source inspection UI confirmation event is invalid"
        )


def _message_items() -> tuple[RecoverySourceInspectionUIMessageItem, ...]:
    return tuple(
        RecoverySourceInspectionUIMessageItem(
            ordinal=index,
            message_key=key,
        )
        for index, key in enumerate(_MESSAGE_KEYS, start=1)
    )


def _confirmation_controls(
) -> tuple[RecoverySourceInspectionUIConfirmationControl, ...]:
    return tuple(
        RecoverySourceInspectionUIConfirmationControl(
            ordinal=index,
            confirmation_key=key,
        )
        for index, key in enumerate(_REQUIRED_CONFIRMATIONS, start=1)
    )


def _validate_adapter_view(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionUIAdapterView:
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter view type is invalid"
        )
    required_true = (
        value.presentation_validated,
        value.fixed_localization_keys_only,
        value.all_required_messages_visible,
        value.all_confirmation_controls_visible,
        value.confirmations_individually_selectable,
        value.confirmation_order_fixed,
        value.all_controls_default_unselected,
        value.process_local,
    )
    required_false = (
        value.physical_gui_rendering_proven,
        value.accessibility_conformance_proven,
        value.auto_accept_available,
        value.select_all_available,
        value.remembered_selection_used,
        value.raw_text_included,
        value.operation_controls_included,
        value.human_understanding_proven,
        value.user_identity_verified,
        value.informed_consent_proven,
        value.operation_authorized,
        value.secrets_retained,
    )
    if (
        type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.message_items) is not tuple
        or len(value.message_items)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or any(
            type(item) is not RecoverySourceInspectionUIMessageItem
            for item in value.message_items
        )
        or type(value.confirmation_controls) is not tuple
        or len(value.confirmation_controls)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or any(
            type(item) is not RecoverySourceInspectionUIConfirmationControl
            for item in value.confirmation_controls
        )
        or type(value.adapter_state)
        is not RecoverySourceInspectionUIAdapterState
        or value.adapter_state
        is not RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter view is invalid"
        )
    for item in value.message_items:
        _validate_message_item(item)
    for item in value.confirmation_controls:
        _validate_confirmation_control(item)
    if (
        tuple(item.ordinal for item in value.message_items)
        != tuple(range(1, RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT + 1))
        or tuple(item.message_key for item in value.message_items)
        != _MESSAGE_KEYS
        or tuple(item.ordinal for item in value.confirmation_controls)
        != tuple(
            range(
                1,
                RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT + 1,
            )
        )
        or tuple(
            item.confirmation_key for item in value.confirmation_controls
        )
        != _REQUIRED_CONFIRMATIONS
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter view order is invalid"
        )


def _view_matches_binding(
    view: VaultRecoverySourceInspectionUIAdapterView,
    binding: _UIAdapterBinding,
) -> bool:
    return (
        _hmac.compare_digest(
            view.presentation_sha256,
            binding.presentation_sha256,
        )
        and view.locale is binding.locale
        and tuple(item.message_key for item in view.message_items)
        == binding.message_keys
        and tuple(
            item.confirmation_key for item in view.confirmation_controls
        )
        == binding.required_confirmations
    )


def _validate_interaction_events(
    value: _Any,
    expected: tuple[RecoverySourceInspectionPresentationConfirmationKey, ...],
) -> tuple[RecoverySourceInspectionUIConfirmationEvent, ...]:
    if (
        type(value) is not tuple
        or len(value)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or any(
            type(item) is not RecoverySourceInspectionUIConfirmationEvent
            for item in value
        )
    ):
        raise VaultRecoverySourceInspectionUIAdapterInteractionError(
            "source inspection UI events must be one exact bounded tuple"
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
            raise VaultRecoverySourceInspectionUIAdapterInteractionError(
                "every confirmation must be visible and selected in exact order"
            )
    return value


def _acknowledgement_matches_binding(
    receipt: VaultRecoverySourceInspectionAcknowledgementReceipt,
    binding: _UIAdapterBinding,
) -> bool:
    return (
        type(receipt)
        is VaultRecoverySourceInspectionAcknowledgementReceipt
        and _hmac.compare_digest(
            receipt.presentation_sha256,
            binding.presentation_sha256,
        )
        and receipt.locale is binding.locale
        and receipt.acknowledgement_state
        is RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED
        and receipt.acknowledged_confirmations
        == binding.required_confirmations
        and receipt.confirmation_count
        == RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        and receipt.operation_authorized is False
        and receipt.operation_performed is False
        and receipt.gate_invoked is False
        and receipt.automatic_transition is False
        and receipt.recovery_secret_received is False
        and receipt.recovery_performed is False
    )


def _validate_adapter_receipt(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionUIAdapterReceipt:
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter receipt type is invalid"
        )
    required_true = (
        value.presentation_revalidated,
        value.ui_view_revalidated,
        value.all_required_messages_visible_reported,
        value.all_confirmation_controls_visible_reported,
        value.confirmation_order_validated,
        value.all_confirmations_user_selected_reported,
        value.user_initiated_events_reported,
        value.stage2_34_acknowledgement_validated,
        value.read_only,
        value.process_local,
        value.ui_event_claims_are_adapter_assertions,
    )
    required_false = (
        value.actual_gui_rendering_proven,
        value.accessibility_conformance_proven,
        value.human_understanding_proven,
        value.user_identity_verified,
        value.informed_consent_proven,
        value.digital_signature_created,
        value.source_provenance_proven,
        value.cryptographic_authenticity_established,
        value.source_freshness_established,
        value.recovery_secret_received,
        value.recovery_performed,
        value.rehearsal_performed,
        value.stage2_8_used,
        value.review_session_prepared,
        value.operation_authorized,
        value.operation_performed,
        value.gate_invoked,
        value.automatic_transition,
        value.filesystem_access_performed,
        value.filesystem_mutation_performed,
        value.network_used,
        value.logging_used,
        value.gui_used,
    )
    if (
        type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.adapter_state)
        is not RecoverySourceInspectionUIAdapterState
        or value.adapter_state
        is not RecoverySourceInspectionUIAdapterState.ACKNOWLEDGED
        or type(value.acknowledged_confirmations) is not tuple
        or value.acknowledged_confirmations != _REQUIRED_CONFIRMATIONS
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value.acknowledged_confirmations
        )
        or type(value.confirmation_count) is not int
        or value.confirmation_count
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or type(value.acknowledgement_sequence) is not int
        or value.acknowledgement_sequence
        != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_ACKNOWLEDGEMENT_SEQUENCE
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION
    ):
        raise VaultRecoverySourceInspectionUIAdapterFormatError(
            "source inspection UI adapter receipt is invalid"
        )


def prepare_recovery_source_inspection_ui_adapter(
    presentation: VaultRecoverySourceInspectionPresentation,
) -> PreparedVaultRecoverySourceInspectionUIAdapter:
    """Create one exact key-only view and private Stage 2.34 lifecycle."""

    binding = _binding_from_source_presentation(presentation)
    acknowledgement = _prepare_acknowledgement(presentation)
    view = VaultRecoverySourceInspectionUIAdapterView(
        presentation_sha256=binding.presentation_sha256,
        locale=binding.locale,
        message_items=_message_items(),
        confirmation_controls=_confirmation_controls(),
    )
    return PreparedVaultRecoverySourceInspectionUIAdapter(
        binding,
        view,
        acknowledgement,
    )
