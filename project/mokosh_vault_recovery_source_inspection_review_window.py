"""Isolated local Tk review window for exact Stage 2.33--2.36 data.

Stage 2.37 renders the fixed Stage 2.36 localized view and may report one
exact, ordered, individually selected confirmation sequence to the already
prepared Stage 2.35 adapter.  It does not read a source, receive a secret,
perform recovery, grant authority, start the main GUI, or retain a callback,
executor, path, source byte sequence, or operation capability.

GUI visibility and interaction values are process-local assertions.  They do
not prove physical rendering, accessibility conformance, human understanding,
identity, informed consent, or legal conformity.
"""

from __future__ import annotations

import hmac as _hmac
import tkinter as tk
import unicodedata as _unicodedata
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from tkinter import ttk
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_localization import (
    VaultRecoverySourceInspectionLocalizationError,
    VaultRecoverySourceInspectionLocalizedUIAdapterView,
    _validate_localized_view,
    localize_recovery_source_inspection_ui_adapter_view,
)
from mokosh_vault_recovery_source_inspection_presentation import (
    RecoverySourceInspectionPresentationConfirmationKey,
    VaultRecoverySourceInspectionPresentation,
)
from mokosh_vault_recovery_source_inspection_ui_adapter import (
    PreparedVaultRecoverySourceInspectionUIAdapter,
    RecoverySourceInspectionUIAdapterState,
    RecoverySourceInspectionUIConfirmationEvent,
    VaultRecoverySourceInspectionUIAdapterError,
    VaultRecoverySourceInspectionUIAdapterReceipt,
    _binding_from_source_presentation,
    _validate_adapter_receipt,
    _validate_adapter_view,
    _view_matches_binding,
)


RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW"
)
RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_VERSION = 1
MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_CODEPOINTS = 180
MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_UTF8_LEN = 576

_FORBIDDEN_BIDI_CLASSES = frozenset(
    {"BN", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
)
_FORBIDDEN_TEMPLATE_CHARACTERS = frozenset({"{", "}", "%", "$"})
_TERMINAL_FAILURE = object()


class VaultRecoverySourceInspectionReviewWindowError(ValueError):
    """Base class for strict Stage 2.37 review-window failures."""


class VaultRecoverySourceInspectionReviewWindowSourceError(
    VaultRecoverySourceInspectionReviewWindowError
):
    """An exact Stage 2.33--2.36 source binding is invalid."""


class VaultRecoverySourceInspectionReviewWindowInteractionError(
    VaultRecoverySourceInspectionReviewWindowError
):
    """A visible ordered individual interaction requirement was not met."""


class VaultRecoverySourceInspectionReviewWindowStateError(
    VaultRecoverySourceInspectionReviewWindowError
):
    """The process-local review controller is terminal or duplicated."""


class VaultRecoverySourceInspectionReviewWindowDisplayError(
    VaultRecoverySourceInspectionReviewWindowError
):
    """The local Tk child window could not be safely displayed."""


class VaultRecoverySourceInspectionReviewWindowFormatError(
    VaultRecoverySourceInspectionReviewWindowError
):
    """A Stage 2.37 bounded record violates its frozen schema."""


class RecoverySourceInspectionReviewWindowState(str, Enum):
    """Process-local lifecycle; no member grants operation authority."""

    AWAITING_VISIBLE_REVIEW = "awaiting_visible_review"
    ACKNOWLEDGED = "acknowledged"
    CANCELLED = "cancelled"
    FAILED_CLOSED = "failed_closed"


class RecoverySourceInspectionReviewWindowDecision(str, Enum):
    """Bounded terminal decision of one local review controller."""

    ACKNOWLEDGED = "acknowledged"
    CANCELLED = "cancelled"


class RecoverySourceInspectionReviewWindowCancelReason(str, Enum):
    """Exact non-authoritative local cancellation routes."""

    CANCEL_BUTTON = "cancel_button"
    ESCAPE_KEY = "escape_key"
    WINDOW_CLOSE = "window_close"


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionReviewWindowText:
    """Fixed, reviewed window chrome for one already-bound locale."""

    locale: RecoveryLocalizationLocale
    title: str
    introduction: str
    confirmations_heading: str
    confirm_button: str
    cancel_button: str

    def __post_init__(self) -> None:
        _validate_window_text(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review-window text cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review-window text cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review-window text cannot be serialized"
        )


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionReviewWindowOutcome:
    """Bounded result without text, source material, secret, or capability."""

    locale: RecoveryLocalizationLocale
    presentation_sha256: bytes = _field(repr=False)
    decision: RecoverySourceInspectionReviewWindowDecision
    cancel_reason: RecoverySourceInspectionReviewWindowCancelReason | None
    acknowledgement_receipt: VaultRecoverySourceInspectionUIAdapterReceipt | None = (
        _field(repr=False)
    )
    messages_visible_reported: bool
    confirmation_count: int
    read_only: bool = True
    process_local: bool = True
    individual_default_false_confirmations: bool = True
    ui_event_claims_are_process_local_assertions: bool = True
    actual_gui_rendering_proven: bool = False
    accessibility_conformance_proven: bool = False
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    select_all_used: bool = False
    remembered_selection_used: bool = False
    auto_accept_used: bool = False
    operation_controls_included: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    secrets_retained: bool = False
    source_material_retained: bool = False
    callbacks_or_executors_retained: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_VERSION

    def __post_init__(self) -> None:
        _validate_outcome(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review outcome cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review outcome cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "source inspection review outcome cannot be serialized"
        )


def _validate_plain_window_text(value: _Any, field_name: str) -> str:
    if type(value) is not str:
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            f"{field_name} must be fixed plain text"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            f"{field_name} must be valid UTF-8 text"
        ) from exc
    if (
        not 1 <= len(value) <= MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_CODEPOINTS
        or len(encoded) > MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_UTF8_LEN
        or value != value.strip()
        or value != _unicodedata.normalize("NFC", value)
        or any(character in value for character in _FORBIDDEN_TEMPLATE_CHARACTERS)
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            f"{field_name} is outside the fixed text policy"
        )
    if any(
        _unicodedata.category(character).startswith("C")
        or _unicodedata.bidirectional(character) in _FORBIDDEN_BIDI_CLASSES
        for character in value
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            f"{field_name} contains a forbidden control or bidi character"
        )
    return value


def _validate_window_text(
    value: _Any,
) -> RecoverySourceInspectionReviewWindowText:
    if (
        type(value) is not RecoverySourceInspectionReviewWindowText
        or type(value.locale) is not RecoveryLocalizationLocale
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "source inspection review-window text record is invalid"
        )
    for name in (
        "title",
        "introduction",
        "confirmations_heading",
        "confirm_button",
        "cancel_button",
    ):
        _validate_plain_window_text(getattr(value, name), name)
    return value


_WINDOW_TEXT_REGISTRY = (
    RecoverySourceInspectionReviewWindowText(
        locale=RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        title="MOKOSH — преглед на проверката на източника",
        introduction=(
            "Прегледайте всички съобщения. Отбележете всяко отделно "
            "потвърждение само след като сте го разбрали."
        ),
        confirmations_heading="Задължителни отделни потвърждения",
        confirm_button="Потвърди прегледа",
        cancel_button="Отказ",
    ),
    RecoverySourceInspectionReviewWindowText(
        locale=RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        title="MOKOSH — recovery source inspection review",
        introduction=(
            "Review every message. Select each confirmation separately only "
            "after you understand it."
        ),
        confirmations_heading="Required individual confirmations",
        confirm_button="Acknowledge review",
        cancel_button="Cancel",
    ),
)


def _window_text_for_locale(
    locale: RecoveryLocalizationLocale,
) -> RecoverySourceInspectionReviewWindowText:
    if type(locale) is not RecoveryLocalizationLocale:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "source inspection review locale is invalid"
        )
    for item in _WINDOW_TEXT_REGISTRY:
        _validate_window_text(item)
        if item.locale is locale:
            return item
    raise VaultRecoverySourceInspectionReviewWindowSourceError(
        "source inspection review locale is unsupported"
    )


def _localized_view_matches_adapter(localized: _Any, source_view: _Any) -> bool:
    return (
        _hmac.compare_digest(
            localized.presentation_sha256,
            source_view.presentation_sha256,
        )
        and localized.locale is source_view.locale
        and localized.adapter_state is source_view.adapter_state
        and tuple(
            (item.ordinal, item.message_key, item.visible)
            for item in localized.message_items
        )
        == tuple(
            (item.ordinal, item.message_key, item.visible)
            for item in source_view.message_items
        )
        and tuple(
            (
                item.ordinal,
                item.confirmation_key,
                item.visible,
                item.required,
                item.individually_selectable,
                item.default_selected,
                item.select_all_available,
            )
            for item in localized.confirmation_controls
        )
        == tuple(
            (
                item.ordinal,
                item.confirmation_key,
                item.visible,
                item.required,
                item.individually_selectable,
                item.default_selected,
                item.select_all_available,
            )
            for item in source_view.confirmation_controls
        )
    )


def _validate_outcome(
    value: _Any,
) -> VaultRecoverySourceInspectionReviewWindowOutcome:
    if type(value) is not VaultRecoverySourceInspectionReviewWindowOutcome:
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "source inspection review outcome type is invalid"
        )
    if (
        value.format != RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_VERSION
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.decision) is not RecoverySourceInspectionReviewWindowDecision
        or type(value.messages_visible_reported) is not bool
        or type(value.confirmation_count) is not int
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "source inspection review outcome schema is invalid"
        )
    required_true = (
        value.read_only,
        value.process_local,
        value.individual_default_false_confirmations,
        value.ui_event_claims_are_process_local_assertions,
    )
    required_false = (
        value.actual_gui_rendering_proven,
        value.accessibility_conformance_proven,
        value.human_understanding_proven,
        value.user_identity_verified,
        value.informed_consent_proven,
        value.select_all_used,
        value.remembered_selection_used,
        value.auto_accept_used,
        value.operation_controls_included,
        value.operation_performed,
        value.operation_authorized,
        value.secrets_retained,
        value.source_material_retained,
        value.callbacks_or_executors_retained,
    )
    if (
        any(type(item) is not bool for item in required_true + required_false)
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "source inspection review outcome authority flags are invalid"
        )
    if value.decision is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED:
        if (
            value.cancel_reason is not None
            or type(value.acknowledgement_receipt)
            is not VaultRecoverySourceInspectionUIAdapterReceipt
            or value.messages_visible_reported is not True
            or value.confirmation_count != 3
        ):
            raise VaultRecoverySourceInspectionReviewWindowFormatError(
                "acknowledged source inspection review outcome is incomplete"
            )
        try:
            _validate_adapter_receipt(value.acknowledgement_receipt)
        except VaultRecoverySourceInspectionUIAdapterError as exc:
            raise VaultRecoverySourceInspectionReviewWindowFormatError(
                "source inspection adapter receipt is invalid"
            ) from exc
        if not _hmac.compare_digest(
            value.presentation_sha256,
            value.acknowledgement_receipt.presentation_sha256,
        ):
            raise VaultRecoverySourceInspectionReviewWindowFormatError(
                "source inspection review receipt binding is invalid"
            )
    elif (
        type(value.cancel_reason)
        is not RecoverySourceInspectionReviewWindowCancelReason
        or value.acknowledgement_receipt is not None
        or value.confirmation_count != 0
    ):
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "cancelled source inspection review outcome is invalid"
        )
    return value


class PreparedVaultRecoverySourceInspectionReviewWindow:
    """One exact controller with one atomic terminal marker."""

    __slots__ = (
        "_presentation",
        "_adapter",
        "_localized_view",
        "_window_text",
        "_binding",
        "_selected",
        "_messages_visible",
        "_terminal",
        "_lock",
    )

    def __init__(
        self,
        presentation: VaultRecoverySourceInspectionPresentation,
        adapter: PreparedVaultRecoverySourceInspectionUIAdapter,
        localized_view: VaultRecoverySourceInspectionLocalizedUIAdapterView,
        window_text: RecoverySourceInspectionReviewWindowText,
    ) -> None:
        binding = _validate_review_sources(
            presentation,
            adapter,
            localized_view,
            window_text,
        )
        self._presentation = presentation
        self._adapter = adapter
        self._localized_view = localized_view
        self._window_text = window_text
        self._binding = binding
        self._selected = tuple(False for _ in localized_view.confirmation_controls)
        self._messages_visible = False
        self._terminal: (
            object | VaultRecoverySourceInspectionReviewWindowOutcome | None
        ) = None
        self._lock = _Lock()

    @property
    def localized_view(self) -> VaultRecoverySourceInspectionLocalizedUIAdapterView:
        return self._localized_view

    @property
    def window_text(self) -> RecoverySourceInspectionReviewWindowText:
        return self._window_text

    @property
    def current_state(self) -> RecoverySourceInspectionReviewWindowState:
        if self._terminal is None:
            return RecoverySourceInspectionReviewWindowState.AWAITING_VISIBLE_REVIEW
        if self._terminal is _TERMINAL_FAILURE:
            return RecoverySourceInspectionReviewWindowState.FAILED_CLOSED
        if type(self._terminal) is VaultRecoverySourceInspectionReviewWindowOutcome:
            if (
                self._terminal.decision
                is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED
            ):
                return RecoverySourceInspectionReviewWindowState.ACKNOWLEDGED
            return RecoverySourceInspectionReviewWindowState.CANCELLED
        raise VaultRecoverySourceInspectionReviewWindowFormatError(
            "source inspection review terminal marker is invalid"
        )

    @property
    def confirmation_selections(self) -> tuple[bool, ...]:
        return self._selected

    @property
    def messages_visible(self) -> bool:
        return self._messages_visible

    @property
    def confirm_enabled(self) -> bool:
        return (
            self._terminal is None
            and self._messages_visible is True
            and all(item is True for item in self._selected)
        )

    @property
    def outcome(self) -> VaultRecoverySourceInspectionReviewWindowOutcome | None:
        if type(self._terminal) is VaultRecoverySourceInspectionReviewWindowOutcome:
            return self._terminal
        return None

    def mark_messages_visible_once(self, ordinals: tuple[int, ...]) -> None:
        """Report exact ordered logical rendering once before interaction."""

        with self._lock:
            self._require_open()
            expected = tuple(item.ordinal for item in self._localized_view.message_items)
            if (
                self._messages_visible
                or type(ordinals) is not tuple
                or ordinals != expected
                or any(type(item) is not int for item in ordinals)
            ):
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "visible message ordinals must be reported exactly once in order"
                )
            self._messages_visible = True

    def record_confirmation_selection(
        self,
        ordinal: int,
        confirmation_key: RecoverySourceInspectionPresentationConfirmationKey,
        selected: bool,
    ) -> None:
        """Record one individual default-false control interaction."""

        with self._lock:
            self._require_open()
            if self._messages_visible is not True:
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "confirmations cannot be selected before messages are visible"
                )
            if (
                type(ordinal) is not int
                or type(confirmation_key)
                is not RecoverySourceInspectionPresentationConfirmationKey
                or type(selected) is not bool
                or not 1 <= ordinal <= len(self._selected)
            ):
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "confirmation selection schema is invalid"
                )
            control = self._localized_view.confirmation_controls[ordinal - 1]
            if (
                control.ordinal != ordinal
                or control.confirmation_key is not confirmation_key
            ):
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "confirmation differs from the visible ordered control"
                )
            changed = list(self._selected)
            changed[ordinal - 1] = selected
            self._selected = tuple(changed)

    def acknowledge_visible_once(
        self,
    ) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        """Delegate one exact sequence after an atomic fail-closed boundary."""

        with self._lock:
            self._require_open()
            if not self.confirm_enabled:
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "every visible individual confirmation must be selected"
                )
            _validate_review_sources(
                self._presentation,
                self._adapter,
                self._localized_view,
                self._window_text,
            )
            events = tuple(
                RecoverySourceInspectionUIConfirmationEvent(
                    ordinal=control.ordinal,
                    confirmation_key=control.confirmation_key,
                    visible=True,
                    user_selected=True,
                    user_initiated=True,
                )
                for control in self._localized_view.confirmation_controls
            )

            # Every interruption or failure after this point is terminal.  The
            # inner Stage 2.35 adapter can therefore never be consumed while
            # this outer controller still appears fresh.
            self._terminal = _TERMINAL_FAILURE
            try:
                receipt = self._adapter.acknowledge_visible_once(
                    self._presentation,
                    events,
                )
                _validate_adapter_receipt(receipt)
            except VaultRecoverySourceInspectionUIAdapterError as exc:
                raise VaultRecoverySourceInspectionReviewWindowSourceError(
                    "Stage 2.35 rejected the visible source inspection review"
                ) from exc
            if (
                self._adapter.current_state
                is not RecoverySourceInspectionUIAdapterState.ACKNOWLEDGED
                or self._adapter.receipt is not receipt
                or not _hmac.compare_digest(
                    receipt.presentation_sha256,
                    self._binding.presentation_sha256,
                )
            ):
                raise VaultRecoverySourceInspectionReviewWindowSourceError(
                    "Stage 2.35 terminal receipt differs from the review binding"
                )
            outcome = VaultRecoverySourceInspectionReviewWindowOutcome(
                locale=self._localized_view.locale,
                presentation_sha256=self._localized_view.presentation_sha256,
                decision=RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED,
                cancel_reason=None,
                acknowledgement_receipt=receipt,
                messages_visible_reported=True,
                confirmation_count=len(events),
            )
            self._terminal = outcome
            return outcome

    def cancel_once(
        self,
        reason: RecoverySourceInspectionReviewWindowCancelReason,
    ) -> VaultRecoverySourceInspectionReviewWindowOutcome:
        """Close without consuming the private Stage 2.35 adapter."""

        with self._lock:
            self._require_open()
            if type(reason) is not RecoverySourceInspectionReviewWindowCancelReason:
                raise VaultRecoverySourceInspectionReviewWindowInteractionError(
                    "source inspection review cancellation reason is invalid"
                )
            outcome = VaultRecoverySourceInspectionReviewWindowOutcome(
                locale=self._localized_view.locale,
                presentation_sha256=self._localized_view.presentation_sha256,
                decision=RecoverySourceInspectionReviewWindowDecision.CANCELLED,
                cancel_reason=reason,
                acknowledgement_receipt=None,
                messages_visible_reported=self._messages_visible,
                confirmation_count=0,
            )
            self._terminal = outcome
            return outcome

    def _require_open(self) -> None:
        if self._terminal is not None:
            raise VaultRecoverySourceInspectionReviewWindowStateError(
                "source inspection review controller is terminal"
            )

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionReviewWindow("
            f"locale={self._localized_view.locale.value!r}, "
            f"state={self.current_state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "prepared source inspection review controller cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "prepared source inspection review controller cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionReviewWindowStateError(
            "prepared source inspection review controller cannot be serialized"
        )


def _validate_review_sources(
    presentation: _Any,
    adapter: _Any,
    localized_view: _Any,
    window_text: _Any,
) -> _Any:
    if type(presentation) is not VaultRecoverySourceInspectionPresentation:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "presentation must be exact Stage 2.33 data"
        )
    if type(adapter) is not PreparedVaultRecoverySourceInspectionUIAdapter:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "adapter must be an exact fresh Stage 2.35 adapter"
        )
    if type(localized_view) is not VaultRecoverySourceInspectionLocalizedUIAdapterView:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "localized view must be exact Stage 2.36 data"
        )
    try:
        binding = _binding_from_source_presentation(presentation)
        source_view = adapter.view
        _validate_adapter_view(source_view)
        _validate_localized_view(localized_view)
        _validate_window_text(window_text)
    except (
        VaultRecoverySourceInspectionUIAdapterError,
        VaultRecoverySourceInspectionLocalizationError,
        VaultRecoverySourceInspectionReviewWindowFormatError,
    ) as exc:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "review source violates a frozen Stage 2.33--2.36 contract"
        ) from exc
    if (
        adapter.current_state
        is not RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
        or adapter.acknowledged is not False
        or adapter.receipt is not None
        or not _view_matches_binding(source_view, binding)
        or not _localized_view_matches_adapter(localized_view, source_view)
        or window_text.locale is not localized_view.locale
    ):
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "presentation, adapter, localized view, and bound locale differ"
        )
    return binding


def prepare_recovery_source_inspection_review_window(
    presentation: VaultRecoverySourceInspectionPresentation,
    adapter: PreparedVaultRecoverySourceInspectionUIAdapter,
) -> PreparedVaultRecoverySourceInspectionReviewWindow:
    """Prepare one fresh exact review using only the adapter-bound locale."""

    if type(adapter) is not PreparedVaultRecoverySourceInspectionUIAdapter:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "adapter must be an exact fresh Stage 2.35 adapter"
        )
    try:
        localized = localize_recovery_source_inspection_ui_adapter_view(
            adapter.view
        )
    except VaultRecoverySourceInspectionLocalizationError as exc:
        raise VaultRecoverySourceInspectionReviewWindowSourceError(
            "Stage 2.35 view cannot be localized under Stage 2.36"
        ) from exc
    text = _window_text_for_locale(localized.locale)
    return PreparedVaultRecoverySourceInspectionReviewWindow(
        presentation,
        adapter,
        localized,
        text,
    )


_MIN_REVIEW_MIDDLE_HEIGHT = 80


def _review_widget_rect(widget: _Any) -> tuple[int, int, int, int] | None:
    try:
        if not bool(widget.winfo_ismapped()):
            return None
        width = int(widget.winfo_width())
        height = int(widget.winfo_height())
        left = int(widget.winfo_rootx())
        top = int(widget.winfo_rooty())
    except (AttributeError, TypeError, ValueError, tk.TclError):
        return None
    if width <= 0 or height <= 0:
        return None
    return left, top, left + width, top + height


def _review_layout_regions_visible(
    container: _Any,
    regions: tuple[_Any, _Any, _Any],
    required_controls: tuple[_Any, ...],
) -> bool:
    container_rect = _review_widget_rect(container)
    region_rects = tuple(_review_widget_rect(widget) for widget in regions)
    control_rects = tuple(
        _review_widget_rect(widget) for widget in required_controls
    )
    if (
        container_rect is None
        or any(rect is None for rect in region_rects)
        or any(rect is None for rect in control_rects)
    ):
        return False
    left, top, right, bottom = container_rect
    checked_regions = tuple(rect for rect in region_rects if rect is not None)
    checked_controls = tuple(rect for rect in control_rects if rect is not None)
    if (
        checked_regions[1][3] - checked_regions[1][1]
        < _MIN_REVIEW_MIDDLE_HEIGHT
    ):
        return False
    for rect in (*checked_regions, *checked_controls):
        if (
            rect[0] < left
            or rect[1] < top
            or rect[2] > right
            or rect[3] > bottom
        ):
            return False
    return (
        checked_regions[0][3] <= checked_regions[1][1]
        and checked_regions[1][3] <= checked_regions[2][1]
    )


class _TkRecoverySourceInspectionReviewWindow:
    """Private concrete child widget; policy remains in the controller."""

    _WRAP_MIN = 240
    _WRAP_MAX = 960
    _WRAP_PADDING = 32
    _RESIZE_SETTLE_MS = 125

    def __init__(
        self,
        parent: _Any,
        prepared: PreparedVaultRecoverySourceInspectionReviewWindow,
    ) -> None:
        if type(prepared) is not PreparedVaultRecoverySourceInspectionReviewWindow:
            raise VaultRecoverySourceInspectionReviewWindowDisplayError(
                "prepared source inspection review controller is invalid"
            )
        self._prepared = prepared
        self._outcome: VaultRecoverySourceInspectionReviewWindowOutcome | None = None
        self._error: BaseException | None = None
        self._closed = False
        self._activated = False
        self._resize_validation_after_id: str | None = None
        self._variables: list[_Any] = []
        self._checks: list[_Any] = []
        self._wrapping_widgets: list[_Any] = []

        window = tk.Toplevel(parent)
        self.window = window
        window.title(prepared.window_text.title)
        window.transient(parent)
        window.minsize(560, 440)
        window.resizable(True, True)
        window.protocol(
            "WM_DELETE_WINDOW",
            lambda: self._cancel(
                RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
            ),
        )
        window.bind("<Escape>", self._escape)

        outer = ttk.Frame(window, padding=16)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)
        header = ttk.Label(
            outer,
            text=prepared.window_text.title,
            justify="left",
            anchor="w",
            wraplength=480,
        )
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self._wrapping_widgets.append(header)

        review_frame = ttk.Frame(outer)
        review_frame.grid(row=1, column=0, sticky="nsew")
        canvas = tk.Canvas(review_frame, highlightthickness=0, takefocus=True)
        scrollbar = ttk.Scrollbar(
            review_frame,
            orient="vertical",
            command=canvas.yview,
        )
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        content = ttk.Frame(canvas, padding=(4, 4, 12, 4))
        content_id = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind(
            "<Configure>",
            lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda event: self._resize_content(canvas, content_id, event.width),
        )
        window.bind("<MouseWheel>", self._mousewheel)
        window.bind("<Button-4>", lambda event: self._scroll(canvas, -1))
        window.bind("<Button-5>", lambda event: self._scroll(canvas, 1))
        canvas.bind("<Prior>", lambda event: self._page(canvas, -1))
        canvas.bind("<Next>", lambda event: self._page(canvas, 1))
        canvas.bind("<Home>", lambda event: self._edge(canvas, 0.0))
        canvas.bind("<End>", lambda event: self._edge(canvas, 1.0))
        self._canvas = canvas
        self._content = content

        introduction = ttk.Label(
            content,
            text=prepared.window_text.introduction,
            justify="left",
            anchor="w",
            wraplength=480,
        )
        introduction.pack(fill="x", pady=(0, 12))
        self._wrapping_widgets.append(introduction)

        message_ordinals = []
        for item in prepared.localized_view.message_items:
            message = ttk.Label(
                content,
                text=item.text,
                justify="left",
                anchor="w",
                wraplength=480,
            )
            message.pack(fill="x", pady=(0, 8))
            self._wrapping_widgets.append(message)
            message_ordinals.append(item.ordinal)

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=(4, 12))
        ttk.Label(
            content,
            text=prepared.window_text.confirmations_heading,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        for control in prepared.localized_view.confirmation_controls:
            variable = tk.BooleanVar(master=window, value=False)
            check = tk.Checkbutton(
                content,
                text=control.text,
                variable=variable,
                takefocus=True,
                state="disabled",
                justify="left",
                anchor="w",
                wraplength=480,
                padx=0,
                pady=2,
                command=lambda c=control, v=variable: self._toggle(c, v),
            )
            check.pack(fill="x", anchor="w", pady=(0, 8))
            check.bind(
                "<FocusIn>",
                lambda event, widget=check: self._schedule_focus_reveal(widget),
            )
            self._variables.append(variable)
            self._checks.append(check)
            self._wrapping_widgets.append(check)

        buttons = ttk.Frame(outer)
        buttons.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        self._cancel_button = ttk.Button(
            buttons,
            text=prepared.window_text.cancel_button,
            command=lambda: self._cancel(
                RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
            ),
        )
        self._cancel_button.pack(side="right")
        self._confirm_button = ttk.Button(
            buttons,
            text=prepared.window_text.confirm_button,
            command=self._confirm,
            state="disabled",
        )
        self._confirm_button.pack(side="right", padx=(0, 8))
        self._message_ordinals = tuple(message_ordinals)
        self._header = header
        self._review_frame = review_frame
        self._footer = buttons
        window.bind(
            "<Configure>",
            self._schedule_runtime_layout_validation,
            add="+",
        )

    @property
    def outcome(self) -> VaultRecoverySourceInspectionReviewWindowOutcome | None:
        return self._outcome

    @property
    def error(self) -> BaseException | None:
        return self._error

    def activate(self) -> None:
        try:
            self.window.update_idletasks()
            self.window.wait_visibility()
            self.window.grab_set()
            self.window.after(75, self._finish_activation)
        except BaseException as exc:
            self._error = exc
            self._destroy()

    def _finish_activation(self) -> None:
        if self._closed:
            return
        try:
            self.window.update_idletasks()
            if not _review_layout_regions_visible(
                self.window,
                (self._header, self._canvas, self._footer),
                (self._cancel_button, self._confirm_button),
            ):
                raise VaultRecoverySourceInspectionReviewWindowDisplayError(
                    "required review layout regions are not fully visible"
                )
            self._prepared.mark_messages_visible_once(self._message_ordinals)
            for check in self._checks:
                check.configure(state="normal")
            self._canvas.yview_moveto(0.0)
            self._canvas.focus_set()
            self._activated = True
        except BaseException as exc:
            self._error = exc
            self._destroy()

    def _schedule_runtime_layout_validation(self, event: _Any) -> None:
        if (
            self._closed
            or not self._activated
            or getattr(event, "widget", None) is not self.window
        ):
            return
        pending = self._resize_validation_after_id
        if pending is not None:
            try:
                self.window.after_cancel(pending)
            except tk.TclError:
                pass
        try:
            self._resize_validation_after_id = self.window.after(
                self._RESIZE_SETTLE_MS,
                self._validate_runtime_layout,
            )
        except BaseException as exc:
            self._error = exc
            self._destroy()

    def _validate_runtime_layout(self) -> None:
        self._resize_validation_after_id = None
        if self._closed or not self._activated:
            return
        try:
            self.window.update_idletasks()
            if not _review_layout_regions_visible(
                self.window,
                (self._header, self._canvas, self._footer),
                (self._cancel_button, self._confirm_button),
            ):
                raise VaultRecoverySourceInspectionReviewWindowDisplayError(
                    "required review layout regions became unavailable after resize"
                )
            self._confirm_button.configure(
                state="normal" if self._prepared.confirm_enabled else "disabled"
            )
            focused = self.window.focus_get()
            if focused in self._checks:
                self._reveal_widget(focused)
        except BaseException as exc:
            self._error = exc
            self._destroy()

    def _toggle(self, control: _Any, variable: _Any) -> None:
        if self._closed:
            return
        try:
            self._prepared.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                bool(variable.get()),
            )
            self._confirm_button.configure(
                state="normal" if self._prepared.confirm_enabled else "disabled"
            )
        except BaseException as exc:
            self._error = exc
            self._destroy()

    def _confirm(self) -> str:
        if self._closed or not self._prepared.confirm_enabled:
            return "break"
        try:
            self._outcome = self._prepared.acknowledge_visible_once()
        except BaseException as exc:
            self._error = exc
        self._destroy()
        return "break"

    def _cancel(
        self,
        reason: RecoverySourceInspectionReviewWindowCancelReason,
    ) -> str:
        if self._closed:
            return "break"
        try:
            self._outcome = self._prepared.cancel_once(reason)
        except BaseException as exc:
            self._error = exc
        self._destroy()
        return "break"

    def _escape(self, event: _Any) -> str:
        del event
        return self._cancel(
            RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
        )

    def _mousewheel(self, event: _Any) -> str:
        delta = getattr(event, "delta", 0)
        if delta:
            self._scroll(self._canvas, -1 if delta > 0 else 1)
        return "break"

    def _resize_content(self, canvas: _Any, content_id: _Any, width: int) -> None:
        canvas.itemconfigure(content_id, width=width)
        wraplength = max(
            self._WRAP_MIN,
            min(self._WRAP_MAX, width - self._WRAP_PADDING),
        )
        for widget in self._wrapping_widgets:
            widget.configure(wraplength=wraplength)

    def _schedule_focus_reveal(self, widget: _Any) -> None:
        self.window.after_idle(self._reveal_widget, widget)

    def _reveal_widget(self, widget: _Any) -> None:
        if self._closed:
            return
        self.window.update_idletasks()
        content_height = max(1, int(self._content.winfo_reqheight()))
        viewport_height = max(1, int(self._canvas.winfo_height()))
        visible_top = float(self._canvas.canvasy(0))
        visible_bottom = visible_top + viewport_height
        widget_top = float(widget.winfo_y())
        widget_bottom = widget_top + float(widget.winfo_height())
        if widget_top < visible_top:
            target = widget_top
        elif widget_bottom > visible_bottom:
            target = widget_bottom - viewport_height
        else:
            return
        maximum = max(0.0, float(content_height - viewport_height))
        self._canvas.yview_moveto(max(0.0, min(maximum, target)) / content_height)

    @staticmethod
    def _scroll(canvas: _Any, units: int) -> str:
        canvas.yview_scroll(units, "units")
        return "break"

    @staticmethod
    def _page(canvas: _Any, pages: int) -> str:
        canvas.yview_scroll(pages, "pages")
        return "break"

    @staticmethod
    def _edge(canvas: _Any, fraction: float) -> str:
        canvas.yview_moveto(fraction)
        return "break"

    def _destroy(self) -> None:
        if self._closed:
            return
        self._closed = True
        pending = self._resize_validation_after_id
        self._resize_validation_after_id = None
        if pending is not None:
            try:
                self.window.after_cancel(pending)
            except tk.TclError:
                pass
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass


def show_recovery_source_inspection_review_window(
    parent: tk.Misc,
    presentation: VaultRecoverySourceInspectionPresentation,
    adapter: PreparedVaultRecoverySourceInspectionUIAdapter,
) -> VaultRecoverySourceInspectionReviewWindowOutcome:
    """Display one modal child window; Return is not bound window-wide."""

    if not isinstance(parent, tk.Misc):
        raise VaultRecoverySourceInspectionReviewWindowDisplayError(
            "parent must be an existing Tk widget"
        )
    prepared = prepare_recovery_source_inspection_review_window(
        presentation,
        adapter,
    )
    widget: _TkRecoverySourceInspectionReviewWindow | None = None
    try:
        widget = _TkRecoverySourceInspectionReviewWindow(parent, prepared)
        widget.activate()
        if widget.error is None:
            parent.wait_window(widget.window)
    except tk.TclError as exc:
        if widget is not None:
            widget._destroy()
        raise VaultRecoverySourceInspectionReviewWindowDisplayError(
            "local source inspection review window could not be displayed"
        ) from exc
    except BaseException:
        if widget is not None:
            widget._destroy()
        raise

    if widget.error is not None:
        if isinstance(widget.error, VaultRecoverySourceInspectionReviewWindowError):
            raise widget.error
        if isinstance(widget.error, Exception):
            raise VaultRecoverySourceInspectionReviewWindowDisplayError(
                "local source inspection review window failed safely"
            ) from widget.error
        raise widget.error
    if widget.outcome is not None:
        return _validate_outcome(widget.outcome)
    if (
        prepared.current_state
        is RecoverySourceInspectionReviewWindowState.AWAITING_VISIBLE_REVIEW
    ):
        return prepared.cancel_once(
            RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
        )
    if prepared.outcome is None:
        raise VaultRecoverySourceInspectionReviewWindowDisplayError(
            "local source inspection review ended fail-closed without an outcome"
        )
    return _validate_outcome(prepared.outcome)


__all__ = (
    "MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_CODEPOINTS",
    "MAX_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_TEXT_UTF8_LEN",
    "RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_FORMAT",
    "RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_VERSION",
    "PreparedVaultRecoverySourceInspectionReviewWindow",
    "RecoverySourceInspectionReviewWindowCancelReason",
    "RecoverySourceInspectionReviewWindowDecision",
    "RecoverySourceInspectionReviewWindowState",
    "RecoverySourceInspectionReviewWindowText",
    "VaultRecoverySourceInspectionReviewWindowDisplayError",
    "VaultRecoverySourceInspectionReviewWindowError",
    "VaultRecoverySourceInspectionReviewWindowFormatError",
    "VaultRecoverySourceInspectionReviewWindowInteractionError",
    "VaultRecoverySourceInspectionReviewWindowOutcome",
    "VaultRecoverySourceInspectionReviewWindowSourceError",
    "VaultRecoverySourceInspectionReviewWindowStateError",
    "prepare_recovery_source_inspection_review_window",
    "show_recovery_source_inspection_review_window",
)
