"""Isolated local Tkinter review window for the Vault recovery workflow.

Stage 2.14 renders one exact Stage 2.13 localized view and reports one exact
Stage 2.12 visible confirmation sequence.  The window is deliberately a
review boundary: it has no Vault, password, path, recovery, publish, cleanup,
network, update, callback, or executor input and it grants no operation
authority.

The public ``show_recovery_review_window`` function creates one ``Toplevel``
owned by an existing Tk application.  It never creates a second ``Tk`` root
and never starts a second ``mainloop``.
"""

from __future__ import annotations

import hmac
import tkinter as tk
import unicodedata
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from tkinter import ttk
from typing import Any

from mokosh_vault_recovery_localization import (
    RecoveryLocalizationLocale,
    VaultRecoveryLocalizationError,
    VaultRecoveryLocalizedUIAdapterView,
    _validate_localized_view,
    localize_recovery_ui_adapter_view,
)
from mokosh_vault_recovery_presentation import (
    RecoveryPresentationConfirmationKey,
    VaultRecoveryWorkflowPresentation,
)
from mokosh_vault_recovery_ui_adapter import (
    PreparedVaultRecoveryUIAdapter,
    RecoveryUIAdapterState,
    RecoveryUIConfirmationEvent,
    VaultRecoveryUIAdapterError,
    VaultRecoveryUIAdapterReceipt,
    _binding_from_source_presentation,
    _validate_adapter_receipt,
    _validate_adapter_view,
    _view_matches_binding,
)


RECOVERY_REVIEW_WINDOW_FORMAT = "MOKOSH_VAULT_RECOVERY_REVIEW_WINDOW"
RECOVERY_REVIEW_WINDOW_VERSION = 1
MAX_RECOVERY_REVIEW_WINDOW_TEXT_CODEPOINTS = 160
MAX_RECOVERY_REVIEW_WINDOW_TEXT_UTF8_LEN = 512


class VaultRecoveryReviewWindowError(ValueError):
    """Base class for strict Stage 2.14 review-window failures."""


class VaultRecoveryReviewWindowSourceError(VaultRecoveryReviewWindowError):
    """A presentation, adapter, locale, or localized view is invalid."""


class VaultRecoveryReviewWindowInteractionError(
    VaultRecoveryReviewWindowError
):
    """A visible ordered individual interaction requirement was not met."""


class VaultRecoveryReviewWindowStateError(VaultRecoveryReviewWindowError):
    """The process-local review window is closed or already consumed."""


class VaultRecoveryReviewWindowDisplayError(VaultRecoveryReviewWindowError):
    """The local Tk window could not be created or displayed."""


class RecoveryReviewWindowState(str, Enum):
    """Process-local widget state; no member grants recovery authority."""

    AWAITING_VISIBLE_REVIEW = "awaiting_visible_review"
    ACKNOWLEDGED = "acknowledged"
    CANCELLED = "cancelled"


class RecoveryReviewWindowDecision(str, Enum):
    """Bounded terminal result of one local review window."""

    ACKNOWLEDGED = "acknowledged"
    CANCELLED = "cancelled"


class RecoveryReviewWindowCancelReason(str, Enum):
    """Exact non-authoritative local cancellation routes."""

    CANCEL_BUTTON = "cancel_button"
    ESCAPE_KEY = "escape_key"
    WINDOW_CLOSE = "window_close"


@_dataclass(frozen=True, slots=True)
class RecoveryReviewWindowText:
    """Fixed Stage 2.14 window chrome for one exact supported locale."""

    locale: RecoveryLocalizationLocale
    title: str
    introduction: str
    confirmations_heading: str
    confirm_button: str
    cancel_button: str

    def __post_init__(self) -> None:
        _validate_window_text(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryReviewWindowOutcome:
    """Bounded result containing no source view, event tuple, or secret."""

    locale: RecoveryLocalizationLocale
    presentation_sha256: bytes = _field(repr=False)
    decision: RecoveryReviewWindowDecision
    cancel_reason: RecoveryReviewWindowCancelReason | None
    acknowledgement_receipt: VaultRecoveryUIAdapterReceipt | None = _field(
        repr=False
    )
    read_only: bool = True
    messages_rendered_before_confirmations: bool = True
    individual_default_false_confirmations: bool = True
    group_select_used: bool = False
    auto_accept_used: bool = False
    operation_controls_included: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    gate_invoked: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_REVIEW_WINDOW_FORMAT
    version: int = RECOVERY_REVIEW_WINDOW_VERSION

    def __post_init__(self) -> None:
        _validate_outcome(self)


def _validate_plain_window_text(value: Any, field_name: str) -> str:
    if type(value) is not str:
        raise VaultRecoveryReviewWindowSourceError(
            f"{field_name} must be fixed plain text"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultRecoveryReviewWindowSourceError(
            f"{field_name} must be valid UTF-8 text"
        ) from exc
    if (
        not 1 <= len(value) <= MAX_RECOVERY_REVIEW_WINDOW_TEXT_CODEPOINTS
        or len(encoded) > MAX_RECOVERY_REVIEW_WINDOW_TEXT_UTF8_LEN
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or "{" in value
        or "}" in value
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.bidirectional(character)
            in {"BN", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
            for character in value
        )
    ):
        raise VaultRecoveryReviewWindowSourceError(
            f"{field_name} is outside the fixed text policy"
        )
    return value


def _validate_window_text(value: Any) -> RecoveryReviewWindowText:
    if (
        type(value) is not RecoveryReviewWindowText
        or type(value.locale) is not RecoveryLocalizationLocale
    ):
        raise VaultRecoveryReviewWindowSourceError(
            "review-window text record is invalid"
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
    RecoveryReviewWindowText(
        locale=RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        title="MOKOSH — преглед на възстановяването",
        introduction=(
            "Прегледайте всички съобщения. Отбележете всяко отделно "
            "потвърждение само ако сте го разбрали."
        ),
        confirmations_heading="Задължителни отделни потвърждения",
        confirm_button="Потвърди прегледа",
        cancel_button="Отказ",
    ),
    RecoveryReviewWindowText(
        locale=RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        title="MOKOSH — recovery review",
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
) -> RecoveryReviewWindowText:
    if type(locale) is not RecoveryLocalizationLocale:
        raise VaultRecoveryReviewWindowSourceError("review locale is invalid")
    for item in _WINDOW_TEXT_REGISTRY:
        _validate_window_text(item)
        if item.locale is locale:
            return item
    raise VaultRecoveryReviewWindowSourceError("review locale is unsupported")


def _localized_view_matches_adapter(
    localized: VaultRecoveryLocalizedUIAdapterView,
    adapter_view: Any,
) -> bool:
    return (
        hmac.compare_digest(
            localized.presentation_sha256,
            adapter_view.presentation_sha256,
        )
        and localized.classification is adapter_view.classification
        and localized.decision is adapter_view.decision
        and localized.state is adapter_view.state
        and localized.adapter_state is adapter_view.adapter_state
        and localized.terminal_stop is adapter_view.terminal_stop
        and localized.downstream_reverification_required
        is adapter_view.downstream_reverification_required
        and tuple(
            (item.ordinal, item.message_key, item.is_gate_message, item.visible)
            for item in localized.message_items
        )
        == tuple(
            (item.ordinal, item.message_key, item.is_gate_message, item.visible)
            for item in adapter_view.message_items
        )
        and tuple(
            (
                item.ordinal,
                item.confirmation_key,
                item.visible,
                item.required,
                item.individually_selectable,
                item.default_selected,
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
            )
            for item in adapter_view.confirmation_controls
        )
    )


def _validate_outcome(
    value: Any,
) -> VaultRecoveryReviewWindowOutcome:
    if type(value) is not VaultRecoveryReviewWindowOutcome:
        raise VaultRecoveryReviewWindowSourceError("review outcome type is invalid")
    if (
        value.format != RECOVERY_REVIEW_WINDOW_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_REVIEW_WINDOW_VERSION
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.decision) is not RecoveryReviewWindowDecision
    ):
        raise VaultRecoveryReviewWindowSourceError(
            "review outcome schema is invalid"
        )
    bool_fields = (
        "read_only",
        "messages_rendered_before_confirmations",
        "individual_default_false_confirmations",
        "group_select_used",
        "auto_accept_used",
        "operation_controls_included",
        "operation_performed",
        "operation_authorized",
        "gate_invoked",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryReviewWindowSourceError(
            "review outcome flags must be exact booleans"
        )
    if (
        value.read_only is not True
        or value.messages_rendered_before_confirmations is not True
        or value.individual_default_false_confirmations is not True
        or any(
            getattr(value, name) is not False
            for name in (
                "group_select_used",
                "auto_accept_used",
                "operation_controls_included",
                "operation_performed",
                "operation_authorized",
                "gate_invoked",
                "secrets_retained",
            )
        )
    ):
        raise VaultRecoveryReviewWindowSourceError(
            "review outcome contains automatic or authoritative state"
        )
    if value.decision is RecoveryReviewWindowDecision.ACKNOWLEDGED:
        if (
            value.cancel_reason is not None
            or type(value.acknowledgement_receipt)
            is not VaultRecoveryUIAdapterReceipt
        ):
            raise VaultRecoveryReviewWindowSourceError(
                "acknowledged outcome lacks its exact adapter receipt"
            )
        try:
            _validate_adapter_receipt(value.acknowledgement_receipt)
        except VaultRecoveryUIAdapterError as exc:
            raise VaultRecoveryReviewWindowSourceError(
                "acknowledgement receipt is invalid"
            ) from exc
        if not hmac.compare_digest(
            value.presentation_sha256,
            value.acknowledgement_receipt.presentation_sha256,
        ):
            raise VaultRecoveryReviewWindowSourceError(
                "acknowledgement receipt binding is invalid"
            )
    elif (
        type(value.cancel_reason) is not RecoveryReviewWindowCancelReason
        or value.acknowledgement_receipt is not None
    ):
        raise VaultRecoveryReviewWindowSourceError(
            "cancelled outcome must contain only one cancellation reason"
        )
    return value


class PreparedVaultRecoveryReviewWindow:
    """One-shot process-local review state consumed only by explicit review."""

    __slots__ = (
        "_presentation",
        "_adapter",
        "_localized_view",
        "_window_text",
        "_binding",
        "_selected",
        "_messages_visible",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        presentation: VaultRecoveryWorkflowPresentation,
        adapter: PreparedVaultRecoveryUIAdapter,
        localized_view: VaultRecoveryLocalizedUIAdapterView,
        window_text: RecoveryReviewWindowText,
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
        self._state = RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW
        self._outcome: VaultRecoveryReviewWindowOutcome | None = None
        self._lock = _Lock()

    @property
    def localized_view(self) -> VaultRecoveryLocalizedUIAdapterView:
        return self._localized_view

    @property
    def window_text(self) -> RecoveryReviewWindowText:
        return self._window_text

    @property
    def current_state(self) -> RecoveryReviewWindowState:
        return self._state

    @property
    def confirmation_selections(self) -> tuple[bool, ...]:
        return self._selected

    @property
    def messages_visible(self) -> bool:
        return self._messages_visible

    @property
    def confirm_enabled(self) -> bool:
        return (
            self._state is RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW
            and self._messages_visible
            and all(item is True for item in self._selected)
        )

    @property
    def outcome(self) -> VaultRecoveryReviewWindowOutcome | None:
        return self._outcome

    def mark_messages_visible_once(self, ordinals: tuple[int, ...]) -> None:
        """Record exact ordered rendering before controls become interactive."""

        with self._lock:
            self._require_open()
            expected = tuple(item.ordinal for item in self._localized_view.message_items)
            if (
                self._messages_visible
                or type(ordinals) is not tuple
                or ordinals != expected
                or any(type(item) is not int for item in ordinals)
            ):
                raise VaultRecoveryReviewWindowInteractionError(
                    "visible message ordinals must be reported exactly once in order"
                )
            self._messages_visible = True

    def record_confirmation_selection(
        self,
        ordinal: int,
        confirmation_key: RecoveryPresentationConfirmationKey,
        selected: bool,
    ) -> None:
        """Record one individual widget selection after messages are visible."""

        with self._lock:
            self._require_open()
            if self._messages_visible is not True:
                raise VaultRecoveryReviewWindowInteractionError(
                    "confirmations cannot be selected before messages are visible"
                )
            if (
                type(ordinal) is not int
                or type(confirmation_key) is not RecoveryPresentationConfirmationKey
                or type(selected) is not bool
                or not 1 <= ordinal <= len(self._selected)
            ):
                raise VaultRecoveryReviewWindowInteractionError(
                    "confirmation selection schema is invalid"
                )
            control = self._localized_view.confirmation_controls[ordinal - 1]
            if control.ordinal != ordinal or control.confirmation_key is not confirmation_key:
                raise VaultRecoveryReviewWindowInteractionError(
                    "confirmation selection differs from the visible ordered control"
                )
            changed = list(self._selected)
            changed[ordinal - 1] = selected
            self._selected = tuple(changed)

    def acknowledge_visible_once(self) -> VaultRecoveryReviewWindowOutcome:
        """Consume all exact selections into one no-authority Stage 2.12 receipt."""

        with self._lock:
            self._require_open()
            if not self.confirm_enabled:
                raise VaultRecoveryReviewWindowInteractionError(
                    "every visible individual confirmation must be selected"
                )
            _validate_review_sources(
                self._presentation,
                self._adapter,
                self._localized_view,
                self._window_text,
            )
            events = tuple(
                RecoveryUIConfirmationEvent(
                    ordinal=control.ordinal,
                    confirmation_key=control.confirmation_key,
                    visible=True,
                    user_selected=True,
                    user_initiated=True,
                )
                for control in self._localized_view.confirmation_controls
            )
            try:
                receipt = self._adapter.acknowledge_visible_once(
                    self._presentation,
                    events,
                )
                _validate_adapter_receipt(receipt)
            except VaultRecoveryUIAdapterError as exc:
                raise VaultRecoveryReviewWindowSourceError(
                    "Stage 2.12 rejected the fresh visible review binding"
                ) from exc
            outcome = VaultRecoveryReviewWindowOutcome(
                locale=self._localized_view.locale,
                presentation_sha256=self._localized_view.presentation_sha256,
                decision=RecoveryReviewWindowDecision.ACKNOWLEDGED,
                cancel_reason=None,
                acknowledgement_receipt=receipt,
            )
            self._outcome = outcome
            self._state = RecoveryReviewWindowState.ACKNOWLEDGED
            return outcome

    def cancel_once(
        self,
        reason: RecoveryReviewWindowCancelReason,
    ) -> VaultRecoveryReviewWindowOutcome:
        """Close without acknowledgement, transition, gate, or operation."""

        with self._lock:
            self._require_open()
            if type(reason) is not RecoveryReviewWindowCancelReason:
                raise VaultRecoveryReviewWindowInteractionError(
                    "cancellation reason is invalid"
                )
            outcome = VaultRecoveryReviewWindowOutcome(
                locale=self._localized_view.locale,
                presentation_sha256=self._localized_view.presentation_sha256,
                decision=RecoveryReviewWindowDecision.CANCELLED,
                cancel_reason=reason,
                acknowledgement_receipt=None,
            )
            self._outcome = outcome
            self._state = RecoveryReviewWindowState.CANCELLED
            return outcome

    def _require_open(self) -> None:
        if self._state is not RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW:
            raise VaultRecoveryReviewWindowStateError(
                "recovery review window is already closed"
            )

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryReviewWindow("
            f"locale={self._localized_view.locale.value!r}, "
            f"state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryReviewWindowStateError(
            "prepared recovery review window cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryReviewWindowStateError(
            "prepared recovery review window cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryReviewWindowStateError(
            "prepared recovery review window cannot be serialized"
        )


def _validate_review_sources(
    presentation: Any,
    adapter: Any,
    localized_view: Any,
    window_text: Any,
) -> Any:
    if type(presentation) is not VaultRecoveryWorkflowPresentation:
        raise VaultRecoveryReviewWindowSourceError(
            "presentation must be exact Stage 2.10 data"
        )
    if type(adapter) is not PreparedVaultRecoveryUIAdapter:
        raise VaultRecoveryReviewWindowSourceError(
            "adapter must be an exact prepared Stage 2.12 adapter"
        )
    if type(localized_view) is not VaultRecoveryLocalizedUIAdapterView:
        raise VaultRecoveryReviewWindowSourceError(
            "localized view must be exact Stage 2.13 data"
        )
    try:
        binding = _binding_from_source_presentation(presentation)
        source_view = _validate_adapter_view(adapter.view)
        _validate_localized_view(localized_view)
        _validate_window_text(window_text)
    except (VaultRecoveryUIAdapterError, VaultRecoveryLocalizationError) as exc:
        raise VaultRecoveryReviewWindowSourceError(
            "review source violates a frozen upstream contract"
        ) from exc
    if (
        adapter.current_state
        is not RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
        or adapter.acknowledged
        or adapter.receipt is not None
        or not _view_matches_binding(source_view, binding)
        or not _localized_view_matches_adapter(localized_view, source_view)
        or window_text.locale is not localized_view.locale
    ):
        raise VaultRecoveryReviewWindowSourceError(
            "presentation, adapter, localized view, and locale differ"
        )
    return binding


def prepare_recovery_review_window(
    presentation: VaultRecoveryWorkflowPresentation,
    adapter: PreparedVaultRecoveryUIAdapter,
    locale_id: str,
) -> PreparedVaultRecoveryReviewWindow:
    """Prepare one fresh exact localized review without displaying a widget."""

    if type(locale_id) is not str:
        raise VaultRecoveryReviewWindowSourceError(
            "locale_id must be one exact supported string"
        )
    if type(adapter) is not PreparedVaultRecoveryUIAdapter:
        raise VaultRecoveryReviewWindowSourceError(
            "adapter must be an exact prepared Stage 2.12 adapter"
        )
    try:
        localized = localize_recovery_ui_adapter_view(adapter.view, locale_id)
    except VaultRecoveryLocalizationError as exc:
        raise VaultRecoveryReviewWindowSourceError(
            "locale or Stage 2.12 source view is invalid"
        ) from exc
    text = _window_text_for_locale(localized.locale)
    return PreparedVaultRecoveryReviewWindow(
        presentation,
        adapter,
        localized,
        text,
    )


class _TkRecoveryReviewWindow:
    """Private concrete Tk widget; security decisions remain in the controller."""

    def __init__(self, parent: Any, prepared: PreparedVaultRecoveryReviewWindow):
        if type(prepared) is not PreparedVaultRecoveryReviewWindow:
            raise VaultRecoveryReviewWindowDisplayError(
                "prepared review controller is invalid"
            )
        self._prepared = prepared
        self._outcome: VaultRecoveryReviewWindowOutcome | None = None
        self._error: Exception | None = None
        self._closed = False
        self._variables: list[Any] = []
        self._checks: list[Any] = []

        window = tk.Toplevel(parent)
        self.window = window
        window.title(prepared.window_text.title)
        window.transient(parent)
        window.minsize(520, 420)
        window.protocol(
            "WM_DELETE_WINDOW",
            lambda: self._cancel(RecoveryReviewWindowCancelReason.WINDOW_CLOSE),
        )
        window.bind("<Escape>", self._escape)
        window.bind("<Return>", self._return)

        outer = ttk.Frame(window, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(
            outer,
            text=prepared.window_text.introduction,
            justify="left",
            anchor="w",
            wraplength=720,
        ).pack(fill="x", pady=(0, 12))

        review_frame = ttk.Frame(outer)
        review_frame.pack(fill="both", expand=True)
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
            lambda event: canvas.itemconfigure(content_id, width=event.width),
        )
        canvas.bind("<MouseWheel>", self._mousewheel)
        canvas.bind("<Button-4>", lambda event: self._scroll(canvas, -1))
        canvas.bind("<Button-5>", lambda event: self._scroll(canvas, 1))
        self._canvas = canvas

        style = ttk.Style(window)
        style.configure("MOKOSH.RecoveryGate.TLabel", font=("TkDefaultFont", 10, "bold"))
        message_ordinals = []
        for item in prepared.localized_view.message_items:
            style_name = "MOKOSH.RecoveryGate.TLabel" if item.is_gate_message else "TLabel"
            ttk.Label(
                content,
                text=item.text,
                justify="left",
                anchor="w",
                wraplength=680,
                style=style_name,
            ).pack(fill="x", pady=(0, 8))
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
            check = ttk.Checkbutton(
                content,
                text=control.text,
                variable=variable,
                takefocus=True,
                state="disabled",
                command=lambda c=control, v=variable: self._toggle(c, v),
            )
            check.pack(fill="x", anchor="w", pady=(0, 8))
            self._variables.append(variable)
            self._checks.append(check)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 0))
        self._cancel_button = ttk.Button(
            buttons,
            text=prepared.window_text.cancel_button,
            command=lambda: self._cancel(
                RecoveryReviewWindowCancelReason.CANCEL_BUTTON
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

    @property
    def outcome(self) -> VaultRecoveryReviewWindowOutcome | None:
        return self._outcome

    @property
    def error(self) -> Exception | None:
        return self._error

    def activate(self) -> None:
        try:
            self.window.update_idletasks()
            self.window.wait_visibility()
            self._prepared.mark_messages_visible_once(self._message_ordinals)
            for check in self._checks:
                check.configure(state="normal")
            self.window.grab_set()
            if self._checks:
                self._checks[0].focus_set()
            else:
                self._cancel_button.focus_set()
        except Exception as exc:
            self._error = exc
            self._destroy()

    def _toggle(self, control: Any, variable: Any) -> None:
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
        except Exception as exc:
            self._error = exc
            self._destroy()

    def _confirm(self) -> str:
        if self._closed or not self._prepared.confirm_enabled:
            return "break"
        try:
            self._outcome = self._prepared.acknowledge_visible_once()
        except Exception as exc:
            self._error = exc
        self._destroy()
        return "break"

    def _cancel(self, reason: RecoveryReviewWindowCancelReason) -> str:
        if self._closed:
            return "break"
        try:
            self._outcome = self._prepared.cancel_once(reason)
        except Exception as exc:
            self._error = exc
        self._destroy()
        return "break"

    def _escape(self, event: Any) -> str:
        return self._cancel(RecoveryReviewWindowCancelReason.ESCAPE_KEY)

    def _return(self, event: Any) -> str:
        if self._prepared.confirm_enabled:
            return self._confirm()
        return "break"

    def _mousewheel(self, event: Any) -> str:
        delta = getattr(event, "delta", 0)
        if delta:
            self._scroll(self._canvas, -1 if delta > 0 else 1)
        return "break"

    @staticmethod
    def _scroll(canvas: Any, units: int) -> str:
        canvas.yview_scroll(units, "units")
        return "break"

    def _destroy(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass


def show_recovery_review_window(
    parent: tk.Misc,
    presentation: VaultRecoveryWorkflowPresentation,
    adapter: PreparedVaultRecoveryUIAdapter,
    locale_id: str,
) -> VaultRecoveryReviewWindowOutcome:
    """Display one modal local review and return acknowledgement or cancel."""

    if not isinstance(parent, tk.Misc):
        raise VaultRecoveryReviewWindowDisplayError(
            "parent must be an existing Tk widget"
        )
    prepared = prepare_recovery_review_window(presentation, adapter, locale_id)
    try:
        widget = _TkRecoveryReviewWindow(parent, prepared)
        widget.activate()
        if widget.error is None:
            parent.wait_window(widget.window)
    except tk.TclError as exc:
        raise VaultRecoveryReviewWindowDisplayError(
            "local recovery review window could not be displayed"
        ) from exc
    if widget.error is not None:
        if isinstance(widget.error, VaultRecoveryReviewWindowError):
            raise widget.error
        raise VaultRecoveryReviewWindowDisplayError(
            "local recovery review window failed safely"
        ) from widget.error
    if widget.outcome is not None:
        return _validate_outcome(widget.outcome)
    if prepared.current_state is RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW:
        return prepared.cancel_once(RecoveryReviewWindowCancelReason.WINDOW_CLOSE)
    if prepared.outcome is None:
        raise VaultRecoveryReviewWindowDisplayError(
            "local recovery review window ended without a bounded outcome"
        )
    return _validate_outcome(prepared.outcome)
