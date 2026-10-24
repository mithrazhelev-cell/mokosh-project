"""Shared, responsive Tk UI primitives for the normal protected profile.

The helpers in this module contain no profile, Vault, recovery, network, or
clipboard operation.  They provide one window contract, word-wrapping text,
responsive grids, explicit secret reveal controls, localized action dialogs,
and deterministic local form validation.
"""

from __future__ import annotations

import enum
import tkinter as tk
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence


MIN_PASSWORD_CHARACTERS = 15
MAX_PASSWORD_UTF8_BYTES = 1024
RECOVERY_WORD_COUNT = 25
MAX_RECOVERY_WORD_CHARACTERS = 8
MAX_RECOVERY_PHRASE_TEXT_BYTES = 512
DEFAULT_BODY_FONT = ("TkDefaultFont", 11)
DEFAULT_ACTION_FONT = ("TkDefaultFont", 11, "bold")


class RecoveryFormIssue(str, enum.Enum):
    MISSING_RECORD = "missing_record"
    INVALID_SOURCE_MODE = "invalid_source_mode"
    MISSING_SHEET = "missing_sheet"
    MISSING_WORDS = "missing_words"
    WORD_COUNT = "word_count"
    WORD_FORMAT = "word_format"
    WORD_TEXT_TOO_LONG = "word_text_too_long"
    MISSING_NEW_PASSWORD = "missing_new_password"
    MISSING_CONFIRMATION = "missing_confirmation"
    PASSWORD_MISMATCH = "password_mismatch"
    PASSWORD_TOO_SHORT = "password_too_short"
    PASSWORD_TOO_LONG = "password_too_long"
    PASSWORD_UNICODE = "password_unicode"


@dataclass(frozen=True, slots=True)
class RecoveryFormFinding:
    issue: RecoveryFormIssue
    message_key: str
    focus_target: str
    word_count: int | None = None


def configure_resizable_window(
    window: tk.Misc,
    *,
    geometry: str,
    minimum: tuple[int, int],
    close: Callable[[], None],
) -> None:
    """Apply the common normal-window contract without transient WM hints."""

    window.geometry(geometry)
    window.minsize(*minimum)
    window.resizable(True, True)
    window.protocol("WM_DELETE_WINDOW", close)
    window.bind("<Escape>", lambda _event: (close(), "break")[-1], add="+")


def responsive_wraplength(
    available_width: Any,
    *,
    horizontal_inset: int = 40,
    minimum: int = 180,
    maximum: int = 1040,
) -> int:
    if isinstance(available_width, bool) or not isinstance(
        available_width, (int, float)
    ):
        return minimum
    return max(minimum, min(maximum, int(available_width) - horizontal_inset))


def bind_responsive_wrap(
    label: tk.Widget,
    container: tk.Misc,
    *,
    horizontal_inset: int = 40,
    minimum: int = 180,
    maximum: int = 1040,
) -> Callable[[tk.Event], None]:
    def reflow(event: tk.Event) -> None:
        label.configure(
            wraplength=responsive_wraplength(
                getattr(event, "width", 0),
                horizontal_inset=horizontal_inset,
                minimum=minimum,
                maximum=maximum,
            )
        )

    container.bind("<Configure>", reflow, add="+")
    return reflow


@dataclass(slots=True)
class ScrollableRegion:
    outer: tk.Frame
    canvas: tk.Canvas
    content: tk.Frame
    scrollbar: tk.Scrollbar
    item: int
    focus_after_id: str | None = None
    last_focus_widget: object | None = None

    def scroll(self, event: tk.Event) -> str | None:
        number = getattr(event, "num", None)
        if number == 4:
            units = -1
        elif number == 5:
            units = 1
        else:
            delta = getattr(event, "delta", 0)
            if isinstance(delta, bool) or not isinstance(delta, (int, float)):
                return None
            if delta == 0:
                return None
            units = -1 if delta > 0 else 1
        self.canvas.yview_scroll(units, "units")
        return "break"

    def _contains(self, widget: object) -> bool:
        current = widget
        visited: set[int] = set()
        while current is not None:
            if current is self.content:
                return True
            identity = id(current)
            if identity in visited:
                return False
            visited.add(identity)
            current = getattr(current, "master", None)
        return False

    def _cancel_focus_reveal(self) -> None:
        identifier = self.focus_after_id
        self.focus_after_id = None
        if identifier is None:
            return
        try:
            self.canvas.after_cancel(identifier)
        except tk.TclError:
            pass

    def _reveal_focused_widget(self, widget: object) -> None:
        self.focus_after_id = None
        try:
            if (
                not self._contains(widget)
                or not bool(widget.winfo_exists())
                or not bool(widget.winfo_ismapped())
                or widget.focus_get() is not widget
            ):
                return
            canvas_top = int(self.canvas.winfo_rooty())
            viewport_height = int(self.canvas.winfo_height())
            widget_top = int(widget.winfo_rooty())
            widget_height = int(widget.winfo_height())
            bounds = self.canvas.bbox("all")
            view = self.canvas.yview()
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return
        if (
            viewport_height <= 0
            or widget_height <= 0
            or bounds is None
            or len(bounds) != 4
            or len(view) != 2
        ):
            return
        canvas_bottom = canvas_top + viewport_height
        widget_bottom = widget_top + widget_height
        if widget_top < canvas_top:
            delta = widget_top - canvas_top
        elif widget_bottom > canvas_bottom:
            delta = widget_bottom - canvas_bottom
        else:
            return
        try:
            content_top = float(bounds[1])
            content_bottom = float(bounds[3])
            content_height = content_bottom - content_top
            first = float(view[0])
        except (TypeError, ValueError):
            return
        if content_height <= viewport_height:
            return
        current_top = content_top + first * content_height
        maximum_top = content_bottom - viewport_height
        target_top = min(max(current_top + delta, content_top), maximum_top)
        fraction = (target_top - content_top) / content_height
        if abs(fraction - first) <= 1e-9:
            return
        try:
            self.canvas.yview_moveto(fraction)
        except tk.TclError:
            pass

    def _settle_focus_reveal(self) -> None:
        self.focus_after_id = None
        try:
            widget = self.canvas.focus_get()
        except (AttributeError, tk.TclError):
            return
        if not self._contains(widget) or widget is self.last_focus_widget:
            return
        self.last_focus_widget = widget
        self._reveal_focused_widget(widget)

    def focus_in(self, event: tk.Event) -> None:
        widget = getattr(event, "widget", None)
        if not self._contains(widget):
            return
        self._cancel_focus_reveal()
        try:
            self.focus_after_id = self.canvas.after_idle(
                self._settle_focus_reveal
            )
        except tk.TclError:
            self.focus_after_id = None


def create_scrollable_region(
    window: tk.Misc,
    *,
    padx: int = 18,
    pady: int = 16,
) -> ScrollableRegion:
    outer = tk.Frame(window)
    outer.pack(fill="both", expand=True)
    canvas = tk.Canvas(outer, highlightthickness=0, takefocus=False)
    scrollbar = tk.Scrollbar(
        outer,
        orient="vertical",
        command=canvas.yview,
        takefocus=False,
    )
    content = tk.Frame(canvas, padx=padx, pady=pady)
    item = canvas.create_window((0, 0), window=content, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    region = ScrollableRegion(outer, canvas, content, scrollbar, item)
    content.bind(
        "<Configure>",
        lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        add="+",
    )
    canvas.bind(
        "<Configure>",
        lambda event: canvas.itemconfigure(item, width=event.width),
        add="+",
    )
    for name in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
        canvas.bind(name, region.scroll, add="+")
    canvas.bind("<Prior>", lambda _event: canvas.yview_scroll(-1, "pages"))
    canvas.bind("<Next>", lambda _event: canvas.yview_scroll(1, "pages"))
    canvas.bind("<Home>", lambda _event: canvas.yview_moveto(0.0))
    canvas.bind("<End>", lambda _event: canvas.yview_moveto(1.0))

    def scroll_page(_event: tk.Event, units: int) -> str:
        canvas.yview_scroll(units, "pages")
        return "break"

    window.bind("<Prior>", lambda event: scroll_page(event, -1), add="+")
    window.bind("<Next>", lambda event: scroll_page(event, 1), add="+")
    window.bind("<FocusIn>", region.focus_in, add="+")
    return region


def create_responsive_label(
    parent: tk.Misc,
    *,
    text: str | None = None,
    textvariable: tk.Variable | None = None,
    background: str | None = None,
    foreground: str | None = None,
    warning: bool = False,
    bold: bool = False,
    padx: int = 10,
    pady: int = 9,
    horizontal_inset: int = 40,
) -> tk.Label:
    options: dict[str, Any] = {
        "justify": "left",
        "anchor": "w",
        "padx": padx,
        "pady": pady,
        "font": ("TkDefaultFont", 11, "bold" if bold else "normal"),
    }
    if text is not None:
        options["text"] = text
    if textvariable is not None:
        options["textvariable"] = textvariable
    if warning:
        options["bg"] = "#fff3cd"
        options["fg"] = "#5b4000"
    else:
        if background is not None:
            options["bg"] = background
        if foreground is not None:
            options["fg"] = foreground
    label = tk.Label(parent, **options)
    bind_responsive_wrap(
        label,
        label,
        horizontal_inset=horizontal_inset,
    )
    return label


class ResponsiveGrid:
    """Re-grid existing widgets as the available width changes."""

    def __init__(
        self,
        container: tk.Misc,
        widgets: Sequence[tk.Widget],
        *,
        column_rules: Sequence[tuple[int, int]],
        padx: int = 5,
        pady: int = 5,
    ) -> None:
        if not widgets or not column_rules:
            raise ValueError("responsive grid requires widgets and column rules")
        self.container = container
        self.widgets = tuple(widgets)
        self.column_rules = tuple(
            sorted(column_rules, key=lambda item: item[0], reverse=True)
        )
        self.padx = padx
        self.pady = pady
        self.columns = 0
        container.bind("<Configure>", self._on_configure, add="+")
        self.relayout(self.column_rules[-1][1])

    def columns_for_width(self, width: Any) -> int:
        exact = 0 if isinstance(width, bool) or not isinstance(width, (int, float)) else int(width)
        for threshold, columns in self.column_rules:
            if exact >= threshold:
                return columns
        return self.column_rules[-1][1]

    def _on_configure(self, event: tk.Event) -> None:
        self.relayout(self.columns_for_width(getattr(event, "width", 0)))

    def relayout(self, columns: int) -> None:
        if type(columns) is not int or columns < 1:
            raise ValueError("responsive grid column count is invalid")
        if columns == self.columns:
            return
        for column in range(max(self.columns, columns)):
            self.container.grid_columnconfigure(column, weight=0, uniform="")
        for column in range(columns):
            self.container.grid_columnconfigure(
                column, weight=1, uniform="responsive-grid"
            )
        for index, widget in enumerate(self.widgets):
            widget.grid_forget()
            widget.grid(
                row=index // columns,
                column=index % columns,
                sticky="ew",
                padx=self.padx,
                pady=self.pady,
            )
        self.columns = columns


class ResponsivePair:
    """Keep a primary area inline with controls, then stack them when narrow."""

    def __init__(
        self,
        container: tk.Misc,
        primary: tk.Widget,
        secondary: tk.Widget,
        *,
        breakpoint: int = 760,
        padx: int = 5,
        pady: int = 3,
        primary_sticky: str = "ew",
        secondary_inline_sticky: str = "e",
        secondary_stacked_sticky: str = "ew",
        fit_requested_widths: bool = False,
    ) -> None:
        if type(breakpoint) is not int or breakpoint < 1:
            raise ValueError("responsive pair breakpoint is invalid")
        if type(fit_requested_widths) is not bool:
            raise ValueError("responsive pair requested-width policy is invalid")
        self.container = container
        self.primary = primary
        self.secondary = secondary
        self.breakpoint = breakpoint
        self.padx = padx
        self.pady = pady
        self.primary_sticky = primary_sticky
        self.secondary_inline_sticky = secondary_inline_sticky
        self.secondary_stacked_sticky = secondary_stacked_sticky
        self.fit_requested_widths = fit_requested_widths
        self.stacked: bool | None = None
        container.bind("<Configure>", self._on_configure, add="+")
        self.relayout(True)

    def stacked_for_width(self, width: Any) -> bool:
        if isinstance(width, bool) or not isinstance(width, (int, float)):
            return True
        exact_width = int(width)
        if exact_width < self.breakpoint:
            return True
        if not self.fit_requested_widths:
            return False
        try:
            requested_inline_width = (
                int(self.primary.winfo_reqwidth())
                + int(self.secondary.winfo_reqwidth())
                + (4 * self.padx)
            )
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return True
        return exact_width < requested_inline_width

    def _on_configure(self, event: tk.Event) -> None:
        self.relayout(self.stacked_for_width(getattr(event, "width", 0)))

    def relayout(self, stacked: bool) -> None:
        if type(stacked) is not bool:
            raise ValueError("responsive pair layout is invalid")
        if stacked is self.stacked:
            return
        self.primary.grid_forget()
        self.secondary.grid_forget()
        for column in (0, 1):
            self.container.grid_columnconfigure(column, weight=0, uniform="")
        self.container.grid_columnconfigure(0, weight=1)
        self.primary.grid(
            row=0,
            column=0,
            sticky=self.primary_sticky,
            padx=self.padx,
            pady=self.pady,
        )
        if stacked:
            self.secondary.grid(
                row=1,
                column=0,
                sticky=self.secondary_stacked_sticky,
                padx=self.padx,
                pady=self.pady,
            )
        else:
            self.secondary.grid(
                row=0,
                column=1,
                sticky=self.secondary_inline_sticky,
                padx=self.padx,
                pady=self.pady,
            )
        self.stacked = stacked


def toggle_secret(
    entry: tk.Entry,
    button: tk.Button | None = None,
    *,
    show_text: str = "Show",
    hide_text: str = "Hide",
) -> None:
    reveal = entry.cget("show") == "*"
    entry.configure(show="" if reveal else "*")
    if button is not None:
        button.configure(text=f"{'🙈' if reveal else '👁'} {hide_text if reveal else show_text}")


def mask_secret(
    entry: tk.Entry,
    button: tk.Button | None = None,
    *,
    show_text: str = "Show",
) -> None:
    try:
        entry.configure(show="*")
        if button is not None:
            button.configure(text=f"👁 {show_text}")
    except tk.TclError:
        pass


def create_secret_toggle(
    parent: tk.Misc,
    entry: tk.Entry,
    *,
    show_text: str,
    hide_text: str,
) -> tk.Button:
    button = tk.Button(
        parent,
        text=f"👁 {show_text}",
        takefocus=True,
    )
    button.configure(
        command=lambda: toggle_secret(
            entry,
            button,
            show_text=show_text,
            hide_text=hide_text,
        )
    )
    return button


def _phrase_finding(value: Any, *, focus_target: str) -> RecoveryFormFinding | None:
    if type(value) is not str or not value.split():
        return RecoveryFormFinding(
            RecoveryFormIssue.MISSING_WORDS,
            "recovery_phrase_missing",
            focus_target,
            0,
        )
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return RecoveryFormFinding(
            RecoveryFormIssue.WORD_FORMAT,
            "recovery_phrase_word_format",
            focus_target,
        )
    if len(encoded) > MAX_RECOVERY_PHRASE_TEXT_BYTES:
        return RecoveryFormFinding(
            RecoveryFormIssue.WORD_TEXT_TOO_LONG,
            "recovery_phrase_text_too_long",
            focus_target,
        )
    words = value.split()
    if len(words) != RECOVERY_WORD_COUNT:
        return RecoveryFormFinding(
            RecoveryFormIssue.WORD_COUNT,
            "recovery_phrase_word_count",
            focus_target,
            len(words),
        )
    if any(
        not word.isascii()
        or not word.isalpha()
        or not word.islower()
        or len(word) > MAX_RECOVERY_WORD_CHARACTERS
        for word in words
    ):
        return RecoveryFormFinding(
            RecoveryFormIssue.WORD_FORMAT,
            "recovery_phrase_word_format",
            focus_target,
        )
    return None


def validate_paper_phrase(value: Any) -> RecoveryFormFinding | None:
    return _phrase_finding(value, focus_target="paper_words")


def validate_password_recovery_form(
    *,
    record_path: Any,
    source_mode: Any,
    sheet_path: Any,
    words: Any,
    new_password: Any,
    confirmation: Any,
) -> RecoveryFormFinding | None:
    if type(record_path) is not str or not record_path.strip():
        return RecoveryFormFinding(
            RecoveryFormIssue.MISSING_RECORD,
            "password_recovery_missing_record",
            "choose_record",
        )
    if source_mode not in {"sheet", "words"}:
        return RecoveryFormFinding(
            RecoveryFormIssue.INVALID_SOURCE_MODE,
            "password_recovery_invalid_source",
            "source_mode",
        )
    if source_mode == "sheet":
        if type(sheet_path) is not str or not sheet_path.strip():
            return RecoveryFormFinding(
                RecoveryFormIssue.MISSING_SHEET,
                "password_recovery_missing_sheet",
                "choose_sheet",
            )
    else:
        phrase_finding = _phrase_finding(words, focus_target="words")
        if phrase_finding is not None:
            return phrase_finding
    if type(new_password) is not str or new_password == "":
        return RecoveryFormFinding(
            RecoveryFormIssue.MISSING_NEW_PASSWORD,
            "password_recovery_missing_new_password",
            "new_password",
        )
    if type(confirmation) is not str or confirmation == "":
        return RecoveryFormFinding(
            RecoveryFormIssue.MISSING_CONFIRMATION,
            "password_recovery_missing_confirmation",
            "confirmation",
        )
    try:
        normalized = unicodedata.normalize("NFC", new_password)
        normalized_confirmation = unicodedata.normalize("NFC", confirmation)
        encoded = normalized.encode("utf-8", errors="strict")
        normalized_confirmation.encode("utf-8", errors="strict")
    except (TypeError, UnicodeError):
        return RecoveryFormFinding(
            RecoveryFormIssue.PASSWORD_UNICODE,
            "password_recovery_password_unicode",
            "new_password",
        )
    if normalized != normalized_confirmation:
        return RecoveryFormFinding(
            RecoveryFormIssue.PASSWORD_MISMATCH,
            "password_recovery_password_mismatch",
            "confirmation",
        )
    if len(normalized) < MIN_PASSWORD_CHARACTERS:
        return RecoveryFormFinding(
            RecoveryFormIssue.PASSWORD_TOO_SHORT,
            "password_recovery_password_too_short",
            "new_password",
        )
    if len(encoded) > MAX_PASSWORD_UTF8_BYTES:
        return RecoveryFormFinding(
            RecoveryFormIssue.PASSWORD_TOO_LONG,
            "password_recovery_password_too_long",
            "new_password",
        )
    return None


class ActionDialog:
    """Resizable localized notice/decision dialog with explicit action labels."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        title: str,
        text: str,
        actions: Iterable[tuple[str, Any]],
        cancel_result: Any,
        geometry: str = "560x330",
        minimum: tuple[int, int] = (440, 260),
        default_index: int = 0,
    ) -> None:
        exact_actions = tuple(actions)
        if not exact_actions:
            raise ValueError("an action dialog needs at least one action")
        if type(default_index) is not int or not 0 <= default_index < len(
            exact_actions
        ):
            raise ValueError("action dialog default index is invalid")
        self.parent = parent
        self.result = cancel_result
        self._closed = False
        self._grab_active = False
        self._default_index = default_index
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        configure_resizable_window(
            self.window,
            geometry=geometry,
            minimum=minimum,
            close=self.cancel,
        )
        body = tk.Frame(self.window, padx=16, pady=14)
        body.pack(fill="both", expand=True)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        text_frame = tk.Frame(body)
        text_frame.grid(row=0, column=0, sticky="nsew")
        message = tk.Text(
            text_frame,
            wrap="word",
            undo=False,
            padx=12,
            pady=10,
            font=DEFAULT_BODY_FONT,
            cursor="arrow",
            takefocus=True,
        )
        scrollbar = tk.Scrollbar(
            text_frame,
            orient="vertical",
            command=message.yview,
            takefocus=False,
        )
        message.configure(yscrollcommand=scrollbar.set)
        message.insert("1.0", text)
        message.configure(state=tk.DISABLED)
        message.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        buttons = tk.Frame(body)
        buttons.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.buttons: list[tk.Button] = []
        for index, (label, result) in enumerate(exact_actions):
            button = tk.Button(
                buttons,
                text=label,
                command=lambda selected=result: self.choose(selected),
                font=DEFAULT_ACTION_FONT,
                takefocus=True,
            )
            button.pack(fill="x", pady=(0 if index == 0 else 5, 0))
            self.buttons.append(button)
        self.window.bind(
            "<Return>",
            lambda _event: (
                self.choose(exact_actions[self._default_index][1]),
                "break",
            )[-1],
            add="+",
        )
        self.window.bind("<Map>", self._on_map, add="+")
        self.window.bind("<Unmap>", self._on_unmap, add="+")
        self.window.after_idle(self.buttons[self._default_index].focus_set)

    def _on_unmap(self, event: tk.Event) -> None:
        """Let a minimized decision window release the rest of the desktop."""

        if getattr(event, "widget", None) is not self.window:
            return
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        self._grab_active = False

    def _on_map(self, event: tk.Event) -> None:
        """Restore local modality after the decision window is restored."""

        if (
            self._closed
            or self._grab_active
            or getattr(event, "widget", None) is not self.window
        ):
            return
        try:
            self.window.after_idle(self._activate)
        except tk.TclError:
            pass

    def _activate(self) -> None:
        if self._closed or self._grab_active:
            return
        try:
            if not self.window.winfo_exists() or not self.window.winfo_viewable():
                return
            self.window.grab_set()
            self.buttons[self._default_index].focus_set()
        except tk.TclError:
            return
        self._grab_active = True

    def choose(self, result: Any) -> None:
        self.result = result
        self.close()

    def cancel(self) -> None:
        self.close()

    def _restore_parent(self) -> None:
        try:
            if not self.parent.winfo_exists():
                return
            self.parent.deiconify()
            self.parent.lift()
            self.parent.focus_force()
        except (AttributeError, tk.TclError):
            return

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        self._grab_active = False
        try:
            self.window.destroy()
        except tk.TclError:
            pass
        try:
            self.parent.after_idle(self._restore_parent)
        except (AttributeError, tk.TclError):
            self._restore_parent()

    def run(self) -> Any:
        try:
            self.window.grab_set()
        except tk.TclError:
            pass
        else:
            self._grab_active = True
        self.window.wait_window()
        return self.result


def show_action_notice(
    parent: tk.Misc,
    *,
    title: str,
    text: str,
    close_label: str,
) -> None:
    ActionDialog(
        parent,
        title=title,
        text=text,
        actions=((close_label, True),),
        cancel_result=False,
    ).run()


def ask_action_decision(
    parent: tk.Misc,
    *,
    title: str,
    text: str,
    approve_label: str,
    cancel_label: str,
) -> bool:
    return bool(
        ActionDialog(
            parent,
            title=title,
            text=text,
            actions=((approve_label, True), (cancel_label, False)),
            cancel_result=False,
            default_index=1,
        ).run()
    )


__all__ = [
    "ActionDialog",
    "DEFAULT_ACTION_FONT",
    "DEFAULT_BODY_FONT",
    "MAX_PASSWORD_UTF8_BYTES",
    "MAX_RECOVERY_PHRASE_TEXT_BYTES",
    "MIN_PASSWORD_CHARACTERS",
    "RECOVERY_WORD_COUNT",
    "RecoveryFormFinding",
    "RecoveryFormIssue",
    "ResponsiveGrid",
    "ResponsivePair",
    "ScrollableRegion",
    "ask_action_decision",
    "bind_responsive_wrap",
    "configure_resizable_window",
    "create_responsive_label",
    "create_scrollable_region",
    "create_secret_toggle",
    "mask_secret",
    "responsive_wraplength",
    "show_action_notice",
    "toggle_secret",
    "validate_paper_phrase",
    "validate_password_recovery_form",
]
