"""Human-facing optional recovery setup and forgotten-password windows.

All windows use the shared resizable/reflow contract.  Secret fields are
masked by default and have explicit localized eye controls.  Native Tk
message boxes are deliberately avoided so Bulgarian never falls back to
system ``OK``/``Yes``/``No`` labels.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any, Callable

from mokosh_profile_localization import ProfileLocale, profile_text
from mokosh_profile_recovery import (
    PreparedProfilePasswordRecovery,
    PreparedProfileRecoverySetup,
    ProfileRecoveryAuthenticationError,
    ProfileRecoveryBackupError,
    ProfileRecoveryDecision,
    ProfileRecoveryExportUncertainError,
    ProfileRecoveryInputError,
    ProfileRecoveryLifecyclePublishError,
    ProfileRecoveryPublishUncertainError,
    ProfileRecoverySeparationError,
    ProfileRecoveryStateError,
    ProfileRecoveryStorageUnsupportedError,
    begin_profile_recovery_setup,
    prepare_profile_password_recovery_from_sheet,
    prepare_profile_password_recovery_from_words,
)
from mokosh_profile_ui import (
    DEFAULT_ACTION_FONT,
    DEFAULT_BODY_FONT,
    RecoveryFormFinding,
    ResponsiveGrid,
    ResponsivePair,
    ask_action_decision,
    bind_responsive_wrap,
    configure_resizable_window,
    create_responsive_label,
    create_scrollable_region,
    create_secret_toggle,
    mask_secret,
    show_action_notice,
    validate_paper_phrase,
    validate_password_recovery_form,
)


RECOVERY_SETUP_GEOMETRY = "900x780"
PASSWORD_RECOVERY_GEOMETRY = "900x760"
RECOVERY_WINDOW_MINIMUM = (620, 520)
PAPER_WINDOW_GEOMETRY = "720x500"
PAPER_WINDOW_MINIMUM = (500, 380)


def _notice(
    parent: tk.Misc,
    text: str,
    *,
    warning: bool = False,
    pady: tuple[int, int] = (0, 12),
    bold: bool = False,
) -> tk.Label:
    label = create_responsive_label(
        parent,
        text=text,
        warning=warning,
        background="#d9f3f0",
        foreground="#124b47",
        bold=bold,
    )
    label.pack(fill="x", pady=pady)
    return label


def _localized_finding(
    locale: ProfileLocale,
    finding: RecoveryFormFinding,
) -> str:
    values = (
        {"count": str(finding.word_count)}
        if finding.message_key == "recovery_phrase_word_count"
        else {}
    )
    return profile_text(locale, finding.message_key, **values)


class PaperPhraseConfirmationWindow:
    """One-time full transcription check for a paper backup."""

    def __init__(
        self,
        parent: tk.Misc,
        locale: ProfileLocale,
        verify: Callable[[tuple[str, ...]], None],
        on_closed: Callable[[], None],
    ) -> None:
        self.locale = locale
        self.verify_callback = verify
        self.on_closed = on_closed
        self._closed = False
        self.window = tk.Toplevel(parent)
        self.window.title(self.t("recovery_paper_title"))
        configure_resizable_window(
            self.window,
            geometry=PAPER_WINDOW_GEOMETRY,
            minimum=PAPER_WINDOW_MINIMUM,
            close=self.close,
        )
        content = tk.Frame(self.window, padx=18, pady=16)
        content.pack(fill="both", expand=True)
        _notice(
            content,
            self.t("recovery_paper_intro"),
            warning=True,
            bold=True,
        )
        label = tk.Label(
            content,
            text=self.t("recovery_paper_words"),
            anchor="w",
            font=DEFAULT_ACTION_FONT,
        )
        label.pack(fill="x")
        self.text = tk.Text(
            content,
            height=10,
            wrap="word",
            undo=False,
            font=DEFAULT_BODY_FONT,
        )
        self.text.pack(fill="both", expand=True, pady=(4, 12))
        actions = tk.Frame(content)
        actions.pack(fill="x")
        verify_button = tk.Button(
            actions,
            text=self.t("recovery_paper_verify"),
            command=self.verify,
            font=DEFAULT_ACTION_FONT,
        )
        verify_button.pack(fill="x", pady=(0, 5))
        cancel = tk.Button(
            actions,
            text=self.t("cancel"),
            command=self.close,
            font=DEFAULT_BODY_FONT,
        )
        cancel.pack(fill="x")
        self.window.bind(
            "<Control-Return>",
            lambda _event: (self.verify(), "break")[-1],
            add="+",
        )
        self.text.focus_set()

    def t(self, key: str, **values: str) -> str:
        return profile_text(self.locale, key, **values)

    def _error(self, text: str) -> None:
        try:
            self.text.delete("1.0", "end")
            self.text.focus_set()
        except tk.TclError:
            pass
        show_action_notice(
            self.window,
            title=self.t("recovery_paper_title"),
            text=text,
            close_label=self.t("understand"),
        )

    def verify(self) -> None:
        value = self.text.get("1.0", "end-1c")
        finding = validate_paper_phrase(value)
        if finding is not None:
            value = ""
            self._error(_localized_finding(self.locale, finding))
            return
        words = tuple(value.split())
        value = ""
        try:
            self.verify_callback(words)
        except ProfileRecoveryBackupError:
            words = ()
            self._error(self.t("recovery_paper_not_match"))
            return
        except Exception:
            words = ()
            self._error(self.t("recovery_setup_failed"))
            return
        words = ()
        self.text.delete("1.0", "end")
        show_action_notice(
            self.window,
            title=self.t("recovery_paper_title"),
            text=self.t("recovery_paper_verified"),
            close_label=self.t("understand"),
        )
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.text.delete("1.0", "end")
        except tk.TclError:
            pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass
        self.on_closed()

    def is_open(self) -> bool:
        if self._closed:
            return False
        try:
            return bool(self.window.winfo_exists())
        except tk.TclError:
            return False

    def present(self) -> None:
        if not self.is_open():
            return
        try:
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
        except tk.TclError:
            pass


class RecoverySetupWindow:
    """Explicit current-password setup with separate backup choices."""

    def __init__(
        self,
        parent: tk.Misc,
        profile_root: Any,
        *,
        locale: ProfileLocale,
        on_closed: Callable[[], None] | None = None,
        on_completed: Callable[[], None] | None = None,
    ) -> None:
        self.parent = parent
        self.profile_root = Path(profile_root)
        self.locale = locale
        self.on_closed = on_closed
        self.on_completed = on_completed
        self.plan: PreparedProfileRecoverySetup | None = None
        self.paper_window: PaperPhraseConfirmationWindow | None = None
        self._completed = False
        self._closed = False
        self.current_password = tk.StringVar(value="")
        self.status = tk.StringVar(value=self.t("recovery_setup_reauth"))
        self.window = tk.Toplevel(parent)
        self.window.title(self.t("recovery_setup_title"))
        configure_resizable_window(
            self.window,
            geometry=RECOVERY_SETUP_GEOMETRY,
            minimum=RECOVERY_WINDOW_MINIMUM,
            close=self.close,
        )
        self.widgets: dict[str, tk.Widget] = {}
        self._build()

    def t(self, key: str, **values: str) -> str:
        return profile_text(self.locale, key, **values)

    def _show(self, key: str) -> None:
        show_action_notice(
            self.window,
            title=self.t("recovery_setup_title"),
            text=self.t(key),
            close_label=self.t("understand"),
        )

    def _mask_current_password(self) -> None:
        mask_secret(
            self.widgets["current_password"],
            self.widgets.get("current_password_toggle"),
            show_text=self.t("show_secret"),
        )

    def _build(self) -> None:
        self.scroll_region = create_scrollable_region(self.window)
        content = self.scroll_region.content
        _notice(content, self.t("recovery_setup_intro"), bold=True)
        status = create_responsive_label(
            content,
            textvariable=self.status,
            background="#eef2f7",
            foreground="#1d2b3a",
        )
        status.pack(fill="x", pady=(0, 12))
        self.widgets["status"] = status

        reauth = tk.Frame(content)
        reauth.pack(fill="x", pady=4)
        tk.Label(
            reauth,
            text=self.t("recovery_current_password"),
            anchor="w",
            font=DEFAULT_BODY_FONT,
        ).pack(fill="x")
        entry_row = tk.Frame(reauth)
        entry_row.pack(fill="x", pady=(4, 0))
        password_fields = tk.Frame(entry_row)
        password_fields.grid_columnconfigure(0, weight=1)
        entry = tk.Entry(
            password_fields,
            textvariable=self.current_password,
            show="*",
            font=DEFAULT_BODY_FONT,
        )
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.widgets["current_password"] = entry
        reveal = create_secret_toggle(
            password_fields,
            entry,
            show_text=self.t("show_secret"),
            hide_text=self.t("hide_secret"),
        )
        reveal.grid(row=0, column=1, sticky="e")
        self.widgets["current_password_toggle"] = reveal
        prepare_controls = tk.Frame(entry_row)
        prepare = tk.Button(
            prepare_controls,
            text=self.t("recovery_prepare"),
            command=self.prepare,
            font=DEFAULT_ACTION_FONT,
        )
        prepare.pack()
        self.widgets["prepare"] = prepare
        self.reauth_row = ResponsivePair(
            entry_row,
            password_fields,
            prepare_controls,
            breakpoint=760,
            secondary_stacked_sticky="e",
            fit_requested_widths=True,
        )

        phrase_box = tk.LabelFrame(
            content,
            text=f"MOKOSH-RP1 — {self.t('password_recovery_words')}",
            padx=10,
            pady=10,
            font=DEFAULT_BODY_FONT,
        )
        phrase_box.pack(fill="x", pady=(14, 8))
        self.widgets["phrase_box"] = phrase_box
        phrase_warning = _notice(
            phrase_box,
            self.t("recovery_phrase_warning"),
            warning=True,
            pady=(0, 10),
            bold=True,
        )
        self.widgets["phrase_warning"] = phrase_warning
        grid = tk.Frame(phrase_box)
        grid.pack(fill="x")
        self.phrase_labels: list[tk.Label] = []
        for index in range(25):
            label = tk.Label(
                grid,
                text=f"{index + 1:02d}. —",
                anchor="w",
                padx=4,
                pady=4,
                font=DEFAULT_BODY_FONT,
            )
            self.phrase_labels.append(label)
        self.phrase_grid = ResponsiveGrid(
            grid,
            self.phrase_labels,
            column_rules=((850, 5), (620, 3), (0, 2)),
            padx=4,
            pady=4,
        )

        _notice(content, self.t("recovery_record_help"), pady=(8, 5))
        record = tk.Button(
            content,
            text=self.t("recovery_record_save"),
            command=self.save_record,
            state=tk.DISABLED,
            font=DEFAULT_ACTION_FONT,
        )
        record.pack(fill="x", pady=(0, 10))
        bind_responsive_wrap(record, content, horizontal_inset=70)
        self.widgets["record"] = record

        phrase_help = _notice(
            content,
            self.t("recovery_phrase_help"),
            warning=True,
            pady=(4, 5),
        )
        self.widgets["phrase_help"] = phrase_help
        backups = tk.Frame(content)
        backups.pack(fill="x", pady=(0, 10))
        phrase = tk.Button(
            backups,
            text=self.t("recovery_phrase_save"),
            command=self.save_phrase,
            state=tk.DISABLED,
            font=DEFAULT_ACTION_FONT,
        )
        phrase.pack(fill="x", pady=(0, 5))
        bind_responsive_wrap(phrase, backups, horizontal_inset=40)
        self.widgets["phrase"] = phrase
        paper = tk.Button(
            backups,
            text=self.t("recovery_paper_confirm"),
            command=self.open_paper_confirmation,
            state=tk.DISABLED,
            font=DEFAULT_ACTION_FONT,
        )
        paper.pack(fill="x")
        bind_responsive_wrap(paper, backups, horizontal_inset=40)
        self.widgets["paper"] = paper

        _notice(content, self.t("recovery_finish_help"), pady=(4, 5))
        actions = tk.Frame(content)
        actions.pack(fill="x", pady=(0, 12))
        finish = tk.Button(
            actions,
            text=self.t("recovery_finish"),
            command=self.finish,
            state=tk.DISABLED,
            font=DEFAULT_ACTION_FONT,
        )
        finish.pack(fill="x", pady=(0, 5))
        self.widgets["finish"] = finish
        cancel = tk.Button(
            actions,
            text=self.t("cancel"),
            command=self.close,
            font=DEFAULT_BODY_FONT,
        )
        cancel.pack(fill="x")
        entry.focus_set()

    def _set_phrase(self, words: tuple[str, ...]) -> None:
        for index, (label, word) in enumerate(zip(self.phrase_labels, words), 1):
            label.configure(text=f"{index:02d}. {word}")

    def prepare(self) -> None:
        if self.plan is not None:
            return
        password = self.current_password.get()
        self.current_password.set("")
        self._mask_current_password()
        try:
            self.plan = begin_profile_recovery_setup(
                self.profile_root,
                password,
                ProfileRecoveryDecision.AUTHORIZE,
            )
            words = self.plan.phrase_words
        except ProfileRecoveryAuthenticationError:
            self.plan = None
            self._show("recovery_current_password_failed")
            self.widgets["current_password"].focus_set()
            return
        except Exception:
            self.plan = None
            self._show("recovery_setup_failed")
            self.widgets["current_password"].focus_set()
            return
        finally:
            password = ""
        self._set_phrase(words)
        words = ()
        for name in ("current_password", "current_password_toggle", "prepare"):
            self.widgets[name].configure(state=tk.DISABLED)
        self.widgets["record"].configure(state=tk.NORMAL)
        self.status.set(self.t("recovery_record_help"))

    def save_record(self) -> None:
        if self.plan is None or self.plan.record_exported:
            return
        parent = filedialog.askdirectory(
            parent=self.window,
            mustexist=True,
            title=self.t("recovery_choose_record_parent"),
        )
        if not parent:
            return
        try:
            self.plan.export_record(parent)
        except ProfileRecoveryExportUncertainError:
            self._show("recovery_export_uncertain")
            return
        except ProfileRecoveryStorageUnsupportedError:
            self._show("recovery_storage_unsupported")
            return
        except Exception:
            self._show("recovery_setup_failed")
            return
        self.widgets["record"].configure(state=tk.DISABLED)
        self.widgets["phrase"].configure(state=tk.NORMAL)
        self.widgets["paper"].configure(state=tk.NORMAL)
        self.status.set(self.t("recovery_record_saved"))

    def save_phrase(self) -> None:
        if self.plan is None or not self.plan.record_exported or self.plan.backup_verified:
            return
        parent = filedialog.askdirectory(
            parent=self.window,
            mustexist=True,
            title=self.t("recovery_choose_phrase_parent"),
        )
        if not parent:
            return
        try:
            self.plan.export_phrase(parent)
        except ProfileRecoverySeparationError:
            self._show("recovery_separation_failed")
            return
        except ProfileRecoveryExportUncertainError:
            self._show("recovery_export_uncertain")
            return
        except ProfileRecoveryStorageUnsupportedError:
            self._show("recovery_storage_unsupported")
            return
        except Exception:
            self._show("recovery_setup_failed")
            return
        self._backup_ready(self.t("recovery_phrase_saved"))

    def open_paper_confirmation(self) -> None:
        if self.plan is None or not self.plan.record_exported or self.plan.backup_verified:
            return
        if self.paper_window is not None and self.paper_window.is_open():
            self.paper_window.present()
            return
        self.paper_window = PaperPhraseConfirmationWindow(
            self.window,
            self.locale,
            self._confirm_paper,
            self._paper_closed,
        )

    def _confirm_paper(self, value: tuple[str, ...]) -> None:
        if self.plan is None:
            raise ProfileRecoveryBackupError("recovery setup is unavailable")
        self.plan.confirm_paper_backup(value)
        self._backup_ready(self.t("recovery_paper_verified"))

    def _paper_closed(self) -> None:
        self.paper_window = None

    def _backup_ready(self, text: str) -> None:
        self.widgets["phrase"].configure(state=tk.DISABLED)
        self.widgets["paper"].configure(state=tk.DISABLED)
        self.widgets["finish"].configure(state=tk.NORMAL)
        self.status.set(text)

    def finish(self) -> None:
        if self.plan is None or not self.plan.backup_verified:
            return
        try:
            self.plan.complete(ProfileRecoveryDecision.AUTHORIZE)
        except ProfileRecoveryLifecyclePublishError:
            self.plan = None
            self.widgets["finish"].configure(state=tk.DISABLED)
            self._show("recovery_state_publish_failed")
            self.force_close()
            return
        except ProfileRecoveryStorageUnsupportedError:
            self._show("recovery_storage_unsupported")
            return
        except Exception:
            self._show("recovery_setup_failed")
            return
        self._completed = True
        if self.on_completed is not None:
            self.on_completed()
        self._show("recovery_setup_success")
        self.close()

    def is_open(self) -> bool:
        try:
            return not self._closed and bool(self.window.winfo_exists())
        except tk.TclError:
            return False

    def present(self) -> None:
        if self.is_open():
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()

    def close(self) -> None:
        if not self._closed:
            self._destroy()

    def force_close(self) -> None:
        """Hide secrets immediately when the parent session locks or exits."""

        if not self._closed:
            self._destroy()

    def _destroy(self) -> None:
        self._closed = True
        self.current_password.set("")
        self._mask_current_password()
        if self.paper_window is not None:
            self.paper_window.close()
        if self.plan is not None:
            self.plan.close()
        self.plan = None
        for label in self.phrase_labels:
            label.configure(text="—")
        self.window.destroy()
        if self.on_closed is not None:
            self.on_closed()


class PasswordRecoveryWindow:
    """Locked-profile recovery with read-only preview before publish."""

    def __init__(
        self,
        parent: tk.Misc,
        profile_root: Any,
        *,
        locale: ProfileLocale,
        on_closed: Callable[[], None] | None = None,
        on_completed: Callable[[], None] | None = None,
    ) -> None:
        self.parent = parent
        self.profile_root = Path(profile_root)
        self.locale = locale
        self.on_closed = on_closed
        self.on_completed = on_completed
        self.plan: PreparedProfilePasswordRecovery | None = None
        self._closed = False
        self._technical_visible = False
        self.record_path = tk.StringVar(value="")
        self.sheet_path = tk.StringVar(value="")
        self.mode = tk.StringVar(value="sheet")
        self.new_password = tk.StringVar(value="")
        self.confirmation = tk.StringVar(value="")
        self.status = tk.StringVar(value=self.t("password_recovery_intro"))
        self.technical_details = tk.StringVar(value="")
        self.window = tk.Toplevel(parent)
        self.window.title(self.t("password_recovery_title"))
        configure_resizable_window(
            self.window,
            geometry=PASSWORD_RECOVERY_GEOMETRY,
            minimum=RECOVERY_WINDOW_MINIMUM,
            close=self.close,
        )
        self.widgets: dict[str, tk.Widget] = {}
        self._build()

    def t(self, key: str, **values: str) -> str:
        return profile_text(self.locale, key, **values)

    def _show_text(self, text: str) -> None:
        show_action_notice(
            self.window,
            title=self.t("password_recovery_title"),
            text=text,
            close_label=self.t("understand"),
        )

    def _show(self, key: str, **values: str) -> None:
        self._show_text(self.t(key, **values))

    def _path_row(
        self,
        parent: tk.Misc,
        label_text: str,
        variable: tk.StringVar,
        button_text: str,
        command: Callable[[], None],
        widget_name: str,
    ) -> None:
        row = tk.Frame(parent)
        row.pack(fill="x", pady=5)
        label = tk.Label(row, text=label_text, anchor="w", font=DEFAULT_BODY_FONT)
        label.pack(fill="x")
        value = tk.Label(
            row,
            textvariable=variable,
            anchor="w",
            justify="left",
            font=DEFAULT_BODY_FONT,
            bg="#f7f7f7",
            padx=6,
            pady=4,
        )
        value.pack(fill="x", pady=(3, 4))
        bind_responsive_wrap(value, row, horizontal_inset=24)
        button = tk.Button(row, text=button_text, command=command, font=DEFAULT_BODY_FONT)
        button.pack(fill="x")
        self.widgets[widget_name] = button
        self.widgets[f"{widget_name}_path"] = value

    def _password_row(
        self,
        parent: tk.Misc,
        label_text: str,
        variable: tk.StringVar,
        widget_name: str,
    ) -> None:
        row = tk.Frame(parent)
        row.pack(fill="x", pady=5)
        tk.Label(row, text=label_text, anchor="w", font=DEFAULT_BODY_FONT).pack(
            fill="x"
        )
        entry_row = tk.Frame(row)
        entry_row.pack(fill="x", pady=(3, 0))
        entry = tk.Entry(
            entry_row,
            textvariable=variable,
            show="*",
            font=DEFAULT_BODY_FONT,
        )
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.widgets[widget_name] = entry
        reveal = create_secret_toggle(
            entry_row,
            entry,
            show_text=self.t("show_secret"),
            hide_text=self.t("hide_secret"),
        )
        reveal.pack(side="right")
        self.widgets[f"{widget_name}_toggle"] = reveal

    def _build(self) -> None:
        self.scroll_region = create_scrollable_region(self.window)
        content = self.scroll_region.content
        status = create_responsive_label(
            content,
            textvariable=self.status,
            warning=True,
            bold=True,
        )
        status.pack(fill="x", pady=(0, 12))
        self.widgets["status"] = status
        self._path_row(
            content,
            self.t("password_recovery_record"),
            self.record_path,
            self.t("password_recovery_choose_record"),
            self.choose_record,
            "choose_record",
        )

        mode_row = tk.LabelFrame(
            content,
            text=self.t("password_recovery_phrase_source"),
            padx=8,
            pady=6,
            font=DEFAULT_BODY_FONT,
        )
        mode_row.pack(fill="x", pady=(10, 6))
        sheet_mode = tk.Radiobutton(
            mode_row,
            text=self.t("password_recovery_sheet_mode"),
            variable=self.mode,
            value="sheet",
            command=self._sync_mode,
            anchor="w",
            font=DEFAULT_BODY_FONT,
        )
        sheet_mode.pack(fill="x", padx=4, pady=2)
        words_mode = tk.Radiobutton(
            mode_row,
            text=self.t("password_recovery_words_mode"),
            variable=self.mode,
            value="words",
            command=self._sync_mode,
            anchor="w",
            font=DEFAULT_BODY_FONT,
        )
        words_mode.pack(fill="x", padx=4, pady=2)
        self.widgets["sheet_mode"] = sheet_mode
        self.widgets["words_mode"] = words_mode
        self._path_row(
            content,
            self.t("password_recovery_sheet"),
            self.sheet_path,
            self.t("password_recovery_choose_sheet"),
            self.choose_sheet,
            "choose_sheet",
        )
        tk.Label(
            content,
            text=self.t("password_recovery_words"),
            anchor="w",
            font=DEFAULT_ACTION_FONT,
        ).pack(fill="x", pady=(8, 2))
        words = tk.Text(
            content,
            height=7,
            wrap="word",
            undo=False,
            font=DEFAULT_BODY_FONT,
        )
        words.pack(fill="x")
        self.widgets["words"] = words

        passwords = tk.LabelFrame(content, padx=8, pady=8)
        passwords.pack(fill="x", pady=(12, 8))
        self._password_row(
            passwords,
            self.t("password_recovery_new_password"),
            self.new_password,
            "new_password",
        )
        self._password_row(
            passwords,
            self.t("password_recovery_confirm_password"),
            self.confirmation,
            "confirmation",
        )
        policy = create_responsive_label(
            passwords,
            text=self.t("password_policy"),
            padx=0,
            pady=5,
            horizontal_inset=12,
        )
        policy.pack(fill="x", pady=(5, 0))
        _notice(content, self.t("password_recovery_preview_help"), pady=(6, 5))

        technical = create_responsive_label(
            content,
            textvariable=self.technical_details,
            background="#eef2f7",
            foreground="#333333",
        )
        self.widgets["technical_details"] = technical
        technical_toggle = tk.Button(
            content,
            text=self.t("technical_details_show"),
            command=self._toggle_technical_details,
            font=DEFAULT_BODY_FONT,
        )
        self.widgets["technical_toggle"] = technical_toggle

        actions = tk.Frame(content)
        actions.pack(fill="x", pady=(0, 12))
        preview = tk.Button(
            actions,
            text=self.t("password_recovery_preview"),
            command=self.prepare_preview,
            font=DEFAULT_ACTION_FONT,
        )
        preview.pack(fill="x", pady=(0, 5))
        self.widgets["preview"] = preview
        publish = tk.Button(
            actions,
            text=self.t("password_recovery_publish"),
            command=self.publish,
            state=tk.DISABLED,
            font=DEFAULT_ACTION_FONT,
        )
        publish.pack(fill="x", pady=(0, 5))
        self.widgets["publish"] = publish
        cancel = tk.Button(
            actions,
            text=self.t("cancel"),
            command=self.close,
            font=DEFAULT_BODY_FONT,
        )
        cancel.pack(fill="x")
        self._sync_mode()

    def _toggle_technical_details(self) -> None:
        label = self.widgets["technical_details"]
        toggle = self.widgets["technical_toggle"]
        if self._technical_visible:
            label.pack_forget()
            toggle.configure(text=self.t("technical_details_show"))
            self._technical_visible = False
        else:
            label.pack(fill="x", pady=(0, 5), before=toggle)
            toggle.configure(text=self.t("technical_details_hide"))
            self._technical_visible = True

    def _sync_mode(self) -> None:
        sheet = self.mode.get() == "sheet"
        self.widgets["choose_sheet"].configure(
            state=tk.NORMAL if sheet else tk.DISABLED
        )
        self.widgets["choose_sheet_path"].configure(
            state=tk.NORMAL if sheet else tk.DISABLED
        )
        self.widgets["words"].configure(
            state=tk.DISABLED if sheet else tk.NORMAL
        )
        if sheet:
            try:
                self.widgets["words"].configure(state=tk.NORMAL)
                self.widgets["words"].delete("1.0", "end")
            finally:
                self.widgets["words"].configure(state=tk.DISABLED)
        else:
            self.sheet_path.set("")

    def choose_record(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.window,
            title=self.t("password_recovery_choose_record_title"),
            filetypes=((self.t("password_recovery_record"), "*.mokr"),),
        )
        if selected:
            self.record_path.set(selected)

    def choose_sheet(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.window,
            title=self.t("password_recovery_choose_sheet_title"),
            filetypes=((self.t("password_recovery_sheet"), "*.txt"),),
        )
        if selected:
            self.sheet_path.set(selected)

    def _mask_passwords(self) -> None:
        for name in ("new_password", "confirmation"):
            mask_secret(
                self.widgets[name],
                self.widgets.get(f"{name}_toggle"),
                show_text=self.t("show_secret"),
            )

    def _clear_secrets(self) -> None:
        self.new_password.set("")
        self.confirmation.set("")
        self._mask_passwords()
        try:
            previous = self.widgets["words"].cget("state")
            self.widgets["words"].configure(state=tk.NORMAL)
            self.widgets["words"].delete("1.0", "end")
            self.widgets["words"].configure(state=previous)
        except (tk.TclError, AttributeError):
            pass

    def _focus(self, name: str) -> None:
        target = self.widgets.get(name)
        if target is not None:
            try:
                target.focus_set()
            except (tk.TclError, AttributeError):
                pass

    def _handle_finding(self, finding: RecoveryFormFinding) -> None:
        # Every failed attempt clears all user-entered secret material.  The
        # selected non-secret paths stay visible so the person can correct one
        # source without having to rediscover the files.
        self._clear_secrets()
        self._show_text(_localized_finding(self.locale, finding))
        self._focus(finding.focus_target)

    def prepare_preview(self) -> None:
        if self.plan is not None:
            return
        record = self.record_path.get()
        password = self.new_password.get()
        confirmation = self.confirmation.get()
        mode = self.mode.get()
        words = self.widgets["words"].get("1.0", "end-1c")
        sheet = self.sheet_path.get()
        finding = validate_password_recovery_form(
            record_path=record,
            source_mode=mode,
            sheet_path=sheet,
            words=words,
            new_password=password,
            confirmation=confirmation,
        )
        if finding is not None:
            password = confirmation = words = ""
            self._handle_finding(finding)
            return
        try:
            if mode == "sheet":
                self.plan = prepare_profile_password_recovery_from_sheet(
                    self.profile_root,
                    record,
                    sheet,
                    password,
                    confirmation,
                    ProfileRecoveryDecision.AUTHORIZE,
                )
            else:
                self.plan = prepare_profile_password_recovery_from_words(
                    self.profile_root,
                    record,
                    words,
                    password,
                    confirmation,
                    ProfileRecoveryDecision.AUTHORIZE,
                )
        except ProfileRecoverySeparationError:
            self.plan = None
            self._clear_secrets()
            self._sync_mode()
            self._show("recovery_separation_failed")
            return
        except ProfileRecoveryStorageUnsupportedError:
            self.plan = None
            self._clear_secrets()
            self._sync_mode()
            self._show("recovery_storage_unsupported")
            return
        except (ProfileRecoveryInputError, ProfileRecoveryStateError):
            self.plan = None
            self._clear_secrets()
            self._sync_mode()
            self._show("password_recovery_failed")
            return
        except Exception:
            self.plan = None
            self._clear_secrets()
            self._sync_mode()
            self._show("password_recovery_failed")
            return
        finally:
            password = confirmation = words = ""
        preview = self.plan.preview
        self._clear_secrets()
        for name in (
            "choose_record",
            "choose_sheet",
            "sheet_mode",
            "words_mode",
            "words",
            "new_password",
            "new_password_toggle",
            "confirmation",
            "confirmation_toggle",
            "preview",
        ):
            self.widgets[name].configure(state=tk.DISABLED)
        self.widgets["publish"].configure(state=tk.NORMAL)
        self.status.set(self.t("password_recovery_preview_ready"))
        self.technical_details.set(
            self.t(
                "password_recovery_technical_details",
                source_revision=str(preview.source_revision),
                target_revision=str(preview.target_revision),
            )
        )
        self.widgets["technical_toggle"].pack(fill="x", pady=(0, 5))

    def publish(self) -> None:
        if self.plan is None:
            return
        if not ask_action_decision(
            self.window,
            title=self.t("password_recovery_title"),
            text=self.t("password_recovery_publish_warning"),
            approve_label=self.t("password_recovery_publish"),
            cancel_label=self.t("back_without_change"),
        ):
            return
        try:
            self.plan.publish(ProfileRecoveryDecision.AUTHORIZE)
        except ProfileRecoveryPublishUncertainError:
            self.plan = None
            self.widgets["publish"].configure(state=tk.DISABLED)
            self._show("password_recovery_uncertain")
            return
        except Exception:
            self.plan = None
            self.widgets["publish"].configure(state=tk.DISABLED)
            self._show("password_recovery_failed")
            return
        self.plan = None
        self._clear_secrets()
        if self.on_completed is not None:
            self.on_completed()
        self._show("password_recovery_success")
        self.close()

    def is_open(self) -> bool:
        try:
            return not self._closed and bool(self.window.winfo_exists())
        except tk.TclError:
            return False

    def present(self) -> None:
        if self.is_open():
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._clear_secrets()
        self.record_path.set("")
        self.sheet_path.set("")
        self.technical_details.set("")
        if self.plan is not None:
            self.plan.close()
        self.plan = None
        self.window.destroy()
        if self.on_closed is not None:
            self.on_closed()


__all__ = [
    "PAPER_WINDOW_GEOMETRY",
    "PAPER_WINDOW_MINIMUM",
    "PASSWORD_RECOVERY_GEOMETRY",
    "RECOVERY_SETUP_GEOMETRY",
    "RECOVERY_WINDOW_MINIMUM",
    "PaperPhraseConfirmationWindow",
    "PasswordRecoveryWindow",
    "RecoverySetupWindow",
]
