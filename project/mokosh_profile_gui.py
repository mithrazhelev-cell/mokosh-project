"""Normal Stage 2.48 protected-profile GUI.

This window intentionally preserves the established MOKOSH layout: language
and local-folder rows, password/nickname login rows, then two symmetric rows
of three action buttons.  Historical MOK1 recovery and the isolated optional
profile-password recovery routes are available through explicit gates;
unfinished actions remain fail-closed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any

from mokosh_profile_localization import ProfileLocale, profile_text
from mokosh_profile_recovery_state import (
    ProfileRecoveryAvailability,
    ProfileRecoveryLoginNotice,
    ProfileRecoveryStateInspection,
    inspect_profile_recovery_state,
    note_successful_login_for_recovery,
)
from mokosh_profile_session import (
    ProfileCapability,
    ProfileLockReason,
    ProfileSessionState,
    SecureProfileSession,
)
from mokosh_profile_storage import (
    ProfileConflictError,
    ProfileInspection,
    ProfileState,
    ProfileValidationError,
    create_profile,
    default_profile_root,
    inspect_profile,
    load_profile,
)
from mokosh_profile_ui import (
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
)


PROFILE_GUI_GEOMETRY = "820x680"
PROFILE_GUI_MINIMUM = (620, 480)
PROFILE_GUI_POLL_MILLISECONDS = 1000


class ProfileGUIError(RuntimeError):
    """The normal protected-profile GUI cannot continue safely."""


class ProfileApplicationController:
    """Small non-Tk controller that keeps all action gates explicit."""

    def __init__(self, profile_root: Any | None = None) -> None:
        self.profile_root = Path(
            default_profile_root() if profile_root is None else profile_root
        )
        self.inspection: ProfileInspection
        self.session: SecureProfileSession | None = None
        self.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.INVALID,
            "uninitialized",
        )
        self.recovery_login_notice: ProfileRecoveryLoginNotice | None = None
        self.refresh()

    def refresh(self) -> ProfileInspection:
        if self.session is not None:
            self.session.close()
            self.session = None
        self.inspection = inspect_profile(self.profile_root)
        if self.inspection.state is ProfileState.READY:
            snapshot = load_profile(self.profile_root)
            self.session = SecureProfileSession(snapshot)
            self.recovery_state = inspect_profile_recovery_state(
                self.profile_root,
                snapshot=snapshot,
            )
        else:
            self.recovery_state = ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.MISSING,
                "profile_not_ready",
            )
        self.recovery_login_notice = None
        return self.inspection

    def refresh_recovery_state(self) -> ProfileRecoveryStateInspection:
        if self.inspection.state is not ProfileState.READY:
            self.recovery_state = ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.MISSING,
                "profile_not_ready",
            )
            return self.recovery_state
        try:
            snapshot = load_profile(self.profile_root)
            self.recovery_state = inspect_profile_recovery_state(
                self.profile_root,
                snapshot=snapshot,
            )
        except Exception as exc:
            self.recovery_state = ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.INVALID,
                type(exc).__name__,
            )
        return self.recovery_state

    @property
    def state(self) -> ProfileSessionState:
        if self.session is None:
            return ProfileSessionState.LOCKED
        return self.session.state

    @property
    def capabilities(self) -> dict[ProfileCapability, bool]:
        if self.session is None:
            from mokosh_profile_session import capability_registry

            return capability_registry(ProfileSessionState.LOCKED)
        return self.session.capabilities

    def create(self, nickname: str, password: str, confirmation: str) -> None:
        if password != confirmation:
            raise ProfileValidationError("password confirmation differs")
        create_profile(nickname, password, self.profile_root)
        inspection = self.refresh()
        if inspection.state is not ProfileState.READY or self.session is None:
            raise ProfileConflictError("new protected profile is not ready")

    def login(self, nickname: str, password: str):
        if self.session is None:
            raise ProfileGUIError("protected profile is unavailable")
        result = self.session.unlock(nickname, password)
        self.recovery_login_notice = None
        if result.unlocked:
            try:
                notice = note_successful_login_for_recovery(self.profile_root)
            except Exception:
                self.refresh_recovery_state()
            else:
                self.recovery_state = notice.inspection
                self.recovery_login_notice = notice
        return result

    def consume_recovery_login_notice(self) -> ProfileRecoveryLoginNotice | None:
        result = self.recovery_login_notice
        self.recovery_login_notice = None
        return result

    def lock(self, reason: ProfileLockReason = ProfileLockReason.USER) -> None:
        if self.session is not None:
            self.session.lock(reason)

    def close(self) -> None:
        if self.session is not None:
            self.session.close()


class FirstRunProfileWindow:
    """Explicit first-run creation; optional recovery waits for first login."""

    def __init__(self, application: "ProfileMainWindow") -> None:
        self.application = application
        self.locale = application.locale
        self.widgets: dict[str, tk.Widget] = {}
        self._closed = False
        self._modal_active = False
        self._activation_after_id: str | None = None
        self.window = tk.Toplevel(application.root)
        self.window.title(self.t("create_title"))
        self.nickname = tk.StringVar(value="")
        self.password = tk.StringVar(value="")
        self.confirmation = tk.StringVar(value="")
        configure_resizable_window(
            self.window,
            geometry="650x520",
            minimum=(500, 420),
            close=self.close,
        )
        self._build()
        self.window.bind("<Map>", self._on_map, add="+")
        self.window.bind("<Unmap>", self._on_unmap, add="+")

    def t(self, key: str) -> str:
        return profile_text(self.locale, key)

    def _build(self) -> None:
        region = create_scrollable_region(self.window)
        outer = region.content
        intro = create_responsive_label(
            outer,
            text=self.t("create_intro"),
            background="#d9f3f0",
            foreground="#124b47",
            bold=True,
        )
        intro.pack(fill="x", pady=(0, 14))
        self.widgets["nickname_entry"] = self._entry_row(
            outer, self.t("create_nickname"), self.nickname, False, None
        )
        self.widgets["password_entry"] = self._entry_row(
            outer,
            self.t("create_password"),
            self.password,
            True,
            "password_toggle",
        )
        self.widgets["confirmation_entry"] = self._entry_row(
            outer,
            self.t("create_confirm"),
            self.confirmation,
            True,
            "confirmation_toggle",
        )
        policy = create_responsive_label(
            outer,
            text=self.t("password_policy"),
            foreground="#333333",
        )
        policy.pack(fill="x", pady=(10, 5))
        recovery = create_responsive_label(
            outer,
            text=self.t("recovery_unavailable"),
            warning=True,
        )
        recovery.pack(fill="x", pady=(4, 14))
        actions = tk.Frame(outer)
        actions.pack(fill="x")
        create = tk.Button(
            actions,
            text=self.t("create_action"),
            command=self.create,
            font=("TkDefaultFont", 11, "bold"),
        )
        create.pack(fill="x", pady=(0, 5))
        self.widgets["create"] = create
        cancel = tk.Button(
            actions,
            text=self.t("cancel"),
            command=self.close,
        )
        cancel.pack(fill="x")
        self.widgets["cancel"] = cancel

    def _entry_row(
        self,
        parent: tk.Misc,
        label: str,
        variable: tk.StringVar,
        secret: bool,
        toggle_name: str | None,
    ) -> tk.Entry:
        frame = tk.Frame(parent)
        frame.pack(fill="x", pady=5)
        tk.Label(frame, text=label, anchor="w").pack(fill="x")
        row = tk.Frame(frame)
        row.pack(fill="x", pady=(3, 0))
        entry = tk.Entry(row, textvariable=variable, show="*" if secret else "")
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        if secret:
            assert toggle_name is not None
            toggle = create_secret_toggle(
                row,
                entry,
                show_text=self.t("show_secret"),
                hide_text=self.t("hide_secret"),
            )
            toggle.pack(side="right")
            self.widgets[toggle_name] = toggle
        return entry

    def _mask_creation_secrets(self) -> None:
        widgets = getattr(self, "widgets", {})
        for entry_name, toggle_name in (
            ("password_entry", "password_toggle"),
            ("confirmation_entry", "confirmation_toggle"),
        ):
            if entry_name not in widgets:
                continue
            mask_secret(
                widgets[entry_name],
                widgets.get(toggle_name),
                show_text=self.t("show_secret"),
            )

    def _on_map(self, event: tk.Event) -> None:
        """Schedule modal activation only after Tk reports the real map."""
        if getattr(event, "widget", None) is self.window:
            self._schedule_modal_activation()

    def _on_unmap(self, event: tk.Event) -> None:
        if getattr(event, "widget", None) is not self.window:
            return
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        self._modal_active = False

    def _schedule_modal_activation(self) -> None:
        """Queue one non-blocking activation after pending map work."""
        if (
            self._closed
            or self._modal_active
            or self._activation_after_id is not None
        ):
            return
        try:
            self._activation_after_id = self.window.after_idle(
                self._activate_when_viewable
            )
        except tk.TclError:
            self._activation_after_id = None

    def _activate_when_viewable(self) -> None:
        """Focus and acquire a local grab without waiting synchronously."""
        self._activation_after_id = None
        if self._closed or self._modal_active:
            return
        try:
            if not self.window.winfo_exists() or not self.window.winfo_viewable():
                return
            self.widgets["nickname_entry"].focus_set()
            self.window.grab_set()
        except tk.TclError:
            return
        self._modal_active = True

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
            self.window.lift()
            if self._modal_active:
                self.widgets["nickname_entry"].focus_set()
            else:
                self._schedule_modal_activation()
        except tk.TclError:
            return

    def create(self) -> None:
        password = self.password.get()
        confirmation = self.confirmation.get()
        if password != confirmation:
            self.password.set("")
            self.confirmation.set("")
            self._mask_creation_secrets()
            show_action_notice(
                self.window,
                title=self.t("create_title"),
                text=self.t("password_mismatch"),
                close_label=self.t("understand"),
            )
            self.widgets["password_entry"].focus_set()
            return
        try:
            self.application.controller.create(
                self.nickname.get(), password, confirmation
            )
        except ProfileValidationError as exc:
            self.password.set("")
            self.confirmation.set("")
            self._mask_creation_secrets()
            key = (
                "invalid_nickname"
                if "nickname" in str(exc)
                else "invalid_password"
            )
            show_action_notice(
                self.window,
                title=self.t("create_title"),
                text=self.t(key),
                close_label=self.t("understand"),
            )
            return
        except Exception:
            self.password.set("")
            self.confirmation.set("")
            self._mask_creation_secrets()
            self.application.controller.refresh()
            self.application.refresh_view()
            show_action_notice(
                self.window,
                title=self.t("create_title"),
                text=self.t("create_failed"),
                close_label=self.t("understand"),
            )
            return
        self.password.set("")
        self.confirmation.set("")
        self.nickname.set("")
        self._mask_creation_secrets()
        show_action_notice(
            self.window,
            title=self.t("create_title"),
            text=self.t("create_success"),
            close_label=self.t("understand"),
        )
        self.close()
        self.application.refresh_view()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.password.set("")
        self.confirmation.set("")
        self.nickname.set("")
        self._mask_creation_secrets()
        if self.application.first_run_window is self:
            self.application.first_run_window = None
        pending = self._activation_after_id
        self._activation_after_id = None
        if pending is not None:
            try:
                self.window.after_cancel(pending)
            except tk.TclError:
                pass
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        self._modal_active = False
        try:
            self.window.destroy()
        except tk.TclError:
            pass


class ProfileMainWindow:
    """Normal user window with the established symmetric MOKOSH layout."""

    def __init__(
        self,
        root: tk.Tk,
        controller: ProfileApplicationController,
        *,
        locale: ProfileLocale = ProfileLocale.ENGLISH,
        auto_first_run_prompt: bool = True,
    ) -> None:
        self.root = root
        self.controller = controller
        self.locale = locale
        self.auto_first_run_prompt = auto_first_run_prompt
        self.widgets: dict[str, tk.Widget] = {}
        self.first_run_window: FirstRunProfileWindow | None = None
        self.recovery_setup_window: Any | None = None
        self.password_recovery_window: Any | None = None
        self.local_v2_window: Any | None = None
        self.legacy_mok1_window: Any | None = None
        self.local_folder = tk.StringVar(value="")
        self.password = tk.StringVar(value="")
        self.nickname = tk.StringVar(value="")
        self.locale_variable = tk.StringVar(value=locale.value)
        self.status_variable = tk.StringVar(value="")
        self.recovery_status_variable = tk.StringVar(value="")
        self.folder_variable = tk.StringVar(value=self.t("no_local_folder"))
        self._closed = False
        self._build()
        self.refresh_view()
        self.root.bind_all("<Control-Shift-L>", self._panic_lock, add="+")
        self.root.bind_all("<Control-Shift-l>", self._panic_lock, add="+")
        self.root.bind("<Return>", self._enter_login, add="+")
        for event_name in ("<KeyPress>", "<ButtonPress>", "<MouseWheel>"):
            self.root.bind_all(event_name, self._user_activity, add="+")
        self.root.after(PROFILE_GUI_POLL_MILLISECONDS, self._poll_session)
        if (
            auto_first_run_prompt
            and controller.inspection.state is ProfileState.ABSENT
        ):
            self.root.after_idle(self.open_first_run)

    def t(self, key: str, **values: str) -> str:
        return profile_text(self.locale, key, **values)

    def _build(self) -> None:
        self.root.title(self.t("title"))
        configure_resizable_window(
            self.root,
            geometry=PROFILE_GUI_GEOMETRY,
            minimum=PROFILE_GUI_MINIMUM,
            close=self.close,
        )

        outer = tk.Frame(self.root)
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, highlightthickness=0)
        scrollbar = tk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        content = tk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        content.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window_id, width=event.width),
        )
        canvas.bind("<MouseWheel>", self._scroll_content, add="+")
        canvas.bind("<Button-4>", self._scroll_content, add="+")
        canvas.bind("<Button-5>", self._scroll_content, add="+")
        canvas.bind("<Prior>", lambda _event: canvas.yview_scroll(-1, "pages"))
        canvas.bind("<Next>", lambda _event: canvas.yview_scroll(1, "pages"))
        canvas.bind("<Home>", lambda _event: canvas.yview_moveto(0.0))
        canvas.bind("<End>", lambda _event: canvas.yview_moveto(1.0))
        self.canvas = canvas
        self.content = content

        status = tk.Label(
            content,
            textvariable=self.status_variable,
            justify="left",
            anchor="w",
            wraplength=760,
            padx=10,
            pady=9,
            font=("TkDefaultFont", 10, "bold"),
        )
        status.pack(fill="x", padx=10, pady=(10, 5))
        bind_responsive_wrap(status, content, horizontal_inset=40)
        self.widgets["status"] = status

        language = tk.Frame(content)
        language.pack(fill="x", padx=10, pady=5)
        label = tk.Label(language, font=("TkDefaultFont", 11), anchor="w")
        label.pack(side="left", padx=5)
        self.widgets["language_label"] = label
        for text, value in (("EN", "en"), ("BG", "bg")):
            tk.Radiobutton(
                language,
                text=text,
                value=value,
                variable=self.locale_variable,
                command=self.change_language,
            ).pack(side="left", padx=3)

        folder = tk.Frame(content)
        folder.pack(fill="x", padx=10, pady=5)
        folder_information = tk.Frame(folder)
        folder_information.grid_columnconfigure(1, weight=1)
        label = tk.Label(
            folder_information,
            width=10,
            font=("TkDefaultFont", 11),
            anchor="w",
        )
        label.grid(row=0, column=0, sticky="w", padx=5)
        self.widgets["folder_label"] = label
        folder_value = tk.Label(
            folder_information,
            textvariable=self.folder_variable,
            font=("TkDefaultFont", 11),
            anchor="w",
            justify="left",
            width=1,
        )
        folder_value.grid(row=0, column=1, sticky="ew", padx=5)
        bind_responsive_wrap(
            folder_value,
            folder_information,
            horizontal_inset=130,
        )
        folder_controls = tk.Frame(folder)
        choose = tk.Button(
            folder_controls,
            command=self.choose_local_folder,
            font=("TkDefaultFont", 11, "bold"),
        )
        choose.pack(fill="x", expand=True)
        self.widgets["choose_folder"] = choose
        self.folder_row = ResponsivePair(
            folder,
            folder_information,
            folder_controls,
            breakpoint=760,
        )

        password_frame = tk.Frame(content)
        password_frame.pack(fill="x", padx=10, pady=5)
        password_fields = tk.Frame(password_frame)
        password_fields.grid_columnconfigure(1, weight=1)
        label = tk.Label(password_fields, width=10, anchor="w", font=("TkDefaultFont", 11))
        label.grid(row=0, column=0, sticky="w", padx=5)
        self.widgets["password_label"] = label
        password_entry = tk.Entry(
            password_fields,
            textvariable=self.password,
            show="*",
            width=1,
            font=("TkDefaultFont", 11),
        )
        password_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.widgets["password_entry"] = password_entry
        password_controls = tk.Frame(password_frame)
        password_controls.grid_columnconfigure(0, weight=1, uniform="password-controls")
        password_controls.grid_columnconfigure(1, weight=1, uniform="password-controls")
        password_toggle = create_secret_toggle(
            password_controls,
            password_entry,
            show_text=self.t("show_secret"),
            hide_text=self.t("hide_secret"),
        )
        password_toggle.grid(row=0, column=0, sticky="ew", padx=5)
        self.widgets["password_toggle"] = password_toggle
        login = tk.Button(
            password_controls,
            command=self.login_or_lock,
            font=("TkDefaultFont", 12, "bold"),
        )
        login.grid(row=0, column=1, sticky="ew", padx=5)
        self.widgets["login"] = login
        self.password_row = ResponsivePair(
            password_frame,
            password_fields,
            password_controls,
            breakpoint=760,
        )

        nickname_frame = tk.Frame(content)
        nickname_frame.pack(fill="x", padx=10, pady=5)
        nickname_fields = tk.Frame(nickname_frame)
        nickname_fields.grid_columnconfigure(1, weight=1)
        label = tk.Label(nickname_fields, width=10, anchor="w", font=("TkDefaultFont", 11))
        label.grid(row=0, column=0, sticky="w", padx=5)
        self.widgets["nickname_label"] = label
        nickname_entry = tk.Entry(
            nickname_fields,
            textvariable=self.nickname,
            show="*",
            width=20,
            font=("TkDefaultFont", 11),
        )
        nickname_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.widgets["nickname_entry"] = nickname_entry
        nickname_toggle = create_secret_toggle(
            nickname_fields,
            nickname_entry,
            show_text=self.t("show_secret"),
            hide_text=self.t("hide_secret"),
        )
        nickname_toggle.grid(row=0, column=2, sticky="e", padx=5)
        self.widgets["nickname_toggle"] = nickname_toggle
        nickname_controls = tk.Frame(nickname_frame)
        create = tk.Button(
            nickname_controls,
            command=self.open_first_run,
            width=22,
            font=("TkDefaultFont", 10, "bold"),
        )
        create.pack()
        self.widgets["create_profile"] = create
        self.nickname_row = ResponsivePair(
            nickname_frame,
            nickname_fields,
            nickname_controls,
            breakpoint=760,
            secondary_stacked_sticky="e",
            fit_requested_widths=True,
        )

        actions = tk.Frame(content)
        actions.pack(fill="x", padx=10, pady=(24, 8))
        definitions = (
            ("encrypt", 0, 0, self.open_local_encrypt),
            ("decrypt", 0, 1, self.open_local_decrypt),
            ("clean", 0, 2, self._unavailable),
            ("contacts", 1, 0, self._unavailable),
            ("contact_crypto", 1, 1, self._unavailable),
            ("sandbox", 1, 2, self._unavailable),
        )
        action_buttons: list[tk.Button] = []
        for name, _row, _column, command in definitions:
            button = tk.Button(
                actions,
                command=command,
                font=("TkDefaultFont", 11, "bold"),
                height=2,
            )
            self.widgets[name] = button
            action_buttons.append(button)
        self.action_grid = ResponsiveGrid(
            actions,
            action_buttons,
            column_rules=((700, 3), (460, 2), (0, 1)),
            padx=5,
            pady=8,
        )

        recovery = tk.LabelFrame(content, padx=10, pady=8)
        recovery.pack(fill="x", padx=15, pady=(8, 6))
        self.widgets["recovery_section"] = recovery
        help_label = tk.Label(
            recovery,
            justify="left",
            anchor="w",
            wraplength=740,
            fg="#333333",
        )
        help_label.pack(fill="x", pady=(0, 7))
        bind_responsive_wrap(help_label, recovery, horizontal_inset=30)
        self.widgets["recovery_main_help"] = help_label
        recovery_status = create_responsive_label(
            recovery,
            textvariable=self.recovery_status_variable,
            background="#eef2f7",
            foreground="#1d2b3a",
            bold=True,
            horizontal_inset=30,
        )
        recovery_status.pack(fill="x", pady=(0, 7))
        self.widgets["recovery_status"] = recovery_status
        recovery_actions = tk.Frame(recovery)
        recovery_actions.pack(fill="x")
        setup_recovery = tk.Button(
            recovery_actions,
            command=self.open_recovery_setup,
            font=("TkDefaultFont", 10, "bold"),
        )
        self.widgets["recovery_setup"] = setup_recovery
        recover_password = tk.Button(
            recovery_actions,
            command=self.open_password_recovery,
            font=("TkDefaultFont", 10, "bold"),
        )
        self.widgets["recovery_password"] = recover_password
        legacy_decrypt = tk.Button(
            recovery_actions,
            command=self.open_legacy_decrypt,
            font=("TkDefaultFont", 10, "bold"),
        )
        self.widgets["recovery_legacy"] = legacy_decrypt
        self.recovery_action_grid = ResponsiveGrid(
            recovery_actions,
            (setup_recovery, recover_password, legacy_decrypt),
            column_rules=((700, 3), (460, 2), (0, 1)),
            padx=5,
            pady=4,
        )

        footer = tk.Frame(content)
        footer.pack(fill="x", padx=15, pady=(8, 14))
        maintenance = tk.Button(footer, command=self.open_maintenance)
        self.widgets["maintenance"] = maintenance
        panic = tk.Label(footer, anchor="e", justify="left", fg="#555555")
        self.widgets["panic_hint"] = panic
        bind_responsive_wrap(panic, footer, horizontal_inset=30)
        self.footer_row = ResponsivePair(
            footer,
            maintenance,
            panic,
            breakpoint=700,
            primary_sticky="w",
            secondary_stacked_sticky="w",
        )

    @staticmethod
    def _toggle_secret(entry: tk.Entry) -> None:
        entry.configure(show="" if entry.cget("show") == "*" else "*")

    def _mask_login_secrets(self) -> None:
        widgets = getattr(self, "widgets", {})
        for entry_name, toggle_name in (
            ("password_entry", "password_toggle"),
            ("nickname_entry", "nickname_toggle"),
        ):
            if entry_name not in widgets:
                continue
            mask_secret(
                widgets[entry_name],
                widgets.get(toggle_name),
                show_text=self.t("show_secret"),
            )

    def _scroll_content(self, event: tk.Event) -> str | None:
        if getattr(event, "num", None) == 4:
            units = -1
        elif getattr(event, "num", None) == 5:
            units = 1
        else:
            delta = getattr(event, "delta", 0)
            if isinstance(delta, bool) or not isinstance(delta, (int, float)) or delta == 0:
                return None
            units = -1 if delta > 0 else 1
        self.canvas.yview_scroll(units, "units")
        return "break"

    def change_language(self) -> None:
        value = self.locale_variable.get()
        self.locale = (
            ProfileLocale.BULGARIAN if value == "bg" else ProfileLocale.ENGLISH
        )
        self.refresh_view()
        current = getattr(self, "local_v2_window", None)
        if current is not None:
            try:
                current.set_locale(self.locale)
            except Exception:
                self._force_close_local_v2()

    def _status_text(self) -> tuple[str, str, str]:
        inspection = self.controller.inspection
        if inspection.state is ProfileState.UNSUPPORTED:
            return self.t("status_unsupported"), "#f8d7da", "#6b1118"
        if inspection.state in {ProfileState.PARTIAL, ProfileState.CONFLICT}:
            return self.t("status_partial"), "#f8d7da", "#6b1118"
        if inspection.state is ProfileState.ABSENT:
            return self.t("status_no_profile"), "#fff3cd", "#6b4b00"
        if self.controller.state is ProfileSessionState.UNLOCKED:
            assert self.controller.session is not None
            return (
                self.t("status_unlocked", nickname=self.controller.session.nickname),
                "#d9f3f0",
                "#124b47",
            )
        text = self.t("status_locked")
        if inspection.legacy_login_records_present:
            text += " " + self.t("status_legacy")
        return text, "#d9f3f0", "#124b47"

    def _recovery_status_text(self) -> tuple[str, str, str]:
        state = getattr(
            self.controller,
            "recovery_state",
            ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.INVALID,
                "unavailable",
            ),
        )
        unlocked = self.controller.state is ProfileSessionState.UNLOCKED
        if not unlocked:
            key = (
                "recovery_status_locked_current"
                if state.recovery_available
                else "recovery_status_locked_unavailable"
            )
            colors = (
                ("#d9f3f0", "#124b47")
                if state.recovery_available
                else ("#fff3cd", "#5b4000")
            )
            return self.t(key), *colors
        mapping = {
            ProfileRecoveryAvailability.CURRENT: (
                "recovery_status_current",
                "#d9f3f0",
                "#124b47",
            ),
            ProfileRecoveryAvailability.MISSING: (
                "recovery_status_missing",
                "#fff3cd",
                "#5b4000",
            ),
            ProfileRecoveryAvailability.REPLACEMENT_REQUIRED: (
                "recovery_status_replacement",
                "#fff3cd",
                "#5b4000",
            ),
            ProfileRecoveryAvailability.INVALID: (
                "recovery_status_invalid",
                "#f8d7da",
                "#6b1118",
            ),
        }
        key, background, foreground = mapping[state.availability]
        return self.t(key), background, foreground

    def refresh_view(self) -> None:
        self.root.title(self.t("title"))
        labels = {
            "language_label": "language",
            "folder_label": "local_folder",
            "choose_folder": "choose_local_folder",
            "password_label": "password",
            "nickname_label": "nickname",
            "create_profile": "create_profile",
            "encrypt": "encrypt",
            "decrypt": "decrypt",
            "clean": "clean",
            "contacts": "contacts",
            "contact_crypto": "contact_crypto",
            "sandbox": "sandbox",
            "recovery_section": "recovery_section",
            "recovery_main_help": "recovery_main_help",
            "recovery_setup": "recovery_setup",
            "recovery_password": "recovery_password",
            "recovery_legacy": "legacy_decrypt",
            "maintenance": "maintenance",
            "panic_hint": "panic_hint",
        }
        for widget_name, key in labels.items():
            self.widgets[widget_name].configure(text=self.t(key))
        status, background, foreground = self._status_text()
        self.status_variable.set(status)
        self.widgets["status"].configure(bg=background, fg=foreground)
        recovery_text, recovery_background, recovery_foreground = (
            self._recovery_status_text()
        )
        self.recovery_status_variable.set(recovery_text)
        self.widgets["recovery_status"].configure(
            bg=recovery_background,
            fg=recovery_foreground,
        )
        self._mask_login_secrets()
        if not self.local_folder.get():
            self.folder_variable.set(self.t("no_local_folder"))

        ready = self.controller.inspection.state is ProfileState.READY
        unlocked = self.controller.state is ProfileSessionState.UNLOCKED
        self.widgets["login"].configure(
            text=self.t("lock" if unlocked else "login"),
            state=tk.NORMAL if ready else tk.DISABLED,
        )
        self.widgets["create_profile"].configure(
            state=(
                tk.NORMAL
                if self.controller.inspection.state is ProfileState.ABSENT
                else tk.DISABLED
            )
        )
        for name in ("password_entry", "nickname_entry"):
            self.widgets[name].configure(state=tk.DISABLED if unlocked else (tk.NORMAL if ready else tk.DISABLED))
        self.widgets["choose_folder"].configure(
            state=tk.NORMAL if unlocked else tk.DISABLED
        )
        capabilities = self.controller.capabilities
        self.widgets["encrypt"].configure(
            state=(
                tk.NORMAL
                if capabilities[ProfileCapability.V2_LOCAL_ENCRYPT]
                else tk.DISABLED
            )
        )
        self.widgets["decrypt"].configure(
            state=(
                tk.NORMAL
                if capabilities[ProfileCapability.V2_LOCAL_DECRYPT]
                else tk.DISABLED
            )
        )
        self.widgets["recovery_legacy"].configure(
            state=(
                tk.NORMAL
                if capabilities[ProfileCapability.LEGACY_MOK1_DECRYPT]
                else tk.DISABLED
            )
        )
        for name in ("clean", "contacts", "contact_crypto", "sandbox"):
            self.widgets[name].configure(state=tk.DISABLED)
        self.widgets["recovery_setup"].configure(
            state=(
                tk.NORMAL
                if ready
                and unlocked
                and capabilities[ProfileCapability.RECOVERY_PHRASE]
                else tk.DISABLED
            )
        )
        self.widgets["recovery_password"].configure(
            state=(
                tk.NORMAL
                if ready
                and not unlocked
                and getattr(
                    self.controller,
                    "recovery_state",
                    ProfileRecoveryStateInspection(
                        ProfileRecoveryAvailability.INVALID,
                        "unavailable",
                    ),
                ).recovery_available
                else tk.DISABLED
            )
        )

    def open_first_run(self) -> None:
        if self.controller.inspection.state is not ProfileState.ABSENT:
            return
        current = self.first_run_window
        if current is not None and current.is_open():
            current.present()
            return
        self.first_run_window = FirstRunProfileWindow(self)

    def _show_notice(self, key: str) -> None:
        show_action_notice(
            self.root,
            title=self.t("title"),
            text=self.t(key),
            close_label=self.t("understand"),
        )

    def _maybe_show_recovery_reminder(self) -> None:
        consumer = getattr(self.controller, "consume_recovery_login_notice", None)
        notice = consumer() if callable(consumer) else None
        if notice is None or not notice.show_reminder:
            return
        set_up = ask_action_decision(
            self.root,
            title=self.t("recovery_reminder_title"),
            text=self.t("recovery_replacement_reminder"),
            approve_label=self.t("set_up_now"),
            cancel_label=self.t("remind_next_time"),
        )
        if set_up and self.controller.state is ProfileSessionState.UNLOCKED:
            self.open_recovery_setup()

    def login_or_lock(self) -> None:
        if self.controller.state is ProfileSessionState.UNLOCKED:
            self._force_close_local_v2()
            self._force_close_legacy_mok1()
            self._force_close_recovery_setup()
            self.password.set("")
            self.nickname.set("")
            self._mask_login_secrets()
            self.controller.lock(ProfileLockReason.USER)
            self.refresh_view()
            return
        try:
            result = self.controller.login(self.nickname.get(), self.password.get())
        except Exception:
            result = None
        self.password.set("")
        if result is not None and result.clear_nickname:
            self.nickname.set("")
        if result is not None and result.unlocked:
            self._force_close_legacy_mok1()
            self._force_close_password_recovery()
        if result is None or not result.unlocked:
            self._mask_login_secrets()
            self._show_notice("login_failed")
        self.refresh_view()
        if result is not None and result.unlocked:
            self._maybe_show_recovery_reminder()

    def _enter_login(self, _event: tk.Event) -> str | None:
        focus = self.root.focus_get()
        if (
            self.controller.state is not ProfileSessionState.UNLOCKED
            and focus in {self.widgets["password_entry"], self.widgets["nickname_entry"]}
        ):
            self.login_or_lock()
            return "break"
        return None

    def choose_local_folder(self) -> None:
        if self.controller.state is not ProfileSessionState.UNLOCKED:
            return
        selected = filedialog.askdirectory(parent=self.root, mustexist=True)
        if selected:
            self.local_folder.set(selected)
            self.folder_variable.set(selected)

    def open_local_encrypt(self) -> None:
        self._open_local_v2("encrypt")

    def open_local_decrypt(self) -> None:
        self._open_local_v2("decrypt")

    def _open_local_v2(self, mode_value: str) -> None:
        capability = (
            ProfileCapability.V2_LOCAL_ENCRYPT
            if mode_value == "encrypt"
            else ProfileCapability.V2_LOCAL_DECRYPT
        )
        if (
            self.controller.state is not ProfileSessionState.UNLOCKED
            or not self.controller.capabilities[capability]
            or self.controller.session is None
        ):
            self._show_notice("login_required")
            return
        recovery = getattr(self, "recovery_setup_window", None)
        if (
            recovery is not None
            and recovery.is_open()
        ) or self._legacy_mok1_is_open():
            self._show_notice("profile_sensitive_window_busy")
            return
        from mokosh_v2_local_gui import LocalV2Mode, LocalV2Window

        mode = (
            LocalV2Mode.ENCRYPT
            if mode_value == "encrypt"
            else LocalV2Mode.DECRYPT
        )
        current = getattr(self, "local_v2_window", None)
        if current is not None and current.is_open():
            current.present(mode)
            return
        self.local_v2_window = LocalV2Window(
            self.root,
            self.controller.session,
            locale=self.locale,
            mode=mode,
            initial_directory=self.local_folder.get(),
            on_closed=self._local_v2_closed,
        )

    def _local_v2_closed(self) -> None:
        self.local_v2_window = None
        if self._closed:
            try:
                self.root.destroy()
            except tk.TclError:
                pass

    def _force_close_local_v2(self) -> None:
        current = getattr(self, "local_v2_window", None)
        if current is not None:
            try:
                current.force_close()
            except Exception:
                self.local_v2_window = None

    def _legacy_mok1_is_open(self) -> bool:
        current = getattr(self, "legacy_mok1_window", None)
        if current is None:
            return False
        try:
            return bool(current.window.winfo_exists())
        except (AttributeError, tk.TclError):
            return False

    def _force_close_legacy_mok1(self) -> None:
        current = getattr(self, "legacy_mok1_window", None)
        self.legacy_mok1_window = None
        if current is not None:
            try:
                current.close()
            except Exception:
                pass

    def open_legacy_decrypt(self) -> None:
        authorized = self.controller.capabilities[
            ProfileCapability.LEGACY_MOK1_DECRYPT
        ]
        if not authorized:
            self._show_notice("login_required")
            return
        local = getattr(self, "local_v2_window", None)
        recovery = getattr(self, "recovery_setup_window", None)
        if (
            local is not None
            and local.is_open()
        ) or (
            recovery is not None
            and recovery.is_open()
        ):
            self._show_notice("profile_sensitive_window_busy")
            return
        current = getattr(self, "legacy_mok1_window", None)
        if self._legacy_mok1_is_open():
            try:
                current.window.deiconify()
                current.window.lift()
                current.window.focus_force()
            except tk.TclError:
                pass
            return
        from mokosh_legacy_mok1_recovery_gui import open_legacy_mok1_recovery

        self.legacy_mok1_window = open_legacy_mok1_recovery(
            self.root, locale=self.locale, authorized=authorized
        )

    def open_recovery_setup(self) -> None:
        authorized = (
            self.controller.inspection.state is ProfileState.READY
            and self.controller.state is ProfileSessionState.UNLOCKED
            and self.controller.capabilities[ProfileCapability.RECOVERY_PHRASE]
        )
        if not authorized:
            self._show_notice("login_required")
            return
        local = getattr(self, "local_v2_window", None)
        if (
            local is not None
            and local.is_open()
        ) or self._legacy_mok1_is_open():
            self._show_notice("profile_sensitive_window_busy")
            return
        current = self.recovery_setup_window
        if current is not None and current.is_open():
            current.present()
            return
        from mokosh_profile_recovery_gui import RecoverySetupWindow

        self.recovery_setup_window = RecoverySetupWindow(
            self.root,
            self.controller.profile_root,
            locale=self.locale,
            on_closed=self._recovery_setup_closed,
            on_completed=self._recovery_setup_completed,
        )

    def _recovery_setup_closed(self) -> None:
        self.recovery_setup_window = None

    def _recovery_setup_completed(self) -> None:
        refresher = getattr(self.controller, "refresh_recovery_state", None)
        if callable(refresher):
            refresher()
        self.refresh_view()

    def _force_close_recovery_setup(self) -> None:
        current = getattr(self, "recovery_setup_window", None)
        if current is not None:
            try:
                current.force_close()
            except Exception:
                self.recovery_setup_window = None

    def open_password_recovery(self) -> None:
        authorized = (
            self.controller.inspection.state is ProfileState.READY
            and self.controller.state is ProfileSessionState.LOCKED
            and getattr(
                self.controller,
                "recovery_state",
                ProfileRecoveryStateInspection(
                    ProfileRecoveryAvailability.INVALID,
                    "unavailable",
                ),
            ).recovery_available
        )
        if not authorized:
            key = (
                "password_recovery_lock_required"
                if self.controller.state is not ProfileSessionState.LOCKED
                else "recovery_status_locked_unavailable"
            )
            self._show_notice(key)
            return
        local = getattr(self, "local_v2_window", None)
        if (
            local is not None
            and local.is_open()
        ) or self._legacy_mok1_is_open():
            self._show_notice("profile_sensitive_window_busy")
            return
        current = self.password_recovery_window
        if current is not None and current.is_open():
            current.present()
            return
        from mokosh_profile_recovery_gui import PasswordRecoveryWindow

        self.password_recovery_window = PasswordRecoveryWindow(
            self.root,
            self.controller.profile_root,
            locale=self.locale,
            on_closed=self._password_recovery_closed,
            on_completed=self._password_recovery_completed,
        )

    def _password_recovery_closed(self) -> None:
        self.password_recovery_window = None

    def _force_close_password_recovery(self) -> None:
        current = getattr(self, "password_recovery_window", None)
        if current is not None:
            try:
                current.close()
            except Exception:
                self.password_recovery_window = None

    def _password_recovery_completed(self) -> None:
        self.password.set("")
        self.nickname.set("")
        self._mask_login_secrets()
        self.controller.refresh()
        self.refresh_view()

    def _unavailable(self) -> None:
        self._show_notice("unavailable_stage")

    def open_maintenance(self) -> None:
        script = os.path.join(os.path.dirname(__file__), "mokosh_gui.py")
        try:
            subprocess.Popen(
                [sys.executable, script, "--maintenance"],
                close_fds=True,
            )
        except OSError:
            self._show_notice("maintenance_info")

    def _panic_lock(self, _event: tk.Event | None = None) -> str:
        self._force_close_local_v2()
        self._force_close_legacy_mok1()
        self._force_close_recovery_setup()
        self._force_close_password_recovery()
        self.password.set("")
        self.nickname.set("")
        self._mask_login_secrets()
        if self.controller.state is ProfileSessionState.UNLOCKED:
            self.controller.lock(ProfileLockReason.PANIC)
        self.refresh_view()
        return "break"

    def _user_activity(self, _event: tk.Event) -> None:
        session = self.controller.session
        if (
            session is None
            or self.controller.state is not ProfileSessionState.UNLOCKED
        ):
            return
        try:
            session.touch()
        except Exception:
            pass
        if self.controller.state is not ProfileSessionState.UNLOCKED:
            self._force_close_local_v2()
            self._force_close_legacy_mok1()
            self._force_close_recovery_setup()
            self.password.set("")
            self.nickname.set("")
            self._mask_login_secrets()
            self.refresh_view()

    def _poll_session(self) -> None:
        if self._closed:
            return
        if self.controller.session is not None:
            result = self.controller.session.check()
            if result.locked:
                self._force_close_local_v2()
                self._force_close_legacy_mok1()
                self._force_close_recovery_setup()
                self.password.set("")
                self.nickname.set("")
                self._mask_login_secrets()
                self.refresh_view()
                self._show_notice("timeout_notice")
        self.root.after(PROFILE_GUI_POLL_MILLISECONDS, self._poll_session)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.password.set("")
        self.nickname.set("")
        self._mask_login_secrets()
        if self.first_run_window is not None:
            self.first_run_window.close()
        self._force_close_legacy_mok1()
        self._force_close_recovery_setup()
        self._force_close_password_recovery()
        self.controller.close()
        current = getattr(self, "local_v2_window", None)
        self._force_close_local_v2()
        if current is not None and not current.worker_drained:
            try:
                self.root.withdraw()
            except tk.TclError:
                pass
            return
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def main(profile_root: Any | None = None) -> None:
    controller = ProfileApplicationController(profile_root)
    root = tk.Tk()
    ProfileMainWindow(root, controller)
    root.mainloop()


__all__ = [
    "FirstRunProfileWindow",
    "PROFILE_GUI_GEOMETRY",
    "PROFILE_GUI_MINIMUM",
    "PROFILE_GUI_POLL_MILLISECONDS",
    "ProfileApplicationController",
    "ProfileGUIError",
    "ProfileMainWindow",
    "main",
]
