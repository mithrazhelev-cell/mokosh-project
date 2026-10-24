"""Explicit one-file GUI boundary for historical password-based MOK1 recovery."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Callable

from mokosh_profile_localization import ProfileLocale, normalize_locale, profile_text


class LegacyMOK1RecoveryGUIError(RuntimeError):
    """The compatibility recovery window or its authorization is invalid."""


def recover_one_legacy_mok1(
    source: Any,
    output: Any,
    password: Any,
    nickname: Any,
    *,
    authorized: bool,
    decryptor: Callable[..., str] | None = None,
) -> str:
    """Run the hardened legacy reader only after an explicit unlocked gate."""

    if authorized is not True:
        raise LegacyMOK1RecoveryGUIError("legacy recovery requires authorization")
    for value in (source, output, password, nickname):
        if type(value) is not str or not value or "\x00" in value:
            raise LegacyMOK1RecoveryGUIError("legacy recovery fields are incomplete")
    if decryptor is None:
        from crypto_core import decrypt_file

        decryptor = decrypt_file
    return decryptor(source, output, password, nickname)


class LegacyMOK1RecoveryWindow:
    """A small modal-like compatibility window with separate old credentials."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        locale: ProfileLocale | str,
        authorized: bool,
    ) -> None:
        if authorized is not True:
            raise LegacyMOK1RecoveryGUIError("legacy recovery requires authorization")
        self.locale = normalize_locale(locale)
        self.authorized = authorized
        self.window = tk.Toplevel(parent)
        self.window.title(profile_text(self.locale, "legacy_decrypt_title"))
        self.window.geometry("720x470")
        self.window.minsize(610, 430)
        self.window.transient(parent)
        self.source = tk.StringVar(value="")
        self.output = tk.StringVar(value="")
        self.password = tk.StringVar(value="")
        self.nickname = tk.StringVar(value="")
        self._build()
        self.window.protocol("WM_DELETE_WINDOW", self.close)

    def _t(self, key: str) -> str:
        return profile_text(self.locale, key)

    def _build(self) -> None:
        outer = tk.Frame(self.window, padx=16, pady=14)
        outer.pack(fill="both", expand=True)
        tk.Label(
            outer,
            text=self._t("legacy_explanation"),
            justify="left",
            anchor="w",
            wraplength=660,
            bg="#d9f3f0",
            fg="#124b47",
            padx=10,
            pady=8,
            font=("TkDefaultFont", 10, "bold"),
        ).pack(fill="x", pady=(0, 12))

        self._path_row(
            outer,
            self._t("legacy_source"),
            self.source,
            self._choose_source,
            self._t("choose_source"),
        )
        self._path_row(
            outer,
            self._t("legacy_output"),
            self.output,
            self._choose_output,
            self._t("choose_output"),
        )
        self._secret_row(outer, self._t("legacy_password"), self.password)
        self._secret_row(outer, self._t("legacy_nickname"), self.nickname)

        actions = tk.Frame(outer)
        actions.pack(fill="x", pady=(18, 0))
        tk.Button(
            actions,
            text=self._t("recover"),
            font=("TkDefaultFont", 11, "bold"),
            command=self._recover,
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(
            actions,
            text=self._t("close"),
            command=self.close,
        ).pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _path_row(
        self,
        parent: tk.Misc,
        label: str,
        variable: tk.StringVar,
        command: Callable[[], None],
        button_text: str,
    ) -> None:
        frame = tk.Frame(parent)
        frame.pack(fill="x", pady=5)
        tk.Label(frame, text=label, width=22, anchor="w").pack(side="left")
        tk.Entry(frame, textvariable=variable).pack(
            side="left", fill="x", expand=True, padx=6
        )
        tk.Button(frame, text=button_text, command=command).pack(side="right")

    def _secret_row(
        self,
        parent: tk.Misc,
        label: str,
        variable: tk.StringVar,
    ) -> None:
        frame = tk.Frame(parent)
        frame.pack(fill="x", pady=5)
        tk.Label(frame, text=label, width=22, anchor="w").pack(side="left")
        entry = tk.Entry(frame, textvariable=variable, show="*")
        entry.pack(side="left", fill="x", expand=True, padx=6)

        def toggle() -> None:
            entry.configure(show="" if entry.cget("show") == "*" else "*")

        tk.Button(frame, text="👁", width=3, command=toggle).pack(side="right")

    def _choose_source(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.window,
            title=self._t("choose_source"),
            filetypes=(("MOK1", "*.mok"), ("All files", "*")),
        )
        if selected:
            self.source.set(selected)
            if not self.output.get():
                base = selected[:-4] if selected.endswith(".mok") else selected
                self.output.set(base + "_dec")

    def _choose_output(self) -> None:
        initial = self.output.get()
        selected = filedialog.asksaveasfilename(
            parent=self.window,
            title=self._t("choose_output"),
            initialdir=os.path.dirname(initial) if initial else None,
            initialfile=os.path.basename(initial) if initial else None,
            confirmoverwrite=False,
        )
        if selected:
            self.output.set(selected)

    def _recover(self) -> None:
        if not all(
            (
                self.source.get(),
                self.output.get(),
                self.password.get(),
                self.nickname.get(),
            )
        ):
            messagebox.showerror(
                self._t("legacy_decrypt_title"),
                self._t("legacy_missing"),
                parent=self.window,
            )
            return
        try:
            recover_one_legacy_mok1(
                self.source.get(),
                self.output.get(),
                self.password.get(),
                self.nickname.get(),
                authorized=self.authorized,
            )
        except Exception:
            self.password.set("")
            messagebox.showerror(
                self._t("legacy_decrypt_title"),
                self._t("legacy_failed"),
                parent=self.window,
            )
            return
        self.password.set("")
        self.nickname.set("")
        messagebox.showinfo(
            self._t("legacy_decrypt_title"),
            self._t("legacy_success"),
            parent=self.window,
        )
        self.close()

    def close(self) -> None:
        self.password.set("")
        self.nickname.set("")
        self.window.destroy()


def open_legacy_mok1_recovery(
    parent: tk.Misc,
    *,
    locale: ProfileLocale | str,
    authorized: bool,
) -> LegacyMOK1RecoveryWindow:
    return LegacyMOK1RecoveryWindow(
        parent,
        locale=locale,
        authorized=authorized,
    )


__all__ = [
    "LegacyMOK1RecoveryGUIError",
    "LegacyMOK1RecoveryWindow",
    "open_legacy_mok1_recovery",
    "recover_one_legacy_mok1",
]
