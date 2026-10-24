#!/usr/bin/env python3
"""Open one synthetic, non-secret Stage 2.48 local-V2 visual case."""

from __future__ import annotations

import argparse
import sys
import tkinter as tk

from mokosh_profile_localization import ProfileLocale, profile_text
from mokosh_profile_ui import (
    ask_action_decision,
    configure_resizable_window,
    create_responsive_label,
    create_scrollable_region,
)
from mokosh_v2_local_gui import (
    LOCAL_V2_GUI_GEOMETRY,
    LOCAL_V2_GUI_MINIMUM,
    LocalV2Mode,
)
from mokosh_v2_local_visual_harness import (
    LOCAL_V2_GUI_VISUAL_MATRIX,
    prepare_local_v2_gui_visual_case,
)


SYNTHETIC_SAFETY_CLAIM = (
    "No profile, file, key, worker thread, or cryptographic operation is created."
)

SYNTHETIC_STATE_LABELS = {
    "ready": "READY",
    "working": "WORKING",
    "cancelled": "CANCELLED",
    "cleanable": "CLEANABLE",
    "blocked": "BLOCKED",
    "published": "PUBLISHED",
    "not_v2": "NOT V2",
}

SYNTHETIC_CHOOSER_FEEDBACK = {
    ProfileLocale.ENGLISH: {
        "source": (
            "Synthetic preview: no source chooser is opened and no file is read."
        ),
        "output": (
            "Synthetic preview: no output chooser is opened and no file is created."
        ),
    },
    ProfileLocale.BULGARIAN: {
        "source": (
            "Синтетичен преглед: не се отваря избор на източник и не се чете файл."
        ),
        "output": (
            "Синтетичен преглед: не се отваря избор на нов изход и не се създава файл."
        ),
    },
}


class _SyntheticLocalV2Preview:
    """Render exact production wording without a session, worker, or file I/O."""

    def __init__(
        self,
        root: tk.Tk,
        *,
        locale: ProfileLocale,
        mode: LocalV2Mode,
    ) -> None:
        self.root = root
        self.locale = locale
        self.mode = mode
        self.source = tk.StringVar(
            value=(
                "synthetic-source.bin"
                if mode is LocalV2Mode.ENCRYPT
                else "synthetic-envelope.data"
            )
        )
        self.output = tk.StringVar(
            value=(
                "MOKOSH-encrypted-0123abcd.mok2"
                if mode is LocalV2Mode.ENCRYPT
                else "MOKOSH-decrypted-0123abcd"
            )
        )
        self.status = tk.StringVar(value="")
        self.synthetic_state = tk.StringVar(value="")
        self.widgets: dict[str, tk.Widget] = {}
        self.state_buttons: dict[str, tk.Button] = {}
        configure_resizable_window(
            root,
            geometry=LOCAL_V2_GUI_GEOMETRY,
            minimum=LOCAL_V2_GUI_MINIMUM,
            close=root.destroy,
        )
        root.title(
            self.t(
                "local_v2_encrypt_title"
                if mode is LocalV2Mode.ENCRYPT
                else "local_v2_decrypt_title"
            )
        )
        self._build()
        self.show_state("ready")

    def t(self, key: str) -> str:
        return profile_text(self.locale, key)

    def _build(self) -> None:
        region = create_scrollable_region(self.root)
        outer = region.content
        harness = tk.LabelFrame(
            outer,
            text="SYNTHETIC STATES / СИНТЕТИЧНИ СЪСТОЯНИЯ",
            padx=6,
            pady=6,
        )
        harness.pack(fill="x", pady=(0, 10))
        for column, (label, state) in enumerate(
            (
                ("READY", "ready"),
                ("WORKING", "working"),
                ("CLEANABLE", "cleanable"),
                ("BLOCKED", "blocked"),
                ("PUBLISHED", "published"),
                ("NOT V2", "not_v2"),
            )
        ):
            button = tk.Button(
                harness,
                text=label,
                command=lambda value=state: self._activate_state(value),
            )
            self._bind_state_keyboard_activation(button)
            button.grid(
                row=column // 3,
                column=column % 3,
                sticky="ew",
                padx=3,
                pady=3,
            )
            self.state_buttons[state] = button
        for column in range(3):
            harness.grid_columnconfigure(column, weight=1)
        tk.Label(
            harness,
            anchor="w",
            textvariable=self.synthetic_state,
        ).grid(row=2, column=0, columnspan=3, sticky="ew", padx=3, pady=(6, 3))

        intro = create_responsive_label(
            outer,
            text=self.t(
                "local_v2_encrypt_intro"
                if self.mode is LocalV2Mode.ENCRYPT
                else "local_v2_decrypt_intro"
            ),
            background="#d9f3f0",
            foreground="#124b47",
            bold=True,
        )
        intro.pack(fill="x", pady=(0, 10))
        safety = create_responsive_label(
            outer,
            text=self.t("local_v2_keep_originals"),
            background="#fff3cd",
            foreground="#5b4000",
            bold=True,
        )
        safety.pack(fill="x", pady=(0, 10))

        for name, variable in (("source", self.source), ("output", self.output)):
            frame = tk.Frame(outer)
            frame.pack(fill="x", pady=5)
            tk.Label(
                frame,
                anchor="w",
                text=self.t(
                    "local_v2_source" if name == "source" else "local_v2_output"
                ),
            ).pack(fill="x")
            row = tk.Frame(frame)
            row.pack(fill="x", pady=(3, 0))
            entry = tk.Entry(row, textvariable=variable, state="readonly")
            entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
            button = tk.Button(
                row,
                text=self.t(
                    "local_v2_choose_source"
                    if name == "source"
                    else "local_v2_choose_output"
                ),
                command=lambda value=name: self.show_synthetic_chooser_feedback(
                    value
                ),
            )
            button.pack(side="right")
            self.widgets[f"choose_{name}"] = button

        status = create_responsive_label(
            outer,
            textvariable=self.status,
            background="#eef2f7",
            foreground="#1d2b3a",
            bold=True,
        )
        status.pack(fill="x", pady=(12, 8))
        self.widgets["status"] = status

        cleanup = tk.Button(
            outer,
            text=self.t("local_v2_cleanup"),
            command=self.confirm_synthetic_cleanup,
        )
        cleanup.pack(fill="x", pady=(0, 8))
        self.widgets["cleanup"] = cleanup

        actions = tk.Frame(outer)
        actions.pack(fill="x", pady=(8, 0))
        run = tk.Button(
            actions,
            text=self.t(
                "local_v2_run_encrypt"
                if self.mode is LocalV2Mode.ENCRYPT
                else "local_v2_run_decrypt"
            ),
            command=lambda: self.show_state("working"),
            font=("TkDefaultFont", 11, "bold"),
        )
        run.pack(fill="x", pady=(0, 5))
        cancel = tk.Button(
            actions,
            text=self.t("local_v2_cancel_operation"),
            command=lambda: self.show_state("cancelled"),
        )
        cancel.pack(fill="x", pady=(0, 5))
        close = tk.Button(
            actions,
            text=self.t("close"),
            command=self.root.destroy,
        )
        close.pack(fill="x")
        self.widgets["run"] = run
        self.widgets["cancel"] = cancel
        self.widgets["close"] = close

    def show_synthetic_chooser_feedback(self, chooser: str) -> None:
        message = SYNTHETIC_CHOOSER_FEEDBACK[self.locale][chooser]
        self.status.set(message)
        self.widgets["status"].configure(bg="#eef2f7", fg="#1d2b3a")

    def _activate_state(self, state: str) -> None:
        button = self.state_buttons[state]
        try:
            button.focus_set()
        except tk.TclError:
            pass
        self.show_state(state)

    def _bind_state_keyboard_activation(self, button: tk.Button) -> None:
        def invoke(_event: tk.Event) -> str:
            try:
                button.invoke()
            except tk.TclError:
                pass
            return "break"

        for sequence in ("<Return>", "<KP_Enter>"):
            button.bind(sequence, invoke, add="+")

    def _apply_control_states(self, states: dict[str, str]) -> None:
        try:
            focused = self.root.focus_get()
        except tk.TclError:
            focused = None
        focused_name = next(
            (
                name
                for name, widget in self.widgets.items()
                if widget is focused and name in states
            ),
            None,
        )
        primed = None
        if focused_name is not None and states[focused_name] == tk.DISABLED:
            for name in (
                "cancel",
                "run",
                "cleanup",
                "choose_source",
                "choose_output",
                "close",
            ):
                widget = self.widgets.get(name)
                if widget is None or states.get(name, tk.NORMAL) != tk.NORMAL:
                    continue
                try:
                    if name in states:
                        widget.configure(state=tk.NORMAL)
                    widget.focus_set()
                except tk.TclError:
                    continue
                primed = name
                break
        for name, state in states.items():
            if name != primed:
                self.widgets[name].configure(state=state)

    def show_state(self, state: str) -> None:
        key = {
            "ready": "local_v2_ready",
            "working": (
                "local_v2_phase_encrypt"
                if self.mode is LocalV2Mode.ENCRYPT
                else "local_v2_phase_decrypt"
            ),
            "cancelled": "local_v2_error_cancelled",
            "cleanable": "local_v2_residue_cleanable",
            "blocked": "local_v2_residue_blocked",
            "published": "local_v2_published_warning",
            "not_v2": "local_v2_error_not_v2",
        }[state]
        self.status.set(self.t(key))
        warning = state in {
            "cancelled",
            "cleanable",
            "blocked",
            "published",
            "not_v2",
        }
        self.widgets["status"].configure(
            bg="#fff3cd" if warning else "#eef2f7",
            fg="#5b4000" if warning else "#1d2b3a",
        )
        self.synthetic_state.set(
            f"DISPLAYED / ПОКАЗАНО: {SYNTHETIC_STATE_LABELS[state]}"
        )
        for value, button in self.state_buttons.items():
            button.configure(relief=tk.SUNKEN if value == state else tk.RAISED)
        working = state == "working"
        ordinary = tk.DISABLED if working else tk.NORMAL
        run_blocked = state in {"working", "cleanable", "blocked", "published"}
        self._apply_control_states(
            {
                "choose_source": ordinary,
                "choose_output": ordinary,
                "run": tk.DISABLED if run_blocked else tk.NORMAL,
                "cancel": tk.NORMAL if working else tk.DISABLED,
                "cleanup": (
                    tk.NORMAL if state == "cleanable" else tk.DISABLED
                ),
            }
        )

    def confirm_synthetic_cleanup(self) -> None:
        approved = ask_action_decision(
            self.root,
            title=self.t("local_v2_cleanup"),
            text=self.t("local_v2_cleanup_confirm"),
            approve_label=self.t("local_v2_cleanup_approve"),
            cancel_label=self.t("local_v2_cleanup_preserve"),
        )
        if approved:
            self.status.set(self.t("local_v2_cleanup_success"))
            self.widgets["cleanup"].configure(state=tk.DISABLED)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MOKOSH Stage 2.48 synthetic local-V2 visual harness"
    )
    parser.add_argument(
        "--case",
        type=int,
        default=1,
        choices=range(1, len(LOCAL_V2_GUI_VISUAL_MATRIX) + 1),
        help="one fixed EN/BG, scale and encrypt/decrypt case",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        case = prepare_local_v2_gui_visual_case(args.case)
        locale = ProfileLocale(case.locale)
        mode = LocalV2Mode(case.mode)
        root = tk.Tk()
        base_scaling = float(root.tk.call("tk", "scaling"))
        root.tk.call("tk", "scaling", base_scaling * case.scale_percent / 100.0)
        print(
            "Synthetic non-secret local-V2 preview. "
            f"{SYNTHETIC_SAFETY_CLAIM}\n"
            "Check text/reflow, explicit source and new output, generic names, "
            "original-preservation/no-overwrite wording, keyboard focus, scrolling, "
            "resize and window controls. Use every SYNTHETIC STATES button; in "
            "CLEANABLE also open the explicit confirmation and choose PRESERVE.\n"
            f"Case {case.case_number}: locale={case.locale}, "
            f"scale={case.scale_percent}%, mode={case.mode}."
        )
        _SyntheticLocalV2Preview(root, locale=locale, mode=mode)
        root.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"Visual harness stopped safely: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
