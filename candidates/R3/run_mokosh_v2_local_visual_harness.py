#!/usr/bin/env python3
"""Open one synthetic, non-secret Stage 2.48 local-V2 visual case."""

from __future__ import annotations


import argparse
import sys
import tkinter as tk

from mokosh_profile_localization import ProfileLocale, profile_text
from d005_state_labels import StateLabelReflow
from d005_action_captions import ActionCaptionReflow
from mokosh_profile_ui import (
    DEFAULT_ACTION_FONT,
    DEFAULT_BODY_FONT,
    ResponsivePair,
    ask_action_decision,
    bind_responsive_wrap,
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
from mokosh_v2_visual_scale_probe import (
    ScaleEvidenceError,
    baseline_tree,
    pixels,
    zoom_font,
    zoom_tree,
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

SYNTHETIC_STATE_LABELS_BG = {
    "ready": "ГОТОВНОСТ", "working": "В ПРОЦЕС", "cancelled": "ПРЕКРАТЕНО",
    "cleanable": "ЗА ПРЕГЛЕД И ПОЧИСТВАНЕ", "blocked": "БЛОКИРАНО",
    "published": "РЕЗУЛТАТЪТ Е СЪЗДАДЕН", "not_v2": "НЕ Е MOKOSH2",
}

def synthetic_state_label(locale, state):
    return (SYNTHETIC_STATE_LABELS_BG if locale is ProfileLocale.BULGARIAN else SYNTHETIC_STATE_LABELS)[state]


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
            "Синтетичен преглед: не се отваря избор на нов резултатен файл и не се създава файл."
        ),
    },
}

SYNTHETIC_ENCRYPT_NOT_V2_REFERENCE = {
    ProfileLocale.ENGLISH: (
        "NOT V2 is a decrypt-only rejection. This encrypt preview has not "
        "checked a source file; use the decrypt preview to inspect that "
        "failure. ENCRYPT FILE remains available for a valid source."
    ),
    ProfileLocale.BULGARIAN: (
        "„НЕ Е MOKOSH2“ е отказ само при декриптиране. Този преглед за криптиране "
        "не е проверявал файл източник; използвайте прегледа за "
        "декриптиране за тази грешка. „КРИПТИРАЙ ФАЙЛА“ остава достъпен "
        "за валиден източник."
    ),
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
        self.scale_percent = 100
        self.modal_baseline = None
        self.retained_fonts = []
        self.scale_failure = None
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
            padx=6,
            pady=6,
        )
        harness.pack(fill="x", pady=(0, 10))
        heading = tk.Label(
            harness,
            anchor="w",
            justify="left",
            text=("СИНТЕТИЧНИ СЪСТОЯНИЯ" if self.locale is ProfileLocale.BULGARIAN else "SYNTHETIC STATES"),
        )
        heading.grid(row=0, column=0, columnspan=3, sticky="ew", padx=3, pady=(0, 6))
        bind_responsive_wrap(heading, harness, horizontal_inset=22, minimum=160)
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
                text=synthetic_state_label(self.locale, state),
                wraplength=0,
                command=lambda value=state: self._activate_state(value),
            )
            self._bind_state_keyboard_activation(button)
            button.grid(
                row=1 + column // 3,
                column=column % 3,
                sticky="ew",
                padx=3,
                pady=3,
            )
            self.state_buttons[state] = button
        for column in range(3):
            harness.grid_columnconfigure(column, weight=1)
        displayed = tk.Label(
            harness,
            anchor="w",
            textvariable=self.synthetic_state,
        )
        displayed.grid(row=3, column=0, columnspan=3, sticky="ew", padx=3, pady=(6, 3))
        self._state_label_reflow = StateLabelReflow(
            harness, self.state_buttons, heading=heading, displayed=displayed,
            viewport=region, on_error=self._state_layout_failed,
        )

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
            ResponsivePair(
                row, entry, button, breakpoint=760, padx=3,
                fit_requested_widths=True,
            )
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
        self._cleanup_caption_reflow = ActionCaptionReflow(
            cleanup, viewport=region, on_error=self._state_layout_failed,
        )

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
            command=self.cancel_synthetic,
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

    def _state_layout_failed(self, error: Exception) -> None:
        self.scale_failure = error
        self.root.after_idle(self.root.destroy)

    def show_synthetic_chooser_feedback(self, chooser: str) -> None:
        message = SYNTHETIC_CHOOSER_FEEDBACK[self.locale][chooser]
        control = self.widgets[f"choose_{chooser}"]
        if control.cget("state") == tk.DISABLED:
            return
        control.focus_set()
        self.status.set(message)
        self.widgets["status"].configure(bg="#eef2f7", fg="#1d2b3a")

    def _activate_state(self, state: str) -> None:
        button = self.state_buttons[state]
        try:
            button.focus_set()
        except tk.TclError:
            pass
        self.show_state(state)

    def cancel_synthetic(self) -> None:
        # A pointer invocation does not necessarily focus its Tk Button.
        # Establish the action as the focus target before disabling it so the
        # regular handoff selects an enabled control in the same viewport.
        self.widgets["cancel"].focus_set()
        self.show_state("cancelled")

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
        self.status.set(
            SYNTHETIC_ENCRYPT_NOT_V2_REFERENCE[self.locale]
            if state == "not_v2" and self.mode is LocalV2Mode.ENCRYPT
            else self.t(key)
        )
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
            f"{'ПОКАЗАНО' if self.locale is ProfileLocale.BULGARIAN else 'DISPLAYED'}: {synthetic_state_label(self.locale, state)}"
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
            before_show=self.audit_cleanup_dialog,
            return_focus_candidates=(
                self.widgets["cleanup"], self.widgets["close"]
            ),
        )
        if approved:
            self.status.set(self.t("local_v2_cleanup_success"))
            self.widgets["cleanup"].configure(state=tk.DISABLED)

    def audit_cleanup_dialog(self, dialog: object, *, actions: int = 2, record: str = "MODAL_FONT_PIXELS") -> None:
        if self.modal_baseline is None:
            return
        try:
            body_base, action_base = self.modal_baseline
            text_widgets = [
                child for w in dialog.window.winfo_children()
                for frame in w.winfo_children()
                for child in frame.winfo_children()
                if isinstance(child, tk.Text)
            ]
            if len(text_widgets) != 1 or len(dialog.buttons) != actions:
                raise ScaleEvidenceError("modal text or action inventory differs")
            observed_body = zoom_font(text_widgets[0], body_base, self.scale_percent, self.retained_fonts)
            line_ratio = 100 * observed_body.linespace // body_base.linespace
            width_ratio = 100 * observed_body.sample_width // body_base.sample_width
            max_line_ratio, max_width_ratio = line_ratio, width_ratio
            for button in dialog.buttons:
                observed_action = zoom_font(button, action_base, self.scale_percent, self.retained_fonts)
                action_line = 100 * observed_action.linespace // action_base.linespace
                action_width = 100 * observed_action.sample_width // action_base.sample_width
                line_ratio = min(line_ratio, action_line)
                width_ratio = min(width_ratio, action_width)
                max_line_ratio = max(max_line_ratio, action_line)
                max_width_ratio = max(max_width_ratio, action_width)
            print(
                f"{record}=MEASURED scale={self.scale_percent}% "
                f"body=1 actions={actions} line_ratio={line_ratio}..{max_line_ratio}% "
                f"width_ratio={width_ratio}..{max_width_ratio}% "
                f"HUMAN_ACCEPTANCE=PENDING", flush=True,
            )
        except BaseException as exc:
            self.scale_failure = exc
            self.root.after_idle(self.root.destroy)
            raise


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
    parser.add_argument(
        "--scale-probe-only", action="store_true",
        help="measure real Tk font pixels without opening the preview",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        case = prepare_local_v2_gui_visual_case(args.case)
        locale = ProfileLocale(case.locale)
        mode = LocalV2Mode(case.mode)
        root = tk.Tk()
        root.withdraw()
        base_scaling = float(root.tk.call("tk", "scaling"))
        body_probe = tk.Text(root, font=DEFAULT_BODY_FONT)
        action_probe = tk.Button(root, font=DEFAULT_ACTION_FONT)
        modal_baseline = (pixels(body_probe), pixels(action_probe))
        body_probe.destroy()
        action_probe.destroy()
        preview = _SyntheticLocalV2Preview(root, locale=locale, mode=mode)
        baseline = baseline_tree(root)
        preview.modal_baseline = modal_baseline
        preview.scale_percent = case.scale_percent
        root.tk.call("tk", "scaling", base_scaling * case.scale_percent / 100.0)
        total, smallest_height, largest_height, smallest_width, largest_width = zoom_tree(
            root, baseline, case.scale_percent, preview.retained_fonts
        )
        print(
            f"CONSTRUCTED_FONT_PIXELS=MEASURED scale={case.scale_percent}% "
            f"widgets={total} line_ratio={smallest_height}..{largest_height}% "
            f"width_ratio={smallest_width}..{largest_width}% "
            f"VISIBLE_ON_SCREEN=UNVERIFIED HUMAN_ACCEPTANCE=PENDING", flush=True,
        )
        body_probe = tk.Text(root, font=DEFAULT_BODY_FONT)
        action_probe = tk.Button(root, font=DEFAULT_ACTION_FONT)
        proxy_body = zoom_font(body_probe, modal_baseline[0], case.scale_percent, preview.retained_fonts)
        proxy_action = zoom_font(action_probe, modal_baseline[1], case.scale_percent, preview.retained_fonts)
        body_probe.destroy()
        action_probe.destroy()
        body_line = 100 * proxy_body.linespace // modal_baseline[0].linespace
        action_line = 100 * proxy_action.linespace // modal_baseline[1].linespace
        body_width = 100 * proxy_body.sample_width // modal_baseline[0].sample_width
        action_width = 100 * proxy_action.sample_width // modal_baseline[1].sample_width
        print(
            f"MODAL_FONT_PROXY_PIXELS=MEASURED scale={case.scale_percent}% "
            f"line_ratio={min(body_line, action_line)}..{max(body_line, action_line)}% "
            f"width_ratio={min(body_width, action_width)}..{max(body_width, action_width)}% "
            f"ACTUAL_MODAL=NOT_OBSERVED HUMAN_ACCEPTANCE=PENDING",
            flush=True,
        )
        if args.scale_probe_only:
            root.destroy()
            print("SCALE_PROBE_ONLY=MEASURED; HUMAN_RESULT_RECORDED=NO", flush=True)
            return 0
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
        root.deiconify()
        root.mainloop()
        if preview.scale_failure is not None:
            raise ScaleEvidenceError("the actual dialog failed its pixel gate")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        diagnostic = (
            f" detail={str(exc)[:360]}"
            if isinstance(exc, ScaleEvidenceError)
            else ""
        )
        print(
            f"Visual harness stopped safely: {type(exc).__name__}{diagnostic}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
