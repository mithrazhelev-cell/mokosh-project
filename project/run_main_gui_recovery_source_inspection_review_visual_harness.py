#!/usr/bin/env python3
"""Run the fixed Stage 2.41 manual Linux main-GUI visual matrix."""

from __future__ import annotations

import argparse
import math
import sys
import tkinter as tk
from tkinter import messagebox

import mokosh_gui
from mokosh_vault_recovery_source_inspection_main_gui_visual_harness import (
    MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX,
    MainGUISourceInspectionReviewObservations,
    MainGUISourceInspectionVisualHarnessObservation,
    VaultRecoverySourceInspectionMainGUIVisualHarnessError,
    build_main_gui_source_inspection_review_report,
    main_gui_source_inspection_review_report_json,
    prepare_synthetic_main_gui_source_inspection_review_case,
    visual_observations_pass,
)


_ACTION_LABELS = {
    "escape_key": "клавиша Escape (Esc)",
    "cancel_button": "бутона Cancel / Отказ",
    "window_close": "системното X на child прозореца",
    "acknowledge": "бутона Confirm / Потвърди след всички отметки",
}


class _MainGUISourceInspectionVisualLaunchError(RuntimeError):
    """The visible main GUI could not satisfy the bounded launcher contract."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open the fixed four-case Stage 2.41 synthetic Linux main-GUI "
            "source-inspection review matrix."
        )
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help="Record not_checked observations and fail the visible gate.",
    )
    return parser


def _prompt(label: str) -> MainGUISourceInspectionVisualHarnessObservation:
    while True:
        answer = input(f"{label} [y/n/s]: ").strip().lower()
        if answer == "y":
            return MainGUISourceInspectionVisualHarnessObservation.PASS
        if answer == "n":
            return MainGUISourceInspectionVisualHarnessObservation.FAIL
        if answer == "s":
            return MainGUISourceInspectionVisualHarnessObservation.NOT_CHECKED
        print("Use y (pass), n (fail), or s (not checked).")


def _observations(skip: bool) -> MainGUISourceInspectionReviewObservations:
    if skip:
        value = MainGUISourceInspectionVisualHarnessObservation.NOT_CHECKED
        return MainGUISourceInspectionReviewObservations(
            value, value, value, value, value, value
        )
    return MainGUISourceInspectionReviewObservations(
        banner_button_visible_no_clipping=_prompt(
            "Were the prepared banner and button visible without clipping?"
        ),
        unrelated_controls_disabled=_prompt(
            "Were all unrelated main-GUI controls disabled?"
        ),
        keyboard_reachable_no_trap=_prompt(
            "Was keyboard navigation reachable and free of a keyboard trap?"
        ),
        child_opened_in_front_modal=_prompt(
            "Did the source-inspection review open in front and behave modally?"
        ),
        localized_layout_readable=_prompt(
            "Was the localized layout readable at the required scaling?"
        ),
        one_shot_button_remained_disabled=_prompt(
            "Did the main-GUI review button remain disabled after completion?"
        ),
    )


def _instructions(root: tk.Tk, case: object) -> None:
    action = case.required_terminal_action.value
    messagebox.showinfo(
        "MOKOSH Stage 2.41 — визуална проверка",
        (
            f"Случай {case.case_number}/4\n"
            f"Език: {case.locale.value}\n"
            f"Tk мащаб: {case.scale_percent}%\n\n"
            "Отвори подготвения source-inspection преглед точно веднъж. "
            f"Завърши child прозореца чрез {_ACTION_LABELS[action]}.\n\n"
            "После провери, че главният бутон остава изключен, затвори "
            "главния MOKOSH прозорец и отговори на шестте въпроса в терминала.\n\n"
            "Използват се само фиксирани синтетични данни. Няма истински "
            "Vault, recovery source, парола, ключ или recovery операция."
        ),
        parent=root,
    )


def _run_case(case_number: int, skip_observations: bool) -> bool:
    case = prepare_synthetic_main_gui_source_inspection_review_case(case_number)
    real_tk = tk.Tk
    root = real_tk()
    original_mokosh_tk = mokosh_gui.tk.Tk
    try:
        base_scaling = float(root.tk.call("tk", "scaling"))
        if not math.isfinite(base_scaling) or base_scaling <= 0.0:
            raise _MainGUISourceInspectionVisualLaunchError(
                "initial Tk scaling is invalid"
            )
        root.tk.call(
            "tk",
            "scaling",
            base_scaling * case.scale_percent / 100.0,
        )
        root.withdraw()
        _instructions(root, case)
        root.deiconify()

        mokosh_gui.tk.Tk = lambda: root
        mokosh_gui.main(
            prepared_recovery_source_inspection_review_binding=case.binding
        )
    finally:
        mokosh_gui.tk.Tk = original_mokosh_tk
        try:
            root.destroy()
        except tk.TclError:
            pass

    outcome = case.binding.outcome
    if outcome is None:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "the conditional Stage 2.41 event was not completed"
        )
    recorded = _observations(skip_observations)
    report = build_main_gui_source_inspection_review_report(
        case,
        outcome,
        recorded,
    )
    print(main_gui_source_inspection_review_report_json(report), flush=True)
    return visual_observations_pass(recorded)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        for case_number in range(
            1,
            len(MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX) + 1,
        ):
            if not _run_case(case_number, args.no_observations):
                print(
                    "The fixed Stage 2.41 visible matrix did not pass.",
                    file=sys.stderr,
                )
                return 2
    except (
        tk.TclError,
        VaultRecoverySourceInspectionMainGUIVisualHarnessError,
        _MainGUISourceInspectionVisualLaunchError,
    ) as exc:
        print(
            "The Stage 2.41 synthetic main-GUI visual harness failed safely: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print(
            "The Stage 2.41 synthetic main-GUI visual harness was cancelled.",
            file=sys.stderr,
        )
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
