#!/usr/bin/env python3
"""Run the fixed Stage 2.42 normal-main-GUI layout audit matrix."""

from __future__ import annotations

import argparse
import math
import sys
import tkinter as tk

import mokosh_gui
from mokosh_main_gui_recovery_chain_layout_audit import (
    MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX,
    MainGUIRecoveryChainLayoutAuditObservation,
    MainGUIRecoveryChainLayoutAuditObservations,
    MainGUIRecoveryChainLayoutAuditProfile,
    MainGUIRecoveryChainLayoutAuditError,
    build_main_gui_recovery_chain_layout_audit_report,
    main_gui_recovery_chain_layout_audit_observations_pass,
    main_gui_recovery_chain_layout_audit_report_json,
    prepare_main_gui_recovery_chain_layout_audit_case,
)


class _MainGUIRecoveryChainLayoutAuditLaunchError(RuntimeError):
    """The bounded visual audit could not run safely."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Observe the existing normal MOKOSH GUI at four fixed Tk scaling "
            "levels without invoking recovery actions."
        )
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help="Record not_checked values and fail the human gate.",
    )
    return parser


def _prompt(label: str) -> MainGUIRecoveryChainLayoutAuditObservation:
    while True:
        answer = input(f"{label} [y/n/s]: ").strip().lower()
        if answer == "y":
            return MainGUIRecoveryChainLayoutAuditObservation.PASS
        if answer == "n":
            return MainGUIRecoveryChainLayoutAuditObservation.FAIL
        if answer == "s":
            return MainGUIRecoveryChainLayoutAuditObservation.NOT_CHECKED
        print("Use y (pass), n (fail), or s (not checked).")


def _observations(
    skip: bool, profile: MainGUIRecoveryChainLayoutAuditProfile
) -> MainGUIRecoveryChainLayoutAuditObservations:
    if skip:
        value = MainGUIRecoveryChainLayoutAuditObservation.NOT_CHECKED
        return MainGUIRecoveryChainLayoutAuditObservations(
            value, value, value, value, value, value, value, value
        )
    resize_label = (
        "After enlarging and restoring the window, were controls still visible and operable?"
        if profile is MainGUIRecoveryChainLayoutAuditProfile.RESIZE_RESTORE_KEYBOARD
        else "At the unchanged initial size, were controls visible and operable?"
    )
    return MainGUIRecoveryChainLayoutAuditObservations(
        safety_and_recovery_controls_visible=_prompt(
            "Were the safety banner and all four recovery action controls fully visible?"
        ),
        non_recovery_controls_visible=_prompt(
            "Were the language, Vault, credential, status and safety-disabled controls reachable?"
        ),
        localized_text_unclipped_and_readable=_prompt(
            "Was all visible localized text readable and free of clipping?"
        ),
        keyboard_reaches_interactive_controls=_prompt(
            "Could the keyboard reach every enabled interactive control?"
        ),
        focus_visible_and_order_meaningful=_prompt(
            "Was focus visible and did traversal follow a meaningful order?"
        ),
        no_keyboard_trap=_prompt("Could keyboard focus leave every reached control?"),
        resize_restore_keeps_controls_operable=_prompt(resize_label),
        no_unexpected_dialog_or_source_access=_prompt(
            "Did no dialog, picker, source access or recovery operation start automatically?"
        ),
    )


def _print_instructions(case: object) -> None:
    print()
    print(f"CASE {case.case_number}/4")
    print(f"Locale: {case.locale}")
    print(f"Tk scaling: {case.scale_percent}%")
    print(f"Profile: {case.profile.value}")
    print("Do not click any recovery action and do not enter a password or choose a Vault.")
    print("Inspect the existing normal GUI only; no fifth action exists in Stage 2.42.")
    print("Use Tab and Shift+Tab to inspect focus reachability, order and traps.")
    print(
        "Use the vertical viewport when needed; each control must be revealable, "
        "not simultaneously visible."
    )
    if case.profile is MainGUIRecoveryChainLayoutAuditProfile.RESIZE_RESTORE_KEYBOARD:
        print("Enlarge the window, then restore it to its initial size before closing it.")
    else:
        print("Keep the initial window size unchanged until closing it.")
    print("Close the MOKOSH window with its system X, then answer eight fixed questions.")


def _run_case(case_number: int, skip_observations: bool) -> bool:
    case = prepare_main_gui_recovery_chain_layout_audit_case(case_number)
    root = tk.Tk()
    original_tk = mokosh_gui.tk.Tk
    original_lang = mokosh_gui.current_lang
    try:
        base_scaling = float(root.tk.call("tk", "scaling"))
        if not math.isfinite(base_scaling) or base_scaling <= 0.0:
            raise _MainGUIRecoveryChainLayoutAuditLaunchError(
                "initial Tk scaling is invalid"
            )
        root.tk.call("tk", "scaling", base_scaling * case.scale_percent / 100.0)
        mokosh_gui.current_lang = "bg" if case.locale == "bg-BG" else "en"
        _print_instructions(case)
        mokosh_gui.tk.Tk = lambda: root
        mokosh_gui.main()
    finally:
        mokosh_gui.tk.Tk = original_tk
        mokosh_gui.current_lang = original_lang
        try:
            root.destroy()
        except tk.TclError:
            pass

    observations = _observations(skip_observations, case.profile)
    report = build_main_gui_recovery_chain_layout_audit_report(case, observations)
    print(main_gui_recovery_chain_layout_audit_report_json(report), flush=True)
    return main_gui_recovery_chain_layout_audit_observations_pass(observations)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        for case_number in range(
            1, len(MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX) + 1
        ):
            if not _run_case(case_number, args.no_observations):
                print(
                    "The Stage 2.42 human layout audit did not pass; activation remains blocked.",
                    file=sys.stderr,
                )
                return 2
    except (
        tk.TclError,
        MainGUIRecoveryChainLayoutAuditError,
        _MainGUIRecoveryChainLayoutAuditLaunchError,
    ) as exc:
        print(
            "The Stage 2.42 layout audit failed safely: " f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print("The Stage 2.42 layout audit was cancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
