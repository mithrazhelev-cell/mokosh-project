#!/usr/bin/env python3
"""Launch the isolated Stage 2.15 synthetic recovery review harness."""

from __future__ import annotations

import argparse
import sys
import tkinter as tk

from mokosh_vault_recovery_review_window import (
    VaultRecoveryReviewWindowError,
    show_recovery_review_window,
)
from mokosh_vault_recovery_visual_harness import (
    RECOVERY_VISUAL_HARNESS_LOCALES,
    RECOVERY_VISUAL_HARNESS_ROUTES,
    RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS,
    RECOVERY_VISUAL_HARNESS_WINDOW_PROFILES,
    RecoveryVisualHarnessObservation,
    RecoveryVisualHarnessObservations,
    VaultRecoveryVisualHarnessError,
    build_recovery_visual_harness_report,
    prepare_synthetic_recovery_visual_case,
    recovery_visual_harness_report_json,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open only fixed non-secret Stage 2.15 fixtures in the real "
            "Stage 2.14 review Toplevel."
        )
    )
    parser.add_argument(
        "--route",
        choices=RECOVERY_VISUAL_HARNESS_ROUTES,
        default="absent",
    )
    parser.add_argument(
        "--locale",
        choices=RECOVERY_VISUAL_HARNESS_LOCALES,
        default="bg-BG",
    )
    parser.add_argument(
        "--scale",
        type=int,
        choices=RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS,
        default=100,
    )
    parser.add_argument(
        "--window-profile",
        choices=RECOVERY_VISUAL_HARNESS_WINDOW_PROFILES,
        default="small",
    )
    matrix_group = parser.add_mutually_exclusive_group()
    matrix_group.add_argument(
        "--matrix",
        action="store_true",
        help="Open all four routes in bg-BG and en-GB sequentially.",
    )
    matrix_group.add_argument(
        "--validation-matrix",
        action="store_true",
        help=(
            "Run the fixed eight-case Linux validation matrix with required "
            "close paths and complete pass observations."
        ),
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help="Record fixed not_checked values instead of terminal prompts.",
    )
    return parser


def _prompt_observation(label: str) -> RecoveryVisualHarnessObservation:
    while True:
        answer = input(f"{label} [y/n/s]: ").strip().lower()
        if answer == "y":
            return RecoveryVisualHarnessObservation.PASS
        if answer == "n":
            return RecoveryVisualHarnessObservation.FAIL
        if answer == "s":
            return RecoveryVisualHarnessObservation.NOT_CHECKED
        print("Use y (pass), n (fail), or s (not checked).")


def _observations(skip: bool) -> RecoveryVisualHarnessObservations:
    if skip:
        value = RecoveryVisualHarnessObservation.NOT_CHECKED
        return RecoveryVisualHarnessObservations(value, value, value, value)
    return RecoveryVisualHarnessObservations(
        scroll_reachability=_prompt_observation(
            "Could every item be reached by scrolling?"
        ),
        text_wrap=_prompt_observation("Did text wrap without visible clipping?"),
        focus_order=_prompt_observation("Was the focus order logical and visible?"),
        keyboard_only=_prompt_observation(
            "Did keyboard-only interaction work for this run?"
        ),
    )


def _apply_window_profile(root: tk.Tk, width: int, height: int) -> None:
    for child in root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.geometry(f"{width}x{height}")
            return
    root.after(25, _apply_window_profile, root, width, height)


def _run_case(
    route_id: str,
    locale_id: str,
    scale_percent: int,
    window_profile_id: str,
    skip_observations: bool,
    expected_outcome: str | None = None,
) -> bool:
    case = prepare_synthetic_recovery_visual_case(
        route_id,
        locale_id,
        scale_percent,
        window_profile_id,
    )
    root = tk.Tk()
    root.title("MOKOSH Stage 2.15 synthetic harness owner")
    root.geometry("420x90")
    root.resizable(False, False)
    tk.Label(
        root,
        text=(
            "Synthetic test owner only. The recovery review window must "
            "remain visible in front."
        ),
        padx=12,
        pady=12,
        wraplength=390,
    ).pack(fill="both", expand=True)
    root.tk.call("tk", "scaling", scale_percent / 100.0)
    root.update_idletasks()
    root.deiconify()
    root.update()
    root.after(25, _apply_window_profile, root, case.width, case.height)
    if expected_outcome is not None:
        print(
            f"Required terminal action for {route_id}/{locale_id}: "
            f"{expected_outcome}",
            flush=True,
        )
    try:
        outcome = show_recovery_review_window(
            root,
            case.presentation,
            case.adapter,
            case.locale.value,
        )
    finally:
        root.destroy()
    recorded_observations = _observations(skip_observations)
    report = build_recovery_visual_harness_report(
        case,
        outcome,
        recorded_observations,
    )
    print(recovery_visual_harness_report_json(report))
    actual_outcome = (
        "acknowledge"
        if outcome.decision.value == "acknowledged"
        else outcome.cancel_reason.value.replace("_", "-")
    )
    observations_pass = all(
        value is RecoveryVisualHarnessObservation.PASS
        for value in (
            recorded_observations.scroll_reachability,
            recorded_observations.text_wrap,
            recorded_observations.focus_order,
            recorded_observations.keyboard_only,
        )
    )
    return (
        (expected_outcome is None or actual_outcome == expected_outcome)
        and observations_pass
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.validation_matrix:
        cases = (
            ("absent", "bg-BG", 100, "small", "escape-key"),
            ("absent", "en-GB", 125, "small", "cancel-button"),
            ("exact", "bg-BG", 150, "standard", "window-close"),
            ("exact", "en-GB", 200, "standard", "acknowledge"),
            ("conflict", "bg-BG", 100, "small", "cancel-button"),
            ("conflict", "en-GB", 125, "small", "escape-key"),
            ("preserve", "bg-BG", 150, "standard", "acknowledge"),
            ("preserve", "en-GB", 200, "standard", "window-close"),
        )
    elif args.matrix:
        cases = tuple(
            (
                route_id,
                locale_id,
                args.scale,
                args.window_profile,
                None,
            )
            for route_id in RECOVERY_VISUAL_HARNESS_ROUTES
            for locale_id in RECOVERY_VISUAL_HARNESS_LOCALES
        )
    else:
        cases = (
            (
                args.route,
                args.locale,
                args.scale,
                args.window_profile,
                None,
            ),
        )
    try:
        validation_passed = True
        for route_id, locale_id, scale, profile, expected_outcome in cases:
            case_passed = _run_case(
                route_id,
                locale_id,
                scale,
                profile,
                args.no_observations,
                expected_outcome,
            )
            validation_passed = validation_passed and case_passed
    except (tk.TclError, VaultRecoveryReviewWindowError, VaultRecoveryVisualHarnessError):
        print("The synthetic recovery review harness failed safely.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("The synthetic recovery review harness was cancelled.", file=sys.stderr)
        return 130
    if args.validation_matrix and not validation_passed:
        print("The fixed visual validation matrix did not pass.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
