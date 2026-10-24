#!/usr/bin/env python3
"""Run the conditional Stage 2.18 main-GUI event with synthetic data only."""

from __future__ import annotations

import argparse
import sys
import tkinter as tk

import mokosh_gui
from mokosh_vault_recovery_main_gui_visual_harness import (
    MAIN_GUI_VISUAL_HARNESS_LOCALES,
    MAIN_GUI_VISUAL_HARNESS_ROUTES,
    MainGUIRecoveryReviewObservations,
    MainGUIVisualHarnessObservation,
    VaultRecoveryMainGUIVisualHarnessError,
    build_main_gui_recovery_review_report,
    main_gui_recovery_review_report_json,
    prepare_synthetic_main_gui_recovery_review_case,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open the real MOKOSH main GUI with one fixed synthetic, "
            "inspection-only Stage 2.18 review button."
        )
    )
    parser.add_argument(
        "--route",
        choices=MAIN_GUI_VISUAL_HARNESS_ROUTES,
        default="absent",
    )
    parser.add_argument(
        "--locale",
        choices=MAIN_GUI_VISUAL_HARNESS_LOCALES,
        default="bg-BG",
    )
    parser.add_argument(
        "--no-observations",
        action="store_true",
        help="Record fixed not_checked values instead of terminal prompts.",
    )
    return parser


def _prompt(label: str) -> MainGUIVisualHarnessObservation:
    while True:
        answer = input(f"{label} [y/n/s]: ").strip().lower()
        if answer == "y":
            return MainGUIVisualHarnessObservation.PASS
        if answer == "n":
            return MainGUIVisualHarnessObservation.FAIL
        if answer == "s":
            return MainGUIVisualHarnessObservation.NOT_CHECKED
        print("Use y (pass), n (fail), or s (not checked).")


def _observations(skip: bool) -> MainGUIRecoveryReviewObservations:
    if skip:
        value = MainGUIVisualHarnessObservation.NOT_CHECKED
        return MainGUIRecoveryReviewObservations(value, value, value, value)
    return MainGUIRecoveryReviewObservations(
        prepared_banner_and_button_visible=_prompt(
            "Was the prepared-review banner and button clearly visible?"
        ),
        unrelated_controls_disabled=_prompt(
            "Were the unrelated main-GUI controls disabled?"
        ),
        review_opened_in_front=_prompt(
            "Did the button open the recovery review in front?"
        ),
        one_shot_button_disabled=_prompt(
            "After the review, did the button remain disabled?"
        ),
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        case = prepare_synthetic_main_gui_recovery_review_case(
            args.route,
            args.locale,
        )
        print(
            "SYNTHETIC INSPECTION ONLY: no Vault, password, keyring, file, "
            "or recovery operation is used.",
            flush=True,
        )
        print(
            "Normal GUI startup performs its existing private runtime-directory "
            "preparation.",
            flush=True,
        )
        print(
            "This report makes no whole-process no-filesystem-access or "
            "no-filesystem-mutation claim.",
            flush=True,
        )
        print(
            "Open the prepared review once, finish or cancel it, inspect the "
            "disabled button, then close the main MOKOSH window.",
            flush=True,
        )
        mokosh_gui.main(case.binding)
        outcome = case.binding.outcome
        if outcome is None:
            raise VaultRecoveryMainGUIVisualHarnessError(
                "the conditional review event was not completed"
            )
        observations = _observations(args.no_observations)
        report = build_main_gui_recovery_review_report(
            case,
            outcome,
            observations,
        )
        print(main_gui_recovery_review_report_json(report))
    except (tk.TclError, VaultRecoveryMainGUIVisualHarnessError):
        print(
            "The synthetic Stage 2.18 main-GUI review failed safely.",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print(
            "The synthetic Stage 2.18 main-GUI review was cancelled.",
            file=sys.stderr,
        )
        return 130
    if not args.no_observations and any(
        value is not MainGUIVisualHarnessObservation.PASS
        for value in (
            observations.prepared_banner_and_button_visible,
            observations.unrelated_controls_disabled,
            observations.review_opened_in_front,
            observations.one_shot_button_disabled,
        )
    ):
        print("The visible Stage 2.18 observations did not pass.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
