#!/usr/bin/env python3
"""Visible Linux gate for the Stage 2.28 recovery source selector."""

from __future__ import annotations

import argparse

import mokosh_gui
from mokosh_vault_recovery_source_selection_main_gui_visual_harness import (
    RecoverySourceSelectionMainGUIVisualObservation,
    RecoverySourceSelectionMainGUIVisualObservations,
    RecoverySourceSelectionMainGUIVisualRoute,
    build_recovery_source_selection_main_gui_visual_report,
    recovery_source_selection_main_gui_visual_report_json,
)


def _read_observation(
    prompt: str,
) -> RecoverySourceSelectionMainGUIVisualObservation:
    while True:
        answer = input(f"{prompt} [y/n/s]: ").strip().lower()
        if answer == "y":
            return RecoverySourceSelectionMainGUIVisualObservation.PASS
        if answer == "n":
            return RecoverySourceSelectionMainGUIVisualObservation.FAIL
        if answer == "s":
            return RecoverySourceSelectionMainGUIVisualObservation.NOT_CHECKED
        print("Use only y (yes), n (no), or s (not checked).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locale", required=True, choices=("bg-BG", "en-GB"))
    parser.add_argument("--route", required=True, choices=("select", "cancel"))
    args = parser.parse_args()
    route = RecoverySourceSelectionMainGUIVisualRoute(args.route)

    mokosh_gui.current_lang = "bg" if args.locale == "bg-BG" else "en"
    print("SYNTHETIC INSPECTION ONLY: never choose a real recovery record.")
    print("Do not enter a password, choose a Vault, or use a sensitive filename.")
    print("Normal GUI startup performs its existing private runtime-directory preparation.")
    print("The native picker may enumerate directories and inspect filesystem metadata.")
    print("MOKOSH does not open/read the selected source or mutate it in this stage.")
    print("This is not a whole-process no-filesystem-access claim.")
    print("Confirm that the third source-selection button starts disabled.")
    print("Use the first button and answer Yes; use the second and answer Yes.")
    if route is RecoverySourceSelectionMainGUIVisualRoute.SELECT:
        print("Use the third button and select only a harmless non-sensitive test file.")
    else:
        print("Use the third button and cancel/close the native picker.")
    print("Then close the MOKOSH window and answer the fixed observations below.")
    mokosh_gui.main()

    observations = RecoverySourceSelectionMainGUIVisualObservations(
        _read_observation("Were all three staged recovery actions clearly visible?"),
        _read_observation(
            "Did the source-selection action stay disabled until both positive steps?"
        ),
        _read_observation(
            "Did the native picker open only after the separate third action?"
        ),
        _read_observation(
            "Was the selection/cancel result generic and free of the selected path?"
        ),
        _read_observation(
            "Was no source content, password, recovery secret, or operation requested?"
        ),
        _read_observation("Did all three used actions remain one-shot/disabled?"),
        _read_observation(
            "Was the native-picker filesystem-metadata limitation clearly disclosed?"
        ),
        _read_observation("Did the safety-mode controls remain visibly disabled?"),
    )
    report = build_recovery_source_selection_main_gui_visual_report(
        args.locale,
        route,
        observations,
    )
    print(recovery_source_selection_main_gui_visual_report_json(report))
    passed = all(
        value is RecoverySourceSelectionMainGUIVisualObservation.PASS
        for value in (
            observations.three_staged_actions_visible,
            observations.source_action_locked_until_positive_transition,
            observations.picker_opened_only_after_third_action,
            observations.selected_or_cancelled_result_was_generic,
            observations.no_source_content_or_secret_access_observed,
            observations.all_three_actions_one_shot,
            observations.picker_metadata_disclosure_visible,
            observations.safety_controls_visible,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
