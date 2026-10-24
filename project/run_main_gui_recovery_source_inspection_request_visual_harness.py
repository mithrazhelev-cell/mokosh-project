#!/usr/bin/env python3
"""Visible Linux gate for the Stage 2.30 inspection-request action."""

from __future__ import annotations

import argparse

import mokosh_gui
from mokosh_vault_recovery_source_inspection_request_main_gui_visual_harness import (
    RecoverySourceInspectionRequestMainGUIVisualObservation,
    RecoverySourceInspectionRequestMainGUIVisualObservations,
    RecoverySourceInspectionRequestMainGUIVisualRoute,
    build_recovery_source_inspection_request_main_gui_visual_report,
    recovery_source_inspection_request_main_gui_visual_report_json,
)


def _read_observation(
    prompt: str,
) -> RecoverySourceInspectionRequestMainGUIVisualObservation:
    while True:
        answer = input(f"{prompt} [y/n/s]: ").strip().lower()
        if answer == "y":
            return RecoverySourceInspectionRequestMainGUIVisualObservation.PASS
        if answer == "n":
            return RecoverySourceInspectionRequestMainGUIVisualObservation.FAIL
        if answer == "s":
            return RecoverySourceInspectionRequestMainGUIVisualObservation.NOT_CHECKED
        print("Use only y (yes), n (no), or s (not checked).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locale", required=True, choices=("bg-BG", "en-GB"))
    parser.add_argument("--route", required=True, choices=("request", "preserve"))
    args = parser.parse_args()
    route = RecoverySourceInspectionRequestMainGUIVisualRoute(args.route)

    mokosh_gui.current_lang = "bg" if args.locale == "bg-BG" else "en"
    print("SYNTHETIC INSPECTION ONLY: never choose a real recovery record.")
    print("Do not enter a password, choose a Vault, or use a sensitive filename.")
    print("Normal GUI startup performs its existing private runtime-directory preparation.")
    print("The native picker may enumerate directories and inspect filesystem metadata.")
    print("MOKOSH does not open/read the selected source or mutate it in this stage.")
    print("The fourth action records only a future request, not source-access authority.")
    print("This is not a whole-process no-filesystem-access claim.")
    print("Confirm that the fourth inspection-request button starts disabled.")
    print("Use the first button and answer Yes; use the second and answer Yes.")
    print("Use the third button and select only a harmless non-sensitive test file.")
    if route is RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST:
        print("Use the fourth button and answer Yes to record only the future request.")
    else:
        print("Use the fourth button and answer No to preserve and stop.")
    print("Then close the MOKOSH window and answer the fixed observations below.")
    mokosh_gui.main()

    observations = RecoverySourceInspectionRequestMainGUIVisualObservations(
        _read_observation("Were all four staged recovery actions clearly visible?"),
        _read_observation(
            "Did the fourth action stay disabled until positive source selection?"
        ),
        _read_observation(
            "Did its confirmation open only after the separate fourth action?"
        ),
        _read_observation(
            "Was the request/preserve result generic and free of the selected path?"
        ),
        _read_observation(
            "Was no source content, password, recovery secret, or operation requested?"
        ),
        _read_observation("Did all four used actions remain one-shot/disabled?"),
        _read_observation(
            "Was the native-picker filesystem-metadata limitation clearly disclosed?"
        ),
        _read_observation(
            "Was it clear that the request does not authorise source access?"
        ),
        _read_observation("Did the safety-mode controls remain visibly disabled?"),
    )
    report = build_recovery_source_inspection_request_main_gui_visual_report(
        args.locale,
        route,
        observations,
    )
    print(recovery_source_inspection_request_main_gui_visual_report_json(report))
    passed = all(
        value is RecoverySourceInspectionRequestMainGUIVisualObservation.PASS
        for value in (
            observations.four_staged_actions_visible,
            observations.request_action_locked_until_positive_selection,
            observations.confirmation_opened_only_after_fourth_action,
            observations.request_or_preserve_result_was_generic,
            observations.no_source_content_or_secret_access_observed,
            observations.all_four_actions_one_shot,
            observations.picker_metadata_disclosure_visible,
            observations.request_no_access_disclosure_visible,
            observations.safety_controls_visible,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
