#!/usr/bin/env python3
"""Visible Linux gate for the Stage 2.25 no-source transition action."""

from __future__ import annotations

import argparse

import mokosh_gui
from mokosh_vault_recovery_entry_transition_main_gui_visual_harness import (
    RecoveryEntryTransitionMainGUIVisualObservation,
    RecoveryEntryTransitionMainGUIVisualObservations,
    build_recovery_entry_transition_main_gui_visual_report,
    recovery_entry_transition_main_gui_visual_report_json,
)


def _read_observation(
    prompt: str,
) -> RecoveryEntryTransitionMainGUIVisualObservation:
    while True:
        answer = input(f"{prompt} [y/n/s]: ").strip().lower()
        if answer == "y":
            return RecoveryEntryTransitionMainGUIVisualObservation.PASS
        if answer == "n":
            return RecoveryEntryTransitionMainGUIVisualObservation.FAIL
        if answer == "s":
            return RecoveryEntryTransitionMainGUIVisualObservation.NOT_CHECKED
        print("Use only y (yes), n (no), or s (not checked).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locale", required=True, choices=("bg-BG", "en-GB"))
    args = parser.parse_args()

    mokosh_gui.current_lang = "bg" if args.locale == "bg-BG" else "en"
    print("SYNTHETIC INSPECTION ONLY: do not enter a password or choose a Vault.")
    print("Normal GUI startup performs its existing private runtime-directory preparation.")
    print("This report makes no whole-process no-filesystem-access or mutation claim.")
    print("First confirm that the second recovery button is disabled.")
    print("Click the request button, choose Yes, and read the bounded result.")
    print("Then click the separately enabled second button, choose Yes, and read")
    print("that only a future source-selection intent was recorded.")
    print("No source, file, Vault, keyring, review, or recovery operation is used.")
    mokosh_gui.main()

    observations = RecoveryEntryTransitionMainGUIVisualObservations(
        _read_observation(
            "Were the request control and locked second-step control clearly visible?"
        ),
        _read_observation(
            "Did the first Yes enable only the second button without opening anything?"
        ),
        _read_observation(
            "Did the second confirmation clearly state that no source or operation starts?"
        ),
        _read_observation(
            "Did the result clearly state that only future intent was recorded?"
        ),
        _read_observation(
            "Did no source picker, file picker, Vault picker, or recovery review open?"
        ),
        _read_observation("Did both used actions remain disabled after one use?"),
        _read_observation("Did the safety-mode controls remain clearly disabled?"),
    )
    report = build_recovery_entry_transition_main_gui_visual_report(
        args.locale,
        observations,
    )
    print(recovery_entry_transition_main_gui_visual_report_json(report))
    passed = all(
        value is RecoveryEntryTransitionMainGUIVisualObservation.PASS
        for value in (
            observations.request_and_locked_transition_visible,
            observations.request_arms_transition_only,
            observations.second_confirmation_boundary_clear,
            observations.transition_result_clear,
            observations.no_source_or_review_opened,
            observations.both_actions_one_shot,
            observations.safety_controls_visible,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
