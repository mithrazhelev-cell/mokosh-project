#!/usr/bin/env python3
"""Visible Linux observation gate for the Stage 2.20 normal-GUI entry."""

from __future__ import annotations

import argparse

import mokosh_gui
from mokosh_vault_recovery_entry_main_gui_visual_harness import (
    RecoveryEntryMainGUIVisualObservation,
    RecoveryEntryMainGUIVisualObservations,
    build_recovery_entry_main_gui_visual_report,
    recovery_entry_main_gui_visual_report_json,
)


def _read_observation(prompt: str) -> RecoveryEntryMainGUIVisualObservation:
    while True:
        answer = input(f"{prompt} [y/n/s]: ").strip().lower()
        if answer == "y":
            return RecoveryEntryMainGUIVisualObservation.PASS
        if answer == "n":
            return RecoveryEntryMainGUIVisualObservation.FAIL
        if answer == "s":
            return RecoveryEntryMainGUIVisualObservation.NOT_CHECKED
        print("Use only y (yes), n (no), or s (not checked).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locale", required=True, choices=("bg-BG", "en-GB"))
    args = parser.parse_args()

    mokosh_gui.current_lang = "bg" if args.locale == "bg-BG" else "en"
    print("SYNTHETIC INSPECTION ONLY: do not enter a password or choose a Vault.")
    print("Normal GUI startup performs its existing private runtime-directory preparation.")
    print("This report makes no whole-process no-filesystem-access or mutation claim.")
    print("Click the recovery-review request button once, choose Yes, read the")
    print("result, inspect the disabled button and safety controls, then close MOKOSH.")
    print("No file, Vault, keyring, recovery review, or recovery operation is used.")
    mokosh_gui.main()

    observations = RecoveryEntryMainGUIVisualObservations(
        _read_observation("Were the recovery-request banner and button clearly visible?"),
        _read_observation("Did the confirmation clearly say that no source or operation starts?"),
        _read_observation("After Yes, did the result clearly say that only a request was recorded?"),
        _read_observation("Did no file picker, Vault picker, or recovery review open?"),
        _read_observation("Did the request button stay disabled and the safety controls remain clear?"),
    )
    report = build_recovery_entry_main_gui_visual_report(args.locale, observations)
    print(recovery_entry_main_gui_visual_report_json(report))
    passed = all(
        value is RecoveryEntryMainGUIVisualObservation.PASS
        for value in (
            observations.banner_and_button_visible,
            observations.confirmation_boundary_clear,
            observations.request_result_clear,
            observations.no_source_or_review_opened,
            observations.one_shot_and_safety_controls_visible,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
