"""Bounded human-observation contract for the Stage 2.48 normal GUI."""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, fields
from typing import Any


PROFILE_MAIN_GUI_VISUAL_VERSION = 4
PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES = 4096
PROFILE_MAIN_GUI_VISUAL_SCALES = (100, 125, 150, 200)
PROFILE_MAIN_GUI_VISUAL_LOCALES = ("en", "bg")
PROFILE_ENTRY_TRANSITION_VISUAL_VERSION = 3
PROFILE_ENTRY_TRANSITION_VISUAL_WORKFLOW = "first_run_login_lock"


class ProfileMainGUIVisualHarnessError(ValueError):
    """A visual case or bounded observation is invalid."""


class VisualObservation(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True, slots=True)
class ProfileMainGUIVisualCase:
    case_number: int
    locale: str
    scale_percent: int
    session_state: str


@dataclass(frozen=True, slots=True)
class ProfileMainGUIVisualObservations:
    text_readable_and_unclipped: VisualObservation
    text_reflows_at_narrow_width: VisualObservation
    rows_logical_and_symmetric: VisualObservation
    scrolling_reaches_every_control: VisualObservation
    keyboard_focus_reaches_every_control: VisualObservation
    password_and_nickname_masked: VisualObservation
    both_eye_controls_show_and_remask: VisualObservation
    locked_recovery_only_gate_correct: VisualObservation
    unlocked_v2_legacy_and_recovery_setup_gates_correct: VisualObservation
    v2_actions_and_historical_mok1_are_visually_separate: VisualObservation
    recovery_status_matches_gate: VisualObservation
    resize_keeps_actions_operable: VisualObservation
    minimize_maximize_restore_and_move_work: VisualObservation


@dataclass(frozen=True, slots=True)
class ProfileMainGUIVisualReport:
    version: int
    case_number: int
    locale: str
    scale_percent: int
    session_state: str
    observations: ProfileMainGUIVisualObservations
    synthetic_non_secret: bool = True
    filesystem_mutation_performed: bool = False
    operation_performed: bool = False


@dataclass(frozen=True, slots=True)
class ProfileEntryTransitionVisualObservations:
    constructor_returns_without_blocking: VisualObservation
    main_and_first_run_windows_map: VisualObservation
    first_run_dialog_single_and_focused: VisualObservation
    first_run_nickname_accepts_typing_and_paste: VisualObservation
    first_run_password_and_confirmation_accept_input: VisualObservation
    first_run_passwords_masked: VisualObservation
    first_run_eyes_show_and_remask: VisualObservation
    create_returns_to_locked_main_window: VisualObservation
    main_login_entries_accept_input: VisualObservation
    successful_login_clears_both_entries: VisualObservation
    unlocked_status_and_lock_button_visible: VisualObservation
    manual_lock_returns_locked: VisualObservation
    all_window_controls_and_reflow_work: VisualObservation
    localized_actions_and_errors_are_plain: VisualObservation


@dataclass(frozen=True, slots=True)
class ProfileEntryTransitionVisualReport:
    version: int
    workflow: str
    locale: str
    scale_percent: int
    observations: ProfileEntryTransitionVisualObservations
    synthetic_non_secret: bool = True
    filesystem_mutation_performed: bool = False
    operation_performed: bool = False


PROFILE_MAIN_GUI_VISUAL_MATRIX = tuple(
    ProfileMainGUIVisualCase(
        case_number=index + 1,
        locale=locale,
        scale_percent=scale,
        session_state="locked" if index % 2 == 0 else "unlocked",
    )
    for index, (locale, scale) in enumerate(
        (locale_scale for locale in PROFILE_MAIN_GUI_VISUAL_LOCALES for locale_scale in ((locale, value) for value in PROFILE_MAIN_GUI_VISUAL_SCALES))
    )
)


def prepare_profile_main_gui_visual_case(case_number: Any) -> ProfileMainGUIVisualCase:
    if type(case_number) is not int or not 1 <= case_number <= len(
        PROFILE_MAIN_GUI_VISUAL_MATRIX
    ):
        raise ProfileMainGUIVisualHarnessError("visual case number is invalid")
    return PROFILE_MAIN_GUI_VISUAL_MATRIX[case_number - 1]


def _validate_observations(value: Any) -> None:
    if not isinstance(value, ProfileMainGUIVisualObservations):
        raise ProfileMainGUIVisualHarnessError("visual observations are invalid")
    if any(not isinstance(item, VisualObservation) for item in asdict(value).values()):
        # asdict preserves Enum objects; arbitrary strings remain detectable.
        raise ProfileMainGUIVisualHarnessError("visual observation value is invalid")


def build_profile_main_gui_visual_report(
    case: Any,
    observations: Any,
) -> ProfileMainGUIVisualReport:
    if not isinstance(case, ProfileMainGUIVisualCase) or case not in PROFILE_MAIN_GUI_VISUAL_MATRIX:
        raise ProfileMainGUIVisualHarnessError("visual case is invalid")
    _validate_observations(observations)
    return ProfileMainGUIVisualReport(
        version=PROFILE_MAIN_GUI_VISUAL_VERSION,
        case_number=case.case_number,
        locale=case.locale,
        scale_percent=case.scale_percent,
        session_state=case.session_state,
        observations=observations,
    )


def profile_main_gui_visual_report_json(report: Any) -> str:
    if not isinstance(report, ProfileMainGUIVisualReport):
        raise ProfileMainGUIVisualHarnessError("visual report is invalid")
    _validate_observations(report.observations)
    mapping = asdict(report)
    mapping["observations"] = {
        field.name: getattr(report.observations, field.name).value
        for field in fields(ProfileMainGUIVisualObservations)
    }
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES:
        raise ProfileMainGUIVisualHarnessError("visual report exceeds its bound")
    return encoded


def profile_main_gui_visual_observations_pass(value: Any) -> bool:
    _validate_observations(value)
    return all(
        getattr(value, field.name) is VisualObservation.PASS
        for field in fields(ProfileMainGUIVisualObservations)
    )


def _validate_entry_transition_observations(value: Any) -> None:
    if not isinstance(value, ProfileEntryTransitionVisualObservations):
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual observations are invalid"
        )
    if any(not isinstance(item, VisualObservation) for item in asdict(value).values()):
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual observation value is invalid"
        )


def build_profile_entry_transition_visual_report(
    observations: Any,
    *,
    locale: Any = "bg",
    scale_percent: Any = 100,
) -> ProfileEntryTransitionVisualReport:
    _validate_entry_transition_observations(observations)
    if locale not in PROFILE_MAIN_GUI_VISUAL_LOCALES:
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual locale is invalid"
        )
    if type(scale_percent) is not int or scale_percent not in PROFILE_MAIN_GUI_VISUAL_SCALES:
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual scale is invalid"
        )
    return ProfileEntryTransitionVisualReport(
        version=PROFILE_ENTRY_TRANSITION_VISUAL_VERSION,
        workflow=PROFILE_ENTRY_TRANSITION_VISUAL_WORKFLOW,
        locale=locale,
        scale_percent=scale_percent,
        observations=observations,
    )


def profile_entry_transition_visual_report_json(report: Any) -> str:
    if not isinstance(report, ProfileEntryTransitionVisualReport):
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual report is invalid"
        )
    _validate_entry_transition_observations(report.observations)
    mapping = asdict(report)
    mapping["observations"] = {
        field.name: getattr(report.observations, field.name).value
        for field in fields(ProfileEntryTransitionVisualObservations)
    }
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES:
        raise ProfileMainGUIVisualHarnessError(
            "entry-transition visual report exceeds its bound"
        )
    return encoded


def profile_entry_transition_visual_observations_pass(value: Any) -> bool:
    _validate_entry_transition_observations(value)
    return all(
        getattr(value, field.name) is VisualObservation.PASS
        for field in fields(ProfileEntryTransitionVisualObservations)
    )


__all__ = [
    "PROFILE_ENTRY_TRANSITION_VISUAL_VERSION",
    "PROFILE_ENTRY_TRANSITION_VISUAL_WORKFLOW",
    "PROFILE_MAIN_GUI_VISUAL_LOCALES",
    "PROFILE_MAIN_GUI_VISUAL_MATRIX",
    "PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES",
    "PROFILE_MAIN_GUI_VISUAL_SCALES",
    "PROFILE_MAIN_GUI_VISUAL_VERSION",
    "ProfileEntryTransitionVisualObservations",
    "ProfileEntryTransitionVisualReport",
    "ProfileMainGUIVisualCase",
    "ProfileMainGUIVisualHarnessError",
    "ProfileMainGUIVisualObservations",
    "ProfileMainGUIVisualReport",
    "VisualObservation",
    "build_profile_entry_transition_visual_report",
    "build_profile_main_gui_visual_report",
    "prepare_profile_main_gui_visual_case",
    "profile_entry_transition_visual_observations_pass",
    "profile_entry_transition_visual_report_json",
    "profile_main_gui_visual_observations_pass",
    "profile_main_gui_visual_report_json",
]
