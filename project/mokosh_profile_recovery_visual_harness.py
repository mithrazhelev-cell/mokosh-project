"""Bounded human-observation contract for the Stage 2.47 recovery GUI."""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, fields
from typing import Any


PROFILE_RECOVERY_GUI_VISUAL_VERSION = 2
PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES = 4096
PROFILE_RECOVERY_GUI_VISUAL_SCALES = (100, 125, 150, 200)
PROFILE_RECOVERY_GUI_VISUAL_LOCALES = ("en", "bg")
PROFILE_RECOVERY_GUI_VISUAL_WORKFLOWS = ("setup", "password_recovery")
PROFILE_RECOVERY_TRANSITION_VISUAL_VERSION = 2
PROFILE_RECOVERY_TRANSITION_VISUAL_WORKFLOW = (
    "unlock_enroll_lock_recover_new_login_lock"
)


class ProfileRecoveryGUIVisualHarnessError(ValueError):
    """A recovery visual case or bounded observation is invalid."""


class RecoveryVisualObservation(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True, slots=True)
class ProfileRecoveryGUIVisualCase:
    case_number: int
    locale: str
    scale_percent: int
    workflow: str


@dataclass(frozen=True, slots=True)
class ProfileRecoveryGUIVisualObservations:
    window_maps_without_blocking: RecoveryVisualObservation
    localized_text_readable_and_unclipped: RecoveryVisualObservation
    text_reflows_at_narrow_width: RecoveryVisualObservation
    contextual_help_precedes_actions: RecoveryVisualObservation
    scrolling_reaches_every_control: RecoveryVisualObservation
    keyboard_focus_reaches_every_control: RecoveryVisualObservation
    password_fields_are_masked: RecoveryVisualObservation
    all_password_eyes_show_and_remask: RecoveryVisualObservation
    phrase_positions_or_source_are_clear: RecoveryVisualObservation
    separate_storage_warning_is_prominent: RecoveryVisualObservation
    ordered_actions_and_gates_are_clear: RecoveryVisualObservation
    localized_action_labels_are_unambiguous: RecoveryVisualObservation
    resize_keeps_actions_operable: RecoveryVisualObservation
    minimize_maximize_restore_and_move_work: RecoveryVisualObservation


@dataclass(frozen=True, slots=True)
class ProfileRecoveryGUIVisualReport:
    version: int
    case_number: int
    locale: str
    scale_percent: int
    workflow: str
    observations: ProfileRecoveryGUIVisualObservations
    synthetic_non_secret: bool = True
    filesystem_mutation_performed: bool = False
    recovery_operation_performed: bool = False


@dataclass(frozen=True, slots=True)
class ProfileRecoveryTransitionVisualObservations:
    starts_unlocked_with_setup_only: RecoveryVisualObservation
    setup_reauthentication_accepts_masked_input: RecoveryVisualObservation
    setup_password_eye_shows_and_remasks: RecoveryVisualObservation
    all_25_numbered_words_are_readable: RecoveryVisualObservation
    record_export_precedes_phrase_backup: RecoveryVisualObservation
    same_device_choice_is_refused_clearly: RecoveryVisualObservation
    separate_sheet_or_full_paper_check_completes: RecoveryVisualObservation
    setup_cancel_and_close_are_safe: RecoveryVisualObservation
    manual_lock_hides_phrase_and_enables_recovery: RecoveryVisualObservation
    recovery_sources_are_explicitly_selected: RecoveryVisualObservation
    new_password_fields_are_masked: RecoveryVisualObservation
    both_new_password_eyes_show_and_remask: RecoveryVisualObservation
    password_mismatch_message_is_specific: RecoveryVisualObservation
    source_mismatch_message_is_safe_and_plain: RecoveryVisualObservation
    preview_is_visibly_read_only: RecoveryVisualObservation
    final_publish_requires_confirmation: RecoveryVisualObservation
    successful_publish_returns_locked: RecoveryVisualObservation
    stale_recovery_button_is_disabled: RecoveryVisualObservation
    replacement_banner_and_login_reminder_are_clear: RecoveryVisualObservation
    old_password_is_refused: RecoveryVisualObservation
    new_password_login_clears_credentials: RecoveryVisualObservation
    final_manual_lock_returns_locked: RecoveryVisualObservation
    child_and_popup_window_controls_work: RecoveryVisualObservation
    narrow_width_reflows_and_keeps_actions_reachable: RecoveryVisualObservation


@dataclass(frozen=True, slots=True)
class ProfileRecoveryTransitionVisualReport:
    version: int
    workflow: str
    locale: str
    scale_percent: int
    observations: ProfileRecoveryTransitionVisualObservations
    synthetic_non_secret: bool = True
    filesystem_mutation_performed: bool = False
    recovery_operation_performed: bool = False


PROFILE_RECOVERY_GUI_VISUAL_MATRIX = tuple(
    ProfileRecoveryGUIVisualCase(
        case_number=index + 1,
        locale=locale,
        scale_percent=scale,
        workflow=workflow,
    )
    for index, (locale, scale, workflow) in enumerate(
        (locale, scale, workflow)
        for locale in PROFILE_RECOVERY_GUI_VISUAL_LOCALES
        for scale in PROFILE_RECOVERY_GUI_VISUAL_SCALES
        for workflow in PROFILE_RECOVERY_GUI_VISUAL_WORKFLOWS
    )
)


def prepare_profile_recovery_gui_visual_case(
    case_number: Any,
) -> ProfileRecoveryGUIVisualCase:
    if type(case_number) is not int or not 1 <= case_number <= len(
        PROFILE_RECOVERY_GUI_VISUAL_MATRIX
    ):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual case number is invalid"
        )
    return PROFILE_RECOVERY_GUI_VISUAL_MATRIX[case_number - 1]


def _validate_observations(value: Any) -> None:
    if not isinstance(value, ProfileRecoveryGUIVisualObservations):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual observations are invalid"
        )
    if any(
        not isinstance(item, RecoveryVisualObservation)
        for item in asdict(value).values()
    ):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual observation value is invalid"
        )


def build_profile_recovery_gui_visual_report(
    case: Any,
    observations: Any,
) -> ProfileRecoveryGUIVisualReport:
    if (
        not isinstance(case, ProfileRecoveryGUIVisualCase)
        or case not in PROFILE_RECOVERY_GUI_VISUAL_MATRIX
    ):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual case is invalid"
        )
    _validate_observations(observations)
    return ProfileRecoveryGUIVisualReport(
        version=PROFILE_RECOVERY_GUI_VISUAL_VERSION,
        case_number=case.case_number,
        locale=case.locale,
        scale_percent=case.scale_percent,
        workflow=case.workflow,
        observations=observations,
    )


def profile_recovery_gui_visual_report_json(report: Any) -> str:
    if not isinstance(report, ProfileRecoveryGUIVisualReport):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual report is invalid"
        )
    _validate_observations(report.observations)
    mapping = asdict(report)
    mapping["observations"] = {
        field.name: getattr(report.observations, field.name).value
        for field in fields(ProfileRecoveryGUIVisualObservations)
    }
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES:
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery visual report exceeds its bound"
        )
    return encoded


def profile_recovery_gui_visual_observations_pass(value: Any) -> bool:
    _validate_observations(value)
    return all(
        getattr(value, field.name) is RecoveryVisualObservation.PASS
        for field in fields(ProfileRecoveryGUIVisualObservations)
    )


def _validate_transition_observations(value: Any) -> None:
    if not isinstance(value, ProfileRecoveryTransitionVisualObservations):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition observations are invalid"
        )
    if any(
        not isinstance(item, RecoveryVisualObservation)
        for item in asdict(value).values()
    ):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition observation value is invalid"
        )


def build_profile_recovery_transition_visual_report(
    observations: Any,
    *,
    locale: Any = "bg",
    scale_percent: Any = 100,
) -> ProfileRecoveryTransitionVisualReport:
    _validate_transition_observations(observations)
    if locale not in PROFILE_RECOVERY_GUI_VISUAL_LOCALES:
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition locale is invalid"
        )
    if (
        type(scale_percent) is not int
        or scale_percent not in PROFILE_RECOVERY_GUI_VISUAL_SCALES
    ):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition scale is invalid"
        )
    return ProfileRecoveryTransitionVisualReport(
        version=PROFILE_RECOVERY_TRANSITION_VISUAL_VERSION,
        workflow=PROFILE_RECOVERY_TRANSITION_VISUAL_WORKFLOW,
        locale=locale,
        scale_percent=scale_percent,
        observations=observations,
    )


def profile_recovery_transition_visual_report_json(report: Any) -> str:
    if not isinstance(report, ProfileRecoveryTransitionVisualReport):
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition visual report is invalid"
        )
    _validate_transition_observations(report.observations)
    mapping = asdict(report)
    mapping["observations"] = {
        field.name: getattr(report.observations, field.name).value
        for field in fields(ProfileRecoveryTransitionVisualObservations)
    }
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES:
        raise ProfileRecoveryGUIVisualHarnessError(
            "recovery transition visual report exceeds its bound"
        )
    return encoded


def profile_recovery_transition_visual_observations_pass(value: Any) -> bool:
    _validate_transition_observations(value)
    return all(
        getattr(value, field.name) is RecoveryVisualObservation.PASS
        for field in fields(ProfileRecoveryTransitionVisualObservations)
    )


__all__ = [
    "PROFILE_RECOVERY_GUI_VISUAL_LOCALES",
    "PROFILE_RECOVERY_GUI_VISUAL_MATRIX",
    "PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES",
    "PROFILE_RECOVERY_GUI_VISUAL_SCALES",
    "PROFILE_RECOVERY_GUI_VISUAL_VERSION",
    "PROFILE_RECOVERY_GUI_VISUAL_WORKFLOWS",
    "PROFILE_RECOVERY_TRANSITION_VISUAL_VERSION",
    "PROFILE_RECOVERY_TRANSITION_VISUAL_WORKFLOW",
    "ProfileRecoveryGUIVisualCase",
    "ProfileRecoveryGUIVisualHarnessError",
    "ProfileRecoveryGUIVisualObservations",
    "ProfileRecoveryGUIVisualReport",
    "ProfileRecoveryTransitionVisualObservations",
    "ProfileRecoveryTransitionVisualReport",
    "RecoveryVisualObservation",
    "build_profile_recovery_gui_visual_report",
    "build_profile_recovery_transition_visual_report",
    "prepare_profile_recovery_gui_visual_case",
    "profile_recovery_gui_visual_observations_pass",
    "profile_recovery_gui_visual_report_json",
    "profile_recovery_transition_visual_observations_pass",
    "profile_recovery_transition_visual_report_json",
]
