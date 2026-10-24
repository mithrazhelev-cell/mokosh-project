"""Bounded visual evidence for the Stage 2.43 fifth normal-GUI action.

This pure report core records only fixed human observations.  It has no GUI,
filesystem, process, network, logging, recovery-source path, secret, callback,
executor, source-access, inspection-preparation, or operation capability.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_VISUAL_REPORT"
)
RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_VERSION = 3
RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_LOCALES = (
    "bg-BG",
    "en-GB",
)


class RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
    ValueError
):
    """A route, observation, or report violates the frozen schema."""


class RecoverySourceInspectionPreparationRequestMainGUIVisualRoute(str, Enum):
    """Exact synthetic preparation-request routes."""

    REQUEST = "request"
    PRESERVE = "preserve"


class RecoverySourceInspectionPreparationRequestMainGUIVisualProfile(
    str,
    Enum,
):
    """Exact bounded interaction profile for one human case."""

    INITIAL_KEYBOARD = "initial_keyboard"
    RESIZE_RESTORE_KEYBOARD = "resize_restore_keyboard"


class RecoverySourceInspectionPreparationRequestMainGUIVisualObservation(
    str,
    Enum,
):
    """Exact observation values; arbitrary notes are not accepted."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


_MATRIX = (
    (
        "bg-BG",
        100,
        RecoverySourceInspectionPreparationRequestMainGUIVisualProfile.INITIAL_KEYBOARD,
        RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST,
    ),
    (
        "en-GB",
        125,
        RecoverySourceInspectionPreparationRequestMainGUIVisualProfile.INITIAL_KEYBOARD,
        RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.PRESERVE,
    ),
    (
        "bg-BG",
        150,
        RecoverySourceInspectionPreparationRequestMainGUIVisualProfile.RESIZE_RESTORE_KEYBOARD,
        RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.PRESERVE,
    ),
    (
        "en-GB",
        200,
        RecoverySourceInspectionPreparationRequestMainGUIVisualProfile.RESIZE_RESTORE_KEYBOARD,
        RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST,
    ),
)
RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_MATRIX = tuple(
    (locale, scale, profile.value, route.value)
    for locale, scale, profile, route in _MATRIX
)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionPreparationRequestMainGUIVisualCase:
    case_number: int
    locale: str
    scale_percent: int
    profile: RecoverySourceInspectionPreparationRequestMainGUIVisualProfile
    route: RecoverySourceInspectionPreparationRequestMainGUIVisualRoute
    synthetic_non_secret: bool = True

    def __post_init__(self) -> None:
        _validate_case(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionPreparationRequestMainGUIVisualObservations:
    parallel_step_guide_visible_and_usable: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    five_staged_actions_reachable: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    fifth_action_locked_until_positive_fourth_action: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    confirmation_opened_only_after_fifth_action: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    request_or_preserve_result_was_generic: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    no_source_content_secret_or_authority_observed: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    all_five_actions_one_shot: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    picker_metadata_disclosure_visible: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    preparation_no_access_disclosure_visible: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    path_retention_and_no_zeroisation_disclosure_visible: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    adaptive_keyboard_reachability_observed: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )
    safety_controls_visible: (
        RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
    )

    def __post_init__(self) -> None:
        for value in (
            self.parallel_step_guide_visible_and_usable,
            self.five_staged_actions_reachable,
            self.fifth_action_locked_until_positive_fourth_action,
            self.confirmation_opened_only_after_fifth_action,
            self.request_or_preserve_result_was_generic,
            self.no_source_content_secret_or_authority_observed,
            self.all_five_actions_one_shot,
            self.picker_metadata_disclosure_visible,
            self.preparation_no_access_disclosure_visible,
            self.path_retention_and_no_zeroisation_disclosure_visible,
            self.adaptive_keyboard_reachability_observed,
            self.safety_controls_visible,
        ):
            if (
                type(value)
                is not RecoverySourceInspectionPreparationRequestMainGUIVisualObservation
            ):
                raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
                    "preparation-request visual observation type is invalid"
                )


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionPreparationRequestMainGUIVisualReport:
    case_number: int
    locale: str
    scale_percent: int
    profile: RecoverySourceInspectionPreparationRequestMainGUIVisualProfile
    route: RecoverySourceInspectionPreparationRequestMainGUIVisualRoute
    observations: RecoverySourceInspectionPreparationRequestMainGUIVisualObservations
    normal_startup_observed: bool = True
    human_observation_only: bool = True
    synthetic_non_secret: bool = True
    true_recovery_input_used: bool = False
    native_source_picker_invoked: bool = True
    native_picker_filesystem_metadata_access_possible: bool = True
    source_selection_performed: bool = True
    source_path_metadata_received: bool = True
    inspection_request_action_invoked: bool = True
    preparation_request_action_invoked: bool = True
    process_local_path_retention_disclosed: bool = True
    memory_zeroisation_proven: bool = False
    parallel_step_guide_visible: bool = False
    per_action_guidance_provided: bool = False
    graphical_observation_wizard_used: bool = True
    observations_defaulted_to_not_checked: bool = True
    synthetic_mokr_fixture_used: bool = True
    visual_fixture_filesystem_mutation_disclosed: bool = True
    visual_fixture_removed_before_report: bool = True
    future_secure_source_inspection_preparation_requested: bool = False
    preparation_request_preserved_and_stopped: bool = True
    application_source_open_read_performed: bool = False
    source_identity_validated: bool = False
    source_access_authorized: bool = False
    filesystem_capability_issued: bool = False
    source_preparation_performed: bool = False
    recovery_secret_received: bool = False
    review_session_prepared: bool = False
    stage_2_32_authorization_activated: bool = False
    stage_2_41_review_activated: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    runtime_directory_preparation_performed: bool = True
    application_recovery_source_filesystem_mutation_performed: bool = False
    whole_process_no_filesystem_access_claimed: bool = False
    network_used: bool = False
    automatic_transition_performed: bool = False
    accessibility_conformity_claimed: bool = False
    legal_or_platform_certification_claimed: bool = False
    format: str = (
        RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_FORMAT
    )
    version: int = (
        RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_VERSION
    )

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_case(
    value: _Any,
) -> RecoverySourceInspectionPreparationRequestMainGUIVisualCase:
    if type(value) is not RecoverySourceInspectionPreparationRequestMainGUIVisualCase:
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual case type is invalid"
        )
    if type(value.case_number) is not int or not 1 <= value.case_number <= len(_MATRIX):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual case number is invalid"
        )
    locale, scale, profile, route = _MATRIX[value.case_number - 1]
    if (
        type(value.locale) is not str
        or value.locale != locale
        or type(value.scale_percent) is not int
        or value.scale_percent != scale
        or type(value.profile)
        is not RecoverySourceInspectionPreparationRequestMainGUIVisualProfile
        or value.profile is not profile
        or type(value.route)
        is not RecoverySourceInspectionPreparationRequestMainGUIVisualRoute
        or value.route is not route
        or value.synthetic_non_secret is not True
    ):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual case differs from the fixed matrix"
        )
    return value


def _validate_report(value: _Any) -> None:
    if type(value) is not RecoverySourceInspectionPreparationRequestMainGUIVisualReport:
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual report type is invalid"
        )
    _validate_case(
        RecoverySourceInspectionPreparationRequestMainGUIVisualCase(
            case_number=value.case_number,
            locale=value.locale,
            scale_percent=value.scale_percent,
            profile=value.profile,
            route=value.route,
        )
    )
    requesting = value.route is RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST
    guide_observed = (
        value.observations.parallel_step_guide_visible_and_usable
        is RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.PASS
    )
    if (
        type(value.observations)
        is not RecoverySourceInspectionPreparationRequestMainGUIVisualObservations
        or value.normal_startup_observed is not True
        or value.human_observation_only is not True
        or value.synthetic_non_secret is not True
        or value.true_recovery_input_used is not False
        or value.native_source_picker_invoked is not True
        or value.native_picker_filesystem_metadata_access_possible is not True
        or value.source_selection_performed is not True
        or value.source_path_metadata_received is not True
        or value.inspection_request_action_invoked is not True
        or value.preparation_request_action_invoked is not True
        or value.process_local_path_retention_disclosed is not True
        or value.memory_zeroisation_proven is not False
        or type(value.parallel_step_guide_visible) is not bool
        or value.parallel_step_guide_visible is not guide_observed
        or type(value.per_action_guidance_provided) is not bool
        or value.per_action_guidance_provided is not guide_observed
        or value.graphical_observation_wizard_used is not True
        or value.observations_defaulted_to_not_checked is not True
        or value.synthetic_mokr_fixture_used is not True
        or value.visual_fixture_filesystem_mutation_disclosed is not True
        or value.visual_fixture_removed_before_report is not True
        or type(value.future_secure_source_inspection_preparation_requested)
        is not bool
        or value.future_secure_source_inspection_preparation_requested
        is not requesting
        or type(value.preparation_request_preserved_and_stopped) is not bool
        or value.preparation_request_preserved_and_stopped is requesting
        or value.application_source_open_read_performed is not False
        or value.source_identity_validated is not False
        or value.source_access_authorized is not False
        or value.filesystem_capability_issued is not False
        or value.source_preparation_performed is not False
        or value.recovery_secret_received is not False
        or value.review_session_prepared is not False
        or value.stage_2_32_authorization_activated is not False
        or value.stage_2_41_review_activated is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.runtime_directory_preparation_performed is not True
        or value.application_recovery_source_filesystem_mutation_performed
        is not False
        or value.whole_process_no_filesystem_access_claimed is not False
        or value.network_used is not False
        or value.automatic_transition_performed is not False
        or value.accessibility_conformity_claimed is not False
        or value.legal_or_platform_certification_claimed is not False
        or type(value.format) is not str
        or value.format
        != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_FORMAT
        or type(value.version) is not int
        or value.version
        != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_REPORT_VERSION
    ):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual report is invalid"
        )


def prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
    case_number: int,
) -> RecoverySourceInspectionPreparationRequestMainGUIVisualCase:
    """Create one exact fixed case without GUI or host inspection."""

    if type(case_number) is not int or not 1 <= case_number <= len(_MATRIX):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual case number is invalid"
        )
    locale, scale, profile, route = _MATRIX[case_number - 1]
    return RecoverySourceInspectionPreparationRequestMainGUIVisualCase(
        case_number=case_number,
        locale=locale,
        scale_percent=scale,
        profile=profile,
        route=route,
    )


def build_recovery_source_inspection_preparation_request_main_gui_visual_report(
    case: RecoverySourceInspectionPreparationRequestMainGUIVisualCase,
    observations: RecoverySourceInspectionPreparationRequestMainGUIVisualObservations,
) -> RecoverySourceInspectionPreparationRequestMainGUIVisualReport:
    """Build one bounded report without retaining selected path metadata."""

    _validate_case(case)
    if (
        type(observations)
        is not RecoverySourceInspectionPreparationRequestMainGUIVisualObservations
    ):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual observations are invalid"
        )
    requesting = case.route is RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST
    guide_observed = (
        observations.parallel_step_guide_visible_and_usable
        is RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.PASS
    )
    return RecoverySourceInspectionPreparationRequestMainGUIVisualReport(
        case_number=case.case_number,
        locale=case.locale,
        scale_percent=case.scale_percent,
        profile=case.profile,
        route=case.route,
        observations=observations,
        parallel_step_guide_visible=guide_observed,
        per_action_guidance_provided=guide_observed,
        future_secure_source_inspection_preparation_requested=requesting,
        preparation_request_preserved_and_stopped=not requesting,
    )


def recovery_source_inspection_preparation_request_main_gui_visual_report_json(
    report: RecoverySourceInspectionPreparationRequestMainGUIVisualReport,
) -> str:
    """Encode the exact bounded report as canonical JSON."""

    _validate_report(report)
    payload = {
        field: getattr(report, field)
        for field in report.__dataclass_fields__
        if field not in {"profile", "route", "observations"}
    }
    payload["profile"] = report.profile.value
    payload["route"] = report.route.value
    payload["observations"] = {
        field: getattr(report.observations, field).value
        for field in report.observations.__dataclass_fields__
    }
    return _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def recovery_source_inspection_preparation_request_main_gui_observations_pass(
    observations: RecoverySourceInspectionPreparationRequestMainGUIVisualObservations,
) -> bool:
    """Return true only when all exact human observations pass."""

    if (
        type(observations)
        is not RecoverySourceInspectionPreparationRequestMainGUIVisualObservations
    ):
        raise RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError(
            "preparation-request visual observations are invalid"
        )
    return all(
        getattr(observations, field)
        is RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.PASS
        for field in observations.__dataclass_fields__
    )
