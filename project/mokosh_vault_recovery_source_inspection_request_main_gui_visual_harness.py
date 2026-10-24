"""Bounded visual evidence for the Stage 2.30 main-GUI request action.

This pure report core records fixed human observations.  It contains no GUI,
filesystem, process, network, logging, recovery-source path, secret, callback,
executor, source-access, or operation capability.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_SOURCE_INSPECTION_REQUEST_VISUAL_REPORT"
)
RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_VERSION = 1
RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_LOCALES = ("bg-BG", "en-GB")


class RecoverySourceInspectionRequestMainGUIVisualHarnessError(ValueError):
    """A route, observation, or report violates the frozen schema."""


class RecoverySourceInspectionRequestMainGUIVisualRoute(str, Enum):
    """Exact synthetic request routes; no selected path is recorded."""

    REQUEST = "request"
    PRESERVE = "preserve"


class RecoverySourceInspectionRequestMainGUIVisualObservation(str, Enum):
    """Exact observation values; arbitrary notes are not accepted."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionRequestMainGUIVisualObservations:
    four_staged_actions_visible: RecoverySourceInspectionRequestMainGUIVisualObservation
    request_action_locked_until_positive_selection: RecoverySourceInspectionRequestMainGUIVisualObservation
    confirmation_opened_only_after_fourth_action: RecoverySourceInspectionRequestMainGUIVisualObservation
    request_or_preserve_result_was_generic: RecoverySourceInspectionRequestMainGUIVisualObservation
    no_source_content_or_secret_access_observed: RecoverySourceInspectionRequestMainGUIVisualObservation
    all_four_actions_one_shot: RecoverySourceInspectionRequestMainGUIVisualObservation
    picker_metadata_disclosure_visible: RecoverySourceInspectionRequestMainGUIVisualObservation
    request_no_access_disclosure_visible: RecoverySourceInspectionRequestMainGUIVisualObservation
    safety_controls_visible: RecoverySourceInspectionRequestMainGUIVisualObservation

    def __post_init__(self) -> None:
        for value in (
            self.four_staged_actions_visible,
            self.request_action_locked_until_positive_selection,
            self.confirmation_opened_only_after_fourth_action,
            self.request_or_preserve_result_was_generic,
            self.no_source_content_or_secret_access_observed,
            self.all_four_actions_one_shot,
            self.picker_metadata_disclosure_visible,
            self.request_no_access_disclosure_visible,
            self.safety_controls_visible,
        ):
            if type(value) is not RecoverySourceInspectionRequestMainGUIVisualObservation:
                raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
                    "recovery source inspection request observation type is invalid"
                )


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionRequestMainGUIVisualReport:
    locale: str
    route: RecoverySourceInspectionRequestMainGUIVisualRoute
    observations: RecoverySourceInspectionRequestMainGUIVisualObservations
    normal_startup_observed: bool = True
    human_observation_only: bool = True
    true_recovery_input_used: bool = False
    native_source_picker_invoked: bool = True
    native_picker_filesystem_metadata_access_possible: bool = True
    source_selection_performed: bool = True
    source_path_metadata_received: bool = True
    inspection_request_action_invoked: bool = True
    future_secure_source_inspection_requested: bool = False
    inspection_request_preserved_and_stopped: bool = True
    application_source_open_read_performed: bool = False
    source_identity_validated: bool = False
    source_access_authorized: bool = False
    source_preparation_performed: bool = False
    recovery_secret_received: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    runtime_directory_preparation_performed: bool = True
    recovery_source_filesystem_mutation_performed: bool = False
    whole_process_no_filesystem_access_claimed: bool = False
    network_used: bool = False
    automatic_transition_performed: bool = False
    platform_certification_claimed: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_report(value: _Any) -> None:
    if type(value) is not RecoverySourceInspectionRequestMainGUIVisualReport:
        raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
            "recovery source inspection request report type is invalid"
        )
    requesting = (
        value.route is RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST
    )
    if (
        type(value.locale) is not str
        or value.locale not in RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_LOCALES
        or type(value.route) is not RecoverySourceInspectionRequestMainGUIVisualRoute
        or type(value.observations)
        is not RecoverySourceInspectionRequestMainGUIVisualObservations
        or value.normal_startup_observed is not True
        or value.human_observation_only is not True
        or value.true_recovery_input_used is not False
        or value.native_source_picker_invoked is not True
        or value.native_picker_filesystem_metadata_access_possible is not True
        or value.source_selection_performed is not True
        or value.source_path_metadata_received is not True
        or value.inspection_request_action_invoked is not True
        or type(value.future_secure_source_inspection_requested) is not bool
        or value.future_secure_source_inspection_requested is not requesting
        or type(value.inspection_request_preserved_and_stopped) is not bool
        or value.inspection_request_preserved_and_stopped is requesting
        or value.application_source_open_read_performed is not False
        or value.source_identity_validated is not False
        or value.source_access_authorized is not False
        or value.source_preparation_performed is not False
        or value.recovery_secret_received is not False
        or value.review_session_prepared is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.runtime_directory_preparation_performed is not True
        or value.recovery_source_filesystem_mutation_performed is not False
        or value.whole_process_no_filesystem_access_claimed is not False
        or value.network_used is not False
        or value.automatic_transition_performed is not False
        or value.platform_certification_claimed is not False
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_FORMAT
        or type(value.version) is not int
        or value.version
        != RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_REPORT_VERSION
    ):
        raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
            "recovery source inspection request report is invalid"
        )


def build_recovery_source_inspection_request_main_gui_visual_report(
    locale: str,
    route: RecoverySourceInspectionRequestMainGUIVisualRoute,
    observations: RecoverySourceInspectionRequestMainGUIVisualObservations,
) -> RecoverySourceInspectionRequestMainGUIVisualReport:
    """Build one bounded report without retaining selected path metadata."""

    if (
        type(locale) is not str
        or locale not in RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_LOCALES
    ):
        raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
            "recovery source inspection request visual locale is unsupported"
        )
    if type(route) is not RecoverySourceInspectionRequestMainGUIVisualRoute:
        raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
            "recovery source inspection request visual route is invalid"
        )
    if (
        type(observations)
        is not RecoverySourceInspectionRequestMainGUIVisualObservations
    ):
        raise RecoverySourceInspectionRequestMainGUIVisualHarnessError(
            "recovery source inspection request observations are invalid"
        )
    requesting = route is RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST
    return RecoverySourceInspectionRequestMainGUIVisualReport(
        locale=locale,
        route=route,
        observations=observations,
        future_secure_source_inspection_requested=requesting,
        inspection_request_preserved_and_stopped=not requesting,
    )


def recovery_source_inspection_request_main_gui_visual_report_json(
    report: RecoverySourceInspectionRequestMainGUIVisualReport,
) -> str:
    """Encode the exact bounded report as canonical JSON."""

    _validate_report(report)
    observations = report.observations
    payload = {
        field: getattr(report, field)
        for field in (
            "application_source_open_read_performed",
            "automatic_transition_performed",
            "format",
            "future_secure_source_inspection_requested",
            "human_observation_only",
            "inspection_request_action_invoked",
            "inspection_request_preserved_and_stopped",
            "locale",
            "native_picker_filesystem_metadata_access_possible",
            "native_source_picker_invoked",
            "network_used",
            "normal_startup_observed",
            "operation_authorized",
            "operation_performed",
            "platform_certification_claimed",
            "recovery_secret_received",
            "recovery_source_filesystem_mutation_performed",
            "review_session_prepared",
            "runtime_directory_preparation_performed",
            "source_access_authorized",
            "source_identity_validated",
            "source_path_metadata_received",
            "source_preparation_performed",
            "source_selection_performed",
            "true_recovery_input_used",
            "version",
            "whole_process_no_filesystem_access_claimed",
        )
    }
    payload["route"] = report.route.value
    payload["observations"] = {
        field: getattr(observations, field).value
        for field in (
            "all_four_actions_one_shot",
            "confirmation_opened_only_after_fourth_action",
            "four_staged_actions_visible",
            "no_source_content_or_secret_access_observed",
            "picker_metadata_disclosure_visible",
            "request_action_locked_until_positive_selection",
            "request_no_access_disclosure_visible",
            "request_or_preserve_result_was_generic",
            "safety_controls_visible",
        )
    }
    return _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
