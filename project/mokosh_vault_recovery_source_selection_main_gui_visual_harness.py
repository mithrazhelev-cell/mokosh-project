"""Bounded visual evidence for the Stage 2.28 main-GUI source selector.

This pure report core records fixed human observations.  It contains no GUI,
filesystem, process, network, logging, recovery-source path, secret, callback,
executor, or operation capability.  Native-picker metadata access is disclosed
explicitly and is not misreported as whole-process filesystem isolation.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_SOURCE_SELECTION_VISUAL_REPORT"
)
RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_VERSION = 1
RECOVERY_SOURCE_SELECTION_MAIN_GUI_LOCALES = ("bg-BG", "en-GB")


class RecoverySourceSelectionMainGUIVisualHarnessError(ValueError):
    """A route, observation, or report violates the frozen schema."""


class RecoverySourceSelectionMainGUIVisualRoute(str, Enum):
    """Exact synthetic inspection routes; no selected path is recorded."""

    SELECT = "select"
    CANCEL = "cancel"


class RecoverySourceSelectionMainGUIVisualObservation(str, Enum):
    """Exact observation values; arbitrary notes are not accepted."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@_dataclass(frozen=True, slots=True)
class RecoverySourceSelectionMainGUIVisualObservations:
    three_staged_actions_visible: RecoverySourceSelectionMainGUIVisualObservation
    source_action_locked_until_positive_transition: RecoverySourceSelectionMainGUIVisualObservation
    picker_opened_only_after_third_action: RecoverySourceSelectionMainGUIVisualObservation
    selected_or_cancelled_result_was_generic: RecoverySourceSelectionMainGUIVisualObservation
    no_source_content_or_secret_access_observed: RecoverySourceSelectionMainGUIVisualObservation
    all_three_actions_one_shot: RecoverySourceSelectionMainGUIVisualObservation
    picker_metadata_disclosure_visible: RecoverySourceSelectionMainGUIVisualObservation
    safety_controls_visible: RecoverySourceSelectionMainGUIVisualObservation

    def __post_init__(self) -> None:
        for value in (
            self.three_staged_actions_visible,
            self.source_action_locked_until_positive_transition,
            self.picker_opened_only_after_third_action,
            self.selected_or_cancelled_result_was_generic,
            self.no_source_content_or_secret_access_observed,
            self.all_three_actions_one_shot,
            self.picker_metadata_disclosure_visible,
            self.safety_controls_visible,
        ):
            if type(value) is not RecoverySourceSelectionMainGUIVisualObservation:
                raise RecoverySourceSelectionMainGUIVisualHarnessError(
                    "recovery source selection observation type is invalid"
                )


@_dataclass(frozen=True, slots=True)
class RecoverySourceSelectionMainGUIVisualReport:
    locale: str
    route: RecoverySourceSelectionMainGUIVisualRoute
    observations: RecoverySourceSelectionMainGUIVisualObservations
    normal_startup_observed: bool = True
    human_observation_only: bool = True
    true_recovery_input_used: bool = False
    native_source_picker_invoked: bool = True
    native_picker_filesystem_metadata_access_possible: bool = True
    source_selection_performed: bool = False
    source_path_metadata_received: bool = False
    preserved_and_stopped: bool = True
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
    format: str = RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_FORMAT
    version: int = RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_report(value: _Any) -> None:
    if type(value) is not RecoverySourceSelectionMainGUIVisualReport:
        raise RecoverySourceSelectionMainGUIVisualHarnessError(
            "recovery source selection report type is invalid"
        )
    selecting = value.route is RecoverySourceSelectionMainGUIVisualRoute.SELECT
    if (
        type(value.locale) is not str
        or value.locale not in RECOVERY_SOURCE_SELECTION_MAIN_GUI_LOCALES
        or type(value.route) is not RecoverySourceSelectionMainGUIVisualRoute
        or type(value.observations)
        is not RecoverySourceSelectionMainGUIVisualObservations
        or value.normal_startup_observed is not True
        or value.human_observation_only is not True
        or value.true_recovery_input_used is not False
        or value.native_source_picker_invoked is not True
        or value.native_picker_filesystem_metadata_access_possible is not True
        or type(value.source_selection_performed) is not bool
        or value.source_selection_performed is not selecting
        or type(value.source_path_metadata_received) is not bool
        or value.source_path_metadata_received is not selecting
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is selecting
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
        or value.format != RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_SELECTION_MAIN_GUI_REPORT_VERSION
    ):
        raise RecoverySourceSelectionMainGUIVisualHarnessError(
            "recovery source selection report is invalid"
        )


def build_recovery_source_selection_main_gui_visual_report(
    locale: str,
    route: RecoverySourceSelectionMainGUIVisualRoute,
    observations: RecoverySourceSelectionMainGUIVisualObservations,
) -> RecoverySourceSelectionMainGUIVisualReport:
    """Build one bounded report without retaining selected path metadata."""

    if (
        type(locale) is not str
        or locale not in RECOVERY_SOURCE_SELECTION_MAIN_GUI_LOCALES
    ):
        raise RecoverySourceSelectionMainGUIVisualHarnessError(
            "recovery source selection visual locale is unsupported"
        )
    if type(route) is not RecoverySourceSelectionMainGUIVisualRoute:
        raise RecoverySourceSelectionMainGUIVisualHarnessError(
            "recovery source selection visual route is invalid"
        )
    if type(observations) is not RecoverySourceSelectionMainGUIVisualObservations:
        raise RecoverySourceSelectionMainGUIVisualHarnessError(
            "recovery source selection observations are invalid"
        )
    selecting = route is RecoverySourceSelectionMainGUIVisualRoute.SELECT
    return RecoverySourceSelectionMainGUIVisualReport(
        locale=locale,
        route=route,
        observations=observations,
        source_selection_performed=selecting,
        source_path_metadata_received=selecting,
        preserved_and_stopped=not selecting,
    )


def recovery_source_selection_main_gui_visual_report_json(
    report: RecoverySourceSelectionMainGUIVisualReport,
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
            "human_observation_only",
            "locale",
            "native_picker_filesystem_metadata_access_possible",
            "native_source_picker_invoked",
            "network_used",
            "normal_startup_observed",
            "operation_authorized",
            "operation_performed",
            "platform_certification_claimed",
            "preserved_and_stopped",
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
            "all_three_actions_one_shot",
            "no_source_content_or_secret_access_observed",
            "picker_metadata_disclosure_visible",
            "picker_opened_only_after_third_action",
            "safety_controls_visible",
            "selected_or_cancelled_result_was_generic",
            "source_action_locked_until_positive_transition",
            "three_staged_actions_visible",
        )
    }
    return _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
