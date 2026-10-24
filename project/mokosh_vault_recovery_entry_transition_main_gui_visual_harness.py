"""Bounded visual report for the Stage 2.25 main-GUI transition action.

The module records only fixed human observations for a synthetic no-source
normal-GUI flow.  It has no GUI, filesystem, network, process, logging,
recovery-source, secret-input, or operation capability.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_ENTRY_TRANSITION_VISUAL_REPORT"
)
RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_VERSION = 2
RECOVERY_ENTRY_TRANSITION_MAIN_GUI_LOCALES = ("bg-BG", "en-GB")


class RecoveryEntryTransitionMainGUIVisualHarnessError(ValueError):
    """A visual observation or report violates the frozen schema."""


class RecoveryEntryTransitionMainGUIVisualObservation(str, Enum):
    """Exact observation values; arbitrary notes are not accepted."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@_dataclass(frozen=True, slots=True)
class RecoveryEntryTransitionMainGUIVisualObservations:
    request_and_locked_transition_visible: RecoveryEntryTransitionMainGUIVisualObservation
    request_arms_transition_only: RecoveryEntryTransitionMainGUIVisualObservation
    second_confirmation_boundary_clear: RecoveryEntryTransitionMainGUIVisualObservation
    transition_result_clear: RecoveryEntryTransitionMainGUIVisualObservation
    no_source_or_review_opened: RecoveryEntryTransitionMainGUIVisualObservation
    both_actions_one_shot: RecoveryEntryTransitionMainGUIVisualObservation
    safety_controls_visible: RecoveryEntryTransitionMainGUIVisualObservation

    def __post_init__(self) -> None:
        for value in (
            self.request_and_locked_transition_visible,
            self.request_arms_transition_only,
            self.second_confirmation_boundary_clear,
            self.transition_result_clear,
            self.no_source_or_review_opened,
            self.both_actions_one_shot,
            self.safety_controls_visible,
        ):
            if type(value) is not RecoveryEntryTransitionMainGUIVisualObservation:
                raise RecoveryEntryTransitionMainGUIVisualHarnessError(
                    "recovery entry transition observation type is invalid"
                )


@_dataclass(frozen=True, slots=True)
class RecoveryEntryTransitionMainGUIVisualReport:
    locale: str
    observations: RecoveryEntryTransitionMainGUIVisualObservations
    normal_startup_observed: bool = True
    human_observation_only: bool = True
    true_recovery_input_used: bool = False
    source_access_authorized: bool = False
    source_selection_performed: bool = False
    source_preparation_performed: bool = False
    review_session_prepared: bool = False
    review_displayed: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    runtime_directory_preparation_performed: bool = True
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    automatic_transition_performed: bool = False
    platform_certification_claimed: bool = False
    format: str = RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_FORMAT
    version: int = RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_report(value: _Any) -> None:
    if type(value) is not RecoveryEntryTransitionMainGUIVisualReport:
        raise RecoveryEntryTransitionMainGUIVisualHarnessError(
            "recovery entry transition report type is invalid"
        )
    if (
        type(value.locale) is not str
        or value.locale not in RECOVERY_ENTRY_TRANSITION_MAIN_GUI_LOCALES
        or type(value.observations)
        is not RecoveryEntryTransitionMainGUIVisualObservations
        or value.normal_startup_observed is not True
        or value.human_observation_only is not True
        or value.true_recovery_input_used is not False
        or value.source_access_authorized is not False
        or value.source_selection_performed is not False
        or value.source_preparation_performed is not False
        or value.review_session_prepared is not False
        or value.review_displayed is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.runtime_directory_preparation_performed is not True
        or value.recovery_source_filesystem_access_performed is not False
        or value.recovery_source_filesystem_mutation_performed is not False
        or value.network_used is not False
        or value.automatic_transition_performed is not False
        or value.platform_certification_claimed is not False
        or type(value.format) is not str
        or value.format != RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_VERSION
    ):
        raise RecoveryEntryTransitionMainGUIVisualHarnessError(
            "recovery entry transition report is invalid"
        )


def build_recovery_entry_transition_main_gui_visual_report(
    locale: str,
    observations: RecoveryEntryTransitionMainGUIVisualObservations,
) -> RecoveryEntryTransitionMainGUIVisualReport:
    """Build one bounded human-observation report."""

    if (
        type(locale) is not str
        or locale not in RECOVERY_ENTRY_TRANSITION_MAIN_GUI_LOCALES
    ):
        raise RecoveryEntryTransitionMainGUIVisualHarnessError(
            "recovery entry transition visual locale is unsupported"
        )
    if type(observations) is not RecoveryEntryTransitionMainGUIVisualObservations:
        raise RecoveryEntryTransitionMainGUIVisualHarnessError(
            "recovery entry transition observations are invalid"
        )
    return RecoveryEntryTransitionMainGUIVisualReport(locale, observations)


def recovery_entry_transition_main_gui_visual_report_json(
    report: RecoveryEntryTransitionMainGUIVisualReport,
) -> str:
    """Encode the exact bounded report as canonical JSON."""

    _validate_report(report)
    observations = report.observations
    payload = {
        "automatic_transition_performed": report.automatic_transition_performed,
        "format": report.format,
        "human_observation_only": report.human_observation_only,
        "locale": report.locale,
        "network_used": report.network_used,
        "normal_startup_observed": report.normal_startup_observed,
        "observations": {
            "both_actions_one_shot": observations.both_actions_one_shot.value,
            "no_source_or_review_opened": (
                observations.no_source_or_review_opened.value
            ),
            "request_and_locked_transition_visible": (
                observations.request_and_locked_transition_visible.value
            ),
            "request_arms_transition_only": (
                observations.request_arms_transition_only.value
            ),
            "safety_controls_visible": observations.safety_controls_visible.value,
            "second_confirmation_boundary_clear": (
                observations.second_confirmation_boundary_clear.value
            ),
            "transition_result_clear": observations.transition_result_clear.value,
        },
        "operation_authorized": report.operation_authorized,
        "operation_performed": report.operation_performed,
        "platform_certification_claimed": report.platform_certification_claimed,
        "review_displayed": report.review_displayed,
        "review_session_prepared": report.review_session_prepared,
        "recovery_source_filesystem_access_performed": (
            report.recovery_source_filesystem_access_performed
        ),
        "recovery_source_filesystem_mutation_performed": (
            report.recovery_source_filesystem_mutation_performed
        ),
        "runtime_directory_preparation_performed": (
            report.runtime_directory_preparation_performed
        ),
        "source_access_authorized": report.source_access_authorized,
        "source_preparation_performed": report.source_preparation_performed,
        "source_selection_performed": report.source_selection_performed,
        "true_recovery_input_used": report.true_recovery_input_used,
        "version": report.version,
    }
    return _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
