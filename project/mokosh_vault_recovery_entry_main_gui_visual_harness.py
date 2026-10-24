"""Bounded human-observation report for the Stage 2.20 normal-GUI entry.

This module has no GUI, filesystem, network, process, logging, recovery source,
or operation capability.  It records only fixed pass/fail/not-checked visual
observations from the separate development launcher.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


RECOVERY_ENTRY_MAIN_GUI_REPORT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_ENTRY_VISUAL_REPORT"
)
RECOVERY_ENTRY_MAIN_GUI_REPORT_VERSION = 2
RECOVERY_ENTRY_MAIN_GUI_LOCALES = ("bg-BG", "en-GB")


class RecoveryEntryMainGUIVisualHarnessError(ValueError):
    """A visual observation or bounded report violates the frozen schema."""


class RecoveryEntryMainGUIVisualObservation(str, Enum):
    """Exact bounded observation values; arbitrary notes are not accepted."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@_dataclass(frozen=True, slots=True)
class RecoveryEntryMainGUIVisualObservations:
    banner_and_button_visible: RecoveryEntryMainGUIVisualObservation
    confirmation_boundary_clear: RecoveryEntryMainGUIVisualObservation
    request_result_clear: RecoveryEntryMainGUIVisualObservation
    no_source_or_review_opened: RecoveryEntryMainGUIVisualObservation
    one_shot_and_safety_controls_visible: RecoveryEntryMainGUIVisualObservation

    def __post_init__(self) -> None:
        for value in (
            self.banner_and_button_visible,
            self.confirmation_boundary_clear,
            self.request_result_clear,
            self.no_source_or_review_opened,
            self.one_shot_and_safety_controls_visible,
        ):
            if type(value) is not RecoveryEntryMainGUIVisualObservation:
                raise RecoveryEntryMainGUIVisualHarnessError(
                    "recovery entry visual observation type is invalid"
                )


@_dataclass(frozen=True, slots=True)
class RecoveryEntryMainGUIVisualReport:
    locale: str
    observations: RecoveryEntryMainGUIVisualObservations
    normal_startup_observed: bool = True
    human_observation_only: bool = True
    true_recovery_input_used: bool = False
    source_access_authorized: bool = False
    source_access_performed: bool = False
    recovery_review_displayed: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    runtime_directory_preparation_performed: bool = True
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    platform_certification_claimed: bool = False
    format: str = RECOVERY_ENTRY_MAIN_GUI_REPORT_FORMAT
    version: int = RECOVERY_ENTRY_MAIN_GUI_REPORT_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_report(value: _Any) -> None:
    if type(value) is not RecoveryEntryMainGUIVisualReport:
        raise RecoveryEntryMainGUIVisualHarnessError(
            "recovery entry visual report type is invalid"
        )
    if (
        type(value.locale) is not str
        or value.locale not in RECOVERY_ENTRY_MAIN_GUI_LOCALES
        or type(value.observations) is not RecoveryEntryMainGUIVisualObservations
        or value.normal_startup_observed is not True
        or value.human_observation_only is not True
        or value.true_recovery_input_used is not False
        or value.source_access_authorized is not False
        or value.source_access_performed is not False
        or value.recovery_review_displayed is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.runtime_directory_preparation_performed is not True
        or value.recovery_source_filesystem_access_performed is not False
        or value.recovery_source_filesystem_mutation_performed is not False
        or value.network_used is not False
        or value.platform_certification_claimed is not False
        or type(value.format) is not str
        or value.format != RECOVERY_ENTRY_MAIN_GUI_REPORT_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_ENTRY_MAIN_GUI_REPORT_VERSION
    ):
        raise RecoveryEntryMainGUIVisualHarnessError(
            "recovery entry visual report is invalid"
        )


def build_recovery_entry_main_gui_visual_report(
    locale: str,
    observations: RecoveryEntryMainGUIVisualObservations,
) -> RecoveryEntryMainGUIVisualReport:
    """Build one bounded report without claiming technical certification."""

    if type(locale) is not str or locale not in RECOVERY_ENTRY_MAIN_GUI_LOCALES:
        raise RecoveryEntryMainGUIVisualHarnessError(
            "recovery entry visual locale is unsupported"
        )
    if type(observations) is not RecoveryEntryMainGUIVisualObservations:
        raise RecoveryEntryMainGUIVisualHarnessError(
            "recovery entry visual observations are invalid"
        )
    return RecoveryEntryMainGUIVisualReport(locale, observations)


def recovery_entry_main_gui_visual_report_json(
    report: RecoveryEntryMainGUIVisualReport,
) -> str:
    """Encode the exact bounded report as canonical JSON."""

    _validate_report(report)
    observations = report.observations
    payload = {
        "format": report.format,
        "human_observation_only": report.human_observation_only,
        "locale": report.locale,
        "network_used": report.network_used,
        "normal_startup_observed": report.normal_startup_observed,
        "observations": {
            "banner_and_button_visible": observations.banner_and_button_visible.value,
            "confirmation_boundary_clear": observations.confirmation_boundary_clear.value,
            "no_source_or_review_opened": observations.no_source_or_review_opened.value,
            "one_shot_and_safety_controls_visible": (
                observations.one_shot_and_safety_controls_visible.value
            ),
            "request_result_clear": observations.request_result_clear.value,
        },
        "operation_authorized": report.operation_authorized,
        "operation_performed": report.operation_performed,
        "platform_certification_claimed": report.platform_certification_claimed,
        "recovery_review_displayed": report.recovery_review_displayed,
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
        "source_access_performed": report.source_access_performed,
        "true_recovery_input_used": report.true_recovery_input_used,
        "version": report.version,
    }
    return _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
