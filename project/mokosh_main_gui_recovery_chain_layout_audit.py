"""Bounded Stage 2.42 normal-main-GUI recovery-chain layout audit core.

The core defines a fixed human-observation matrix and canonical report only.
It has no GUI, filesystem, source/path, process, network, logging, callback,
executor, recovery-operation, or activation capability.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass as _dataclass
from enum import Enum
from typing import Any as _Any


MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_FORMAT = (
    "MOKOSH_MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_REPORT"
)
MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_VERSION = 1
MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MAX_JSON_UTF8_LEN = 4096


class MainGUIRecoveryChainLayoutAuditError(ValueError):
    """A Stage 2.42 case, observation, or report is outside the freeze."""


class MainGUIRecoveryChainLayoutAuditProfile(str, Enum):
    """Exact bounded interaction profile for one human audit case."""

    INITIAL_KEYBOARD = "initial_keyboard"
    RESIZE_RESTORE_KEYBOARD = "resize_restore_keyboard"


class MainGUIRecoveryChainLayoutAuditObservation(str, Enum):
    """Exact human-observation values; arbitrary notes are forbidden."""

    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


_MATRIX = (
    ("bg-BG", 100, MainGUIRecoveryChainLayoutAuditProfile.INITIAL_KEYBOARD),
    ("en-GB", 125, MainGUIRecoveryChainLayoutAuditProfile.INITIAL_KEYBOARD),
    ("bg-BG", 150, MainGUIRecoveryChainLayoutAuditProfile.RESIZE_RESTORE_KEYBOARD),
    ("en-GB", 200, MainGUIRecoveryChainLayoutAuditProfile.RESIZE_RESTORE_KEYBOARD),
)
MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX = tuple(
    (locale, scale, profile.value) for locale, scale, profile in _MATRIX
)


@_dataclass(frozen=True, slots=True)
class MainGUIRecoveryChainLayoutAuditCase:
    case_number: int
    locale: str
    scale_percent: int
    profile: MainGUIRecoveryChainLayoutAuditProfile
    synthetic_non_secret: bool = True

    def __post_init__(self) -> None:
        _validate_case(self)


@_dataclass(frozen=True, slots=True)
class MainGUIRecoveryChainLayoutAuditObservations:
    safety_and_recovery_controls_visible: MainGUIRecoveryChainLayoutAuditObservation
    non_recovery_controls_visible: MainGUIRecoveryChainLayoutAuditObservation
    localized_text_unclipped_and_readable: MainGUIRecoveryChainLayoutAuditObservation
    keyboard_reaches_interactive_controls: MainGUIRecoveryChainLayoutAuditObservation
    focus_visible_and_order_meaningful: MainGUIRecoveryChainLayoutAuditObservation
    no_keyboard_trap: MainGUIRecoveryChainLayoutAuditObservation
    resize_restore_keeps_controls_operable: MainGUIRecoveryChainLayoutAuditObservation
    no_unexpected_dialog_or_source_access: MainGUIRecoveryChainLayoutAuditObservation

    def __post_init__(self) -> None:
        _validate_observations(self)


@_dataclass(frozen=True, slots=True)
class MainGUIRecoveryChainLayoutAuditReport:
    case_number: int
    locale: str
    scale_percent: int
    profile: MainGUIRecoveryChainLayoutAuditProfile
    observations: MainGUIRecoveryChainLayoutAuditObservations
    normal_startup_observed: bool = True
    current_four_action_chain_observed: bool = True
    manual_observations_are_self_reported: bool = True
    runtime_directory_preparation_performed: bool = True
    synthetic_non_secret: bool = True
    true_recovery_input_used: bool = False
    native_source_picker_invoked: bool = False
    source_path_metadata_received: bool = False
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    stage_2_31_gui_wiring_activated: bool = False
    stage_2_32_secure_read_authorized: bool = False
    stage_2_41_normal_activation_performed: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    network_used: bool = False
    automatic_gui_event_injection_used: bool = False
    screen_capture_performed: bool = False
    host_or_geometry_metadata_recorded: bool = False
    accessibility_conformance_claimed: bool = False
    legal_conformity_claimed: bool = False
    platform_certification_claimed: bool = False
    human_understanding_proven: bool = False
    format: str = MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_FORMAT
    version: int = MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _validate_case(value: _Any) -> MainGUIRecoveryChainLayoutAuditCase:
    if type(value) is not MainGUIRecoveryChainLayoutAuditCase:
        raise MainGUIRecoveryChainLayoutAuditError("layout audit case type is invalid")
    if type(value.case_number) is not int or not 1 <= value.case_number <= len(_MATRIX):
        raise MainGUIRecoveryChainLayoutAuditError("layout audit case number is invalid")
    expected_locale, expected_scale, expected_profile = _MATRIX[value.case_number - 1]
    if (
        type(value.locale) is not str
        or value.locale != expected_locale
        or type(value.scale_percent) is not int
        or value.scale_percent != expected_scale
        or type(value.profile) is not MainGUIRecoveryChainLayoutAuditProfile
        or value.profile is not expected_profile
        or value.synthetic_non_secret is not True
    ):
        raise MainGUIRecoveryChainLayoutAuditError("layout audit case differs from the matrix")
    return value


def _observation_field_names() -> tuple[str, ...]:
    return (
        "safety_and_recovery_controls_visible",
        "non_recovery_controls_visible",
        "localized_text_unclipped_and_readable",
        "keyboard_reaches_interactive_controls",
        "focus_visible_and_order_meaningful",
        "no_keyboard_trap",
        "resize_restore_keeps_controls_operable",
        "no_unexpected_dialog_or_source_access",
    )


def _validate_observations(
    value: _Any,
) -> MainGUIRecoveryChainLayoutAuditObservations:
    if type(value) is not MainGUIRecoveryChainLayoutAuditObservations or any(
        type(getattr(value, name)) is not MainGUIRecoveryChainLayoutAuditObservation
        for name in _observation_field_names()
    ):
        raise MainGUIRecoveryChainLayoutAuditError("layout audit observations are invalid")
    return value


def _validate_report(value: _Any) -> MainGUIRecoveryChainLayoutAuditReport:
    if type(value) is not MainGUIRecoveryChainLayoutAuditReport:
        raise MainGUIRecoveryChainLayoutAuditError("layout audit report type is invalid")
    _validate_case(
        MainGUIRecoveryChainLayoutAuditCase(
            case_number=value.case_number,
            locale=value.locale,
            scale_percent=value.scale_percent,
            profile=value.profile,
            synthetic_non_secret=value.synthetic_non_secret,
        )
    )
    _validate_observations(value.observations)
    if (
        value.normal_startup_observed is not True
        or value.current_four_action_chain_observed is not True
        or value.manual_observations_are_self_reported is not True
        or value.runtime_directory_preparation_performed is not True
        or value.true_recovery_input_used is not False
        or value.native_source_picker_invoked is not False
        or value.source_path_metadata_received is not False
        or value.recovery_source_filesystem_access_performed is not False
        or value.recovery_source_filesystem_mutation_performed is not False
        or value.stage_2_31_gui_wiring_activated is not False
        or value.stage_2_32_secure_read_authorized is not False
        or value.stage_2_41_normal_activation_performed is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.network_used is not False
        or value.automatic_gui_event_injection_used is not False
        or value.screen_capture_performed is not False
        or value.host_or_geometry_metadata_recorded is not False
        or value.accessibility_conformance_claimed is not False
        or value.legal_conformity_claimed is not False
        or value.platform_certification_claimed is not False
        or value.human_understanding_proven is not False
        or type(value.format) is not str
        or value.format != MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_FORMAT
        or type(value.version) is not int
        or value.version != MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_VERSION
    ):
        raise MainGUIRecoveryChainLayoutAuditError("layout audit report claims are invalid")
    return value


def prepare_main_gui_recovery_chain_layout_audit_case(
    case_number: int,
) -> MainGUIRecoveryChainLayoutAuditCase:
    """Create one exact fixed case without GUI or host inspection."""

    if type(case_number) is not int or not 1 <= case_number <= len(_MATRIX):
        raise MainGUIRecoveryChainLayoutAuditError("layout audit case number is invalid")
    locale, scale, profile = _MATRIX[case_number - 1]
    return MainGUIRecoveryChainLayoutAuditCase(
        case_number=case_number,
        locale=locale,
        scale_percent=scale,
        profile=profile,
    )


def build_main_gui_recovery_chain_layout_audit_report(
    case: MainGUIRecoveryChainLayoutAuditCase,
    observations: MainGUIRecoveryChainLayoutAuditObservations,
) -> MainGUIRecoveryChainLayoutAuditReport:
    """Bind exact self-reported observations to one fixed case."""

    _validate_case(case)
    _validate_observations(observations)
    return MainGUIRecoveryChainLayoutAuditReport(
        case_number=case.case_number,
        locale=case.locale,
        scale_percent=case.scale_percent,
        profile=case.profile,
        observations=observations,
    )


def main_gui_recovery_chain_layout_audit_report_json(
    report: MainGUIRecoveryChainLayoutAuditReport,
) -> str:
    """Return canonical bounded JSON containing no dimensions or free text."""

    _validate_report(report)
    payload = {
        name: getattr(report, name)
        for name in (
            "accessibility_conformance_claimed",
            "automatic_gui_event_injection_used",
            "case_number",
            "current_four_action_chain_observed",
            "format",
            "host_or_geometry_metadata_recorded",
            "human_understanding_proven",
            "legal_conformity_claimed",
            "locale",
            "manual_observations_are_self_reported",
            "native_source_picker_invoked",
            "network_used",
            "normal_startup_observed",
            "operation_authorized",
            "operation_performed",
            "platform_certification_claimed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "runtime_directory_preparation_performed",
            "scale_percent",
            "screen_capture_performed",
            "source_path_metadata_received",
            "stage_2_31_gui_wiring_activated",
            "stage_2_32_secure_read_authorized",
            "stage_2_41_normal_activation_performed",
            "synthetic_non_secret",
            "true_recovery_input_used",
            "version",
        )
    }
    payload["profile"] = report.profile.value
    payload["observations"] = {
        name: getattr(report.observations, name).value
        for name in _observation_field_names()
    }
    encoded = _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded.encode("utf-8")) > MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MAX_JSON_UTF8_LEN:
        raise MainGUIRecoveryChainLayoutAuditError("layout audit report is too large")
    return encoded


def main_gui_recovery_chain_layout_audit_observations_pass(
    observations: MainGUIRecoveryChainLayoutAuditObservations,
) -> bool:
    """Return true only when all eight exact human observations pass."""

    _validate_observations(observations)
    return all(
        getattr(observations, name) is MainGUIRecoveryChainLayoutAuditObservation.PASS
        for name in _observation_field_names()
    )
