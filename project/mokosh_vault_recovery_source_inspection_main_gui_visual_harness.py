"""Bounded synthetic evidence for the Stage 2.41 main-GUI review event.

The four fixed cases create only deterministic, non-secret Stage 2.32 outcomes
and carry them through the exact Stage 2.39 session and Stage 2.40 binding.  The
core has no GUI, filesystem, network, process, logging, source-reader, secret,
callback, executor, or recovery-operation capability.

The report records self-reported local visual observations.  It is not an
accessibility, legal, or platform-conformity claim and proves neither human
understanding nor recovery authorisation.
"""

from __future__ import annotations

import hashlib as _hashlib
import hmac as _hmac
import json as _json
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_execution import (
    RecoverySourceInspectionExecutionDecision,
    RecoverySourceInspectionExecutionState,
    VaultRecoverySourceInspectionExecutionOutcome,
)
from mokosh_vault_recovery_source_inspection_main_gui_bridge import (
    PreparedMainGUIRecoverySourceInspectionReviewBinding,
    RecoverySourceInspectionMainGUIBridgeState,
    prepare_main_gui_recovery_source_inspection_review_binding,
)
from mokosh_vault_recovery_source_inspection_review_controller import (
    prepare_recovery_source_inspection_review_session,
)
from mokosh_vault_recovery_source_inspection_review_window import (
    RecoverySourceInspectionReviewWindowCancelReason,
    RecoverySourceInspectionReviewWindowDecision,
    VaultRecoverySourceInspectionReviewWindowOutcome,
    _validate_outcome,
)


MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT = (
    "MOKOSH_MAIN_GUI_SOURCE_INSPECTION_REVIEW_REPORT"
)
MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION = 1
MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN = 4096

_SYNTHETIC_DOMAIN = (
    b"MOKOSH\x00STAGE-2.41\x00MAIN-GUI-SOURCE-INSPECTION-SYNTHETIC-V1\x00"
)
_MATRIX = (
    ("bg-BG", 100, "escape_key"),
    ("en-GB", 125, "cancel_button"),
    ("bg-BG", 150, "window_close"),
    ("en-GB", 200, "acknowledge"),
)
MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX = _MATRIX


class VaultRecoverySourceInspectionMainGUIVisualHarnessError(ValueError):
    """A Stage 2.41 fixture, observation, or report is invalid."""


class MainGUISourceInspectionVisualHarnessTerminalAction(str, Enum):
    ESCAPE_KEY = "escape_key"
    CANCEL_BUTTON = "cancel_button"
    WINDOW_CLOSE = "window_close"
    ACKNOWLEDGE = "acknowledge"


class MainGUISourceInspectionVisualHarnessObservation(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


@_dataclass(frozen=True, slots=True)
class SyntheticMainGUISourceInspectionReviewCase:
    case_number: int
    locale: RecoveryLocalizationLocale
    scale_percent: int
    required_terminal_action: MainGUISourceInspectionVisualHarnessTerminalAction
    binding: PreparedMainGUIRecoverySourceInspectionReviewBinding = _field(repr=False)
    synthetic_non_secret: bool = True
    true_vault_input_used: bool = False
    operation_capability_included: bool = False

    def __post_init__(self) -> None:
        _validate_case(self, require_fresh=True)


@_dataclass(frozen=True, slots=True)
class MainGUISourceInspectionReviewObservations:
    banner_button_visible_no_clipping: MainGUISourceInspectionVisualHarnessObservation
    unrelated_controls_disabled: MainGUISourceInspectionVisualHarnessObservation
    keyboard_reachable_no_trap: MainGUISourceInspectionVisualHarnessObservation
    child_opened_in_front_modal: MainGUISourceInspectionVisualHarnessObservation
    localized_layout_readable: MainGUISourceInspectionVisualHarnessObservation
    one_shot_button_remained_disabled: MainGUISourceInspectionVisualHarnessObservation

    def __post_init__(self) -> None:
        _validate_observations(self)


@_dataclass(frozen=True, slots=True)
class MainGUISourceInspectionReviewReport:
    case_number: int
    locale: RecoveryLocalizationLocale
    scale_percent: int
    terminal_action: MainGUISourceInspectionVisualHarnessTerminalAction
    presentation_sha256: bytes = _field(repr=False)
    decision: RecoverySourceInspectionReviewWindowDecision
    cancel_reason: RecoverySourceInspectionReviewWindowCancelReason | None
    observations: MainGUISourceInspectionReviewObservations
    synthetic_non_secret: bool = True
    exact_stage_2_40_binding_used: bool = True
    real_stage_2_41_event_requested: bool = True
    conditional_main_gui_activated: bool = True
    manual_observations_are_self_reported: bool = True
    runtime_directory_preparation_performed: bool = True
    normal_startup_activated: bool = False
    true_vault_input_used: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    automatic_gui_event_injection_used: bool = False
    accessibility_conformance_claimed: bool = False
    legal_conformity_claimed: bool = False
    platform_certification_claimed: bool = False
    human_understanding_proven: bool = False
    secrets_retained: bool = False
    source_material_retained: bool = False
    source_path_metadata_retained: bool = False
    callbacks_or_executors_retained: bool = False
    format: str = MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT
    version: int = MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _exact_enum(enum_type: type[Enum], value: _Any, field_name: str) -> Enum:
    if type(value) is not str:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            f"{field_name} must be exact text"
        )
    try:
        return enum_type(value)
    except ValueError as exc:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            f"{field_name} is outside the fixed allowlist"
        ) from exc


def _synthetic_digest(label: bytes) -> bytes:
    return _hashlib.sha256(_SYNTHETIC_DOMAIN + label).digest()


def _prepare_synthetic_execution(
    case_number: int,
    locale: RecoveryLocalizationLocale,
) -> VaultRecoverySourceInspectionExecutionOutcome:
    label = f"{case_number}:{locale.value}".encode("ascii")
    return VaultRecoverySourceInspectionExecutionOutcome(
        locale=locale,
        execution_decision=(
            RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
        ),
        state=RecoverySourceInspectionExecutionState.COMPLETED,
        recovery_id=_synthetic_digest(b"RECOVERY-ID\x00" + label)[:16],
        vault_id=_synthetic_digest(b"VAULT-ID\x00" + label)[:16],
        source_revision=41,
        source_vault_sha256=_synthetic_digest(b"SOURCE-VAULT\x00" + label),
        record_sha256=_synthetic_digest(b"RECORD\x00" + label),
        encoded_size=841,
        secure_source_inspection_performed=True,
        preserved_and_stopped=False,
        header_structurally_validated=True,
    )


def _validate_case(
    value: _Any,
    *,
    require_fresh: bool,
) -> SyntheticMainGUISourceInspectionReviewCase:
    if type(value) is not SyntheticMainGUISourceInspectionReviewCase:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "synthetic main-GUI source inspection case type is invalid"
        )
    if (
        type(value.case_number) is not int
        or not 1 <= value.case_number <= len(_MATRIX)
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or type(value.required_terminal_action)
        is not MainGUISourceInspectionVisualHarnessTerminalAction
        or type(value.binding)
        is not PreparedMainGUIRecoverySourceInspectionReviewBinding
        or value.binding.locale is not value.locale
        or value.synthetic_non_secret is not True
        or value.true_vault_input_used is not False
        or value.operation_capability_included is not False
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "synthetic main-GUI source inspection case is invalid"
        )
    expected = _MATRIX[value.case_number - 1]
    actual = (
        value.locale.value,
        value.scale_percent,
        value.required_terminal_action.value,
    )
    if actual != expected:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "synthetic main-GUI source inspection case differs from the matrix"
        )
    allowed_states = (
        (RecoverySourceInspectionMainGUIBridgeState.READY,)
        if require_fresh
        else (
            RecoverySourceInspectionMainGUIBridgeState.COMPLETED,
            RecoverySourceInspectionMainGUIBridgeState.FAILED,
        )
    )
    if value.binding.current_state not in allowed_states:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "synthetic main-GUI source inspection binding lifecycle is invalid"
        )
    return value


def _validate_observations(
    value: _Any,
) -> MainGUISourceInspectionReviewObservations:
    names = (
        "banner_button_visible_no_clipping",
        "unrelated_controls_disabled",
        "keyboard_reachable_no_trap",
        "child_opened_in_front_modal",
        "localized_layout_readable",
        "one_shot_button_remained_disabled",
    )
    if (
        type(value) is not MainGUISourceInspectionReviewObservations
        or any(
            type(getattr(value, name))
            is not MainGUISourceInspectionVisualHarnessObservation
            for name in names
        )
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection observations are invalid"
        )
    return value


def visual_observations_pass(
    value: MainGUISourceInspectionReviewObservations,
) -> bool:
    checked = _validate_observations(value)
    return all(
        item is MainGUISourceInspectionVisualHarnessObservation.PASS
        for item in (
            checked.banner_button_visible_no_clipping,
            checked.unrelated_controls_disabled,
            checked.keyboard_reachable_no_trap,
            checked.child_opened_in_front_modal,
            checked.localized_layout_readable,
            checked.one_shot_button_remained_disabled,
        )
    )


def _terminal_action_matches_outcome(
    action: MainGUISourceInspectionVisualHarnessTerminalAction,
    outcome: VaultRecoverySourceInspectionReviewWindowOutcome,
) -> bool:
    if action is MainGUISourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE:
        return (
            outcome.decision
            is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED
            and outcome.cancel_reason is None
        )
    reasons = {
        MainGUISourceInspectionVisualHarnessTerminalAction.ESCAPE_KEY: (
            RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
        ),
        MainGUISourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON: (
            RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        ),
        MainGUISourceInspectionVisualHarnessTerminalAction.WINDOW_CLOSE: (
            RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
        ),
    }
    return (
        outcome.decision is RecoverySourceInspectionReviewWindowDecision.CANCELLED
        and outcome.cancel_reason is reasons[action]
    )


def _validate_report(value: _Any) -> MainGUISourceInspectionReviewReport:
    if type(value) is not MainGUISourceInspectionReviewReport:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection report type is invalid"
        )
    _validate_observations(value.observations)
    if (
        value.format != MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT
        or type(value.version) is not int
        or value.version != MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION
        or type(value.case_number) is not int
        or not 1 <= value.case_number <= len(_MATRIX)
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or type(value.terminal_action)
        is not MainGUISourceInspectionVisualHarnessTerminalAction
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.decision) is not RecoverySourceInspectionReviewWindowDecision
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection report schema is invalid"
        )
    if (
        (
            value.locale.value,
            value.scale_percent,
            value.terminal_action.value,
        )
        != _MATRIX[value.case_number - 1]
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection report differs from the matrix"
        )
    true_names = (
        "synthetic_non_secret",
        "exact_stage_2_40_binding_used",
        "real_stage_2_41_event_requested",
        "conditional_main_gui_activated",
        "manual_observations_are_self_reported",
        "runtime_directory_preparation_performed",
    )
    false_names = (
        "normal_startup_activated",
        "true_vault_input_used",
        "operation_performed",
        "operation_authorized",
        "recovery_source_filesystem_access_performed",
        "recovery_source_filesystem_mutation_performed",
        "network_used",
        "automatic_gui_event_injection_used",
        "accessibility_conformance_claimed",
        "legal_conformity_claimed",
        "platform_certification_claimed",
        "human_understanding_proven",
        "secrets_retained",
        "source_material_retained",
        "source_path_metadata_retained",
        "callbacks_or_executors_retained",
    )
    if (
        any(type(getattr(value, name)) is not bool for name in (*true_names, *false_names))
        or any(getattr(value, name) is not True for name in true_names)
        or any(getattr(value, name) is not False for name in false_names)
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection report safety claims are invalid"
        )
    if value.decision is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED:
        if (
            value.terminal_action
            is not MainGUISourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE
            or value.cancel_reason is not None
        ):
            raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
                "acknowledged report differs from its terminal action"
            )
    else:
        expected_reasons = {
            MainGUISourceInspectionVisualHarnessTerminalAction.ESCAPE_KEY: (
                RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
            ),
            MainGUISourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON: (
                RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
            ),
            MainGUISourceInspectionVisualHarnessTerminalAction.WINDOW_CLOSE: (
                RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
            ),
        }
        if (
            value.terminal_action
            is MainGUISourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE
            or value.cancel_reason is not expected_reasons[value.terminal_action]
        ):
            raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
                "cancelled report differs from its terminal action"
            )
    return value


def prepare_synthetic_main_gui_source_inspection_review_case(
    case_number: int,
) -> SyntheticMainGUISourceInspectionReviewCase:
    """Create one exact fresh Stage 2.40 binding for the fixed matrix."""

    if type(case_number) is not int or not 1 <= case_number <= len(_MATRIX):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "case_number must select one exact fixed matrix case"
        )
    locale_id, scale_percent, action_id = _MATRIX[case_number - 1]
    locale = _exact_enum(RecoveryLocalizationLocale, locale_id, "locale")
    action = _exact_enum(
        MainGUISourceInspectionVisualHarnessTerminalAction,
        action_id,
        "required_terminal_action",
    )
    execution = _prepare_synthetic_execution(case_number, locale)
    session = prepare_recovery_source_inspection_review_session(execution)
    binding = prepare_main_gui_recovery_source_inspection_review_binding(session)
    return SyntheticMainGUISourceInspectionReviewCase(
        case_number=case_number,
        locale=locale,
        scale_percent=scale_percent,
        required_terminal_action=action,
        binding=binding,
    )


def build_main_gui_source_inspection_review_report(
    case: SyntheticMainGUISourceInspectionReviewCase,
    outcome: VaultRecoverySourceInspectionReviewWindowOutcome,
    observations: MainGUISourceInspectionReviewObservations,
) -> MainGUISourceInspectionReviewReport:
    """Bind one exact completed Stage 2.40 result to six observations."""

    checked_case = _validate_case(case, require_fresh=False)
    checked_observations = _validate_observations(observations)
    try:
        checked_outcome = _validate_outcome(outcome)
    except ValueError as exc:
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "Stage 2.40 binding outcome is invalid"
        ) from exc
    if (
        checked_case.binding.current_state
        is not RecoverySourceInspectionMainGUIBridgeState.COMPLETED
        or checked_case.binding.outcome is not outcome
        or checked_outcome.locale is not checked_case.locale
        or not _hmac.compare_digest(
            checked_case.binding.outcome.presentation_sha256,
            checked_outcome.presentation_sha256,
        )
        or not _terminal_action_matches_outcome(
            checked_case.required_terminal_action,
            checked_outcome,
        )
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "case, binding result, or required terminal action differs"
        )
    return MainGUISourceInspectionReviewReport(
        case_number=checked_case.case_number,
        locale=checked_case.locale,
        scale_percent=checked_case.scale_percent,
        terminal_action=checked_case.required_terminal_action,
        presentation_sha256=checked_outcome.presentation_sha256,
        decision=checked_outcome.decision,
        cancel_reason=checked_outcome.cancel_reason,
        observations=checked_observations,
    )


def main_gui_source_inspection_review_report_json(
    report: MainGUISourceInspectionReviewReport,
) -> str:
    """Return canonical bounded JSON without source or secret metadata."""

    checked = _validate_report(report)
    payload = {
        field: getattr(checked, field)
        for field in (
            "accessibility_conformance_claimed",
            "automatic_gui_event_injection_used",
            "callbacks_or_executors_retained",
            "case_number",
            "conditional_main_gui_activated",
            "exact_stage_2_40_binding_used",
            "format",
            "human_understanding_proven",
            "legal_conformity_claimed",
            "manual_observations_are_self_reported",
            "network_used",
            "normal_startup_activated",
            "operation_authorized",
            "operation_performed",
            "platform_certification_claimed",
            "real_stage_2_41_event_requested",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "runtime_directory_preparation_performed",
            "secrets_retained",
            "source_material_retained",
            "source_path_metadata_retained",
            "synthetic_non_secret",
            "true_vault_input_used",
            "version",
        )
    }
    payload.update(
        {
            "cancel_reason": (
                checked.cancel_reason.value
                if checked.cancel_reason is not None
                else None
            ),
            "decision": checked.decision.value,
            "locale": checked.locale.value,
            "observations": {
                name: getattr(checked.observations, name).value
                for name in (
                    "banner_button_visible_no_clipping",
                    "child_opened_in_front_modal",
                    "keyboard_reachable_no_trap",
                    "localized_layout_readable",
                    "one_shot_button_remained_disabled",
                    "unrelated_controls_disabled",
                )
            },
            "presentation_sha256": checked.presentation_sha256.hex(),
            "scale_percent": checked.scale_percent,
            "terminal_action": checked.terminal_action.value,
        }
    )
    encoded = _json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if (
        len(encoded.encode("utf-8"))
        > MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN
    ):
        raise VaultRecoverySourceInspectionMainGUIVisualHarnessError(
            "main-GUI source inspection report JSON exceeds the fixed bound"
        )
    return encoded


__all__ = (
    "MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT",
    "MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX",
    "MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN",
    "MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION",
    "MainGUISourceInspectionReviewObservations",
    "MainGUISourceInspectionReviewReport",
    "MainGUISourceInspectionVisualHarnessObservation",
    "MainGUISourceInspectionVisualHarnessTerminalAction",
    "SyntheticMainGUISourceInspectionReviewCase",
    "VaultRecoverySourceInspectionMainGUIVisualHarnessError",
    "build_main_gui_source_inspection_review_report",
    "main_gui_source_inspection_review_report_json",
    "prepare_synthetic_main_gui_source_inspection_review_case",
    "visual_observations_pass",
)
