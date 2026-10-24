"""Pure synthetic contract for the Stage 2.37 visual review harness.

Stage 2.38 creates only fixed, deterministic, non-secret fixtures for the
real Stage 2.37 ``Toplevel``.  This core has no GUI, filesystem, network,
process, logging, source-reader, secret, recovery, or operation capability.

The bounded report records manual observations and one matching terminal
action.  It is self-reported local test evidence, not accessibility or legal
conformity, platform certification, proof of comprehension, identity,
informed consent, recovery authorization, or proof of an operation.
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
from mokosh_vault_recovery_source_inspection_presentation import (
    VaultRecoverySourceInspectionPresentation,
    _validate_source_inspection_presentation,
    prepare_recovery_source_inspection_presentation,
)
from mokosh_vault_recovery_source_inspection_review_window import (
    RecoverySourceInspectionReviewWindowCancelReason,
    RecoverySourceInspectionReviewWindowDecision,
    VaultRecoverySourceInspectionReviewWindowOutcome,
    _validate_outcome,
)
from mokosh_vault_recovery_source_inspection_ui_adapter import (
    PreparedVaultRecoverySourceInspectionUIAdapter,
    RecoverySourceInspectionUIAdapterState,
    _binding_from_source_presentation,
    _validate_adapter_view,
    _view_matches_binding,
    prepare_recovery_source_inspection_ui_adapter,
)


RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT = (
    "MOKOSH_RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_REPORT"
)
RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION = 1
RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_LOCALES = ("bg-BG", "en-GB")
RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_SCALE_PERCENTS = (100, 125, 150, 200)
RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_WINDOW_PROFILES = (
    "small",
    "standard",
)
RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN = 4096

_SYNTHETIC_DOMAIN = (
    b"MOKOSH\x00STAGE-2.38\x00SYNTHETIC-SOURCE-INSPECTION-VISUAL-V1\x00"
)


class VaultRecoverySourceInspectionVisualHarnessError(ValueError):
    """A Stage 2.38 fixture, observation, or report is invalid."""


class RecoverySourceInspectionVisualHarnessWindowProfile(str, Enum):
    SMALL = "small"
    STANDARD = "standard"


class RecoverySourceInspectionVisualHarnessTerminalAction(str, Enum):
    ESCAPE_KEY = "escape_key"
    CANCEL_BUTTON = "cancel_button"
    WINDOW_CLOSE = "window_close"
    ACKNOWLEDGE = "acknowledge"


class RecoverySourceInspectionVisualHarnessObservation(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


_WINDOW_DIMENSIONS = {
    RecoverySourceInspectionVisualHarnessWindowProfile.SMALL: (560, 440),
    RecoverySourceInspectionVisualHarnessWindowProfile.STANDARD: (800, 640),
}

_MATRIX = (
    ("bg-BG", 100, "small", "escape_key"),
    ("en-GB", 125, "small", "cancel_button"),
    ("bg-BG", 150, "standard", "window_close"),
    ("en-GB", 200, "standard", "acknowledge"),
    ("bg-BG", 125, "standard", "cancel_button"),
    ("en-GB", 150, "small", "escape_key"),
    ("bg-BG", 200, "small", "acknowledge"),
    ("en-GB", 100, "standard", "window_close"),
)

RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX = _MATRIX


@_dataclass(frozen=True, slots=True)
class SyntheticRecoverySourceInspectionVisualHarnessCase:
    """One exact non-secret fixture for one real Stage 2.37 window."""

    case_number: int
    locale: RecoveryLocalizationLocale
    scale_percent: int
    window_profile: RecoverySourceInspectionVisualHarnessWindowProfile
    width: int
    height: int
    required_terminal_action: RecoverySourceInspectionVisualHarnessTerminalAction
    presentation: VaultRecoverySourceInspectionPresentation = _field(repr=False)
    adapter: PreparedVaultRecoverySourceInspectionUIAdapter = _field(repr=False)
    synthetic_non_secret: bool = True
    real_source_input_used: bool = False
    operation_capability_included: bool = False

    def __post_init__(self) -> None:
        _validate_case(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionVisualHarnessObservations:
    """Six fixed manual checks; arbitrary notes are intentionally excluded."""

    content_reachability_and_scrolling: RecoverySourceInspectionVisualHarnessObservation
    text_wrapping_no_clipping_or_overlap: RecoverySourceInspectionVisualHarnessObservation
    focus_order_visible_unobscured: RecoverySourceInspectionVisualHarnessObservation
    keyboard_only_no_trap: RecoverySourceInspectionVisualHarnessObservation
    default_false_and_enable_redisable: RecoverySourceInspectionVisualHarnessObservation
    locale_title_and_labels: RecoverySourceInspectionVisualHarnessObservation

    def __post_init__(self) -> None:
        _validate_observations(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionVisualHarnessReport:
    """Canonical bounded evidence for one mapped synthetic visible review."""

    case_number: int
    locale: RecoveryLocalizationLocale
    scale_percent: int
    window_profile: RecoverySourceInspectionVisualHarnessWindowProfile
    width: int
    height: int
    presentation_sha256: bytes = _field(repr=False)
    terminal_action: RecoverySourceInspectionVisualHarnessTerminalAction
    decision: RecoverySourceInspectionReviewWindowDecision
    cancel_reason: RecoverySourceInspectionReviewWindowCancelReason | None
    observations: RecoverySourceInspectionVisualHarnessObservations
    synthetic_non_secret: bool = True
    real_stage_2_37_toplevel_requested: bool = True
    window_mapped_before_timeout: bool = True
    inspection_only: bool = True
    manual_observations_are_self_reported: bool = True
    ui_event_claims_are_process_local_assertions: bool = True
    automatic_gui_event_injection_used: bool = False
    platform_certification_claimed: bool = False
    accessibility_conformance_claimed: bool = False
    screen_reader_behavior_verified: bool = False
    accessibility_api_verified: bool = False
    contrast_conformance_verified: bool = False
    platform_user_preferences_verified: bool = False
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    main_gui_activated: bool = False
    true_vault_input_used: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    secrets_retained: bool = False
    source_material_retained: bool = False
    source_path_metadata_retained: bool = False
    callbacks_or_executors_retained: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _exact_enum(enum_type: type[Enum], value: _Any, field_name: str) -> Enum:
    if type(value) is not str:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            f"{field_name} must be exact text"
        )
    try:
        return enum_type(value)
    except ValueError as exc:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            f"{field_name} is outside the fixed visual harness allowlist"
        ) from exc


def _synthetic_digest(label: bytes) -> bytes:
    return _hashlib.sha256(_SYNTHETIC_DOMAIN + label).digest()


def _prepare_synthetic_execution(
    locale: RecoveryLocalizationLocale,
) -> VaultRecoverySourceInspectionExecutionOutcome:
    locale_label = locale.value.encode("ascii")
    return VaultRecoverySourceInspectionExecutionOutcome(
        locale=locale,
        execution_decision=(
            RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
        ),
        state=RecoverySourceInspectionExecutionState.COMPLETED,
        recovery_id=_synthetic_digest(b"RECOVERY-ID\x00" + locale_label)[:16],
        vault_id=_synthetic_digest(b"VAULT-ID\x00" + locale_label)[:16],
        source_revision=17,
        source_vault_sha256=_synthetic_digest(b"SOURCE-VAULT\x00" + locale_label),
        record_sha256=_synthetic_digest(b"RECORD\x00" + locale_label),
        encoded_size=777,
        secure_source_inspection_performed=True,
        preserved_and_stopped=False,
        header_structurally_validated=True,
    )


def _validate_case(
    value: _Any,
    *,
    allow_acknowledged_adapter: bool = False,
) -> SyntheticRecoverySourceInspectionVisualHarnessCase:
    if type(value) is not SyntheticRecoverySourceInspectionVisualHarnessCase:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "synthetic source inspection visual case type is invalid"
        )
    if (
        type(value.case_number) is not int
        or not 1 <= value.case_number <= len(_MATRIX)
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or value.scale_percent
        not in RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_SCALE_PERCENTS
        or type(value.window_profile)
        is not RecoverySourceInspectionVisualHarnessWindowProfile
        or type(value.width) is not int
        or type(value.height) is not int
        or (value.width, value.height) != _WINDOW_DIMENSIONS[value.window_profile]
        or type(value.required_terminal_action)
        is not RecoverySourceInspectionVisualHarnessTerminalAction
        or type(value.presentation) is not VaultRecoverySourceInspectionPresentation
        or type(value.adapter) is not PreparedVaultRecoverySourceInspectionUIAdapter
        or value.synthetic_non_secret is not True
        or value.real_source_input_used is not False
        or value.operation_capability_included is not False
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "synthetic source inspection visual case is invalid"
        )
    matrix_value = _MATRIX[value.case_number - 1]
    if matrix_value != (
        value.locale.value,
        value.scale_percent,
        value.window_profile.value,
        value.required_terminal_action.value,
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "synthetic source inspection visual case differs from the fixed matrix"
        )
    try:
        _validate_source_inspection_presentation(value.presentation)
        binding = _binding_from_source_presentation(value.presentation)
        adapter_view = value.adapter.view
        _validate_adapter_view(adapter_view)
    except ValueError as exc:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "synthetic presentation or adapter is invalid"
        ) from exc
    fresh = (
        value.adapter.current_state
        is RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
        and value.adapter.acknowledged is False
        and value.adapter.receipt is None
    )
    acknowledged = (
        value.adapter.current_state is RecoverySourceInspectionUIAdapterState.ACKNOWLEDGED
        and value.adapter.acknowledged is True
        and value.adapter.receipt is not None
    )
    if (
        value.presentation.locale is not value.locale
        or not _view_matches_binding(adapter_view, binding)
        or not (fresh or (allow_acknowledged_adapter and acknowledged))
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "synthetic presentation and adapter binding differ"
        )
    return value


def _validate_observations(
    value: _Any,
) -> RecoverySourceInspectionVisualHarnessObservations:
    names = (
        "content_reachability_and_scrolling",
        "text_wrapping_no_clipping_or_overlap",
        "focus_order_visible_unobscured",
        "keyboard_only_no_trap",
        "default_false_and_enable_redisable",
        "locale_title_and_labels",
    )
    if (
        type(value) is not RecoverySourceInspectionVisualHarnessObservations
        or any(
            type(getattr(value, name))
            is not RecoverySourceInspectionVisualHarnessObservation
            for name in names
        )
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual observations are invalid"
        )
    return value


def visual_observations_pass(
    value: RecoverySourceInspectionVisualHarnessObservations,
) -> bool:
    """Return true only for six exact PASS observations."""

    checked = _validate_observations(value)
    return all(
        item is RecoverySourceInspectionVisualHarnessObservation.PASS
        for item in (
            checked.content_reachability_and_scrolling,
            checked.text_wrapping_no_clipping_or_overlap,
            checked.focus_order_visible_unobscured,
            checked.keyboard_only_no_trap,
            checked.default_false_and_enable_redisable,
            checked.locale_title_and_labels,
        )
    )


def _terminal_action_matches_outcome(
    action: RecoverySourceInspectionVisualHarnessTerminalAction,
    outcome: VaultRecoverySourceInspectionReviewWindowOutcome,
) -> bool:
    if action is RecoverySourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE:
        return (
            outcome.decision
            is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED
            and outcome.cancel_reason is None
        )
    reasons = {
        RecoverySourceInspectionVisualHarnessTerminalAction.ESCAPE_KEY: (
            RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
        ),
        RecoverySourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON: (
            RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        ),
        RecoverySourceInspectionVisualHarnessTerminalAction.WINDOW_CLOSE: (
            RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
        ),
    }
    return (
        outcome.decision is RecoverySourceInspectionReviewWindowDecision.CANCELLED
        and outcome.cancel_reason is reasons[action]
    )


def _validate_report(
    value: _Any,
) -> RecoverySourceInspectionVisualHarnessReport:
    if type(value) is not RecoverySourceInspectionVisualHarnessReport:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report type is invalid"
        )
    _validate_observations(value.observations)
    if (
        value.format != RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION
        or type(value.case_number) is not int
        or not 1 <= value.case_number <= len(_MATRIX)
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or type(value.window_profile)
        is not RecoverySourceInspectionVisualHarnessWindowProfile
        or (value.width, value.height) != _WINDOW_DIMENSIONS[value.window_profile]
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.terminal_action)
        is not RecoverySourceInspectionVisualHarnessTerminalAction
        or type(value.decision) is not RecoverySourceInspectionReviewWindowDecision
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report schema is invalid"
        )
    matrix_value = _MATRIX[value.case_number - 1]
    if matrix_value != (
        value.locale.value,
        value.scale_percent,
        value.window_profile.value,
        value.terminal_action.value,
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report differs from the fixed matrix"
        )
    if value.decision is RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED:
        if value.cancel_reason is not None:
            raise VaultRecoverySourceInspectionVisualHarnessError(
                "acknowledged visual report has a cancel reason"
            )
    elif type(value.cancel_reason) is not RecoverySourceInspectionReviewWindowCancelReason:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "cancelled visual report lacks an exact reason"
        )
    expected_decision_and_reason = {
        RecoverySourceInspectionVisualHarnessTerminalAction.ESCAPE_KEY: (
            RecoverySourceInspectionReviewWindowDecision.CANCELLED,
            RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY,
        ),
        RecoverySourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON: (
            RecoverySourceInspectionReviewWindowDecision.CANCELLED,
            RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON,
        ),
        RecoverySourceInspectionVisualHarnessTerminalAction.WINDOW_CLOSE: (
            RecoverySourceInspectionReviewWindowDecision.CANCELLED,
            RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE,
        ),
        RecoverySourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE: (
            RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED,
            None,
        ),
    }[value.terminal_action]
    if (value.decision, value.cancel_reason) != expected_decision_and_reason:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report terminal action does not match"
        )
    required_true_names = (
        "synthetic_non_secret",
        "real_stage_2_37_toplevel_requested",
        "window_mapped_before_timeout",
        "inspection_only",
        "manual_observations_are_self_reported",
        "ui_event_claims_are_process_local_assertions",
    )
    required_false_names = (
        "automatic_gui_event_injection_used",
        "platform_certification_claimed",
        "accessibility_conformance_claimed",
        "screen_reader_behavior_verified",
        "accessibility_api_verified",
        "contrast_conformance_verified",
        "platform_user_preferences_verified",
        "human_understanding_proven",
        "user_identity_verified",
        "informed_consent_proven",
        "main_gui_activated",
        "true_vault_input_used",
        "operation_performed",
        "operation_authorized",
        "filesystem_mutation_performed",
        "network_used",
        "secrets_retained",
        "source_material_retained",
        "source_path_metadata_retained",
        "callbacks_or_executors_retained",
    )
    if (
        any(type(getattr(value, name)) is not bool for name in required_true_names)
        or any(type(getattr(value, name)) is not bool for name in required_false_names)
        or any(getattr(value, name) is not True for name in required_true_names)
        or any(getattr(value, name) is not False for name in required_false_names)
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report safety flags are invalid"
        )
    return value


def prepare_synthetic_recovery_source_inspection_visual_case(
    case_number: int,
) -> SyntheticRecoverySourceInspectionVisualHarnessCase:
    """Prepare one exact fixed matrix case without real source input."""

    if type(case_number) is not int or not 1 <= case_number <= len(_MATRIX):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "case_number must select one exact fixed matrix case"
        )
    locale_id, scale_percent, profile_id, action_id = _MATRIX[case_number - 1]
    locale = _exact_enum(RecoveryLocalizationLocale, locale_id, "locale")
    profile = _exact_enum(
        RecoverySourceInspectionVisualHarnessWindowProfile,
        profile_id,
        "window_profile",
    )
    action = _exact_enum(
        RecoverySourceInspectionVisualHarnessTerminalAction,
        action_id,
        "required_terminal_action",
    )
    execution = _prepare_synthetic_execution(locale)
    presentation = prepare_recovery_source_inspection_presentation(execution)
    adapter = prepare_recovery_source_inspection_ui_adapter(presentation)
    width, height = _WINDOW_DIMENSIONS[profile]
    return SyntheticRecoverySourceInspectionVisualHarnessCase(
        case_number=case_number,
        locale=locale,
        scale_percent=scale_percent,
        window_profile=profile,
        width=width,
        height=height,
        required_terminal_action=action,
        presentation=presentation,
        adapter=adapter,
    )


def build_recovery_source_inspection_visual_harness_report(
    case: SyntheticRecoverySourceInspectionVisualHarnessCase,
    outcome: VaultRecoverySourceInspectionReviewWindowOutcome,
    observations: RecoverySourceInspectionVisualHarnessObservations,
) -> RecoverySourceInspectionVisualHarnessReport:
    """Bind one exact mapped outcome and six manual observations."""

    checked_case = _validate_case(case, allow_acknowledged_adapter=True)
    checked_observations = _validate_observations(observations)
    try:
        checked_outcome = _validate_outcome(outcome)
    except ValueError as exc:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "Stage 2.37 visual outcome is invalid"
        ) from exc
    if (
        checked_outcome.locale is not checked_case.locale
        or not _hmac.compare_digest(
            checked_case.adapter.view.presentation_sha256,
            checked_outcome.presentation_sha256,
        )
        or not _terminal_action_matches_outcome(
            checked_case.required_terminal_action,
            checked_outcome,
        )
    ):
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "visual case, Stage 2.37 outcome, or required terminal action differs"
        )
    return RecoverySourceInspectionVisualHarnessReport(
        case_number=checked_case.case_number,
        locale=checked_case.locale,
        scale_percent=checked_case.scale_percent,
        window_profile=checked_case.window_profile,
        width=checked_case.width,
        height=checked_case.height,
        presentation_sha256=checked_case.adapter.view.presentation_sha256,
        terminal_action=checked_case.required_terminal_action,
        decision=checked_outcome.decision,
        cancel_reason=checked_outcome.cancel_reason,
        observations=checked_observations,
    )


def recovery_source_inspection_visual_harness_report_json(
    report: RecoverySourceInspectionVisualHarnessReport,
) -> str:
    """Return one canonical bounded JSON object without sensitive metadata."""

    checked = _validate_report(report)
    payload = {
        "accessibility_api_verified": checked.accessibility_api_verified,
        "accessibility_conformance_claimed": checked.accessibility_conformance_claimed,
        "automatic_gui_event_injection_used": checked.automatic_gui_event_injection_used,
        "callbacks_or_executors_retained": checked.callbacks_or_executors_retained,
        "cancel_reason": (
            checked.cancel_reason.value if checked.cancel_reason is not None else None
        ),
        "case_number": checked.case_number,
        "contrast_conformance_verified": checked.contrast_conformance_verified,
        "decision": checked.decision.value,
        "filesystem_mutation_performed": checked.filesystem_mutation_performed,
        "format": checked.format,
        "height": checked.height,
        "human_understanding_proven": checked.human_understanding_proven,
        "informed_consent_proven": checked.informed_consent_proven,
        "inspection_only": checked.inspection_only,
        "locale": checked.locale.value,
        "main_gui_activated": checked.main_gui_activated,
        "manual_observations_are_self_reported": (
            checked.manual_observations_are_self_reported
        ),
        "network_used": checked.network_used,
        "observations": {
            "content_reachability_and_scrolling": (
                checked.observations.content_reachability_and_scrolling.value
            ),
            "default_false_and_enable_redisable": (
                checked.observations.default_false_and_enable_redisable.value
            ),
            "focus_order_visible_unobscured": (
                checked.observations.focus_order_visible_unobscured.value
            ),
            "keyboard_only_no_trap": (
                checked.observations.keyboard_only_no_trap.value
            ),
            "locale_title_and_labels": (
                checked.observations.locale_title_and_labels.value
            ),
            "text_wrapping_no_clipping_or_overlap": (
                checked.observations.text_wrapping_no_clipping_or_overlap.value
            ),
        },
        "operation_authorized": checked.operation_authorized,
        "operation_performed": checked.operation_performed,
        "platform_certification_claimed": checked.platform_certification_claimed,
        "platform_user_preferences_verified": (
            checked.platform_user_preferences_verified
        ),
        "presentation_sha256": checked.presentation_sha256.hex(),
        "real_stage_2_37_toplevel_requested": (
            checked.real_stage_2_37_toplevel_requested
        ),
        "scale_percent": checked.scale_percent,
        "screen_reader_behavior_verified": checked.screen_reader_behavior_verified,
        "secrets_retained": checked.secrets_retained,
        "source_material_retained": checked.source_material_retained,
        "source_path_metadata_retained": checked.source_path_metadata_retained,
        "synthetic_non_secret": checked.synthetic_non_secret,
        "terminal_action": checked.terminal_action.value,
        "true_vault_input_used": checked.true_vault_input_used,
        "ui_event_claims_are_process_local_assertions": (
            checked.ui_event_claims_are_process_local_assertions
        ),
        "user_identity_verified": checked.user_identity_verified,
        "version": checked.version,
        "width": checked.width,
        "window_mapped_before_timeout": checked.window_mapped_before_timeout,
        "window_profile": checked.window_profile.value,
    }
    encoded = _json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN:
        raise VaultRecoverySourceInspectionVisualHarnessError(
            "source inspection visual report JSON exceeds the fixed bound"
        )
    return encoded


__all__ = (
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_FORMAT",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_LOCALES",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_SCALE_PERCENTS",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_VERSION",
    "RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_WINDOW_PROFILES",
    "RecoverySourceInspectionVisualHarnessObservation",
    "RecoverySourceInspectionVisualHarnessObservations",
    "RecoverySourceInspectionVisualHarnessReport",
    "RecoverySourceInspectionVisualHarnessTerminalAction",
    "RecoverySourceInspectionVisualHarnessWindowProfile",
    "SyntheticRecoverySourceInspectionVisualHarnessCase",
    "VaultRecoverySourceInspectionVisualHarnessError",
    "build_recovery_source_inspection_visual_harness_report",
    "prepare_synthetic_recovery_source_inspection_visual_case",
    "recovery_source_inspection_visual_harness_report_json",
    "visual_observations_pass",
)
