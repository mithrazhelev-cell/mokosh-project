"""Synthetic visual/platform harness contract for the recovery review window.

Stage 2.15 creates only fixed, non-secret development fixtures for the real
Stage 2.14 ``Toplevel``.  It cannot accept a Vault, password, recovery record,
path, keyring, candidate, callback, executor, or operation capability.

The bounded report records explicit human observations.  It is local test
evidence, not accessibility certification, proof of comprehension, recovery
authorization, or evidence that any recovery operation was performed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from typing import Any

from mokosh_vault_recovery_localization import RecoveryLocalizationLocale
from mokosh_vault_recovery_presentation import (
    VaultRecoveryWorkflowPresentation,
    _presentation_components,
)
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification
from mokosh_vault_recovery_review_window import (
    RecoveryReviewWindowCancelReason,
    RecoveryReviewWindowDecision,
    VaultRecoveryReviewWindowOutcome,
    _validate_outcome,
)
from mokosh_vault_recovery_ui_adapter import (
    PreparedVaultRecoveryUIAdapter,
    RecoveryUIAdapterState,
    _binding_from_source_presentation,
    _validate_adapter_view,
    _view_matches_binding,
    prepare_recovery_ui_adapter,
)
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowState,
)


RECOVERY_VISUAL_HARNESS_FORMAT = "MOKOSH_RECOVERY_VISUAL_HARNESS_REPORT"
RECOVERY_VISUAL_HARNESS_VERSION = 1
RECOVERY_VISUAL_HARNESS_ROUTES = ("absent", "exact", "conflict", "preserve")
RECOVERY_VISUAL_HARNESS_LOCALES = ("bg-BG", "en-GB")
RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS = (100, 125, 150, 200)
RECOVERY_VISUAL_HARNESS_WINDOW_PROFILES = ("small", "standard")

_SYNTHETIC_DIGEST_DOMAIN = (
    b"MOKOSH\x00STAGE-2.15\x00SYNTHETIC-RECOVERY-REVIEW-V1\x00"
)


class VaultRecoveryVisualHarnessError(ValueError):
    """A Stage 2.15 fixture, observation, or report is invalid."""


class RecoveryVisualHarnessRoute(str, Enum):
    ABSENT = "absent"
    EXACT = "exact"
    CONFLICT = "conflict"
    PRESERVE = "preserve"


class RecoveryVisualHarnessWindowProfile(str, Enum):
    SMALL = "small"
    STANDARD = "standard"


class RecoveryVisualHarnessObservation(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


_ROUTE_COMPONENTS = {
    RecoveryVisualHarnessRoute.ABSENT: (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        False,
        True,
    ),
    RecoveryVisualHarnessRoute.EXACT: (
        RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        False,
        True,
    ),
    RecoveryVisualHarnessRoute.CONFLICT: (
        RecoveryPublishClassification.CONFLICT,
        RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        True,
        False,
    ),
    RecoveryVisualHarnessRoute.PRESERVE: (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        RecoveryWorkflowState.PRESERVED_STOP,
        True,
        False,
    ),
}

_WINDOW_DIMENSIONS = {
    RecoveryVisualHarnessWindowProfile.SMALL: (520, 420),
    RecoveryVisualHarnessWindowProfile.STANDARD: (800, 640),
}


@_dataclass(frozen=True, slots=True)
class SyntheticRecoveryVisualHarnessCase:
    """One exact non-secret fixture for one real Stage 2.14 window."""

    route: RecoveryVisualHarnessRoute
    locale: RecoveryLocalizationLocale
    scale_percent: int
    window_profile: RecoveryVisualHarnessWindowProfile
    width: int
    height: int
    presentation: VaultRecoveryWorkflowPresentation = _field(repr=False)
    adapter: PreparedVaultRecoveryUIAdapter = _field(repr=False)
    synthetic_non_secret: bool = True
    operation_capability_included: bool = False

    def __post_init__(self) -> None:
        _validate_case(self)


@_dataclass(frozen=True, slots=True)
class RecoveryVisualHarnessObservations:
    """Fixed manual observations; arbitrary notes are intentionally excluded."""

    scroll_reachability: RecoveryVisualHarnessObservation
    text_wrap: RecoveryVisualHarnessObservation
    focus_order: RecoveryVisualHarnessObservation
    keyboard_only: RecoveryVisualHarnessObservation

    def __post_init__(self) -> None:
        _validate_observations(self)


@_dataclass(frozen=True, slots=True)
class RecoveryVisualHarnessReport:
    """Bounded non-secret report for one synthetic visible review."""

    route: RecoveryVisualHarnessRoute
    locale: RecoveryLocalizationLocale
    scale_percent: int
    window_profile: RecoveryVisualHarnessWindowProfile
    width: int
    height: int
    presentation_sha256: bytes = _field(repr=False)
    decision: RecoveryReviewWindowDecision
    cancel_reason: RecoveryReviewWindowCancelReason | None
    observations: RecoveryVisualHarnessObservations
    synthetic_non_secret: bool = True
    real_stage_2_14_toplevel_requested: bool = True
    inspection_only: bool = True
    platform_certification_claimed: bool = False
    main_gui_activated: bool = False
    true_vault_input_used: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_VISUAL_HARNESS_FORMAT
    version: int = RECOVERY_VISUAL_HARNESS_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _exact_enum(enum_type: type[Enum], value: Any, field_name: str) -> Enum:
    if type(value) is not str:
        raise VaultRecoveryVisualHarnessError(f"{field_name} must be exact text")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise VaultRecoveryVisualHarnessError(
            f"{field_name} is outside the fixed harness allowlist"
        ) from exc


def _validate_case(
    value: Any,
    *,
    require_fresh_adapter: bool = True,
) -> SyntheticRecoveryVisualHarnessCase:
    if type(value) is not SyntheticRecoveryVisualHarnessCase:
        raise VaultRecoveryVisualHarnessError("synthetic harness case type is invalid")
    if (
        type(value.route) is not RecoveryVisualHarnessRoute
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or value.scale_percent not in RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS
        or type(value.window_profile) is not RecoveryVisualHarnessWindowProfile
        or type(value.width) is not int
        or type(value.height) is not int
        or (value.width, value.height) != _WINDOW_DIMENSIONS[value.window_profile]
        or type(value.presentation) is not VaultRecoveryWorkflowPresentation
        or type(value.adapter) is not PreparedVaultRecoveryUIAdapter
        or value.synthetic_non_secret is not True
        or value.operation_capability_included is not False
    ):
        raise VaultRecoveryVisualHarnessError("synthetic harness case is invalid")
    try:
        binding = _binding_from_source_presentation(value.presentation)
        adapter_view = _validate_adapter_view(value.adapter.view)
    except ValueError as exc:
        raise VaultRecoveryVisualHarnessError(
            "synthetic presentation or adapter is invalid"
        ) from exc
    adapter_is_fresh = (
        value.adapter.current_state
        is RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
        and value.adapter.acknowledged is False
        and value.adapter.receipt is None
    )
    adapter_is_acknowledged = (
        value.adapter.current_state is RecoveryUIAdapterState.ACKNOWLEDGED
        and value.adapter.acknowledged is True
        and value.adapter.receipt is not None
    )
    if (
        not _view_matches_binding(adapter_view, binding)
        or (require_fresh_adapter and not adapter_is_fresh)
        or (
            not require_fresh_adapter
            and not (adapter_is_fresh or adapter_is_acknowledged)
        )
    ):
        raise VaultRecoveryVisualHarnessError(
            "synthetic presentation and fresh adapter differ"
        )
    expected = _ROUTE_COMPONENTS[value.route]
    if (
        value.presentation.classification is not expected[0]
        or value.presentation.decision is not expected[1]
        or value.presentation.state is not expected[2]
        or value.presentation.terminal_stop is not expected[3]
        or value.presentation.downstream_reverification_required is not expected[4]
    ):
        raise VaultRecoveryVisualHarnessError("synthetic route binding is invalid")
    return value


def _validate_observations(value: Any) -> RecoveryVisualHarnessObservations:
    if type(value) is not RecoveryVisualHarnessObservations or any(
        type(getattr(value, name)) is not RecoveryVisualHarnessObservation
        for name in ("scroll_reachability", "text_wrap", "focus_order", "keyboard_only")
    ):
        raise VaultRecoveryVisualHarnessError("visual observations are invalid")
    return value


def _validate_report(value: Any) -> RecoveryVisualHarnessReport:
    if type(value) is not RecoveryVisualHarnessReport:
        raise VaultRecoveryVisualHarnessError("visual harness report type is invalid")
    _validate_observations(value.observations)
    if (
        value.format != RECOVERY_VISUAL_HARNESS_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_VISUAL_HARNESS_VERSION
        or type(value.route) is not RecoveryVisualHarnessRoute
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.scale_percent) is not int
        or value.scale_percent not in RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS
        or type(value.window_profile) is not RecoveryVisualHarnessWindowProfile
        or (value.width, value.height) != _WINDOW_DIMENSIONS[value.window_profile]
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.decision) is not RecoveryReviewWindowDecision
    ):
        raise VaultRecoveryVisualHarnessError("visual harness report schema is invalid")
    if value.decision is RecoveryReviewWindowDecision.ACKNOWLEDGED:
        if value.cancel_reason is not None:
            raise VaultRecoveryVisualHarnessError("acknowledged report has cancel reason")
    elif type(value.cancel_reason) is not RecoveryReviewWindowCancelReason:
        raise VaultRecoveryVisualHarnessError("cancelled report lacks exact reason")
    bool_fields = (
        "synthetic_non_secret",
        "real_stage_2_14_toplevel_requested",
        "inspection_only",
        "platform_certification_claimed",
        "main_gui_activated",
        "true_vault_input_used",
        "operation_performed",
        "operation_authorized",
        "filesystem_mutation_performed",
        "network_used",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryVisualHarnessError("report flags must be exact booleans")
    if (
        value.synthetic_non_secret is not True
        or value.real_stage_2_14_toplevel_requested is not True
        or value.inspection_only is not True
        or any(
            getattr(value, name) is not False
            for name in (
                "platform_certification_claimed",
                "main_gui_activated",
                "true_vault_input_used",
                "operation_performed",
                "operation_authorized",
                "filesystem_mutation_performed",
                "network_used",
                "secrets_retained",
            )
        )
    ):
        raise VaultRecoveryVisualHarnessError("report contains a false authority claim")
    return value


def prepare_synthetic_recovery_visual_case(
    route_id: str,
    locale_id: str,
    scale_percent: int,
    window_profile_id: str,
) -> SyntheticRecoveryVisualHarnessCase:
    """Build one fixed synthetic case without reading runtime or user data."""

    route = _exact_enum(RecoveryVisualHarnessRoute, route_id, "route_id")
    locale = _exact_enum(RecoveryLocalizationLocale, locale_id, "locale_id")
    profile = _exact_enum(
        RecoveryVisualHarnessWindowProfile,
        window_profile_id,
        "window_profile_id",
    )
    if type(scale_percent) is not int or scale_percent not in (
        RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS
    ):
        raise VaultRecoveryVisualHarnessError(
            "scale_percent is outside the fixed harness allowlist"
        )
    components = _ROUTE_COMPONENTS[route]
    messages, gates, confirmations = _presentation_components(*components)
    digest = hashlib.sha256(
        _SYNTHETIC_DIGEST_DOMAIN + route.value.encode("ascii")
    ).digest()
    presentation = VaultRecoveryWorkflowPresentation(
        workflow_state_sha256=digest,
        classification=components[0],
        decision=components[1],
        state=components[2],
        message_keys=messages,
        gate_message_keys=gates,
        confirmation_requirements=confirmations,
        terminal_stop=components[3],
        downstream_reverification_required=components[4],
    )
    width, height = _WINDOW_DIMENSIONS[profile]
    return SyntheticRecoveryVisualHarnessCase(
        route=route,
        locale=locale,
        scale_percent=scale_percent,
        window_profile=profile,
        width=width,
        height=height,
        presentation=presentation,
        adapter=prepare_recovery_ui_adapter(presentation),
    )


def build_recovery_visual_harness_report(
    case: SyntheticRecoveryVisualHarnessCase,
    outcome: VaultRecoveryReviewWindowOutcome,
    observations: RecoveryVisualHarnessObservations,
) -> RecoveryVisualHarnessReport:
    """Bind exact manual observations to one exact Stage 2.14 outcome."""

    _validate_case(case, require_fresh_adapter=False)
    _validate_observations(observations)
    try:
        _validate_outcome(outcome)
    except ValueError as exc:
        raise VaultRecoveryVisualHarnessError("review outcome is invalid") from exc
    if (
        outcome.locale is not case.locale
        or outcome.presentation_sha256 != case.adapter.view.presentation_sha256
        or outcome.operation_performed is not False
        or outcome.operation_authorized is not False
        or outcome.secrets_retained is not False
    ):
        raise VaultRecoveryVisualHarnessError("case and review outcome differ")
    if outcome.decision is RecoveryReviewWindowDecision.ACKNOWLEDGED:
        if (
            case.adapter.current_state is not RecoveryUIAdapterState.ACKNOWLEDGED
            or case.adapter.receipt is not outcome.acknowledgement_receipt
        ):
            raise VaultRecoveryVisualHarnessError(
                "acknowledged outcome and adapter lifecycle differ"
            )
    elif (
        case.adapter.current_state
        is not RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
        or case.adapter.acknowledged
        or case.adapter.receipt is not None
    ):
        raise VaultRecoveryVisualHarnessError(
            "cancelled outcome consumed the adapter unexpectedly"
        )
    return RecoveryVisualHarnessReport(
        route=case.route,
        locale=case.locale,
        scale_percent=case.scale_percent,
        window_profile=case.window_profile,
        width=case.width,
        height=case.height,
        presentation_sha256=outcome.presentation_sha256,
        decision=outcome.decision,
        cancel_reason=outcome.cancel_reason,
        observations=observations,
    )


def recovery_visual_harness_report_json(
    report: RecoveryVisualHarnessReport,
) -> str:
    """Return canonical bounded JSON with no arbitrary notes or runtime data."""

    _validate_report(report)
    payload = {
        "cancel_reason": (
            None if report.cancel_reason is None else report.cancel_reason.value
        ),
        "decision": report.decision.value,
        "filesystem_mutation_performed": report.filesystem_mutation_performed,
        "focus_order": report.observations.focus_order.value,
        "format": report.format,
        "height": report.height,
        "inspection_only": report.inspection_only,
        "keyboard_only": report.observations.keyboard_only.value,
        "locale": report.locale.value,
        "main_gui_activated": report.main_gui_activated,
        "network_used": report.network_used,
        "operation_authorized": report.operation_authorized,
        "operation_performed": report.operation_performed,
        "platform_certification_claimed": report.platform_certification_claimed,
        "presentation_sha256": report.presentation_sha256.hex(),
        "real_stage_2_14_toplevel_requested": (
            report.real_stage_2_14_toplevel_requested
        ),
        "route": report.route.value,
        "scale_percent": report.scale_percent,
        "scroll_reachability": report.observations.scroll_reachability.value,
        "secrets_retained": report.secrets_retained,
        "synthetic_non_secret": report.synthetic_non_secret,
        "text_wrap": report.observations.text_wrap.value,
        "true_vault_input_used": report.true_vault_input_used,
        "version": report.version,
        "width": report.width,
        "window_profile": report.window_profile.value,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
