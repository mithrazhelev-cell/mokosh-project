"""Bounded synthetic evidence for the Stage 2.18 main-GUI review event.

The fixtures are fixed, non-secret, in-memory Stage 2.9 workflow states.  They
exist only to exercise the conditional Stage 2.18 widget through the exact
Stage 2.16 controller and Stage 2.17 binding.  No runtime source, Vault,
password, keyring, callback, executor, or recovery operation is accepted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from typing import Any

from mokosh_vault_recovery_localization import RecoveryLocalizationLocale
from mokosh_vault_recovery_main_gui_bridge import (
    PreparedMainGUIRecoveryReviewBinding,
    RecoveryMainGUIBridgeState,
    prepare_main_gui_recovery_review_binding,
)
from mokosh_vault_recovery_reconciliation import (
    RecoveryPublishClassification,
    RecoveryReconciliationAction,
)
from mokosh_vault_recovery_review_controller import (
    prepare_recovery_review_session,
)
from mokosh_vault_recovery_review_window import (
    RecoveryReviewWindowCancelReason,
    RecoveryReviewWindowDecision,
    VaultRecoveryReviewWindowOutcome,
)
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowGate,
    RecoveryWorkflowState,
    VaultRecoveryWorkflowEvidence,
    VaultRecoveryWorkflowState,
)


MAIN_GUI_VISUAL_HARNESS_FORMAT = "MOKOSH_MAIN_GUI_RECOVERY_REVIEW_REPORT"
MAIN_GUI_VISUAL_HARNESS_VERSION = 2
MAIN_GUI_VISUAL_HARNESS_ROUTES = ("absent", "exact", "conflict", "preserve")
MAIN_GUI_VISUAL_HARNESS_LOCALES = ("bg-BG", "en-GB")

_SYNTHETIC_DOMAIN = b"MOKOSH\x00STAGE-2.18\x00MAIN-GUI-SYNTHETIC-V1\x00"


class VaultRecoveryMainGUIVisualHarnessError(ValueError):
    """A Stage 2.18 fixture, observation, or report is invalid."""


class MainGUIVisualHarnessRoute(str, Enum):
    ABSENT = "absent"
    EXACT = "exact"
    CONFLICT = "conflict"
    PRESERVE = "preserve"


class MainGUIVisualHarnessObservation(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not_checked"


_ROUTE_COMPONENTS = {
    MainGUIVisualHarnessRoute.ABSENT: (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        (RecoveryWorkflowGate.STAGE_2_6_NEW_CANDIDATE_DECISION,),
        False,
        True,
        None,
    ),
    MainGUIVisualHarnessRoute.EXACT: (
        RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY,
        RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        (
            RecoveryWorkflowGate.NORMAL_VAULT_UNLOCK,
            RecoveryWorkflowGate.STAGE_2_5_NEW_RECOVERY_SETUP_DECISION,
        ),
        False,
        True,
        b"T" * 32,
    ),
    MainGUIVisualHarnessRoute.CONFLICT: (
        RecoveryPublishClassification.CONFLICT,
        RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW,
        RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        (RecoveryWorkflowGate.MANUAL_REVIEW_ONLY,),
        True,
        False,
        None,
    ),
    MainGUIVisualHarnessRoute.PRESERVE: (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        RecoveryWorkflowState.PRESERVED_STOP,
        (),
        True,
        False,
        None,
    ),
}


@_dataclass(frozen=True, slots=True)
class SyntheticMainGUIRecoveryReviewCase:
    route: MainGUIVisualHarnessRoute
    locale: RecoveryLocalizationLocale
    binding: PreparedMainGUIRecoveryReviewBinding = _field(repr=False)
    synthetic_non_secret: bool = True
    true_vault_input_used: bool = False
    operation_capability_included: bool = False

    def __post_init__(self) -> None:
        _validate_case(self, require_fresh=True)


@_dataclass(frozen=True, slots=True)
class MainGUIRecoveryReviewObservations:
    prepared_banner_and_button_visible: MainGUIVisualHarnessObservation
    unrelated_controls_disabled: MainGUIVisualHarnessObservation
    review_opened_in_front: MainGUIVisualHarnessObservation
    one_shot_button_disabled: MainGUIVisualHarnessObservation

    def __post_init__(self) -> None:
        _validate_observations(self)


@_dataclass(frozen=True, slots=True)
class MainGUIRecoveryReviewReport:
    route: MainGUIVisualHarnessRoute
    locale: RecoveryLocalizationLocale
    presentation_sha256: bytes = _field(repr=False)
    decision: RecoveryReviewWindowDecision
    cancel_reason: RecoveryReviewWindowCancelReason | None
    observations: MainGUIRecoveryReviewObservations
    synthetic_non_secret: bool = True
    exact_stage_2_17_binding_used: bool = True
    conditional_main_gui_activated: bool = True
    normal_startup_activated: bool = False
    true_vault_input_used: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    runtime_directory_preparation_performed: bool = True
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    platform_certification_claimed: bool = False
    format: str = MAIN_GUI_VISUAL_HARNESS_FORMAT
    version: int = MAIN_GUI_VISUAL_HARNESS_VERSION

    def __post_init__(self) -> None:
        _validate_report(self)


def _exact_enum(enum_type: type[Enum], value: Any, field_name: str) -> Enum:
    if type(value) is not str:
        raise VaultRecoveryMainGUIVisualHarnessError(
            f"{field_name} must be exact text"
        )
    try:
        return enum_type(value)
    except ValueError as exc:
        raise VaultRecoveryMainGUIVisualHarnessError(
            f"{field_name} is outside the fixed allowlist"
        ) from exc


def _synthetic_state(route: MainGUIVisualHarnessRoute) -> VaultRecoveryWorkflowState:
    components = _ROUTE_COMPONENTS[route]
    digest = hashlib.sha256(_SYNTHETIC_DOMAIN + route.value.encode("ascii")).digest()
    evidence = VaultRecoveryWorkflowEvidence(
        reconciliation_result_sha256=digest,
        classification=components[0],
        recommended_action=components[1],
        recovery_id=b"R" * 16,
        vault_id=b"V" * 16,
        source_revision=1,
        target_revision=2,
        source_vault_sha256=b"S" * 32,
        record_sha256=b"D" * 32,
        keyring_sha256=b"K" * 32,
        target_vault_sha256=components[7],
        storage_complete=True,
        stable_observation=True,
    )
    return VaultRecoveryWorkflowState(
        evidence=evidence,
        decision=components[2],
        state=components[3],
        required_gates=components[4],
        terminal_stop=components[5],
        downstream_reverification_required=components[6],
    )


def _validate_case(
    value: Any,
    *,
    require_fresh: bool,
) -> SyntheticMainGUIRecoveryReviewCase:
    if (
        type(value) is not SyntheticMainGUIRecoveryReviewCase
        or type(value.route) is not MainGUIVisualHarnessRoute
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.binding) is not PreparedMainGUIRecoveryReviewBinding
        or value.binding.locale is not value.locale
        or value.synthetic_non_secret is not True
        or value.true_vault_input_used is not False
        or value.operation_capability_included is not False
    ):
        raise VaultRecoveryMainGUIVisualHarnessError("synthetic case is invalid")
    expected_states = (
        (RecoveryMainGUIBridgeState.READY,)
        if require_fresh
        else (
            RecoveryMainGUIBridgeState.COMPLETED,
            RecoveryMainGUIBridgeState.FAILED,
        )
    )
    if value.binding.current_state not in expected_states:
        raise VaultRecoveryMainGUIVisualHarnessError(
            "synthetic binding lifecycle is invalid"
        )
    return value


def _validate_observations(
    value: Any,
) -> MainGUIRecoveryReviewObservations:
    if type(value) is not MainGUIRecoveryReviewObservations or any(
        type(getattr(value, name)) is not MainGUIVisualHarnessObservation
        for name in (
            "prepared_banner_and_button_visible",
            "unrelated_controls_disabled",
            "review_opened_in_front",
            "one_shot_button_disabled",
        )
    ):
        raise VaultRecoveryMainGUIVisualHarnessError("observations are invalid")
    return value


def _validate_report(value: Any) -> MainGUIRecoveryReviewReport:
    if type(value) is not MainGUIRecoveryReviewReport:
        raise VaultRecoveryMainGUIVisualHarnessError("report type is invalid")
    _validate_observations(value.observations)
    if (
        value.format != MAIN_GUI_VISUAL_HARNESS_FORMAT
        or type(value.version) is not int
        or value.version != MAIN_GUI_VISUAL_HARNESS_VERSION
        or type(value.route) is not MainGUIVisualHarnessRoute
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256) != 32
        or type(value.decision) is not RecoveryReviewWindowDecision
    ):
        raise VaultRecoveryMainGUIVisualHarnessError("report schema is invalid")
    if value.decision is RecoveryReviewWindowDecision.ACKNOWLEDGED:
        if value.cancel_reason is not None:
            raise VaultRecoveryMainGUIVisualHarnessError(
                "acknowledged report has a cancel reason"
            )
    elif type(value.cancel_reason) is not RecoveryReviewWindowCancelReason:
        raise VaultRecoveryMainGUIVisualHarnessError(
            "cancelled report lacks an exact reason"
        )
    true_fields = (
        "synthetic_non_secret",
        "exact_stage_2_17_binding_used",
        "conditional_main_gui_activated",
        "runtime_directory_preparation_performed",
    )
    false_fields = (
        "normal_startup_activated",
        "true_vault_input_used",
        "operation_performed",
        "operation_authorized",
        "recovery_source_filesystem_access_performed",
        "recovery_source_filesystem_mutation_performed",
        "network_used",
        "platform_certification_claimed",
    )
    if any(getattr(value, name) is not True for name in true_fields) or any(
        getattr(value, name) is not False for name in false_fields
    ):
        raise VaultRecoveryMainGUIVisualHarnessError(
            "report contains a false activation or authority claim"
        )
    return value


def prepare_synthetic_main_gui_recovery_review_case(
    route_id: str,
    locale_id: str,
) -> SyntheticMainGUIRecoveryReviewCase:
    """Prepare one fixed in-memory route through Stages 2.16 and 2.17."""

    route = _exact_enum(MainGUIVisualHarnessRoute, route_id, "route_id")
    locale = _exact_enum(RecoveryLocalizationLocale, locale_id, "locale_id")
    session = prepare_recovery_review_session(_synthetic_state(route), locale.value)
    binding = prepare_main_gui_recovery_review_binding(session, locale.value)
    return SyntheticMainGUIRecoveryReviewCase(route, locale, binding)


def build_main_gui_recovery_review_report(
    case: SyntheticMainGUIRecoveryReviewCase,
    outcome: VaultRecoveryReviewWindowOutcome,
    observations: MainGUIRecoveryReviewObservations,
) -> MainGUIRecoveryReviewReport:
    """Bind exact human observations to the completed conditional event."""

    _validate_case(case, require_fresh=False)
    _validate_observations(observations)
    if (
        case.binding.current_state is not RecoveryMainGUIBridgeState.COMPLETED
        or type(outcome) is not VaultRecoveryReviewWindowOutcome
        or case.binding.outcome is not outcome
        or outcome.locale is not case.locale
        or outcome.operation_performed is not False
        or outcome.operation_authorized is not False
        or outcome.secrets_retained is not False
    ):
        raise VaultRecoveryMainGUIVisualHarnessError(
            "case and completed bounded outcome differ"
        )
    return MainGUIRecoveryReviewReport(
        route=case.route,
        locale=case.locale,
        presentation_sha256=outcome.presentation_sha256,
        decision=outcome.decision,
        cancel_reason=outcome.cancel_reason,
        observations=observations,
    )


def main_gui_recovery_review_report_json(
    report: MainGUIRecoveryReviewReport,
) -> str:
    """Return canonical bounded JSON without paths, secrets, or notes."""

    _validate_report(report)
    return json.dumps(
        {
            "conditional_main_gui_activated": report.conditional_main_gui_activated,
            "decision": report.decision.value,
            "exact_stage_2_17_binding_used": report.exact_stage_2_17_binding_used,
            "format": report.format,
            "locale": report.locale.value,
            "network_used": report.network_used,
            "normal_startup_activated": report.normal_startup_activated,
            "observations": {
                "one_shot_button_disabled": (
                    report.observations.one_shot_button_disabled.value
                ),
                "prepared_banner_and_button_visible": (
                    report.observations.prepared_banner_and_button_visible.value
                ),
                "review_opened_in_front": (
                    report.observations.review_opened_in_front.value
                ),
                "unrelated_controls_disabled": (
                    report.observations.unrelated_controls_disabled.value
                ),
            },
            "operation_authorized": report.operation_authorized,
            "operation_performed": report.operation_performed,
            "platform_certification_claimed": report.platform_certification_claimed,
            "presentation_sha256": report.presentation_sha256.hex(),
            "recovery_source_filesystem_access_performed": (
                report.recovery_source_filesystem_access_performed
            ),
            "recovery_source_filesystem_mutation_performed": (
                report.recovery_source_filesystem_mutation_performed
            ),
            "route": report.route.value,
            "runtime_directory_preparation_performed": (
                report.runtime_directory_preparation_performed
            ),
            "synthetic_non_secret": report.synthetic_non_secret,
            "terminal_reason": (
                None if report.cancel_reason is None else report.cancel_reason.value
            ),
            "true_vault_input_used": report.true_vault_input_used,
            "version": report.version,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
