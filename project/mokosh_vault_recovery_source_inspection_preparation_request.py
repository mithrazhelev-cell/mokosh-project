"""Inactive one-shot preparation request for future source inspection.

Stage 2.31 consumes only an exact positive Stage 2.29 inspection-request
outcome and records either a request for later secure inspection preparation or
an exact stop decision.  The selected path remains untrusted process-local
sensitive metadata.  This module never opens, reads, resolves, identifies,
authorizes, or prepares the source and provides no filesystem or operation
capability.  One-shot consumption is per prepared object; the caller-owned
Stage 2.29 outcome is neither globally consumed nor memory-zeroized here.
"""

from __future__ import annotations

from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_entry_request import (
    RECOVERY_ENTRY_REQUEST_SEQUENCE,
    RecoveryEntryRequestDecision,
)
from mokosh_vault_recovery_entry_transition import (
    RECOVERY_ENTRY_TRANSITION_SEQUENCE,
    RecoveryEntryTransitionDecision,
)
from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_selection import (
    RECOVERY_SOURCE_SELECTION_SEQUENCE,
    RecoverySourceSelectionDecision,
    _validate_selected_path,
)
from mokosh_vault_recovery_source_inspection_request import (
    RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE,
    RecoverySourceInspectionRequestDecision,
    VaultRecoverySourceInspectionRequestOutcome,
    _validate_source_inspection_request_outcome,
)


RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST"
)
RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_VERSION = 1
RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE = 1


class VaultRecoverySourceInspectionPreparationRequestError(ValueError):
    """Base class for strict Stage 2.31 preparation-request failures."""


class VaultRecoverySourceInspectionPreparationRequestSourceError(
    VaultRecoverySourceInspectionPreparationRequestError
):
    """The exact Stage 2.29 inspection-request outcome is invalid."""


class VaultRecoverySourceInspectionPreparationRequestDecisionError(
    VaultRecoverySourceInspectionPreparationRequestError
):
    """The exact Stage 2.31 decision is invalid."""


class VaultRecoverySourceInspectionPreparationRequestReplayError(
    VaultRecoverySourceInspectionPreparationRequestError
):
    """A prepared request was consumed or cannot be copied."""


class VaultRecoverySourceInspectionPreparationRequestFormatError(
    VaultRecoverySourceInspectionPreparationRequestError
):
    """A bounded Stage 2.31 outcome violates the frozen schema."""


class RecoverySourceInspectionPreparationRequestDecision(str, Enum):
    """Exact intent choice; neither member grants source access."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION = (
        "request_future_secure_source_inspection_preparation"
    )


class RecoverySourceInspectionPreparationRequestState(str, Enum):
    """One-shot process-local inspection-preparation-request lifecycle."""

    AWAITING_PREPARATION_DECISION = "awaiting_preparation_decision"
    COMPLETED = "completed"


_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionPreparationRequestOutcome:
    """Bounded preparation intent carrying no access or operation authority."""

    locale: RecoveryLocalizationLocale
    entry_decision: RecoveryEntryRequestDecision
    transition_decision: RecoveryEntryTransitionDecision
    selection_decision: RecoverySourceSelectionDecision
    inspection_decision: RecoverySourceInspectionRequestDecision
    preparation_decision: RecoverySourceInspectionPreparationRequestDecision
    state: RecoverySourceInspectionPreparationRequestState
    selected_path: str | None = _field(repr=False)
    future_secure_source_inspection_preparation_requested: bool
    preserved_and_stopped: bool
    source_path_metadata_retained: bool
    contains_sensitive_path_metadata: bool
    entry_request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    transition_sequence: int = RECOVERY_ENTRY_TRANSITION_SEQUENCE
    selection_sequence: int = RECOVERY_SOURCE_SELECTION_SEQUENCE
    inspection_request_sequence: int = RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
    preparation_request_sequence: int = RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE
    exact_inspection_request_outcome_validated: bool = True
    exact_preparation_decision_validated: bool = True
    one_shot: bool = True
    process_local: bool = True
    global_source_outcome_consumption_enforced: bool = False
    memory_zeroization_proven: bool = False
    source_opened: bool = False
    source_content_read: bool = False
    source_identity_validated: bool = False
    source_access_authorized: bool = False
    filesystem_capability_issued: bool = False
    source_preparation_performed: bool = False
    recovery_secret_received: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    automatic_transition: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_VERSION

    def __post_init__(self) -> None:
        _validate_source_inspection_preparation_request_outcome(self)

    def __copy__(self) -> None:
        raise TypeError("recovery source inspection preparation request outcome cannot be copied")

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise TypeError("recovery source inspection preparation request outcome cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError(
            "recovery source inspection preparation request outcome cannot be serialized"
        )


class PreparedVaultRecoverySourceInspectionPreparationRequest:
    """One-shot request retaining no original Stage 2.29 outcome."""

    __slots__ = (
        "_locale",
        "_entry_decision",
        "_transition_decision",
        "_selection_decision",
        "_inspection_decision",
        "_selected_path",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        locale: RecoveryLocalizationLocale,
        entry_decision: RecoveryEntryRequestDecision,
        transition_decision: RecoveryEntryTransitionDecision,
        selection_decision: RecoverySourceSelectionDecision,
        inspection_decision: RecoverySourceInspectionRequestDecision,
        selected_path: str,
    ) -> None:
        if type(locale) is not RecoveryLocalizationLocale or locale not in _SUPPORTED_LOCALES:
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request locale is invalid"
            )
        if entry_decision is not RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW:
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request entry route is invalid"
            )
        if (
            transition_decision
            is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        ):
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request transition route is invalid"
            )
        if (
            selection_decision
            is not RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
        ):
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request selection route is invalid"
            )
        if (
            inspection_decision
            is not RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        ):
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request inspection route is invalid"
            )
        try:
            exact_path = _validate_selected_path(selected_path)
        except Exception:
            raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                "recovery source inspection preparation request path is invalid"
            ) from None
        self._locale = locale
        self._entry_decision = entry_decision
        self._transition_decision = transition_decision
        self._selection_decision = selection_decision
        self._inspection_decision = inspection_decision
        self._selected_path: str | None = exact_path
        self._state = (
            RecoverySourceInspectionPreparationRequestState.AWAITING_PREPARATION_DECISION
        )
        self._outcome: VaultRecoverySourceInspectionPreparationRequestOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def current_state(self) -> RecoverySourceInspectionPreparationRequestState:
        return self._state

    @property
    def retains_source_path_metadata(self) -> bool:
        return self._selected_path is not None

    @property
    def outcome(self) -> VaultRecoverySourceInspectionPreparationRequestOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoverySourceInspectionPreparationRequestDecision,
    ) -> VaultRecoverySourceInspectionPreparationRequestOutcome:
        """Record one bounded request or stop without accessing the source."""

        with self._lock:
            if (
                self._state
                is not RecoverySourceInspectionPreparationRequestState.AWAITING_PREPARATION_DECISION
            ):
                raise VaultRecoverySourceInspectionPreparationRequestReplayError(
                    "recovery source inspection preparation request was already consumed"
                )
            if type(decision) is not RecoverySourceInspectionPreparationRequestDecision:
                raise VaultRecoverySourceInspectionPreparationRequestDecisionError(
                    "recovery source inspection preparation request decision type is invalid"
                )
            requesting = (
                decision
                is RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
            )
            selected_path = self._selected_path
            if selected_path is None:
                raise VaultRecoverySourceInspectionPreparationRequestSourceError(
                    "recovery source inspection preparation request lost path metadata"
                )
            outcome_path = selected_path if requesting else None
            outcome = VaultRecoverySourceInspectionPreparationRequestOutcome(
                locale=self._locale,
                entry_decision=self._entry_decision,
                transition_decision=self._transition_decision,
                selection_decision=self._selection_decision,
                inspection_decision=self._inspection_decision,
                preparation_decision=decision,
                state=RecoverySourceInspectionPreparationRequestState.COMPLETED,
                selected_path=outcome_path,
                future_secure_source_inspection_preparation_requested=requesting,
                preserved_and_stopped=not requesting,
                source_path_metadata_retained=requesting,
                contains_sensitive_path_metadata=requesting,
            )
            self._selected_path = None
            self._outcome = outcome
            self._state = RecoverySourceInspectionPreparationRequestState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionPreparationRequest("
            f"locale={self._locale.value!r}, state={self._state.value!r}, "
            f"retains_source_path_metadata={self.retains_source_path_metadata!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionPreparationRequestReplayError(
            "prepared recovery source inspection preparation request cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionPreparationRequestReplayError(
            "prepared recovery source inspection preparation request cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionPreparationRequestReplayError(
            "prepared recovery source inspection preparation request cannot be serialized"
        )


def _validate_source_inspection_request_source(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionRequestOutcome:
        raise VaultRecoverySourceInspectionPreparationRequestSourceError(
            "recovery source inspection request outcome type is invalid"
        )
    try:
        _validate_source_inspection_request_outcome(value)
    except Exception:
        raise VaultRecoverySourceInspectionPreparationRequestSourceError(
            "recovery source inspection request outcome is invalid"
        ) from None
    if (
        value.inspection_decision
        is not RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        or value.future_secure_source_inspection_requested is not True
        or value.preserved_and_stopped is not False
        or value.source_path_metadata_retained is not True
        or value.contains_sensitive_path_metadata is not True
    ):
        raise VaultRecoverySourceInspectionPreparationRequestSourceError(
            "preserved inspection request cannot prepare a preparation request"
        )


def _validate_source_inspection_preparation_request_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionPreparationRequestOutcome:
        raise VaultRecoverySourceInspectionPreparationRequestFormatError(
            "recovery source inspection preparation request outcome type is invalid"
        )
    requesting = (
        value.preparation_decision
        is RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
    )
    if requesting:
        try:
            exact_path = _validate_selected_path(value.selected_path)
        except Exception as exc:
            raise VaultRecoverySourceInspectionPreparationRequestFormatError(
                "recovery source inspection preparation request outcome path is invalid"
            ) from exc
    else:
        exact_path = None
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or value.entry_decision is not RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        or value.transition_decision
        is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        or value.selection_decision
        is not RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
        or value.inspection_decision
        is not RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        or type(value.preparation_decision)
        is not RecoverySourceInspectionPreparationRequestDecision
        or value.state is not RecoverySourceInspectionPreparationRequestState.COMPLETED
        or value.selected_path != exact_path
        or type(value.future_secure_source_inspection_preparation_requested) is not bool
        or value.future_secure_source_inspection_preparation_requested is not requesting
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is requesting
        or type(value.source_path_metadata_retained) is not bool
        or value.source_path_metadata_retained is not requesting
        or type(value.contains_sensitive_path_metadata) is not bool
        or value.contains_sensitive_path_metadata is not requesting
        or type(value.entry_request_sequence) is not int
        or value.entry_request_sequence != RECOVERY_ENTRY_REQUEST_SEQUENCE
        or type(value.transition_sequence) is not int
        or value.transition_sequence != RECOVERY_ENTRY_TRANSITION_SEQUENCE
        or type(value.selection_sequence) is not int
        or value.selection_sequence != RECOVERY_SOURCE_SELECTION_SEQUENCE
        or type(value.inspection_request_sequence) is not int
        or value.inspection_request_sequence != RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
        or type(value.preparation_request_sequence) is not int
        or value.preparation_request_sequence
        != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE
        or value.exact_inspection_request_outcome_validated is not True
        or value.exact_preparation_decision_validated is not True
        or value.one_shot is not True
        or value.process_local is not True
        or value.global_source_outcome_consumption_enforced is not False
        or value.memory_zeroization_proven is not False
        or value.source_opened is not False
        or value.source_content_read is not False
        or value.source_identity_validated is not False
        or value.source_access_authorized is not False
        or value.filesystem_capability_issued is not False
        or value.source_preparation_performed is not False
        or value.recovery_secret_received is not False
        or value.review_session_prepared is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.recovery_source_filesystem_access_performed is not False
        or value.recovery_source_filesystem_mutation_performed is not False
        or value.network_used is not False
        or value.automatic_transition is not False
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_VERSION
    ):
        raise VaultRecoverySourceInspectionPreparationRequestFormatError(
            "recovery source inspection preparation request outcome is invalid"
        )


def prepare_recovery_source_inspection_preparation_request(
    inspection_request_outcome: VaultRecoverySourceInspectionRequestOutcome,
) -> PreparedVaultRecoverySourceInspectionPreparationRequest:
    """Prepare one inactive request from an exact positive Stage 2.29 outcome."""

    _validate_source_inspection_request_source(inspection_request_outcome)
    return PreparedVaultRecoverySourceInspectionPreparationRequest(
        inspection_request_outcome.locale,
        inspection_request_outcome.entry_decision,
        inspection_request_outcome.transition_decision,
        inspection_request_outcome.selection_decision,
        inspection_request_outcome.inspection_decision,
        inspection_request_outcome.selected_path,
    )
