"""One-shot request for a future secure recovery-source inspection.

Stage 2.29 consumes only an exact positive Stage 2.27 source-selection outcome
and records either a request for a later secure inspection or an exact stop
decision.  The selected path remains untrusted process-local sensitive
metadata.  This module never opens, reads, resolves, identifies, authorizes, or
prepares the source and provides no recovery or operation capability.
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
    VaultRecoverySourceSelectionOutcome,
    _validate_selected_path,
    _validate_source_selection_outcome,
)


RECOVERY_SOURCE_INSPECTION_REQUEST_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_REQUEST"
)
RECOVERY_SOURCE_INSPECTION_REQUEST_VERSION = 1
RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE = 1


class VaultRecoverySourceInspectionRequestError(ValueError):
    """Base class for strict Stage 2.29 inspection-request failures."""


class VaultRecoverySourceInspectionRequestSourceError(
    VaultRecoverySourceInspectionRequestError
):
    """The exact Stage 2.27 source-selection outcome is invalid."""


class VaultRecoverySourceInspectionRequestDecisionError(
    VaultRecoverySourceInspectionRequestError
):
    """The exact Stage 2.29 decision is invalid."""


class VaultRecoverySourceInspectionRequestReplayError(
    VaultRecoverySourceInspectionRequestError
):
    """A prepared request was consumed or cannot be copied."""


class VaultRecoverySourceInspectionRequestFormatError(
    VaultRecoverySourceInspectionRequestError
):
    """A bounded Stage 2.29 outcome violates the frozen schema."""


class RecoverySourceInspectionRequestDecision(str, Enum):
    """Exact intent choice; neither member grants source access."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    REQUEST_FUTURE_SECURE_SOURCE_INSPECTION = (
        "request_future_secure_source_inspection"
    )


class RecoverySourceInspectionRequestState(str, Enum):
    """One-shot process-local inspection-request lifecycle."""

    AWAITING_INSPECTION_DECISION = "awaiting_inspection_decision"
    COMPLETED = "completed"


_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionRequestOutcome:
    """Bounded inspection intent carrying no access or operation authority."""

    locale: RecoveryLocalizationLocale
    entry_decision: RecoveryEntryRequestDecision
    transition_decision: RecoveryEntryTransitionDecision
    selection_decision: RecoverySourceSelectionDecision
    inspection_decision: RecoverySourceInspectionRequestDecision
    state: RecoverySourceInspectionRequestState
    selected_path: str | None = _field(repr=False)
    future_secure_source_inspection_requested: bool
    preserved_and_stopped: bool
    source_path_metadata_retained: bool
    contains_sensitive_path_metadata: bool
    entry_request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    transition_sequence: int = RECOVERY_ENTRY_TRANSITION_SEQUENCE
    selection_sequence: int = RECOVERY_SOURCE_SELECTION_SEQUENCE
    inspection_request_sequence: int = RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
    exact_source_selection_outcome_validated: bool = True
    exact_inspection_decision_validated: bool = True
    one_shot: bool = True
    process_local: bool = True
    source_opened: bool = False
    source_content_read: bool = False
    source_identity_validated: bool = False
    source_access_authorized: bool = False
    source_preparation_performed: bool = False
    recovery_secret_received: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    recovery_source_filesystem_access_performed: bool = False
    recovery_source_filesystem_mutation_performed: bool = False
    network_used: bool = False
    automatic_transition: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_REQUEST_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_REQUEST_VERSION

    def __post_init__(self) -> None:
        _validate_source_inspection_request_outcome(self)

    def __copy__(self) -> None:
        raise TypeError("recovery source inspection request outcome cannot be copied")

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise TypeError("recovery source inspection request outcome cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError(
            "recovery source inspection request outcome cannot be serialized"
        )


class PreparedVaultRecoverySourceInspectionRequest:
    """One-shot request retaining no original Stage 2.27 outcome."""

    __slots__ = (
        "_locale",
        "_entry_decision",
        "_transition_decision",
        "_selection_decision",
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
        selected_path: str,
    ) -> None:
        if type(locale) is not RecoveryLocalizationLocale or locale not in _SUPPORTED_LOCALES:
            raise VaultRecoverySourceInspectionRequestSourceError(
                "recovery source inspection request locale is invalid"
            )
        if entry_decision is not RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW:
            raise VaultRecoverySourceInspectionRequestSourceError(
                "recovery source inspection request entry route is invalid"
            )
        if (
            transition_decision
            is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        ):
            raise VaultRecoverySourceInspectionRequestSourceError(
                "recovery source inspection request transition route is invalid"
            )
        if (
            selection_decision
            is not RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
        ):
            raise VaultRecoverySourceInspectionRequestSourceError(
                "recovery source inspection request selection route is invalid"
            )
        try:
            exact_path = _validate_selected_path(selected_path)
        except Exception:
            raise VaultRecoverySourceInspectionRequestSourceError(
                "recovery source inspection request path is invalid"
            ) from None
        self._locale = locale
        self._entry_decision = entry_decision
        self._transition_decision = transition_decision
        self._selection_decision = selection_decision
        self._selected_path: str | None = exact_path
        self._state = (
            RecoverySourceInspectionRequestState.AWAITING_INSPECTION_DECISION
        )
        self._outcome: VaultRecoverySourceInspectionRequestOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def current_state(self) -> RecoverySourceInspectionRequestState:
        return self._state

    @property
    def retains_source_path_metadata(self) -> bool:
        return self._selected_path is not None

    @property
    def outcome(self) -> VaultRecoverySourceInspectionRequestOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoverySourceInspectionRequestDecision,
    ) -> VaultRecoverySourceInspectionRequestOutcome:
        """Record one bounded request or stop without accessing the source."""

        with self._lock:
            if (
                self._state
                is not RecoverySourceInspectionRequestState.AWAITING_INSPECTION_DECISION
            ):
                raise VaultRecoverySourceInspectionRequestReplayError(
                    "recovery source inspection request was already consumed"
                )
            if type(decision) is not RecoverySourceInspectionRequestDecision:
                raise VaultRecoverySourceInspectionRequestDecisionError(
                    "recovery source inspection request decision type is invalid"
                )
            requesting = (
                decision
                is RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
            )
            selected_path = self._selected_path
            if selected_path is None:
                raise VaultRecoverySourceInspectionRequestSourceError(
                    "recovery source inspection request lost path metadata"
                )
            outcome_path = selected_path if requesting else None
            outcome = VaultRecoverySourceInspectionRequestOutcome(
                locale=self._locale,
                entry_decision=self._entry_decision,
                transition_decision=self._transition_decision,
                selection_decision=self._selection_decision,
                inspection_decision=decision,
                state=RecoverySourceInspectionRequestState.COMPLETED,
                selected_path=outcome_path,
                future_secure_source_inspection_requested=requesting,
                preserved_and_stopped=not requesting,
                source_path_metadata_retained=requesting,
                contains_sensitive_path_metadata=requesting,
            )
            self._selected_path = None
            self._outcome = outcome
            self._state = RecoverySourceInspectionRequestState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionRequest("
            f"locale={self._locale.value!r}, state={self._state.value!r}, "
            f"retains_source_path_metadata={self.retains_source_path_metadata!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionRequestReplayError(
            "prepared recovery source inspection request cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionRequestReplayError(
            "prepared recovery source inspection request cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionRequestReplayError(
            "prepared recovery source inspection request cannot be serialized"
        )


def _validate_source_selection_source(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceSelectionOutcome:
        raise VaultRecoverySourceInspectionRequestSourceError(
            "recovery source selection outcome type is invalid"
        )
    try:
        _validate_source_selection_outcome(value)
    except Exception:
        raise VaultRecoverySourceInspectionRequestSourceError(
            "recovery source selection outcome is invalid"
        ) from None
    if (
        value.selection_decision
        is not RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
        or value.source_selected is not True
        or value.preserved_and_stopped is not False
        or value.source_path_metadata_received is not True
        or value.contains_sensitive_path_metadata is not True
    ):
        raise VaultRecoverySourceInspectionRequestSourceError(
            "preserved source selection cannot prepare an inspection request"
        )


def _validate_source_inspection_request_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionRequestOutcome:
        raise VaultRecoverySourceInspectionRequestFormatError(
            "recovery source inspection request outcome type is invalid"
        )
    requesting = (
        value.inspection_decision
        is RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
    )
    if requesting:
        try:
            exact_path = _validate_selected_path(value.selected_path)
        except Exception as exc:
            raise VaultRecoverySourceInspectionRequestFormatError(
                "recovery source inspection request outcome path is invalid"
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
        or type(value.inspection_decision)
        is not RecoverySourceInspectionRequestDecision
        or value.state is not RecoverySourceInspectionRequestState.COMPLETED
        or value.selected_path != exact_path
        or type(value.future_secure_source_inspection_requested) is not bool
        or value.future_secure_source_inspection_requested is not requesting
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
        or value.inspection_request_sequence
        != RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
        or value.exact_source_selection_outcome_validated is not True
        or value.exact_inspection_decision_validated is not True
        or value.one_shot is not True
        or value.process_local is not True
        or value.source_opened is not False
        or value.source_content_read is not False
        or value.source_identity_validated is not False
        or value.source_access_authorized is not False
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
        or value.format != RECOVERY_SOURCE_INSPECTION_REQUEST_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_REQUEST_VERSION
    ):
        raise VaultRecoverySourceInspectionRequestFormatError(
            "recovery source inspection request outcome is invalid"
        )


def prepare_recovery_source_inspection_request(
    selection_outcome: VaultRecoverySourceSelectionOutcome,
) -> PreparedVaultRecoverySourceInspectionRequest:
    """Prepare one inactive request from an exact positive Stage 2.27 outcome."""

    _validate_source_selection_source(selection_outcome)
    return PreparedVaultRecoverySourceInspectionRequest(
        selection_outcome.locale,
        selection_outcome.entry_decision,
        selection_outcome.transition_decision,
        selection_outcome.selection_decision,
        selection_outcome.selected_path,
    )
