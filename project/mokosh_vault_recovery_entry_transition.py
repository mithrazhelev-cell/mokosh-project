"""Inactive one-shot transition after a bounded recovery-entry request.

Stage 2.21 revalidates only an exact Stage 2.19 non-secret request outcome and
records one further explicit caller decision.  It accepts and creates no
recovery source, secret, path, GUI object, callback, executor, or capability.
Proceed means only "request a future source-selection boundary"; it neither
selects nor prepares a source and it never performs an automatic transition.
"""

from __future__ import annotations

from dataclasses import dataclass as _dataclass
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_entry_request import (
    RECOVERY_ENTRY_REQUEST_FORMAT,
    RECOVERY_ENTRY_REQUEST_SEQUENCE,
    RECOVERY_ENTRY_REQUEST_VERSION,
    RecoveryEntryRequestDecision,
    RecoveryEntryRequestState,
    VaultRecoveryEntryRequestOutcome,
)
from mokosh_vault_recovery_locale import RecoveryLocalizationLocale


RECOVERY_ENTRY_TRANSITION_FORMAT = "MOKOSH_VAULT_RECOVERY_ENTRY_TRANSITION"
RECOVERY_ENTRY_TRANSITION_VERSION = 1
RECOVERY_ENTRY_TRANSITION_SEQUENCE = 1


class VaultRecoveryEntryTransitionError(ValueError):
    """Base class for strict Stage 2.21 transition failures."""


class VaultRecoveryEntryTransitionSourceError(VaultRecoveryEntryTransitionError):
    """The exact Stage 2.19 outcome source is invalid."""


class VaultRecoveryEntryTransitionDecisionError(VaultRecoveryEntryTransitionError):
    """The transition decision type or route is invalid."""


class VaultRecoveryEntryTransitionReplayError(VaultRecoveryEntryTransitionError):
    """A prepared transition was already consumed or cannot be copied."""


class VaultRecoveryEntryTransitionFormatError(VaultRecoveryEntryTransitionError):
    """A bounded transition outcome violates the frozen schema."""


class RecoveryEntryTransitionDecision(str, Enum):
    """Exact intent; neither member grants source or operation access."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    PROCEED_TO_FUTURE_SOURCE_SELECTION = "proceed_to_future_source_selection"


class RecoveryEntryTransitionState(str, Enum):
    """One-shot process-local transition lifecycle."""

    AWAITING_TRANSITION_DECISION = "awaiting_transition_decision"
    COMPLETED = "completed"


_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryEntryTransitionOutcome:
    """Bounded non-secret receipt with every authority/capability flag false."""

    locale: RecoveryLocalizationLocale
    entry_decision: RecoveryEntryRequestDecision
    transition_decision: RecoveryEntryTransitionDecision
    state: RecoveryEntryTransitionState
    future_source_selection_requested: bool
    preserved_and_stopped: bool
    entry_request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    transition_sequence: int = RECOVERY_ENTRY_TRANSITION_SEQUENCE
    exact_entry_outcome_validated: bool = True
    exact_transition_decision_validated: bool = True
    one_shot: bool = True
    non_secret: bool = True
    source_access_authorized: bool = False
    source_selection_performed: bool = False
    source_preparation_performed: bool = False
    review_session_prepared: bool = False
    main_gui_binding_prepared: bool = False
    review_displayed: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    filesystem_access_performed: bool = False
    network_used: bool = False
    automatic_transition: bool = False
    format: str = RECOVERY_ENTRY_TRANSITION_FORMAT
    version: int = RECOVERY_ENTRY_TRANSITION_VERSION

    def __post_init__(self) -> None:
        _validate_transition_outcome(self)


class PreparedVaultRecoveryEntryTransition:
    """Process-local transition retaining only locale and bounded entry intent."""

    __slots__ = ("_locale", "_entry_decision", "_state", "_outcome", "_lock")

    def __init__(
        self,
        locale: RecoveryLocalizationLocale,
        entry_decision: RecoveryEntryRequestDecision,
    ) -> None:
        if type(locale) is not RecoveryLocalizationLocale or locale not in _SUPPORTED_LOCALES:
            raise VaultRecoveryEntryTransitionSourceError(
                "recovery entry transition locale is invalid"
            )
        if type(entry_decision) is not RecoveryEntryRequestDecision:
            raise VaultRecoveryEntryTransitionSourceError(
                "recovery entry transition source decision is invalid"
            )
        self._locale = locale
        self._entry_decision = entry_decision
        self._state = RecoveryEntryTransitionState.AWAITING_TRANSITION_DECISION
        self._outcome: VaultRecoveryEntryTransitionOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def entry_decision(self) -> RecoveryEntryRequestDecision:
        return self._entry_decision

    @property
    def current_state(self) -> RecoveryEntryTransitionState:
        return self._state

    @property
    def outcome(self) -> VaultRecoveryEntryTransitionOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoveryEntryTransitionDecision,
    ) -> VaultRecoveryEntryTransitionOutcome:
        """Record one explicit no-capability transition decision."""

        with self._lock:
            if self._state is not RecoveryEntryTransitionState.AWAITING_TRANSITION_DECISION:
                raise VaultRecoveryEntryTransitionReplayError(
                    "recovery entry transition was already consumed"
                )
            if type(decision) is not RecoveryEntryTransitionDecision:
                raise VaultRecoveryEntryTransitionDecisionError(
                    "recovery entry transition decision type is invalid"
                )
            requested = (
                self._entry_decision
                is RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
            )
            proceeding = (
                decision
                is RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
            )
            if proceeding and not requested:
                raise VaultRecoveryEntryTransitionDecisionError(
                    "preserved entry request cannot proceed to future source selection"
                )
            outcome = VaultRecoveryEntryTransitionOutcome(
                locale=self._locale,
                entry_decision=self._entry_decision,
                transition_decision=decision,
                state=RecoveryEntryTransitionState.COMPLETED,
                future_source_selection_requested=proceeding,
                preserved_and_stopped=not proceeding,
            )
            self._outcome = outcome
            self._state = RecoveryEntryTransitionState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryEntryTransition("
            f"locale={self._locale.value!r}, "
            f"entry_decision={self._entry_decision.value!r}, "
            f"state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryEntryTransitionReplayError(
            "prepared recovery entry transition cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoveryEntryTransitionReplayError(
            "prepared recovery entry transition cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryEntryTransitionReplayError(
            "prepared recovery entry transition cannot be serialized"
        )


def _validate_entry_request_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoveryEntryRequestOutcome:
        raise VaultRecoveryEntryTransitionSourceError(
            "recovery entry request outcome type is invalid"
        )
    requested = value.decision is RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.decision) is not RecoveryEntryRequestDecision
        or value.state is not RecoveryEntryRequestState.COMPLETED
        or type(value.review_requested) is not bool
        or value.review_requested is not requested
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is requested
        or type(value.request_sequence) is not int
        or value.request_sequence != RECOVERY_ENTRY_REQUEST_SEQUENCE
        or value.exact_locale_validated is not True
        or value.exact_decision_validated is not True
        or value.one_shot is not True
        or value.non_secret is not True
        or value.source_access_authorized is not False
        or value.source_selection_performed is not False
        or value.source_preparation_performed is not False
        or value.review_session_prepared is not False
        or value.main_gui_binding_prepared is not False
        or value.review_displayed is not False
        or value.normal_startup_activated is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.filesystem_access_performed is not False
        or value.network_used is not False
        or value.automatic_transition is not False
        or type(value.format) is not str
        or value.format != RECOVERY_ENTRY_REQUEST_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_ENTRY_REQUEST_VERSION
    ):
        raise VaultRecoveryEntryTransitionSourceError(
            "recovery entry request outcome is invalid"
        )


def _validate_transition_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoveryEntryTransitionOutcome:
        raise VaultRecoveryEntryTransitionFormatError(
            "recovery entry transition outcome type is invalid"
        )
    proceeding = (
        value.transition_decision
        is RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )
    requested = (
        value.entry_decision is RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.entry_decision) is not RecoveryEntryRequestDecision
        or type(value.transition_decision) is not RecoveryEntryTransitionDecision
        or value.state is not RecoveryEntryTransitionState.COMPLETED
        or proceeding and not requested
        or type(value.future_source_selection_requested) is not bool
        or value.future_source_selection_requested is not proceeding
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is proceeding
        or type(value.entry_request_sequence) is not int
        or value.entry_request_sequence != RECOVERY_ENTRY_REQUEST_SEQUENCE
        or type(value.transition_sequence) is not int
        or value.transition_sequence != RECOVERY_ENTRY_TRANSITION_SEQUENCE
        or value.exact_entry_outcome_validated is not True
        or value.exact_transition_decision_validated is not True
        or value.one_shot is not True
        or value.non_secret is not True
        or value.source_access_authorized is not False
        or value.source_selection_performed is not False
        or value.source_preparation_performed is not False
        or value.review_session_prepared is not False
        or value.main_gui_binding_prepared is not False
        or value.review_displayed is not False
        or value.operation_authorized is not False
        or value.operation_performed is not False
        or value.filesystem_access_performed is not False
        or value.network_used is not False
        or value.automatic_transition is not False
        or type(value.format) is not str
        or value.format != RECOVERY_ENTRY_TRANSITION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_ENTRY_TRANSITION_VERSION
    ):
        raise VaultRecoveryEntryTransitionFormatError(
            "recovery entry transition outcome is invalid"
        )


def prepare_recovery_entry_transition(
    entry_outcome: VaultRecoveryEntryRequestOutcome,
) -> PreparedVaultRecoveryEntryTransition:
    """Prepare an inactive no-capability transition from one exact outcome."""

    try:
        _validate_entry_request_outcome(entry_outcome)
    except VaultRecoveryEntryTransitionSourceError:
        raise
    except Exception:
        raise VaultRecoveryEntryTransitionSourceError(
            "recovery entry request outcome is invalid"
        ) from None
    return PreparedVaultRecoveryEntryTransition(
        entry_outcome.locale,
        entry_outcome.decision,
    )
