"""Inactive one-shot request boundary for a future recovery entry flow.

Stage 2.19 records only an exact, locale-bound caller decision to request a
future recovery review or to stop.  It accepts no recovery source, secret,
path, callback, executor, GUI object, or operation capability.  A request is
not source-access authority and cannot prepare or display a recovery review.
"""

from __future__ import annotations

from dataclasses import dataclass as _dataclass
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale


RECOVERY_ENTRY_REQUEST_FORMAT = "MOKOSH_VAULT_RECOVERY_ENTRY_REQUEST"
RECOVERY_ENTRY_REQUEST_VERSION = 1
RECOVERY_ENTRY_REQUEST_SEQUENCE = 1


class VaultRecoveryEntryRequestError(ValueError):
    """Base class for strict Stage 2.19 request failures."""


class VaultRecoveryEntryRequestSourceError(VaultRecoveryEntryRequestError):
    """The request locale or decision source is invalid."""


class VaultRecoveryEntryRequestReplayError(VaultRecoveryEntryRequestError):
    """A prepared request was already consumed or cannot be copied."""


class VaultRecoveryEntryRequestFormatError(VaultRecoveryEntryRequestError):
    """A bounded request outcome violates the frozen schema."""


class RecoveryEntryRequestDecision(str, Enum):
    """Exact caller intent; neither member grants source or operation access."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    REQUEST_RECOVERY_REVIEW = "request_recovery_review"


class RecoveryEntryRequestState(str, Enum):
    """One-shot process-local request lifecycle."""

    AWAITING_DECISION = "awaiting_decision"
    COMPLETED = "completed"


_LOCALE_BY_ID = {
    "bg-BG": RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    "en-GB": RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
}


@_dataclass(frozen=True, slots=True)
class VaultRecoveryEntryRequestOutcome:
    """Bounded non-secret intent evidence with every authority flag false."""

    locale: RecoveryLocalizationLocale
    decision: RecoveryEntryRequestDecision
    state: RecoveryEntryRequestState
    review_requested: bool
    preserved_and_stopped: bool
    request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    exact_locale_validated: bool = True
    exact_decision_validated: bool = True
    one_shot: bool = True
    non_secret: bool = True
    source_access_authorized: bool = False
    source_selection_performed: bool = False
    source_preparation_performed: bool = False
    review_session_prepared: bool = False
    main_gui_binding_prepared: bool = False
    review_displayed: bool = False
    normal_startup_activated: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    filesystem_access_performed: bool = False
    network_used: bool = False
    automatic_transition: bool = False
    format: str = RECOVERY_ENTRY_REQUEST_FORMAT
    version: int = RECOVERY_ENTRY_REQUEST_VERSION

    def __post_init__(self) -> None:
        _validate_entry_request_outcome(self)


class PreparedVaultRecoveryEntryRequest:
    """Locale-bound process-local request that accepts one exact decision."""

    __slots__ = ("_locale", "_state", "_outcome", "_lock")

    def __init__(self, locale: RecoveryLocalizationLocale) -> None:
        if type(locale) is not RecoveryLocalizationLocale:
            raise VaultRecoveryEntryRequestSourceError(
                "recovery entry request locale type is invalid"
            )
        self._locale = locale
        self._state = RecoveryEntryRequestState.AWAITING_DECISION
        self._outcome: VaultRecoveryEntryRequestOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def current_state(self) -> RecoveryEntryRequestState:
        return self._state

    @property
    def outcome(self) -> VaultRecoveryEntryRequestOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoveryEntryRequestDecision,
    ) -> VaultRecoveryEntryRequestOutcome:
        """Record one exact bounded intent without starting another layer."""

        with self._lock:
            if self._state is not RecoveryEntryRequestState.AWAITING_DECISION:
                raise VaultRecoveryEntryRequestReplayError(
                    "recovery entry request was already consumed"
                )
            if type(decision) is not RecoveryEntryRequestDecision:
                raise VaultRecoveryEntryRequestSourceError(
                    "recovery entry request decision type is invalid"
                )
            requested = decision is RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
            outcome = VaultRecoveryEntryRequestOutcome(
                locale=self._locale,
                decision=decision,
                state=RecoveryEntryRequestState.COMPLETED,
                review_requested=requested,
                preserved_and_stopped=not requested,
            )
            self._outcome = outcome
            self._state = RecoveryEntryRequestState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoveryEntryRequest("
            f"locale={self._locale.value!r}, state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoveryEntryRequestReplayError(
            "prepared recovery entry request cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        raise VaultRecoveryEntryRequestReplayError(
            "prepared recovery entry request cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryEntryRequestReplayError(
            "prepared recovery entry request cannot be serialized"
        )


def _validate_entry_request_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoveryEntryRequestOutcome:
        raise VaultRecoveryEntryRequestFormatError(
            "recovery entry request outcome type is invalid"
        )
    requested = value.decision is RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _LOCALE_BY_ID.values()
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
        raise VaultRecoveryEntryRequestFormatError(
            "recovery entry request outcome is invalid"
        )


def prepare_recovery_entry_request(
    locale_id: str,
) -> PreparedVaultRecoveryEntryRequest:
    """Prepare an inactive locale-bound request with no source capability."""

    if type(locale_id) is not str:
        raise VaultRecoveryEntryRequestSourceError(
            "recovery entry request locale must be exact text"
        )
    locale = _LOCALE_BY_ID.get(locale_id)
    if locale is None:
        raise VaultRecoveryEntryRequestSourceError(
            "recovery entry request locale is unsupported"
        )
    return PreparedVaultRecoveryEntryRequest(locale)
