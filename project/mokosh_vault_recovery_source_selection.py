"""Inactive one-shot selection of one untrusted local recovery source path.

Stage 2.27 consumes only an exact positive Stage 2.21 transition outcome and
records either one absolute POSIX path selected by the caller or an exact stop
decision.  The path is process-local sensitive metadata.  This module never
opens, resolves, normalizes, displays, logs, validates, or authorizes access to
the selected source, and it accepts no recovery secret or operation capability.
"""

from __future__ import annotations

from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
import posixpath as _posixpath
from threading import Lock as _Lock
from typing import Any as _Any
import unicodedata as _unicodedata

from mokosh_vault_recovery_entry_request import (
    RECOVERY_ENTRY_REQUEST_SEQUENCE,
    RecoveryEntryRequestDecision,
)
from mokosh_vault_recovery_entry_transition import (
    RECOVERY_ENTRY_TRANSITION_FORMAT,
    RECOVERY_ENTRY_TRANSITION_SEQUENCE,
    RECOVERY_ENTRY_TRANSITION_VERSION,
    RecoveryEntryTransitionDecision,
    RecoveryEntryTransitionState,
    VaultRecoveryEntryTransitionOutcome,
)
from mokosh_vault_recovery_locale import RecoveryLocalizationLocale


RECOVERY_SOURCE_SELECTION_FORMAT = "MOKOSH_VAULT_RECOVERY_SOURCE_SELECTION"
RECOVERY_SOURCE_SELECTION_VERSION = 1
RECOVERY_SOURCE_SELECTION_SEQUENCE = 1
MAX_RECOVERY_SOURCE_PATH_UTF8_BYTES = 4096


class VaultRecoverySourceSelectionError(ValueError):
    """Base class for strict Stage 2.27 source-selection failures."""


class VaultRecoverySourceSelectionSourceError(VaultRecoverySourceSelectionError):
    """The exact Stage 2.21 source outcome or selected path is invalid."""


class VaultRecoverySourceSelectionDecisionError(VaultRecoverySourceSelectionError):
    """The selection decision or its path route is invalid."""


class VaultRecoverySourceSelectionReplayError(VaultRecoverySourceSelectionError):
    """A prepared selection was consumed or cannot be copied."""


class VaultRecoverySourceSelectionFormatError(VaultRecoverySourceSelectionError):
    """A bounded selection outcome violates the frozen schema."""


class RecoverySourceSelectionDecision(str, Enum):
    """Exact selection choice; neither member grants source access."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    SELECT_LOCAL_RECOVERY_RECORD = "select_local_recovery_record"


class RecoverySourceSelectionState(str, Enum):
    """One-shot process-local selection lifecycle."""

    AWAITING_SELECTION_DECISION = "awaiting_selection_decision"
    COMPLETED = "completed"


_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceSelectionOutcome:
    """Bounded path metadata with no source-access or operation authority."""

    locale: RecoveryLocalizationLocale
    entry_decision: RecoveryEntryRequestDecision
    transition_decision: RecoveryEntryTransitionDecision
    selection_decision: RecoverySourceSelectionDecision
    state: RecoverySourceSelectionState
    selected_path: str | None = _field(repr=False)
    source_selected: bool
    preserved_and_stopped: bool
    source_path_metadata_received: bool
    contains_sensitive_path_metadata: bool
    entry_request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    transition_sequence: int = RECOVERY_ENTRY_TRANSITION_SEQUENCE
    selection_sequence: int = RECOVERY_SOURCE_SELECTION_SEQUENCE
    exact_transition_outcome_validated: bool = True
    exact_selection_decision_validated: bool = True
    exact_path_syntax_validated: bool = True
    one_shot: bool = True
    process_local: bool = True
    source_opened: bool = False
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
    format: str = RECOVERY_SOURCE_SELECTION_FORMAT
    version: int = RECOVERY_SOURCE_SELECTION_VERSION

    def __post_init__(self) -> None:
        _validate_source_selection_outcome(self)

    def __copy__(self) -> None:
        raise TypeError("recovery source selection outcome cannot be copied")

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise TypeError("recovery source selection outcome cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("recovery source selection outcome cannot be serialized")


class PreparedVaultRecoverySourceSelection:
    """One-shot selection retaining no original transition outcome."""

    __slots__ = (
        "_locale",
        "_entry_decision",
        "_transition_decision",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(
        self,
        locale: RecoveryLocalizationLocale,
        entry_decision: RecoveryEntryRequestDecision,
        transition_decision: RecoveryEntryTransitionDecision,
    ) -> None:
        if type(locale) is not RecoveryLocalizationLocale or locale not in _SUPPORTED_LOCALES:
            raise VaultRecoverySourceSelectionSourceError(
                "recovery source selection locale is invalid"
            )
        if entry_decision is not RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW:
            raise VaultRecoverySourceSelectionSourceError(
                "recovery source selection entry route is invalid"
            )
        if (
            transition_decision
            is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        ):
            raise VaultRecoverySourceSelectionSourceError(
                "recovery source selection transition route is invalid"
            )
        self._locale = locale
        self._entry_decision = entry_decision
        self._transition_decision = transition_decision
        self._state = RecoverySourceSelectionState.AWAITING_SELECTION_DECISION
        self._outcome: VaultRecoverySourceSelectionOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def current_state(self) -> RecoverySourceSelectionState:
        return self._state

    @property
    def outcome(self) -> VaultRecoverySourceSelectionOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoverySourceSelectionDecision,
        selected_path: str | None = None,
    ) -> VaultRecoverySourceSelectionOutcome:
        """Record one selection or stop decision without accessing the source."""

        with self._lock:
            if self._state is not RecoverySourceSelectionState.AWAITING_SELECTION_DECISION:
                raise VaultRecoverySourceSelectionReplayError(
                    "recovery source selection was already consumed"
                )
            if type(decision) is not RecoverySourceSelectionDecision:
                raise VaultRecoverySourceSelectionDecisionError(
                    "recovery source selection decision type is invalid"
                )
            selecting = (
                decision
                is RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
            )
            if selecting:
                exact_path = _validate_selected_path(selected_path)
            else:
                if selected_path is not None:
                    raise VaultRecoverySourceSelectionDecisionError(
                        "preserve route cannot carry source path metadata"
                    )
                exact_path = None
            outcome = VaultRecoverySourceSelectionOutcome(
                locale=self._locale,
                entry_decision=self._entry_decision,
                transition_decision=self._transition_decision,
                selection_decision=decision,
                state=RecoverySourceSelectionState.COMPLETED,
                selected_path=exact_path,
                source_selected=selecting,
                preserved_and_stopped=not selecting,
                source_path_metadata_received=selecting,
                contains_sensitive_path_metadata=selecting,
            )
            self._outcome = outcome
            self._state = RecoverySourceSelectionState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceSelection("
            f"locale={self._locale.value!r}, state={self._state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceSelectionReplayError(
            "prepared recovery source selection cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceSelectionReplayError(
            "prepared recovery source selection cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceSelectionReplayError(
            "prepared recovery source selection cannot be serialized"
        )


def _validate_selected_path(value: _Any) -> str:
    if type(value) is not str:
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path must be exact text"
        )
    if not value or not _posixpath.isabs(value) or value == "/":
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path must be an absolute POSIX file path"
        )
    if value.startswith("//") or value.endswith("/"):
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path is lexically ambiguous"
        )
    parts = value[1:].split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path is lexically ambiguous"
        )
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path is not strict UTF-8 text"
        ) from exc
    if len(encoded) > MAX_RECOVERY_SOURCE_PATH_UTF8_BYTES:
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path exceeds its UTF-8 bound"
        )
    if "\x00" in value or any(
        _unicodedata.category(character) in ("Cc", "Cf") for character in value
    ):
        raise VaultRecoverySourceSelectionSourceError(
            "selected recovery source path contains unsafe control text"
        )
    return value


def _validate_transition_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoveryEntryTransitionOutcome:
        raise VaultRecoverySourceSelectionSourceError(
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
        raise VaultRecoverySourceSelectionSourceError(
            "recovery entry transition outcome is invalid"
        )


def _validate_source_selection_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceSelectionOutcome:
        raise VaultRecoverySourceSelectionFormatError(
            "recovery source selection outcome type is invalid"
        )
    selecting = (
        value.selection_decision
        is RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD
    )
    if selecting:
        try:
            exact_path = _validate_selected_path(value.selected_path)
        except VaultRecoverySourceSelectionSourceError as exc:
            raise VaultRecoverySourceSelectionFormatError(
                "recovery source selection outcome path is invalid"
            ) from exc
    else:
        exact_path = None
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or value.entry_decision is not RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        or value.transition_decision
        is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        or type(value.selection_decision) is not RecoverySourceSelectionDecision
        or value.state is not RecoverySourceSelectionState.COMPLETED
        or value.selected_path != exact_path
        or type(value.source_selected) is not bool
        or value.source_selected is not selecting
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is selecting
        or type(value.source_path_metadata_received) is not bool
        or value.source_path_metadata_received is not selecting
        or type(value.contains_sensitive_path_metadata) is not bool
        or value.contains_sensitive_path_metadata is not selecting
        or type(value.entry_request_sequence) is not int
        or value.entry_request_sequence != RECOVERY_ENTRY_REQUEST_SEQUENCE
        or type(value.transition_sequence) is not int
        or value.transition_sequence != RECOVERY_ENTRY_TRANSITION_SEQUENCE
        or type(value.selection_sequence) is not int
        or value.selection_sequence != RECOVERY_SOURCE_SELECTION_SEQUENCE
        or value.exact_transition_outcome_validated is not True
        or value.exact_selection_decision_validated is not True
        or value.exact_path_syntax_validated is not True
        or value.one_shot is not True
        or value.process_local is not True
        or value.source_opened is not False
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
        or value.format != RECOVERY_SOURCE_SELECTION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_SELECTION_VERSION
    ):
        raise VaultRecoverySourceSelectionFormatError(
            "recovery source selection outcome is invalid"
        )


def prepare_recovery_source_selection(
    transition_outcome: VaultRecoveryEntryTransitionOutcome,
) -> PreparedVaultRecoverySourceSelection:
    """Prepare one inactive path-selection boundary from an exact outcome."""

    try:
        _validate_transition_outcome(transition_outcome)
    except VaultRecoverySourceSelectionSourceError:
        raise
    except Exception:
        raise VaultRecoverySourceSelectionSourceError(
            "recovery entry transition outcome is invalid"
        ) from None
    if (
        transition_outcome.transition_decision
        is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    ):
        raise VaultRecoverySourceSelectionDecisionError(
            "preserved transition cannot prepare recovery source selection"
        )
    return PreparedVaultRecoverySourceSelection(
        transition_outcome.locale,
        transition_outcome.entry_decision,
        transition_outcome.transition_decision,
    )
