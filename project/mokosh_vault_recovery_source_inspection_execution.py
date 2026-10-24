"""Inactive one-shot secure recovery-source inspection execution.

Stage 2.32 consumes only an exact positive Stage 2.31 outcome.  A positive
decision conditionally loads the established Stage 2.5 POSIX secure reader and
performs exactly one bounded structural inspection.  The result retains only
bounded non-secret evidence: it never retains the source path, descriptor,
record bytes, header bytes, nonce, or ciphertext and grants no recovery or
operation authority.

Structural parsing without the recovery secret is not cryptographic
authentication.  Python immutable bytes cannot be proven zeroized.  Filesystem
identity evidence is valid only for this completed inspection; any later use
must securely reopen and revalidate the source.
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
from mokosh_vault_recovery import (
    MAX_RECOVERY_CIPHERTEXT_LEN,
    MAX_RECOVERY_HEADER_LEN,
    RECOVERY_PREAMBLE_LEN,
)
from mokosh_vault_recovery_source_inspection_preparation_request import (
    RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE,
    RecoverySourceInspectionPreparationRequestDecision,
    VaultRecoverySourceInspectionPreparationRequestOutcome,
    _validate_source_inspection_preparation_request_outcome,
)
from mokosh_vault_recovery_source_inspection_request import (
    RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE,
    RecoverySourceInspectionRequestDecision,
)
from mokosh_vault_recovery_source_selection import (
    RECOVERY_SOURCE_SELECTION_SEQUENCE,
    RecoverySourceSelectionDecision,
    _validate_selected_path,
)


RECOVERY_SOURCE_INSPECTION_EXECUTION_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_EXECUTION"
)
RECOVERY_SOURCE_INSPECTION_EXECUTION_VERSION = 1
RECOVERY_SOURCE_INSPECTION_EXECUTION_SEQUENCE = 1
RECOVERY_SOURCE_INSPECTION_MAX_ENCODED_SIZE = (
    RECOVERY_PREAMBLE_LEN + MAX_RECOVERY_HEADER_LEN + MAX_RECOVERY_CIPHERTEXT_LEN
)


class VaultRecoverySourceInspectionExecutionError(ValueError):
    """Base class for strict Stage 2.32 execution failures."""


class VaultRecoverySourceInspectionExecutionSourceError(
    VaultRecoverySourceInspectionExecutionError
):
    """The exact positive Stage 2.31 source outcome is invalid."""


class VaultRecoverySourceInspectionExecutionDecisionError(
    VaultRecoverySourceInspectionExecutionError
):
    """The exact Stage 2.32 decision is invalid."""


class VaultRecoverySourceInspectionExecutionReplayError(
    VaultRecoverySourceInspectionExecutionError
):
    """A prepared execution is terminal or cannot be copied."""


class VaultRecoverySourceInspectionExecutionFormatError(
    VaultRecoverySourceInspectionExecutionError
):
    """A bounded Stage 2.32 outcome violates the frozen schema."""


class RecoverySourceInspectionExecutionDecision(str, Enum):
    """Exact decision authorizing at most one structural source inspection."""

    PRESERVE_AND_STOP = "preserve_and_stop"
    AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION = (
        "authorize_one_secure_source_inspection"
    )


class RecoverySourceInspectionExecutionState(str, Enum):
    """Process-local one-shot execution lifecycle."""

    AWAITING_INSPECTION_DECISION = "awaiting_inspection_decision"
    COMPLETED = "completed"
    FAILED = "failed"


_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionExecutionOutcome:
    """Bounded evidence with no retained source or recovery capability."""

    locale: RecoveryLocalizationLocale
    execution_decision: RecoverySourceInspectionExecutionDecision
    state: RecoverySourceInspectionExecutionState
    recovery_id: bytes | None = _field(repr=False)
    vault_id: bytes | None = _field(repr=False)
    source_revision: int | None = _field(repr=False)
    source_vault_sha256: bytes | None = _field(repr=False)
    record_sha256: bytes | None = _field(repr=False)
    encoded_size: int | None = _field(repr=False)
    secure_source_inspection_performed: bool
    preserved_and_stopped: bool
    header_structurally_validated: bool
    cryptographically_authenticated: bool = False
    source_path_metadata_retained: bool = False
    source_descriptor_retained: bool = False
    source_content_retained: bool = False
    ciphertext_retained: bool = False
    recovery_secret_received: bool = False
    recovery_performed: bool = False
    rehearsal_performed: bool = False
    stage2_8_used: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    logging_used: bool = False
    gui_used: bool = False
    one_shot: bool = True
    process_local: bool = True
    global_source_outcome_consumption_enforced: bool = False
    memory_zeroization_proven: bool = False
    filesystem_identity_future_validity_claimed: bool = False
    entry_request_sequence: int = RECOVERY_ENTRY_REQUEST_SEQUENCE
    transition_sequence: int = RECOVERY_ENTRY_TRANSITION_SEQUENCE
    selection_sequence: int = RECOVERY_SOURCE_SELECTION_SEQUENCE
    inspection_request_sequence: int = RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
    preparation_request_sequence: int = RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE
    execution_sequence: int = RECOVERY_SOURCE_INSPECTION_EXECUTION_SEQUENCE
    exact_preparation_request_outcome_validated: bool = True
    exact_execution_decision_validated: bool = True
    format: str = RECOVERY_SOURCE_INSPECTION_EXECUTION_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_EXECUTION_VERSION

    def __post_init__(self) -> None:
        _validate_source_inspection_execution_outcome(self)

    def __copy__(self) -> None:
        raise TypeError("recovery source inspection execution outcome cannot be copied")

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise TypeError("recovery source inspection execution outcome cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError(
            "recovery source inspection execution outcome cannot be serialized"
        )


def _read_source_once(path: str) -> _Any:
    """Conditionally load and invoke the established secure reader once."""

    from mokosh_vault_recovery_storage import _read_recovery_path

    return _read_recovery_path(path)


class PreparedVaultRecoverySourceInspectionExecution:
    """One-shot execution retaining no original Stage 2.31 outcome."""

    __slots__ = (
        "_locale",
        "_selected_path",
        "_state",
        "_outcome",
        "_lock",
    )

    def __init__(self, locale: RecoveryLocalizationLocale, selected_path: str) -> None:
        if type(locale) is not RecoveryLocalizationLocale or locale not in _SUPPORTED_LOCALES:
            raise VaultRecoverySourceInspectionExecutionSourceError(
                "recovery source inspection execution locale is invalid"
            )
        try:
            exact_path = _validate_selected_path(selected_path)
        except Exception:
            raise VaultRecoverySourceInspectionExecutionSourceError(
                "recovery source inspection execution path is invalid"
            ) from None
        self._locale = locale
        self._selected_path: str | None = exact_path
        self._state = RecoverySourceInspectionExecutionState.AWAITING_INSPECTION_DECISION
        self._outcome: VaultRecoverySourceInspectionExecutionOutcome | None = None
        self._lock = _Lock()

    @property
    def locale(self) -> RecoveryLocalizationLocale:
        return self._locale

    @property
    def current_state(self) -> RecoverySourceInspectionExecutionState:
        return self._state

    @property
    def retains_source_path_metadata(self) -> bool:
        return self._selected_path is not None

    @property
    def outcome(self) -> VaultRecoverySourceInspectionExecutionOutcome | None:
        return self._outcome

    def decide_once(
        self,
        decision: RecoverySourceInspectionExecutionDecision,
    ) -> VaultRecoverySourceInspectionExecutionOutcome:
        """Preserve or perform exactly one secure structural source read."""

        with self._lock:
            if self._state is not RecoverySourceInspectionExecutionState.AWAITING_INSPECTION_DECISION:
                raise VaultRecoverySourceInspectionExecutionReplayError(
                    "recovery source inspection execution is terminal"
                )
            if type(decision) is not RecoverySourceInspectionExecutionDecision:
                raise VaultRecoverySourceInspectionExecutionDecisionError(
                    "recovery source inspection execution decision type is invalid"
                )
            selected_path = self._selected_path
            if selected_path is None:
                self._state = RecoverySourceInspectionExecutionState.FAILED
                raise VaultRecoverySourceInspectionExecutionSourceError(
                    "recovery source inspection execution lost path metadata"
                )
            self._selected_path = None
            if decision is RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP:
                outcome = VaultRecoverySourceInspectionExecutionOutcome(
                    locale=self._locale,
                    execution_decision=decision,
                    state=RecoverySourceInspectionExecutionState.COMPLETED,
                    recovery_id=None,
                    vault_id=None,
                    source_revision=None,
                    source_vault_sha256=None,
                    record_sha256=None,
                    encoded_size=None,
                    secure_source_inspection_performed=False,
                    preserved_and_stopped=True,
                    header_structurally_validated=False,
                )
                self._outcome = outcome
                self._state = RecoverySourceInspectionExecutionState.COMPLETED
                return outcome
            self._state = RecoverySourceInspectionExecutionState.FAILED
            try:
                imported = _read_source_once(selected_path)
                parsed = imported.parsed
                outcome = VaultRecoverySourceInspectionExecutionOutcome(
                    locale=self._locale,
                    execution_decision=decision,
                    state=RecoverySourceInspectionExecutionState.COMPLETED,
                    recovery_id=bytes(parsed.recovery_id),
                    vault_id=bytes(parsed.vault_id),
                    source_revision=parsed.source_revision,
                    source_vault_sha256=bytes(parsed.source_vault_sha256),
                    record_sha256=bytes(imported.record_sha256),
                    encoded_size=imported.encoded_size,
                    secure_source_inspection_performed=True,
                    preserved_and_stopped=False,
                    header_structurally_validated=True,
                )
            except BaseException:
                raise
            finally:
                if "imported" in locals():
                    del imported
                del selected_path
            self._outcome = outcome
            self._state = RecoverySourceInspectionExecutionState.COMPLETED
            return outcome

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionExecution("
            f"locale={self._locale.value!r}, state={self._state.value!r}, "
            f"retains_source_path_metadata={self.retains_source_path_metadata!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionExecutionReplayError(
            "prepared recovery source inspection execution cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionExecutionReplayError(
            "prepared recovery source inspection execution cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionExecutionReplayError(
            "prepared recovery source inspection execution cannot be serialized"
        )


def _validate_source_inspection_preparation_source(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionPreparationRequestOutcome:
        raise VaultRecoverySourceInspectionExecutionSourceError(
            "recovery source inspection preparation outcome type is invalid"
        )
    try:
        _validate_source_inspection_preparation_request_outcome(value)
    except Exception:
        raise VaultRecoverySourceInspectionExecutionSourceError(
            "recovery source inspection preparation outcome is invalid"
        ) from None
    if (
        value.preparation_decision
        is not RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        or value.future_secure_source_inspection_preparation_requested is not True
        or value.preserved_and_stopped is not False
        or value.source_path_metadata_retained is not True
        or value.contains_sensitive_path_metadata is not True
    ):
        raise VaultRecoverySourceInspectionExecutionSourceError(
            "preserved preparation outcome cannot prepare source inspection execution"
        )


def _validate_source_inspection_execution_outcome(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionExecutionOutcome:
        raise VaultRecoverySourceInspectionExecutionFormatError(
            "recovery source inspection execution outcome type is invalid"
        )
    performed = (
        value.execution_decision
        is RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
    )
    if performed:
        evidence_valid = (
            type(value.recovery_id) is bytes
            and len(value.recovery_id) == 16
            and type(value.vault_id) is bytes
            and len(value.vault_id) == 16
            and type(value.source_revision) is int
            and value.source_revision >= 1
            and type(value.source_vault_sha256) is bytes
            and len(value.source_vault_sha256) == 32
            and type(value.record_sha256) is bytes
            and len(value.record_sha256) == 32
            and type(value.encoded_size) is int
            and 1 <= value.encoded_size <= RECOVERY_SOURCE_INSPECTION_MAX_ENCODED_SIZE
        )
    else:
        evidence_valid = all(
            item is None
            for item in (
                value.recovery_id,
                value.vault_id,
                value.source_revision,
                value.source_vault_sha256,
                value.record_sha256,
                value.encoded_size,
            )
        )
    false_claims = (
        "cryptographically_authenticated",
        "source_path_metadata_retained",
        "source_descriptor_retained",
        "source_content_retained",
        "ciphertext_retained",
        "recovery_secret_received",
        "recovery_performed",
        "rehearsal_performed",
        "stage2_8_used",
        "review_session_prepared",
        "operation_authorized",
        "operation_performed",
        "filesystem_mutation_performed",
        "network_used",
        "logging_used",
        "gui_used",
        "global_source_outcome_consumption_enforced",
        "memory_zeroization_proven",
        "filesystem_identity_future_validity_claimed",
    )
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.execution_decision) is not RecoverySourceInspectionExecutionDecision
        or value.state is not RecoverySourceInspectionExecutionState.COMPLETED
        or not evidence_valid
        or type(value.secure_source_inspection_performed) is not bool
        or value.secure_source_inspection_performed is not performed
        or type(value.preserved_and_stopped) is not bool
        or value.preserved_and_stopped is performed
        or type(value.header_structurally_validated) is not bool
        or value.header_structurally_validated is not performed
        or any(getattr(value, name) is not False for name in false_claims)
        or value.one_shot is not True
        or value.process_local is not True
        or type(value.entry_request_sequence) is not int
        or value.entry_request_sequence != RECOVERY_ENTRY_REQUEST_SEQUENCE
        or type(value.transition_sequence) is not int
        or value.transition_sequence != RECOVERY_ENTRY_TRANSITION_SEQUENCE
        or type(value.selection_sequence) is not int
        or value.selection_sequence != RECOVERY_SOURCE_SELECTION_SEQUENCE
        or type(value.inspection_request_sequence) is not int
        or value.inspection_request_sequence != RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE
        or type(value.preparation_request_sequence) is not int
        or value.preparation_request_sequence != RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE
        or type(value.execution_sequence) is not int
        or value.execution_sequence != RECOVERY_SOURCE_INSPECTION_EXECUTION_SEQUENCE
        or value.exact_preparation_request_outcome_validated is not True
        or value.exact_execution_decision_validated is not True
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_EXECUTION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_EXECUTION_VERSION
    ):
        raise VaultRecoverySourceInspectionExecutionFormatError(
            "recovery source inspection execution outcome is invalid"
        )


def prepare_recovery_source_inspection_execution(
    preparation_request_outcome: VaultRecoverySourceInspectionPreparationRequestOutcome,
) -> PreparedVaultRecoverySourceInspectionExecution:
    """Prepare one execution from an exact positive Stage 2.31 outcome."""

    _validate_source_inspection_preparation_source(preparation_request_outcome)
    return PreparedVaultRecoverySourceInspectionExecution(
        preparation_request_outcome.locale,
        preparation_request_outcome.selected_path,
    )
