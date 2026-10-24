"""Session-bound Linux-only local MOKOSH2 encryption and decryption.

The service exposes only stable non-secret outcomes.  It never deletes an
original, never overwrites an output, never falls back to MOK1 or another key
slot, and never releases Vault key material to a GUI.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mokosh_profile_session import (
    ProfileOperationBusyError,
    ProfileSessionError,
    SecureProfileSession,
)
from mokosh_v2_cleanup_authorization import (
    CleanupAuthorizationError,
    CleanupUserDecision,
    prepare_cleanup_authorization,
)
from mokosh_v2_cleanup_executor import (
    CleanupExecutionError,
    CleanupExecutionStatus,
    execute_cleanup,
)
from mokosh_v2_complete_envelope import (
    CompleteEnvelopePolicyError,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_filesystem import FileIdentity, VerifiedFileSource
from mokosh_v2_format import MAGIC, V2FormatError
from mokosh_v2_key_slots import KeyVaultSlot
from mokosh_v2_operation_lifecycle import (
    CancellationToken,
    OperationCancelled,
    OperationErrorCode,
    ProgressObserver,
    SafeOperationFailure,
    classify_operation_error,
    run_decryption_operation,
    run_encryption_operation,
)
from mokosh_v2_operation_journal import (
    OperationJournalError,
    validate_operation_id,
)
from mokosh_v2_reconciliation import (
    ReconciliationError,
    scan_quarantine_directory,
)
from mokosh_v2_reconciliation_evidence import (
    MAX_EVIDENCE_ITEMS,
    EvidenceClassification,
    ReconciliationEvidenceError,
    ReconciliationEvidenceReport,
    build_reconciliation_evidence,
)
from mokosh_v2_streaming import inspect_envelope_stream
from mokosh_vault_keyring import VaultKeyringError


MAX_LOCAL_V2_DIRECTORY_ENTRIES = 4096


class LocalV2ServiceError(RuntimeError):
    """A local service contract was violated without exposing path details."""


class LocalV2ErrorCode(str, Enum):
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    SESSION_UNAVAILABLE = "session_unavailable"
    OPERATION_BUSY = "operation_busy"
    RESIDUE_REVIEW_REQUIRED = "residue_review_required"
    INVALID_SELECTION = "invalid_selection"
    NOT_MOKOSH2 = "not_mokosh2"
    UNSUPPORTED_ENVELOPE = "unsupported_envelope"
    CANCELLED = "operation_cancelled"
    INTERRUPTED = "operation_interrupted"
    UNSAFE_PATH = "unsafe_path"
    SOURCE_CHANGED = "source_changed"
    OUTPUT_COLLISION = "output_collision"
    ATOMIC_PUBLISH_UNSUPPORTED = "atomic_publish_unsupported"
    AUTHENTICATION_FAILED = "authentication_failed"
    VERIFICATION_FAILED = "verification_failed"
    CLEANUP_FAILED = "cleanup_failed"
    INVALID_INPUT = "invalid_input"
    RESOURCE_LIMIT = "resource_limit"
    IO_FAILED = "io_failed"
    INTERNAL_ERROR = "internal_error"


class LocalV2WarningCode(str, Enum):
    PUBLISHED_REVIEW_REQUIRED = "published_review_required"
    CLEANUP_REVIEW_REQUIRED = "cleanup_review_required"


class ResidueReviewState(str, Enum):
    CLEAR = "clear"
    CLEANABLE = "cleanable"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class SafeLocalV2Failure:
    code: LocalV2ErrorCode
    retryable: bool
    message_key: str

    def __post_init__(self) -> None:
        if type(self.code) is not LocalV2ErrorCode:
            raise LocalV2ServiceError("local failure code is invalid")
        if type(self.retryable) is not bool:
            raise LocalV2ServiceError("local failure retry flag is invalid")
        if type(self.message_key) is not str:
            raise LocalV2ServiceError("local failure message key type is invalid")
        if self.message_key != f"local_v2.error.{self.code.value}":
            raise LocalV2ServiceError("local failure message key is invalid")


@dataclass(frozen=True, slots=True)
class SafeLocalV2Warning:
    code: LocalV2WarningCode
    message_key: str

    def __post_init__(self) -> None:
        if type(self.code) is not LocalV2WarningCode:
            raise LocalV2ServiceError("local warning code is invalid")
        if type(self.message_key) is not str:
            raise LocalV2ServiceError("local warning message key type is invalid")
        if self.message_key != f"local_v2.warning.{self.code.value}":
            raise LocalV2ServiceError("local warning message key is invalid")


@dataclass(frozen=True, slots=True)
class ResidueReview:
    state: ResidueReviewState
    finding_count: int
    blocked_count: int
    cleanup_operation_ids: tuple[str, ...]
    scan_complete: bool
    evidence: ReconciliationEvidenceReport | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.state) is not ResidueReviewState:
            raise LocalV2ServiceError("residue review state is invalid")
        if type(self.finding_count) is not int or self.finding_count < 0:
            raise LocalV2ServiceError("residue finding count is invalid")
        if (
            type(self.blocked_count) is not int
            or not 0 <= self.blocked_count <= self.finding_count
        ):
            raise LocalV2ServiceError("residue blocked count is invalid")
        if type(self.cleanup_operation_ids) is not tuple:
            raise LocalV2ServiceError("cleanup operation identifiers must be immutable")
        if any(type(item) is not str for item in self.cleanup_operation_ids):
            raise LocalV2ServiceError(
                "cleanup operation identifier type is invalid"
            )
        if len(set(self.cleanup_operation_ids)) != len(self.cleanup_operation_ids):
            raise LocalV2ServiceError("cleanup operation identifiers must be unique")
        for operation_id in self.cleanup_operation_ids:
            try:
                validate_operation_id(operation_id)
            except OperationJournalError as exc:
                raise LocalV2ServiceError(
                    "cleanup operation identifier is invalid"
                ) from exc
        if type(self.scan_complete) is not bool:
            raise LocalV2ServiceError("residue scan completeness is invalid")
        if (
            self.evidence is not None
            and type(self.evidence) is not ReconciliationEvidenceReport
        ):
            raise LocalV2ServiceError("residue evidence type is invalid")
        if self.evidence is not None and (
            self.evidence.source_findings != self.finding_count
            or self.evidence.complete != self.scan_complete
        ):
            raise LocalV2ServiceError("residue evidence counts are inconsistent")
        if self.state is ResidueReviewState.CLEAR:
            valid = (
                self.scan_complete
                and self.finding_count == 0
                and self.blocked_count == 0
                and not self.cleanup_operation_ids
                and (
                    self.evidence is None
                    or not self.evidence.items
                )
            )
        elif self.state is ResidueReviewState.CLEANABLE:
            exact_evidence_ids = (
                ()
                if self.evidence is None
                else tuple(
                    item.operation_id
                    for item in self.evidence.items
                    if item.classification is EvidenceClassification.INODE_MATCH
                    and item.operation_id is not None
                )
            )
            valid = (
                self.scan_complete
                and self.finding_count > 0
                and self.blocked_count == 0
                and len(self.cleanup_operation_ids) == self.finding_count
                and self.evidence is not None
                and len(self.evidence.items) == self.finding_count
                and exact_evidence_ids == self.cleanup_operation_ids
            )
        else:
            if self.scan_complete:
                nonexact = (
                    sum(
                        item.classification
                        is not EvidenceClassification.INODE_MATCH
                        for item in self.evidence.items
                    )
                    if self.evidence is not None
                    else 0
                )
                valid = (
                    not self.cleanup_operation_ids
                    and self.finding_count > 0
                    and self.blocked_count > 0
                    and self.evidence is not None
                    and len(self.evidence.items) == self.finding_count
                    and nonexact == self.blocked_count
                )
            else:
                valid = (
                    not self.cleanup_operation_ids
                    and self.blocked_count == self.finding_count
                )
        if not valid:
            raise LocalV2ServiceError("residue review fields are inconsistent")


@dataclass(frozen=True, slots=True)
class LocalV2Result:
    ok: bool
    failure: SafeLocalV2Failure | None = None
    warning: SafeLocalV2Warning | None = None
    residue: ResidueReview | None = None
    cleanup_status: CleanupExecutionStatus | None = None

    def __post_init__(self) -> None:
        if type(self.ok) is not bool:
            raise LocalV2ServiceError("local result status must be boolean")
        if (
            self.failure is not None
            and type(self.failure) is not SafeLocalV2Failure
        ):
            raise LocalV2ServiceError("local result failure type is invalid")
        if (
            self.warning is not None
            and type(self.warning) is not SafeLocalV2Warning
        ):
            raise LocalV2ServiceError("local result warning type is invalid")
        if self.residue is not None and type(self.residue) is not ResidueReview:
            raise LocalV2ServiceError("local result residue type is invalid")
        if (
            self.cleanup_status is not None
            and type(self.cleanup_status) is not CleanupExecutionStatus
        ):
            raise LocalV2ServiceError("local cleanup result status is invalid")
        if self.ok:
            valid = self.failure is None and (
                self.cleanup_status is None or self.residue is not None
            )
            if valid and self.warning is not None:
                expected_warning = (
                    LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED
                    if self.cleanup_status is None
                    else LocalV2WarningCode.CLEANUP_REVIEW_REQUIRED
                )
                valid = self.warning.code is expected_warning
        else:
            valid = (
                self.failure is not None
                and self.warning is None
                and self.cleanup_status is None
            )
        if not valid:
            raise LocalV2ServiceError("local result fields are inconsistent")


class _LocalRefusal(Exception):
    def __init__(self, code: LocalV2ErrorCode, *, retryable: bool = False) -> None:
        super().__init__(code.value)
        self.code = code
        self.retryable = retryable


class _CancellableReadSource:
    __slots__ = ("_source", "_cancellation")

    def __init__(self, source: Any, cancellation: CancellationToken) -> None:
        self._source = source
        self._cancellation = cancellation

    def read(self, size: int) -> bytes:
        self._cancellation.checkpoint()
        result = self._source.read(size)
        self._cancellation.checkpoint()
        return result


_CORE_ERROR_MAP = {
    OperationErrorCode.CANCELLED: LocalV2ErrorCode.CANCELLED,
    OperationErrorCode.INTERRUPTED: LocalV2ErrorCode.INTERRUPTED,
    OperationErrorCode.UNSAFE_PATH: LocalV2ErrorCode.UNSAFE_PATH,
    OperationErrorCode.SOURCE_CHANGED: LocalV2ErrorCode.SOURCE_CHANGED,
    OperationErrorCode.OUTPUT_COLLISION: LocalV2ErrorCode.OUTPUT_COLLISION,
    OperationErrorCode.ATOMIC_PUBLISH_UNSUPPORTED: LocalV2ErrorCode.ATOMIC_PUBLISH_UNSUPPORTED,
    OperationErrorCode.AUTHENTICATION_FAILED: LocalV2ErrorCode.AUTHENTICATION_FAILED,
    OperationErrorCode.VERIFICATION_FAILED: LocalV2ErrorCode.VERIFICATION_FAILED,
    OperationErrorCode.CLEANUP_FAILED: LocalV2ErrorCode.CLEANUP_FAILED,
    OperationErrorCode.INVALID_INPUT: LocalV2ErrorCode.INVALID_INPUT,
    OperationErrorCode.RESOURCE_LIMIT: LocalV2ErrorCode.RESOURCE_LIMIT,
    OperationErrorCode.IO_FAILED: LocalV2ErrorCode.IO_FAILED,
    OperationErrorCode.INTERNAL_ERROR: LocalV2ErrorCode.INTERNAL_ERROR,
}


def _failure(
    code: LocalV2ErrorCode,
    *,
    retryable: bool = False,
    residue: ResidueReview | None = None,
) -> LocalV2Result:
    return LocalV2Result(
        ok=False,
        failure=SafeLocalV2Failure(
            code,
            retryable,
            f"local_v2.error.{code.value}",
        ),
        residue=residue,
    )


def _core_failure(
    failure: SafeOperationFailure,
    residue: ResidueReview | None,
) -> LocalV2Result:
    code = _CORE_ERROR_MAP.get(failure.code, LocalV2ErrorCode.INTERNAL_ERROR)
    return _failure(code, retryable=failure.retryable, residue=residue)


def _text_path(value: Any) -> str:
    try:
        path = os.fspath(value)
    except TypeError as exc:
        raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION) from exc
    if type(path) is not str or not path or "\x00" in path:
        raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
    return os.path.abspath(path)


def _output_selection(value: Any, *, require_mok2_suffix: bool) -> tuple[str, str]:
    path = _text_path(value)
    name = os.path.basename(path)
    if name in {"", ".", ".."}:
        raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
    if require_mok2_suffix and not name.endswith(".mok2"):
        raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
    return path, os.path.dirname(path)


def _unknown_review() -> ResidueReview:
    return ResidueReview(
        ResidueReviewState.BLOCKED,
        0,
        0,
        (),
        False,
        None,
    )


def _directory_scan_is_bounded(
    directory: Any,
    cancellation: CancellationToken | None,
) -> bool:
    """Refuse an unbounded reconciliation list before the legacy full scan."""

    try:
        with os.scandir(directory) as entries:
            for count, _entry in enumerate(entries, 1):
                if cancellation is not None:
                    cancellation.checkpoint()
                if count > MAX_LOCAL_V2_DIRECTORY_ENTRIES:
                    return False
    except OperationCancelled:
        raise
    except OSError as exc:
        raise LocalV2ServiceError("residue directory bound check failed") from exc
    return True


def _review(
    directory: Any,
    cancellation: CancellationToken | None = None,
) -> ResidueReview:
    if not _directory_scan_is_bounded(directory, cancellation):
        return _unknown_review()
    if cancellation is not None:
        cancellation.checkpoint()
    try:
        evidence = build_reconciliation_evidence(
            scan_quarantine_directory(directory),
            max_items=MAX_EVIDENCE_ITEMS,
        )
    except (OSError, ReconciliationError, ReconciliationEvidenceError) as exc:
        raise LocalV2ServiceError("residue review failed") from exc
    if not evidence.complete or evidence.omitted_findings:
        return ResidueReview(
            ResidueReviewState.BLOCKED,
            evidence.source_findings,
            evidence.source_findings,
            (),
            False,
            evidence,
        )
    if not evidence.items:
        return ResidueReview(
            ResidueReviewState.CLEAR,
            0,
            0,
            (),
            True,
            evidence,
        )
    exact = tuple(
        item.operation_id
        for item in evidence.items
        if item.classification is EvidenceClassification.INODE_MATCH
        and item.operation_id is not None
    )
    if len(exact) == len(evidence.items):
        return ResidueReview(
            ResidueReviewState.CLEANABLE,
            len(evidence.items),
            0,
            exact,
            True,
            evidence,
        )
    return ResidueReview(
        ResidueReviewState.BLOCKED,
        len(evidence.items),
        len(evidence.items) - len(exact),
        (),
        True,
        evidence,
    )


def _post_review(directory: str) -> ResidueReview:
    try:
        return _review(directory)
    except LocalV2ServiceError:
        return _unknown_review()


def _require_linux() -> None:
    if os.name != "posix" or sys.platform != "linux":
        raise _LocalRefusal(LocalV2ErrorCode.UNSUPPORTED_PLATFORM)


def _random_generic_name(prefix: str, suffix: str) -> str:
    token = secrets.token_hex(4)
    if len(token) != 8 or any(character not in "0123456789abcdef" for character in token):
        raise LocalV2ServiceError("secure random source returned an invalid name token")
    return f"{prefix}-{token}{suffix}"


def propose_encrypted_name() -> str:
    return _random_generic_name("MOKOSH-encrypted", ".mok2")


def propose_decrypted_name() -> str:
    return _random_generic_name("MOKOSH-decrypted", "")


class LocalV2Service:
    """Bind local file operations to one unlocked SecureProfileSession."""

    __slots__ = ("_session",)

    def __init__(self, profile_session: SecureProfileSession) -> None:
        if type(profile_session) is not SecureProfileSession:
            raise LocalV2ServiceError("secure profile session is required")
        self._session = profile_session

    def review_directory(self, directory: Any) -> ResidueReview:
        _require_linux()
        return _review(_text_path(directory))

    def _preflight_output(
        self,
        output_path: Any,
        *,
        require_mok2_suffix: bool,
        cancellation: CancellationToken,
    ) -> tuple[str, str, ResidueReview]:
        output, directory = _output_selection(
            output_path,
            require_mok2_suffix=require_mok2_suffix,
        )
        review = _review(directory, cancellation)
        return output, directory, review

    def encrypt(
        self,
        *,
        source_path: Any,
        output_path: Any,
        cancellation: CancellationToken | None = None,
        observer: ProgressObserver | None = None,
    ) -> LocalV2Result:
        review: ResidueReview | None = None
        directory: str | None = None
        try:
            _require_linux()
            token = CancellationToken() if cancellation is None else cancellation
            if type(token) is not CancellationToken:
                raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
            source = _text_path(source_path)
            original_name = os.path.basename(source)
            if original_name in {"", ".", ".."}:
                raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
            output, directory, review = self._preflight_output(
                output_path,
                require_mok2_suffix=True,
                cancellation=token,
            )
            if review.state is not ResidueReviewState.CLEAR:
                raise _LocalRefusal(LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED)
            with self._session._begin_local_v2_operation(token) as lease:
                review = _review(directory, token)
                if review.state is not ResidueReviewState.CLEAR:
                    raise _LocalRefusal(
                        LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED
                    )
                plan, _slot = lease.encryption_plan()
                outcome = run_encryption_operation(
                    source_path=source,
                    output_path=output,
                    key_plan=plan,
                    original_name=original_name,
                    signing=UnsignedEnvelopeSigning(),
                    cancellation=token,
                    observer=observer,
                )
        except _LocalRefusal as exc:
            return _failure(exc.code, retryable=exc.retryable, residue=review)
        except OperationCancelled:
            return _failure(LocalV2ErrorCode.CANCELLED, retryable=True, residue=review)
        except ProfileOperationBusyError:
            return _failure(LocalV2ErrorCode.OPERATION_BUSY, residue=review)
        except ProfileSessionError:
            return _failure(LocalV2ErrorCode.SESSION_UNAVAILABLE, residue=review)
        except LocalV2ServiceError:
            return _failure(LocalV2ErrorCode.IO_FAILED, residue=review)
        except Exception:
            return _failure(LocalV2ErrorCode.INTERNAL_ERROR, residue=review)

        final_review = _post_review(directory)
        if not outcome.ok:
            assert outcome.failure is not None
            return _core_failure(outcome.failure, final_review)
        warning = None
        if outcome.warning is not None or final_review.state is not ResidueReviewState.CLEAR:
            warning = SafeLocalV2Warning(
                LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED,
                "local_v2.warning.published_review_required",
            )
        return LocalV2Result(ok=True, warning=warning, residue=final_review)

    def _inspect_local_unsigned(
        self,
        source: str,
        cancellation: CancellationToken,
    ) -> tuple[FileIdentity, KeyVaultSlot]:
        try:
            with VerifiedFileSource(source) as magic_source:
                magic_identity = magic_source.identity
                head = _CancellableReadSource(magic_source, cancellation).read(
                    len(MAGIC)
                )
            if head != MAGIC:
                raise _LocalRefusal(LocalV2ErrorCode.NOT_MOKOSH2)
            with VerifiedFileSource(source) as public_source:
                source_identity = public_source.identity
                if source_identity != magic_identity:
                    raise _LocalRefusal(
                        LocalV2ErrorCode.SOURCE_CHANGED,
                        retryable=True,
                    )
                inspection = inspect_envelope_stream(
                    _CancellableReadSource(public_source, cancellation),
                    verification=RequireUnsignedEnvelope(),
                )
        except _LocalRefusal:
            raise
        except CompleteEnvelopePolicyError as exc:
            raise _LocalRefusal(LocalV2ErrorCode.UNSUPPORTED_ENVELOPE) from exc
        except V2FormatError as exc:
            # Once exact MOKOSH2 magic is present, altered authenticated bytes
            # and a wrong profile share one user-visible refusal.
            raise _LocalRefusal(LocalV2ErrorCode.AUTHENTICATION_FAILED) from exc
        except OperationCancelled:
            raise
        except Exception as exc:
            core = classify_operation_error(exc)
            code = _CORE_ERROR_MAP.get(core, LocalV2ErrorCode.INTERNAL_ERROR)
            raise _LocalRefusal(
                code,
                retryable=core
                in {
                    OperationErrorCode.SOURCE_CHANGED,
                    OperationErrorCode.IO_FAILED,
                },
            ) from exc
        if (
            len(inspection.slots) != 1
            or type(inspection.slots[0]) is not KeyVaultSlot
        ):
            raise _LocalRefusal(LocalV2ErrorCode.UNSUPPORTED_ENVELOPE)
        return source_identity, inspection.slots[0]

    def decrypt(
        self,
        *,
        source_path: Any,
        output_path: Any,
        cancellation: CancellationToken | None = None,
        observer: ProgressObserver | None = None,
    ) -> LocalV2Result:
        review: ResidueReview | None = None
        directory: str | None = None
        try:
            _require_linux()
            token = CancellationToken() if cancellation is None else cancellation
            if type(token) is not CancellationToken:
                raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
            source = _text_path(source_path)
            output, directory, review = self._preflight_output(
                output_path,
                require_mok2_suffix=False,
                cancellation=token,
            )
            if review.state is not ResidueReviewState.CLEAR:
                raise _LocalRefusal(LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED)
            with self._session._begin_local_v2_operation(token) as lease:
                review = _review(directory, token)
                if review.state is not ResidueReviewState.CLEAR:
                    raise _LocalRefusal(
                        LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED
                    )
                source_identity, slot = self._inspect_local_unsigned(source, token)
                try:
                    credential = lease.credential_for_version(
                        slot.vault_key_version
                    )
                except VaultKeyringError as exc:
                    raise _LocalRefusal(
                        LocalV2ErrorCode.AUTHENTICATION_FAILED
                    ) from exc
                outcome = run_decryption_operation(
                    source_path=source,
                    output_path=output,
                    verification=RequireUnsignedEnvelope(),
                    selected_slot_id=slot.slot_id,
                    credential=credential,
                    expected_source_identity=source_identity,
                    cancellation=token,
                    observer=observer,
                )
        except _LocalRefusal as exc:
            return _failure(exc.code, retryable=exc.retryable, residue=review)
        except OperationCancelled:
            return _failure(LocalV2ErrorCode.CANCELLED, retryable=True, residue=review)
        except ProfileOperationBusyError:
            return _failure(LocalV2ErrorCode.OPERATION_BUSY, residue=review)
        except ProfileSessionError:
            return _failure(LocalV2ErrorCode.SESSION_UNAVAILABLE, residue=review)
        except LocalV2ServiceError:
            return _failure(LocalV2ErrorCode.IO_FAILED, residue=review)
        except Exception:
            return _failure(LocalV2ErrorCode.INTERNAL_ERROR, residue=review)

        final_review = _post_review(directory)
        if not outcome.ok:
            assert outcome.failure is not None
            if outcome.failure.code in {
                OperationErrorCode.AUTHENTICATION_FAILED,
                OperationErrorCode.INVALID_INPUT,
                OperationErrorCode.VERIFICATION_FAILED,
            }:
                return _failure(
                    LocalV2ErrorCode.AUTHENTICATION_FAILED,
                    residue=final_review,
                )
            return _core_failure(outcome.failure, final_review)
        warning = None
        if outcome.warning is not None or final_review.state is not ResidueReviewState.CLEAR:
            warning = SafeLocalV2Warning(
                LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED,
                "local_v2.warning.published_review_required",
            )
        return LocalV2Result(ok=True, warning=warning, residue=final_review)

    def cleanup_reviewed_residue(
        self,
        *,
        directory: Any,
        reviewed: ResidueReview,
        operation_id: Any,
        decision: CleanupUserDecision,
        cancellation: CancellationToken | None = None,
    ) -> LocalV2Result:
        try:
            _require_linux()
            path = _text_path(directory)
            if (
                type(reviewed) is not ResidueReview
                or reviewed.state is not ResidueReviewState.CLEANABLE
                or reviewed.evidence is None
                or type(operation_id) is not str
                or operation_id not in reviewed.cleanup_operation_ids
                or decision is not CleanupUserDecision.AUTHORIZE_CLEANUP
            ):
                raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
            token = CancellationToken() if cancellation is None else cancellation
            if type(token) is not CancellationToken:
                raise _LocalRefusal(LocalV2ErrorCode.INVALID_SELECTION)
            with self._session._begin_local_v2_cleanup_operation(token):
                token.checkpoint()
                prepared = prepare_cleanup_authorization(
                    path,
                    reviewed.evidence,
                    operation_id,
                    decision,
                )
                # Cancellation is honored before the cleanup executor can
                # perform its first unlink.  Once execution begins, its exact
                # one-shot pair removal must reach a bounded terminal result.
                token.checkpoint()
                execution = execute_cleanup(path, prepared)
        except _LocalRefusal as exc:
            return _failure(
                exc.code,
                retryable=exc.retryable,
                residue=reviewed if type(reviewed) is ResidueReview else None,
            )
        except OperationCancelled:
            return _failure(
                LocalV2ErrorCode.CANCELLED,
                retryable=True,
                residue=reviewed if type(reviewed) is ResidueReview else None,
            )
        except ProfileOperationBusyError:
            return _failure(
                LocalV2ErrorCode.OPERATION_BUSY,
                residue=reviewed if type(reviewed) is ResidueReview else None,
            )
        except ProfileSessionError:
            return _failure(
                LocalV2ErrorCode.SESSION_UNAVAILABLE,
                residue=reviewed if type(reviewed) is ResidueReview else None,
            )
        except (CleanupAuthorizationError, CleanupExecutionError):
            return _failure(LocalV2ErrorCode.CLEANUP_FAILED, residue=_post_review(path))
        except Exception:
            return _failure(LocalV2ErrorCode.INTERNAL_ERROR)

        final_review = _post_review(path)
        warning = None
        if (
            execution.status is not CleanupExecutionStatus.COMPLETED
            or final_review.state is not ResidueReviewState.CLEAR
        ):
            warning = SafeLocalV2Warning(
                LocalV2WarningCode.CLEANUP_REVIEW_REQUIRED,
                "local_v2.warning.cleanup_review_required",
            )
        return LocalV2Result(
            ok=True,
            warning=warning,
            residue=final_review,
            cleanup_status=execution.status,
        )


__all__ = [
    "MAX_LOCAL_V2_DIRECTORY_ENTRIES",
    "LocalV2ErrorCode",
    "LocalV2Result",
    "LocalV2Service",
    "LocalV2ServiceError",
    "LocalV2WarningCode",
    "ResidueReview",
    "ResidueReviewState",
    "SafeLocalV2Failure",
    "SafeLocalV2Warning",
    "propose_decrypted_name",
    "propose_encrypted_name",
]
