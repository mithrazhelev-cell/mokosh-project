"""Strict, one-shot cleanup executor for verified quarantine artifacts.

Stage 1.23 is intentionally narrow.  It consumes one prepared Stage 1.22
authorization, acquires and retains the exact journal lease, repeats the full
read-only evidence scan, and can unlink only the canonically bound temporary
inode followed by its journal.  It cannot name or reach a source or output
file.

The authorization is a process-local misuse-prevention contract, not a
cryptographic capability against arbitrary code execution.  The private
directory and current-user account remain part of the security boundary.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_v2_cleanup_authorization import (
    CleanupAuthorizationClaim,
    CleanupAuthorizationError,
    PreparedCleanupAuthorization,
)
from mokosh_v2_operation_journal import (
    MAX_JOURNAL_SIZE,
    OperationJournalError,
    decode_operation_journal,
    journal_name_for,
    temporary_name_for,
)
from mokosh_v2_operation_lease import LeaseProbeStatus, probe_operation_lease
from mokosh_v2_reconciliation import (
    ReconciliationError,
    _identity,
    _open_private_directory,
    _path_text,
    _private_regular_journal,
    scan_quarantine_directory,
)
from mokosh_v2_reconciliation_evidence import (
    MAX_EVIDENCE_ITEMS,
    EvidenceClassification,
    ReconciliationEvidenceError,
    build_reconciliation_evidence,
    reconciliation_evidence_sha256,
)


class CleanupExecutionError(OSError):
    """Cleanup was refused before any filesystem mutation."""


class CleanupExecutionStatus(str, Enum):
    COMPLETED = "completed"
    TEMPORARY_REMOVED_JOURNAL_RETAINED = "temporary_removed_journal_retained"
    PAIR_REMOVED_FINAL_SYNC_UNCERTAIN = "pair_removed_final_sync_uncertain"


@dataclass(frozen=True, slots=True)
class CleanupExecutionResult:
    operation_id: str
    authorization_id: str
    status: CleanupExecutionStatus
    temporary_removed: bool
    journal_removed: bool
    rescan_required: bool
    original_touched: bool = False
    output_touched: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, CleanupExecutionStatus):
            raise CleanupExecutionError("cleanup result status is invalid")
        if type(self.temporary_removed) is not bool:
            raise CleanupExecutionError("temporary result flag is invalid")
        if type(self.journal_removed) is not bool:
            raise CleanupExecutionError("journal result flag is invalid")
        if type(self.rescan_required) is not bool:
            raise CleanupExecutionError("rescan result flag is invalid")
        expected = {
            CleanupExecutionStatus.COMPLETED: (True, True, False),
            CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED: (
                True,
                False,
                True,
            ),
            CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN: (
                True,
                True,
                True,
            ),
        }[self.status]
        if (
            self.temporary_removed,
            self.journal_removed,
            self.rescan_required,
        ) != expected:
            raise CleanupExecutionError("cleanup result flags are inconsistent")
        if self.original_touched is not False or self.output_touched is not False:
            raise CleanupExecutionError("cleanup cannot report user-file mutation")


def _journal_open_flags() -> int:
    flags = os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _read_locked_journal(descriptor: int) -> tuple[Any, os.stat_result]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if not _private_regular_journal(before):
            raise CleanupExecutionError("journal metadata is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_JOURNAL_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CleanupExecutionError("journal cannot be read safely") from exc
    if _identity(before) != _identity(after):
        raise CleanupExecutionError("journal changed while reading")
    if not data or len(data) > MAX_JOURNAL_SIZE:
        raise CleanupExecutionError("journal size is invalid")
    try:
        return decode_operation_journal(data), before
    except OperationJournalError as exc:
        raise CleanupExecutionError("journal encoding is invalid") from exc


def _exact_temp_stat(directory_fd: int, record: Any) -> os.stat_result:
    try:
        current = os.stat(
            record.temporary_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise CleanupExecutionError("temporary inode is unavailable") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != record.temp_device
        or current.st_ino != record.temp_inode
        or stat.S_IMODE(current.st_mode) != record.mode
        or getattr(current, "st_uid", 0) != record.owner_uid
        or getattr(current, "st_gid", 0) != record.owner_gid
        or current.st_nlink != record.initial_links
    ):
        raise CleanupExecutionError("temporary inode identity is inconsistent")
    return current


def _strict_directory_sync(directory_fd: int) -> None:
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise CleanupExecutionError("durable directory synchronization failed") from exc


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    """Identity fields that are not changed by unlinking a child entry."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        getattr(value, "st_uid", 0),
        getattr(value, "st_gid", 0),
        value.st_nlink,
    )


def _verify_directory(path: str, directory_fd: int, expected: os.stat_result) -> None:
    try:
        opened = os.fstat(directory_fd)
        current = os.lstat(path)
    except OSError as exc:
        raise CleanupExecutionError("directory identity cannot be revalidated") from exc
    if (
        _directory_identity(expected) != _directory_identity(opened)
        or _directory_identity(expected) != _directory_identity(current)
    ):
        raise CleanupExecutionError("directory identity changed")


def _verify_journal_path(
    directory_fd: int,
    journal_name: str,
    expected: os.stat_result,
    lease_descriptor: int,
) -> None:
    try:
        current = os.stat(
            journal_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        held = os.fstat(lease_descriptor)
    except OSError as exc:
        raise CleanupExecutionError("journal identity cannot be revalidated") from exc
    if _identity(expected) != _identity(current) or _identity(expected) != _identity(held):
        raise CleanupExecutionError("journal identity changed")


def _validate_fresh_evidence(
    path: str,
    claim: CleanupAuthorizationClaim,
) -> None:
    try:
        report = build_reconciliation_evidence(
            scan_quarantine_directory(path),
            max_items=MAX_EVIDENCE_ITEMS,
        )
        digest = reconciliation_evidence_sha256(report)
    except (OSError, ReconciliationError, ReconciliationEvidenceError) as exc:
        raise CleanupExecutionError("executor reconciliation scan failed") from exc
    if (
        not report.complete
        or report.omitted_findings != 0
        or report.directory_device != claim.directory_device
        or report.directory_inode != claim.directory_inode
        or digest != claim.evidence_sha256
        or claim.evidence_sequence >= len(report.items)
    ):
        raise CleanupExecutionError("executor evidence differs from authorization")
    item = report.items[claim.evidence_sequence]
    if (
        item.operation_id != claim.operation_id
        or item.classification is not EvidenceClassification.INODE_MATCH
        or item.identity_prerequisite_met is not True
        or item.user_decision_required is not True
        or item.rescan_required is not True
        or item.mutation_permitted is not False
    ):
        raise CleanupExecutionError("authorized evidence item is no longer eligible")


def _result(
    claim: CleanupAuthorizationClaim,
    status: CleanupExecutionStatus,
) -> CleanupExecutionResult:
    flags = {
        CleanupExecutionStatus.COMPLETED: (True, True, False),
        CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED: (
            True,
            False,
            True,
        ),
        CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN: (
            True,
            True,
            True,
        ),
    }[status]
    return CleanupExecutionResult(
        claim.operation_id,
        claim.authorization_id,
        status,
        flags[0],
        flags[1],
        flags[2],
    )


def execute_cleanup(
    directory: Any,
    authorization: PreparedCleanupAuthorization,
) -> CleanupExecutionResult:
    """Consume one authorization and remove only its exact owned pair."""

    if not isinstance(authorization, PreparedCleanupAuthorization):
        raise CleanupExecutionError("prepared cleanup authorization is required")
    try:
        claim = authorization.claim_once()
    except CleanupAuthorizationError as exc:
        raise CleanupExecutionError("cleanup authorization cannot be claimed") from exc

    path = _path_text(directory)
    directory_fd: int | None = None
    descriptor: int | None = None
    lease = None
    temporary_removed = False
    journal_removed = False
    try:
        directory_fd, directory_before = _open_private_directory(path)
        if (
            directory_before.st_dev != claim.directory_device
            or directory_before.st_ino != claim.directory_inode
        ):
            raise CleanupExecutionError("authorization directory identity differs")

        journal_name = journal_name_for(claim.operation_id)
        temporary_name = temporary_name_for(claim.operation_id)
        try:
            journal_before = os.stat(
                journal_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if not _private_regular_journal(journal_before):
                raise CleanupExecutionError("journal metadata is unsafe")
            descriptor = os.open(
                journal_name,
                _journal_open_flags(),
                dir_fd=directory_fd,
            )
            if _identity(journal_before) != _identity(os.fstat(descriptor)):
                raise CleanupExecutionError("journal changed while opening")
        except OSError as exc:
            raise CleanupExecutionError("journal cannot be opened safely") from exc

        probe = probe_operation_lease(descriptor)
        descriptor = None
        if (
            probe.status is not LeaseProbeStatus.ACQUIRED
            or probe.lease is None
            or probe.backend is not claim.lease_backend
        ):
            raise CleanupExecutionError("exact operation lease is unavailable")
        lease = probe.lease

        record, journal_opened = _read_locked_journal(lease.fileno())
        if (
            record.operation_id != claim.operation_id
            or record.temporary_name != temporary_name
            or record.parent_device != claim.directory_device
            or record.parent_inode != claim.directory_inode
            or _identity(journal_before) != _identity(journal_opened)
        ):
            raise CleanupExecutionError("journal binding differs from authorization")
        temp_before = _exact_temp_stat(directory_fd, record)

        _validate_fresh_evidence(path, claim)
        _verify_directory(path, directory_fd, directory_before)
        _verify_journal_path(
            directory_fd,
            journal_name,
            journal_before,
            lease.fileno(),
        )
        if _identity(temp_before) != _identity(_exact_temp_stat(directory_fd, record)):
            raise CleanupExecutionError("temporary inode changed before cleanup")

        # Capability preflight: never start mutation if directory durability is
        # unsupported.  The same strict sync is repeated after each unlink.
        _strict_directory_sync(directory_fd)
        _verify_directory(path, directory_fd, directory_before)
        _verify_journal_path(
            directory_fd,
            journal_name,
            journal_before,
            lease.fileno(),
        )
        if _identity(temp_before) != _identity(_exact_temp_stat(directory_fd, record)):
            raise CleanupExecutionError("temporary inode changed at cleanup boundary")

        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_removed = True
        try:
            _strict_directory_sync(directory_fd)
            _verify_directory(path, directory_fd, directory_before)
            _verify_journal_path(
                directory_fd,
                journal_name,
                journal_before,
                lease.fileno(),
            )
            try:
                os.stat(
                    temporary_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise CleanupExecutionError("temporary name unexpectedly reappeared")
        except Exception:
            return _result(
                claim,
                CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED,
            )

        os.unlink(journal_name, dir_fd=directory_fd)
        journal_removed = True
        try:
            _strict_directory_sync(directory_fd)
            _verify_directory(path, directory_fd, directory_before)
            os.fstat(lease.fileno())
        except Exception:
            return _result(
                claim,
                CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN,
            )
        return _result(claim, CleanupExecutionStatus.COMPLETED)
    except CleanupExecutionError:
        if temporary_removed:
            status = (
                CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN
                if journal_removed
                else CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED
            )
            return _result(claim, status)
        raise
    except OSError as exc:
        if temporary_removed:
            status = (
                CleanupExecutionStatus.PAIR_REMOVED_FINAL_SYNC_UNCERTAIN
                if journal_removed
                else CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED
            )
            return _result(claim, status)
        raise CleanupExecutionError("cleanup execution failed before mutation") from exc
    finally:
        if lease is not None:
            try:
                lease.close()
            except OSError:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
