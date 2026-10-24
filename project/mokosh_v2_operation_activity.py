"""Lease-backed, non-mutating activity assessment for operation journals.

The assessment revalidates an exact journal/temporary pair and observes the
OS-managed journal lease.  A released lease only means that no cooperating
writer held the lease at that instant.  It is not proof of authenticity or
abandonment and never grants cleanup permission.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_v2_operation_journal import (
    MAX_JOURNAL_SIZE,
    OperationJournalError,
    decode_operation_journal,
    journal_name_for,
    temporary_name_for,
    validate_operation_id,
)
from mokosh_v2_operation_lease import (
    LeaseProbeStatus,
    OperationLeaseBackend,
    probe_operation_lease,
)
from mokosh_v2_reconciliation import (
    ReconciliationError,
    _identity,
    _open_private_directory,
    _path_text,
    _private_regular_journal,
)


class OperationActivityError(ReconciliationError):
    """An operation activity assessment cannot be accepted safely."""


class OperationActivityStatus(str, Enum):
    ACTIVE = "active"
    RELEASED_CANDIDATE = "released_candidate"
    LEASE_UNSUPPORTED = "lease_unsupported"
    IDENTITY_CONFLICT = "identity_conflict"


@dataclass(frozen=True, slots=True)
class OperationActivityAssessment:
    operation_id: str
    status: OperationActivityStatus
    backend: OperationLeaseBackend | None
    exact_identity_verified: bool
    active_writer_observed: bool
    cooperating_writer_absent: bool
    user_decision_required: bool = True
    rescan_required: bool = True
    abandonment_proven: bool = False
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        try:
            validate_operation_id(self.operation_id)
        except OperationJournalError as exc:
            raise OperationActivityError("assessment operation_id is invalid") from exc
        if not isinstance(self.status, OperationActivityStatus):
            raise OperationActivityError("activity status is invalid")
        if self.backend is not None and not isinstance(
            self.backend,
            OperationLeaseBackend,
        ):
            raise OperationActivityError("activity backend is invalid")
        for field, value in (
            ("exact_identity_verified", self.exact_identity_verified),
            ("active_writer_observed", self.active_writer_observed),
            ("cooperating_writer_absent", self.cooperating_writer_absent),
        ):
            if type(value) is not bool:
                raise OperationActivityError(f"{field} must be boolean")
        expected = {
            OperationActivityStatus.ACTIVE: (True, True, False),
            OperationActivityStatus.RELEASED_CANDIDATE: (True, False, True),
            OperationActivityStatus.LEASE_UNSUPPORTED: (True, False, False),
            OperationActivityStatus.IDENTITY_CONFLICT: (False, False, False),
        }[self.status]
        actual = (
            self.exact_identity_verified,
            self.active_writer_observed,
            self.cooperating_writer_absent,
        )
        if actual != expected:
            raise OperationActivityError("activity status flags are inconsistent")
        if self.user_decision_required is not True:
            raise OperationActivityError("user decision must remain required")
        if self.rescan_required is not True:
            raise OperationActivityError("rescan must remain required")
        if self.abandonment_proven is not False:
            raise OperationActivityError("lease observation cannot prove abandonment")
        if self.mutation_permitted is not False:
            raise OperationActivityError("activity assessment never permits mutation")


def _lease_open_flags() -> int:
    flags = os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _read_exact_journal(descriptor: int) -> tuple[bytes, os.stat_result]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if not _private_regular_journal(before):
            raise OperationActivityError("journal metadata is unsafe")
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
        raise OperationActivityError("journal cannot be read safely") from exc
    if _identity(before) != _identity(after):
        raise OperationActivityError("journal changed while reading")
    if not data or len(data) > MAX_JOURNAL_SIZE:
        raise OperationActivityError("journal size is invalid")
    return data, before


def _exact_temp_stat(
    directory_fd: int,
    record: Any,
) -> os.stat_result:
    try:
        current = os.stat(
            record.temporary_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise OperationActivityError("temporary inode is unavailable") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != record.temp_device
        or current.st_ino != record.temp_inode
        or stat.S_IMODE(current.st_mode) != record.mode
        or getattr(current, "st_uid", 0) != record.owner_uid
        or getattr(current, "st_gid", 0) != record.owner_gid
        or current.st_nlink != record.initial_links
    ):
        raise OperationActivityError("temporary inode identity is inconsistent")
    return current


def _assessment(
    operation_id: str,
    status: OperationActivityStatus,
    backend: OperationLeaseBackend | None,
) -> OperationActivityAssessment:
    flags = {
        OperationActivityStatus.ACTIVE: (True, True, False),
        OperationActivityStatus.RELEASED_CANDIDATE: (True, False, True),
        OperationActivityStatus.LEASE_UNSUPPORTED: (True, False, False),
        OperationActivityStatus.IDENTITY_CONFLICT: (False, False, False),
    }[status]
    return OperationActivityAssessment(
        operation_id=operation_id,
        status=status,
        backend=backend,
        exact_identity_verified=flags[0],
        active_writer_observed=flags[1],
        cooperating_writer_absent=flags[2],
    )


def assess_operation_activity(
    directory: Any,
    operation_id: Any,
) -> OperationActivityAssessment:
    """Observe one exact pair and lease without changing filesystem contents."""

    try:
        exact_id = validate_operation_id(operation_id)
    except OperationJournalError as exc:
        raise OperationActivityError("operation_id is invalid") from exc
    path = _path_text(directory)
    directory_fd, directory_before = _open_private_directory(path)
    journal_name = journal_name_for(exact_id)
    temp_name = temporary_name_for(exact_id)
    descriptor: int | None = None
    probe = None
    journal_before = None
    temp_before = None
    try:
        try:
            journal_before = os.stat(
                journal_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if not _private_regular_journal(journal_before):
                raise OperationActivityError("journal metadata is unsafe")
            descriptor = os.open(
                journal_name,
                _lease_open_flags(),
                dir_fd=directory_fd,
            )
            opened = os.fstat(descriptor)
            if _identity(journal_before) != _identity(opened):
                raise OperationActivityError("journal changed while opening")
            data, journal_opened = _read_exact_journal(descriptor)
            if _identity(opened) != _identity(journal_opened):
                raise OperationActivityError("journal changed before lease probe")
            record = decode_operation_journal(data)
            if (
                record.operation_id != exact_id
                or record.temporary_name != temp_name
                or record.parent_device != directory_before.st_dev
                or record.parent_inode != directory_before.st_ino
            ):
                raise OperationActivityError("journal binding is inconsistent")
            temp_before = _exact_temp_stat(directory_fd, record)
        except (OSError, OperationJournalError, OperationActivityError):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                descriptor = None
            return _assessment(
                exact_id,
                OperationActivityStatus.IDENTITY_CONFLICT,
                None,
            )

        probe = probe_operation_lease(descriptor)
        descriptor = None
        backend = probe.backend
        if probe.status is LeaseProbeStatus.ERROR:
            return _assessment(
                exact_id,
                OperationActivityStatus.IDENTITY_CONFLICT,
                backend,
            )

        try:
            directory_opened = os.fstat(directory_fd)
            directory_current = os.lstat(path)
            journal_current = os.stat(
                journal_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            temp_current = os.stat(
                temp_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                _identity(directory_before) != _identity(directory_opened)
                or _identity(directory_before) != _identity(directory_current)
                or _identity(journal_before) != _identity(journal_current)
                or _identity(temp_before) != _identity(temp_current)
            ):
                raise OperationActivityError("operation identity changed during probe")
            if probe.lease is not None:
                held_current = os.fstat(probe.lease.fileno())
                if _identity(journal_before) != _identity(held_current):
                    raise OperationActivityError("held journal identity changed")
        except (OSError, OperationActivityError):
            return _assessment(
                exact_id,
                OperationActivityStatus.IDENTITY_CONFLICT,
                backend,
            )

        if probe.status is LeaseProbeStatus.HELD_BY_OTHER:
            return _assessment(exact_id, OperationActivityStatus.ACTIVE, backend)
        if probe.status is LeaseProbeStatus.UNSUPPORTED:
            return _assessment(
                exact_id,
                OperationActivityStatus.LEASE_UNSUPPORTED,
                backend,
            )
        if probe.status is LeaseProbeStatus.ACQUIRED:
            return _assessment(
                exact_id,
                OperationActivityStatus.RELEASED_CANDIDATE,
                backend,
            )
        return _assessment(
            exact_id,
            OperationActivityStatus.IDENTITY_CONFLICT,
            backend,
        )
    finally:
        if probe is not None and probe.lease is not None:
            probe.lease.close()
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)
