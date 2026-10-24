"""Read-only discovery of MOKOSH v2 operation journals and quarantine files.

This module never deletes, renames, publishes, decrypts, recovers, or writes a
file.  A matched journal is only a reconciliation finding.  It is not proof
that the operation is abandoned and does not authorize cleanup.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_v2_operation_journal import (
    JOURNAL_NAME_PREFIX,
    MAX_JOURNAL_SIZE,
    PRIVATE_FILE_MODE,
    TEMP_NAME_PREFIX,
    OperationJournalError,
    decode_operation_journal,
    journal_name_for,
    operation_id_from_journal_name,
    operation_id_from_temporary_name,
    temporary_name_for,
)


class ReconciliationError(OSError):
    """A read-only reconciliation snapshot cannot be trusted."""


class UnsafeReconciliationDirectory(ReconciliationError):
    """The requested directory is not a private stable real directory."""


class ReconciliationDirectoryChanged(ReconciliationError):
    """The directory changed while the read-only snapshot was collected."""


class ReconciliationStatus(str, Enum):
    RECORDED_INODE_MATCH = "recorded_inode_match"
    TEMPORARY_MISSING = "temporary_missing"
    TEMPORARY_IDENTITY_MISMATCH = "temporary_identity_mismatch"
    TEMPORARY_LINK_COUNT_CHANGED = "temporary_link_count_changed"
    INVALID_JOURNAL = "invalid_journal"
    UNSAFE_JOURNAL = "unsafe_journal"
    UNRECORDED_TEMPORARY = "unrecorded_temporary"


@dataclass(frozen=True, slots=True)
class ReconciliationFinding:
    status: ReconciliationStatus
    operation_id: str | None
    journal_name: str | None
    temporary_name: str | None
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if self.mutation_permitted:
            raise ReconciliationError("Stage 1.19 findings are always read-only")


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    findings: tuple[ReconciliationFinding, ...]
    scanned_entries: int
    directory_device: int
    directory_inode: int
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if self.mutation_permitted:
            raise ReconciliationError("Stage 1.19 reports are always read-only")
        if type(self.scanned_entries) is not int or self.scanned_entries < 0:
            raise ReconciliationError("scanned_entries must be non-negative")
        for field, value in (
            ("directory_device", self.directory_device),
            ("directory_inode", self.directory_inode),
        ):
            if type(value) is not int or not 0 <= value < (1 << 64):
                raise ReconciliationError(f"{field} must be a bounded integer")


def _path_text(value: Any) -> str:
    try:
        path = os.fspath(value)
    except TypeError as exc:
        raise UnsafeReconciliationDirectory("directory must be path-like") from exc
    if isinstance(path, bytes):
        raise UnsafeReconciliationDirectory("directory must be a text path")
    if not isinstance(path, str) or not path or "\x00" in path:
        raise UnsafeReconciliationDirectory("directory path is invalid")
    return os.path.abspath(path)


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _read_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        getattr(value, "st_uid", 0),
        getattr(value, "st_gid", 0),
        value.st_nlink,
    )


def _open_private_directory(path: str) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise UnsafeReconciliationDirectory("cannot inspect directory") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise UnsafeReconciliationDirectory("directory must be real")
    if hasattr(os, "getuid"):
        if before.st_uid != os.getuid():
            raise UnsafeReconciliationDirectory("directory owner is invalid")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UnsafeReconciliationDirectory("directory is publicly writable")
    try:
        descriptor = os.open(path, _directory_flags())
    except OSError as exc:
        raise UnsafeReconciliationDirectory("cannot securely open directory") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if _identity(before) != _identity(opened) or _identity(before) != _identity(current):
            raise UnsafeReconciliationDirectory("directory changed while opening")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, before


def _private_regular_journal(value: os.stat_result) -> bool:
    if not stat.S_ISREG(value.st_mode):
        return False
    if stat.S_IMODE(value.st_mode) != PRIVATE_FILE_MODE or value.st_nlink != 1:
        return False
    if hasattr(os, "getuid") and value.st_uid != os.getuid():
        return False
    return 0 < value.st_size <= MAX_JOURNAL_SIZE


def _read_journal(directory_fd: int, name: str) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise ReconciliationError("journal is unavailable") from exc
    if not _private_regular_journal(before):
        raise UnsafeReconciliationDirectory("journal metadata is unsafe")
    try:
        descriptor = os.open(name, _read_flags(), dir_fd=directory_fd)
    except OSError as exc:
        raise ReconciliationError("journal cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise ReconciliationError("journal changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_JOURNAL_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after_opened = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _identity(opened) != _identity(after_opened) or _identity(opened) != _identity(after_path):
            raise ReconciliationError("journal changed while reading")
    finally:
        os.close(descriptor)
    if len(data) > MAX_JOURNAL_SIZE:
        raise ReconciliationError("journal exceeds its read limit")
    return data


def _journal_finding(
    directory_fd: int,
    directory_stat: os.stat_result,
    name: str,
) -> tuple[ReconciliationFinding, str | None]:
    operation_id: str | None = None
    try:
        operation_id = operation_id_from_journal_name(name)
    except OperationJournalError:
        return (
            ReconciliationFinding(
                ReconciliationStatus.INVALID_JOURNAL,
                None,
                name,
                None,
            ),
            None,
        )
    try:
        data = _read_journal(directory_fd, name)
    except UnsafeReconciliationDirectory:
        return (
            ReconciliationFinding(
                ReconciliationStatus.UNSAFE_JOURNAL,
                operation_id,
                name,
                temporary_name_for(operation_id),
            ),
            None,
        )
    except ReconciliationError:
        return (
            ReconciliationFinding(
                ReconciliationStatus.INVALID_JOURNAL,
                operation_id,
                name,
                temporary_name_for(operation_id),
            ),
            None,
        )
    try:
        record = decode_operation_journal(data)
        if record.operation_id != operation_id:
            raise OperationJournalError("journal filename and record differ")
        if journal_name_for(operation_id) != name:
            raise OperationJournalError("journal filename is not canonical")
        if record.parent_device != directory_stat.st_dev:
            raise OperationJournalError("journal parent device differs")
        if record.parent_inode != directory_stat.st_ino:
            raise OperationJournalError("journal parent inode differs")
    except OperationJournalError:
        return (
            ReconciliationFinding(
                ReconciliationStatus.INVALID_JOURNAL,
                operation_id,
                name,
                temporary_name_for(operation_id),
            ),
            None,
        )

    temp_name = record.temporary_name
    try:
        current = os.stat(
            temp_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return (
            ReconciliationFinding(
                ReconciliationStatus.TEMPORARY_MISSING,
                operation_id,
                name,
                temp_name,
            ),
            temp_name,
        )
    except OSError:
        return (
            ReconciliationFinding(
                ReconciliationStatus.TEMPORARY_IDENTITY_MISMATCH,
                operation_id,
                name,
                temp_name,
            ),
            temp_name,
        )

    exact_metadata = (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == record.temp_device
        and current.st_ino == record.temp_inode
        and stat.S_IMODE(current.st_mode) == record.mode
        and getattr(current, "st_uid", 0) == record.owner_uid
        and getattr(current, "st_gid", 0) == record.owner_gid
    )
    if not exact_metadata:
        status = ReconciliationStatus.TEMPORARY_IDENTITY_MISMATCH
    elif current.st_nlink != record.initial_links:
        status = ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED
    else:
        status = ReconciliationStatus.RECORDED_INODE_MATCH
    return (
        ReconciliationFinding(status, operation_id, name, temp_name),
        temp_name,
    )


def scan_quarantine_directory(directory: Any) -> ReconciliationReport:
    """Collect one stable read-only snapshot of explicit directory contents."""

    path = _path_text(directory)
    descriptor, directory_before = _open_private_directory(path)
    try:
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise ReconciliationError("cannot enumerate directory") from exc
        findings: list[ReconciliationFinding] = []
        referenced_temporaries: set[str] = set()
        for name in names:
            if name.startswith(JOURNAL_NAME_PREFIX):
                finding, referenced = _journal_finding(
                    descriptor,
                    directory_before,
                    name,
                )
                findings.append(finding)
                if referenced is not None:
                    referenced_temporaries.add(referenced)
        for name in names:
            if not name.startswith(TEMP_NAME_PREFIX):
                continue
            if name in referenced_temporaries:
                continue
            operation_id: str | None
            try:
                operation_id = operation_id_from_temporary_name(name)
            except OperationJournalError:
                operation_id = None
            findings.append(
                ReconciliationFinding(
                    ReconciliationStatus.UNRECORDED_TEMPORARY,
                    operation_id,
                    None,
                    name,
                )
            )
        after_opened = os.fstat(descriptor)
        after_path = os.lstat(path)
        if _identity(directory_before) != _identity(after_opened):
            raise ReconciliationDirectoryChanged("directory changed during scan")
        if _identity(directory_before) != _identity(after_path):
            raise ReconciliationDirectoryChanged("directory path changed during scan")
    finally:
        os.close(descriptor)
    findings.sort(
        key=lambda item: (
            item.journal_name or "",
            item.temporary_name or "",
            item.status.value,
        )
    )
    return ReconciliationReport(
        tuple(findings),
        len(names),
        directory_before.st_dev,
        directory_before.st_ino,
    )
