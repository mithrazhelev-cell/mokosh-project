"""Durable no-clobber export and read-only import for Vault recovery records.

This POSIX-only integration writes the encrypted Stage 2.4 recovery record to
one explicitly selected private directory.  It never writes the recovery key.
Every export is bound to the exact latest durable Vault receipt and is read
back before durable success.  Import is strictly bounded and read-only, and it
returns only non-secret rehearsal evidence.

The module performs no Vault publish, password reset, key rotation, migration,
key deletion, user-file operation, network access, logging, GUI work, software
update discovery, or automatic recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Any

from mokosh_vault_format import VaultError, VaultSession, VaultSessionState
from mokosh_vault_recovery import (
    MAX_RECOVERY_CIPHERTEXT_LEN,
    MAX_RECOVERY_HEADER_LEN,
    RECOVERY_ID_LEN,
    RECOVERY_PREAMBLE_LEN,
    ParsedVaultRecoveryRecord,
    VaultRecoveryConflictError,
    VaultRecoveryError,
    VaultRecoveryRehearsal,
    VaultRecoverySetup,
    create_recovery_record,
    parse_recovery_record,
    rehearse_recovery,
)
from mokosh_vault_storage import (
    VaultGenerationReceipt,
    VaultStorage,
    VaultStorageError,
)


PRIVATE_RECOVERY_DIRECTORY_MODE = 0o700
PRIVATE_RECOVERY_FILE_MODE = 0o600
MAX_RECOVERY_FILE_BYTES = (
    RECOVERY_PREAMBLE_LEN
    + MAX_RECOVERY_HEADER_LEN
    + MAX_RECOVERY_CIPHERTEXT_LEN
)
RECOVERY_FILE_PREFIX = "mokosh-vault-recovery-"
RECOVERY_FILE_SUFFIX = ".mokr"

_RECOVERY_FILE_RE = re.compile(
    rf"^{re.escape(RECOVERY_FILE_PREFIX)}([0-9a-f]{{32}})"
    rf"{re.escape(RECOVERY_FILE_SUFFIX)}$"
)


class VaultRecoveryStorageError(VaultRecoveryError):
    """Base class for strict recovery filesystem integration failures."""


class UnsafeRecoveryDirectoryError(VaultRecoveryStorageError):
    """A recovery path, directory identity, owner, or mode is unsafe."""


class VaultRecoveryStorageStateError(VaultRecoveryStorageError):
    """The Vault storage or session is not the exact latest durable state."""


class RecoveryFileConflictError(VaultRecoveryStorageError):
    """A recovery file is conflicting, non-canonical, or not private."""


class RecoveryStorageLimitError(VaultRecoveryStorageError):
    """A recovery filesystem resource exceeds its strict bound."""


class RecoveryExportUnsupportedError(VaultRecoveryStorageError):
    """The platform cannot provide a required durable export primitive."""


class RecoveryExportUncertainError(VaultRecoveryStorageError):
    """An exported record may be visible but cannot be reported as success."""


class RecoverySourceChangedError(VaultRecoveryStorageError):
    """A recovery file or its directory changed during read-only import."""


@dataclass(frozen=True, slots=True)
class VaultRecoveryExportReceipt:
    directory_device: int
    directory_inode: int
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    source_vault_sha256: bytes
    record_sha256: bytes
    file_device: int
    file_inode: int
    encoded_size: int
    durable: bool = True

    def __copy__(self) -> None:
        raise TypeError("VaultRecoveryExportReceipt cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultRecoveryExportReceipt cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultRecoveryExportReceipt cannot be pickled")


@dataclass(frozen=True, slots=True)
class VaultRecoveryFileRehearsal:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    source_vault_sha256: bytes
    created_utc: str
    keyring_sha256: bytes
    active_key_version: int
    key_count: int
    record_sha256: bytes
    file_device: int
    file_inode: int
    encoded_size: int

    def __copy__(self) -> None:
        raise TypeError("VaultRecoveryFileRehearsal cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultRecoveryFileRehearsal cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultRecoveryFileRehearsal cannot be pickled")


@dataclass(frozen=True, slots=True)
class _ImportedRecoveryFile:
    record: bytes = field(repr=False)
    parsed: ParsedVaultRecoveryRecord
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    encoded_size: int
    record_sha256: bytes


def _exact_recovery_id(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryFileConflictError("recovery_id must be bytes")
    result = bytes(value)
    if len(result) != RECOVERY_ID_LEN:
        raise RecoveryFileConflictError(
            f"recovery_id must contain exactly {RECOVERY_ID_LEN} bytes"
        )
    return result


def recovery_record_name(recovery_id: Any) -> str:
    """Return the one canonical non-secret filename for a recovery ID."""

    return (
        RECOVERY_FILE_PREFIX
        + _exact_recovery_id(recovery_id).hex()
        + RECOVERY_FILE_SUFFIX
    )


def _path_text(value: Any, field_name: str) -> str:
    try:
        result = os.fspath(value)
    except TypeError as exc:
        raise UnsafeRecoveryDirectoryError(
            f"{field_name} must be a path"
        ) from exc
    if not isinstance(result, str) or not result or "\x00" in result:
        raise UnsafeRecoveryDirectoryError(
            f"{field_name} must be non-empty text"
        )
    absolute = os.path.abspath(result)
    if os.path.realpath(absolute) != absolute:
        raise UnsafeRecoveryDirectoryError(
            f"{field_name} must not contain symlinks"
        )
    return absolute


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise RecoveryExportUnsupportedError(
            f"required filesystem flag {name} is unavailable"
        )
    return value


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= _required_flag("O_DIRECTORY")
    flags |= _required_flag("O_CLOEXEC")
    flags |= _required_flag("O_NOFOLLOW")
    return flags


def _file_flags(*, write: bool = False) -> int:
    flags = os.O_RDWR if write else os.O_RDONLY
    flags |= _required_flag("O_CLOEXEC")
    flags |= _required_flag("O_NOFOLLOW")
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _read_file_flags() -> int:
    """Return non-blocking flags for a content-capable recovery read."""

    return _file_flags() | _required_flag("O_NONBLOCK")


def _create_flags() -> int:
    return (
        _file_flags(write=True)
        | _required_flag("O_CREAT")
        | _required_flag("O_EXCL")
    )


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _require_private_directory(value: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise UnsafeRecoveryDirectoryError(f"{label} must be a directory")
    if stat.S_IMODE(value.st_mode) != PRIVATE_RECOVERY_DIRECTORY_MODE:
        raise UnsafeRecoveryDirectoryError(
            f"{label} mode must be exactly 0700"
        )
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise UnsafeRecoveryDirectoryError(
            f"{label} must be owned by the current user"
        )


def _require_private_file(
    value: os.stat_result,
    label: str,
    *,
    allow_empty: bool = False,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise RecoveryFileConflictError(f"{label} must be a regular file")
    if stat.S_IMODE(value.st_mode) != PRIVATE_RECOVERY_FILE_MODE:
        raise RecoveryFileConflictError(f"{label} mode must be exactly 0600")
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise RecoveryFileConflictError(f"{label} owner is invalid")
    if value.st_nlink != 1:
        raise RecoveryFileConflictError(f"{label} link count must be one")
    minimum = 0 if allow_empty else 1
    if not minimum <= value.st_size <= MAX_RECOVERY_FILE_BYTES:
        raise RecoveryStorageLimitError(f"{label} size is outside its bound")


def _open_private_directory(path: Any, label: str) -> tuple[str, int, os.stat_result]:
    exact_path = _path_text(path, label)
    descriptor: int | None = None
    try:
        before = os.lstat(exact_path)
        descriptor = os.open(exact_path, _directory_flags())
        opened = os.fstat(descriptor)
        current = os.lstat(exact_path)
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise UnsafeRecoveryDirectoryError(
            f"cannot securely open {label}"
        ) from exc
    try:
        if not _same_inode(before, opened) or not _same_inode(opened, current):
            raise UnsafeRecoveryDirectoryError(
                f"{label} changed while opening"
            )
        _require_private_directory(before, label)
        _require_private_directory(opened, f"opened {label}")
        _require_private_directory(current, label)
    except BaseException:
        os.close(descriptor)
        raise
    return exact_path, descriptor, opened


def _verify_open_directory(
    path: str,
    descriptor: int,
    initial: os.stat_result,
    label: str,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
    except OSError as exc:
        raise UnsafeRecoveryDirectoryError(
            f"{label} is unavailable"
        ) from exc
    if not _same_inode(initial, opened) or not _same_inode(opened, current):
        raise UnsafeRecoveryDirectoryError(f"{label} identity changed")
    _require_private_directory(opened, f"opened {label}")
    _require_private_directory(current, label)
    return opened


def _close_descriptors(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_private_read_directory_chain(
    exact_path: str,
    label: str,
) -> tuple[str, tuple[int, ...], tuple[str, ...], tuple[os.stat_result, ...]]:
    """Open and retain every directory component leading to one read path."""

    parent = os.path.dirname(exact_path)
    components = tuple(item for item in parent.split(os.sep) if item)
    descriptors: list[int] = []
    opened_stats: list[os.stat_result] = []
    try:
        before_root = os.lstat(os.sep)
        root_descriptor = os.open(os.sep, _directory_flags())
        descriptors.append(root_descriptor)
        opened_root = os.fstat(root_descriptor)
        current_root = os.lstat(os.sep)
        if (
            not _same_inode(before_root, opened_root)
            or not _same_inode(opened_root, current_root)
            or not stat.S_ISDIR(opened_root.st_mode)
        ):
            raise UnsafeRecoveryDirectoryError(
                f"{label} root changed while opening"
            )
        opened_stats.append(opened_root)

        for component in components:
            parent_descriptor = descriptors[-1]
            before = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(before.st_mode):
                raise UnsafeRecoveryDirectoryError(
                    f"{label} must not contain symlinks or non-directories"
                )
            descriptor = os.open(
                component,
                _directory_flags(),
                dir_fd=parent_descriptor,
            )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            current = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not _same_inode(before, opened)
                or not _same_inode(opened, current)
                or not stat.S_ISDIR(opened.st_mode)
            ):
                raise UnsafeRecoveryDirectoryError(
                    f"{label} component changed while opening"
                )
            opened_stats.append(opened)

        _require_private_directory(opened_stats[-1], label)
    except OSError as exc:
        _close_descriptors(descriptors)
        raise UnsafeRecoveryDirectoryError(
            f"cannot securely open {label}"
        ) from exc
    except BaseException:
        _close_descriptors(descriptors)
        raise
    return exact_path, tuple(descriptors), components, tuple(opened_stats)


def _verify_private_read_directory_chain(
    descriptors: tuple[int, ...],
    components: tuple[str, ...],
    initial: tuple[os.stat_result, ...],
    label: str,
) -> os.stat_result:
    """Revalidate every retained directory link from root to private parent."""

    if (
        len(descriptors) != len(initial)
        or len(descriptors) != len(components) + 1
    ):
        raise UnsafeRecoveryDirectoryError(f"{label} chain is invalid")
    try:
        for index, descriptor in enumerate(descriptors):
            opened = os.fstat(descriptor)
            current = (
                os.lstat(os.sep)
                if index == 0
                else os.stat(
                    components[index - 1],
                    dir_fd=descriptors[index - 1],
                    follow_symlinks=False,
                )
            )
            if (
                not _same_inode(initial[index], opened)
                or not _same_inode(opened, current)
                or not stat.S_ISDIR(opened.st_mode)
            ):
                raise UnsafeRecoveryDirectoryError(
                    f"{label} identity changed"
                )
    except OSError as exc:
        raise UnsafeRecoveryDirectoryError(
            f"{label} is unavailable"
        ) from exc
    _require_private_directory(initial[-1], label)
    _require_private_directory(opened, f"opened {label}")
    _require_private_directory(current, label)
    return opened


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except (OSError, NotImplementedError) as exc:
        raise RecoveryExportUnsupportedError(
            "recovery directory fsync is unavailable"
        ) from exc


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset : offset + 64 * 1024])
        if not 1 <= written <= min(64 * 1024, len(data) - offset):
            raise RecoveryExportUnsupportedError(
                "recovery file write made invalid progress"
            )
        offset += written


def _read_exact_descriptor(descriptor: int, expected_size: int) -> bytes:
    if type(expected_size) is not int or not 1 <= expected_size <= MAX_RECOVERY_FILE_BYTES:
        raise RecoveryStorageLimitError(
            "recovery file size is outside its bound"
        )
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        requested = min(64 * 1024, expected_size - offset)
        try:
            chunk = os.pread(descriptor, requested, offset)
        except (AttributeError, OSError) as exc:
            raise RecoveryFileConflictError(
                "bounded recovery descriptor read is unavailable"
            ) from exc
        if not chunk:
            raise RecoverySourceChangedError(
                "recovery file became truncated while reading"
            )
        if len(chunk) > requested:
            raise RecoverySourceChangedError(
                "recovery descriptor read exceeded its bound"
            )
        chunks.append(chunk)
        offset += len(chunk)
    try:
        trailing = os.pread(descriptor, 1, expected_size)
    except (AttributeError, OSError) as exc:
        raise RecoveryFileConflictError(
            "bounded recovery descriptor read is unavailable"
        ) from exc
    if trailing:
        raise RecoverySourceChangedError("recovery file grew while reading")
    return b"".join(chunks)


def _mutation_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_uid,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _verified_latest_vault(
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
) -> bytes:
    if not isinstance(storage, VaultStorage):
        raise VaultRecoveryStorageStateError(
            "storage must be an open VaultStorage"
        )
    if not isinstance(latest, VaultGenerationReceipt):
        raise VaultRecoveryStorageStateError(
            "latest must be a durable VaultGenerationReceipt"
        )
    try:
        before = storage.scan()
        if (
            not before.complete
            or before.has_conflict
            or not before.generations
            or before.generations[-1] != latest
        ):
            raise VaultRecoveryStorageStateError(
                "Vault history is not clean, complete, and exact latest"
            )
        encoded = storage.verify_receipt(latest)
        after = storage.scan()
        if (
            not after.complete
            or after.has_conflict
            or not after.generations
            or after.generations[-1] != latest
            or after.generations != before.generations
        ):
            raise VaultRecoveryStorageStateError(
                "Vault history changed during latest-state verification"
            )
        return encoded
    except VaultRecoveryStorageError:
        raise
    except VaultStorageError as exc:
        raise VaultRecoveryStorageStateError(
            "Vault latest durable state cannot be verified"
        ) from exc


def _session_exact_vault(session: Any, encoded: bytes) -> None:
    if not isinstance(session, VaultSession):
        raise VaultRecoveryStorageStateError(
            "recovery export preparation requires VaultSession"
        )
    if session.state is not VaultSessionState.UNLOCKED:
        raise VaultRecoveryStorageStateError(
            "recovery export preparation requires an unlocked session"
        )
    try:
        if session.check_inactivity():
            raise VaultRecoveryStorageStateError(
                "Vault session expired during recovery export preparation"
            )
        if session.encoded != encoded:
            raise VaultRecoveryStorageStateError(
                "Vault session does not match the exact latest receipt"
            )
    except VaultRecoveryStorageError:
        raise
    except VaultError as exc:
        raise VaultRecoveryStorageStateError(
            "Vault session cannot prove the exact latest state"
        ) from exc


def _validate_setup_against_vault(
    setup: Any,
    current_vault: bytes,
) -> tuple[ParsedVaultRecoveryRecord, VaultRecoveryRehearsal]:
    if not isinstance(setup, VaultRecoverySetup):
        raise VaultRecoveryStorageStateError(
            "export requires VaultRecoverySetup"
        )
    if (
        type(setup.record) is not bytes
        or type(setup.recovery_key) is not bytes
        or type(setup.recovery_id) is not bytes
        or type(setup.vault_id) is not bytes
        or type(setup.source_vault_sha256) is not bytes
        or type(setup.source_revision) is not int
    ):
        raise VaultRecoveryStorageStateError(
            "export setup fields must be immutable exact values"
        )
    parsed = parse_recovery_record(setup.record)
    if (
        not hmac.compare_digest(parsed.recovery_id, setup.recovery_id)
        or not hmac.compare_digest(parsed.vault_id, setup.vault_id)
        or parsed.source_revision != setup.source_revision
        or not hmac.compare_digest(
            parsed.source_vault_sha256, setup.source_vault_sha256
        )
    ):
        raise VaultRecoveryConflictError(
            "recovery setup metadata conflicts with its record"
        )
    result = rehearse_recovery(
        setup.record,
        setup.recovery_key,
        current_vault,
    )
    return parsed, result


def prepare_recovery_export(
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    session: VaultSession,
    *,
    created_utc: str | None = None,
) -> VaultRecoverySetup:
    """Create a setup only for an exact latest durable schema-two Vault."""

    current = _verified_latest_vault(storage, latest)
    _session_exact_vault(session, current)
    setup = create_recovery_record(session, created_utc=created_utc)
    _session_exact_vault(session, current)
    confirmed = _verified_latest_vault(storage, latest)
    if not hmac.compare_digest(confirmed, current):
        raise VaultRecoveryStorageStateError(
            "Vault changed during recovery export preparation"
        )
    _validate_setup_against_vault(setup, current)
    return setup


def _cleanup_owned_file(
    directory_descriptor: int,
    name: str,
    file_descriptor: int,
    created: os.stat_result,
) -> bool:
    try:
        current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        opened = os.fstat(file_descriptor)
        if (
            _same_inode(current, opened)
            and _same_inode(opened, created)
            and current.st_nlink == 1
            and opened.st_nlink == 1
        ):
            os.unlink(name, dir_fd=directory_descriptor)
            _sync_directory(directory_descriptor)
            return True
    except Exception:
        return False
    return False


def export_recovery_record(
    setup: VaultRecoverySetup,
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    directory: Any,
) -> VaultRecoveryExportReceipt:
    """Durably create one private encrypted record without writing its key."""

    current = _verified_latest_vault(storage, latest)
    parsed, _ = _validate_setup_against_vault(setup, current)
    exact_record = bytes(setup.record)
    if not 1 <= len(exact_record) <= MAX_RECOVERY_FILE_BYTES:
        raise RecoveryStorageLimitError(
            "recovery record size is outside its export bound"
        )
    name = recovery_record_name(parsed.recovery_id)
    exact_path, directory_descriptor, directory_opened = _open_private_directory(
        directory, "recovery export directory"
    )
    descriptor: int | None = None
    created: os.stat_result | None = None
    directory_synced = False
    try:
        if (
            directory_opened.st_dev == latest.directory_device
            and directory_opened.st_ino == latest.directory_inode
        ):
            raise UnsafeRecoveryDirectoryError(
                "recovery record cannot be stored inside the Vault directory"
            )
        _sync_directory(directory_descriptor)
        _verify_open_directory(
            exact_path,
            directory_descriptor,
            directory_opened,
            "recovery export directory",
        )
        try:
            os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RecoveryFileConflictError(
                "cannot inspect recovery export target"
            ) from exc
        else:
            raise RecoveryFileConflictError(
                "recovery export target already exists"
            )
        try:
            descriptor = os.open(
                name,
                _create_flags(),
                PRIVATE_RECOVERY_FILE_MODE,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as exc:
            raise RecoveryFileConflictError(
                "recovery export target collided"
            ) from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise RecoveryExportUnsupportedError(
                "relative exclusive recovery creation is unavailable"
            ) from exc
        created = os.fstat(descriptor)
        os.fchmod(descriptor, PRIVATE_RECOVERY_FILE_MODE)
        created = os.fstat(descriptor)
        _require_private_file(created, "new recovery file", allow_empty=True)
        _write_all(descriptor, exact_record)
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        _require_private_file(written, "sealed recovery file")
        if not _same_inode(created, written) or written.st_size != len(exact_record):
            raise RecoverySourceChangedError(
                "recovery file identity or size changed while writing"
            )
        readback = _read_exact_descriptor(descriptor, written.st_size)
        readback_parsed = parse_recovery_record(readback)
        if (
            not hmac.compare_digest(readback, exact_record)
            or not hmac.compare_digest(
                readback_parsed.recovery_id, parsed.recovery_id
            )
            or not hmac.compare_digest(readback_parsed.vault_id, parsed.vault_id)
            or readback_parsed.source_revision != parsed.source_revision
            or not hmac.compare_digest(
                readback_parsed.source_vault_sha256,
                parsed.source_vault_sha256,
            )
        ):
            raise RecoverySourceChangedError(
                "recovery file read-back verification failed"
            )
        before_publish = _verified_latest_vault(storage, latest)
        if not hmac.compare_digest(before_publish, current):
            raise VaultRecoveryStorageStateError(
                "Vault changed before recovery export became durable"
            )
        _verify_open_directory(
            exact_path,
            directory_descriptor,
            directory_opened,
            "recovery export directory",
        )
        _sync_directory(directory_descriptor)
        directory_synced = True
        final_stat = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _require_private_file(final_stat, "durable recovery file")
        final_opened = os.fstat(descriptor)
        _require_private_file(final_opened, "opened durable recovery file")
        if (
            not _same_inode(final_stat, written)
            or not _same_inode(final_opened, written)
            or _mutation_signature(final_stat) != _mutation_signature(written)
            or _mutation_signature(final_opened) != _mutation_signature(written)
        ):
            raise RecoveryExportUncertainError(
                "durable recovery file identity or state changed"
            )
        durable_readback = _read_exact_descriptor(
            descriptor,
            final_opened.st_size,
        )
        durable_after = os.fstat(descriptor)
        durable_current = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not hmac.compare_digest(durable_readback, exact_record)
            or _mutation_signature(durable_after) != _mutation_signature(written)
            or _mutation_signature(durable_current) != _mutation_signature(written)
        ):
            raise RecoveryExportUncertainError(
                "durable recovery file changed after read-back"
            )
        _verify_open_directory(
            exact_path,
            directory_descriptor,
            directory_opened,
            "recovery export directory",
        )
        after_publish = _verified_latest_vault(storage, latest)
        if not hmac.compare_digest(after_publish, current):
            raise RecoveryExportUncertainError(
                "Vault changed after recovery record became durable"
            )
        return VaultRecoveryExportReceipt(
            directory_device=directory_opened.st_dev,
            directory_inode=directory_opened.st_ino,
            recovery_id=parsed.recovery_id,
            vault_id=parsed.vault_id,
            source_revision=parsed.source_revision,
            source_vault_sha256=parsed.source_vault_sha256,
            record_sha256=hashlib.sha256(exact_record).digest(),
            file_device=final_stat.st_dev,
            file_inode=final_stat.st_ino,
            encoded_size=final_stat.st_size,
        )
    except BaseException as exc:
        if descriptor is not None:
            if created is None:
                raise RecoveryExportUncertainError(
                    "recovery target was created but its identity is uncertain"
                ) from exc
            if directory_synced:
                if isinstance(exc, RecoveryExportUncertainError):
                    raise
                raise RecoveryExportUncertainError(
                    "recovery record may be durable; manual inspection is required"
                ) from exc
            if not _cleanup_owned_file(
                directory_descriptor,
                name,
                descriptor,
                created,
            ):
                raise RecoveryExportUncertainError(
                    "recovery export cleanup state is uncertain; manual inspection is required"
                ) from exc
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(directory_descriptor)
        except OSError:
            pass


def _read_recovery_path(path: Any) -> _ImportedRecoveryFile:
    exact_path = _path_text(path, "recovery record path")
    name = os.path.basename(exact_path)
    match = _RECOVERY_FILE_RE.fullmatch(name)
    if match is None:
        raise RecoveryFileConflictError(
            "recovery filename is not canonical"
        )
    expected_recovery_id = bytes.fromhex(match.group(1))
    _, directory_chain, directory_components, directory_stats = (
        _open_private_read_directory_chain(
            exact_path,
            "recovery import directory",
        )
    )
    directory_descriptor = directory_chain[-1]
    directory_opened = directory_stats[-1]
    descriptor: int | None = None
    try:
        try:
            before = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            _require_private_file(before, "recovery file")
            descriptor = os.open(
                name,
                _read_file_flags(),
                dir_fd=directory_descriptor,
            )
            opened = os.fstat(descriptor)
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise RecoveryFileConflictError(
                "cannot securely open recovery file"
            ) from exc
        if (
            not _same_inode(before, opened)
            or not _same_inode(opened, current)
        ):
            raise RecoverySourceChangedError(
                "recovery file changed while opening"
            )
        _require_private_file(opened, "opened recovery file")
        before_signature = _mutation_signature(opened)
        encoded = _read_exact_descriptor(descriptor, opened.st_size)
        after = os.fstat(descriptor)
        current_after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            before_signature != _mutation_signature(after)
            or before_signature != _mutation_signature(current_after)
        ):
            raise RecoverySourceChangedError(
                "recovery file changed during bounded read"
            )
        _verify_private_read_directory_chain(
            directory_chain,
            directory_components,
            directory_stats,
            "recovery import directory",
        )
        parsed = parse_recovery_record(encoded)
        if not hmac.compare_digest(parsed.recovery_id, expected_recovery_id):
            raise RecoveryFileConflictError(
                "recovery filename does not match its structurally observed identifier"
            )
        current_final = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if before_signature != _mutation_signature(current_final):
            raise RecoverySourceChangedError(
                "recovery file changed before inspection completed"
            )
        _verify_private_read_directory_chain(
            directory_chain,
            directory_components,
            directory_stats,
            "recovery import directory",
        )
        return _ImportedRecoveryFile(
            record=encoded,
            parsed=parsed,
            directory_device=directory_opened.st_dev,
            directory_inode=directory_opened.st_ino,
            file_device=opened.st_dev,
            file_inode=opened.st_ino,
            encoded_size=opened.st_size,
            record_sha256=hashlib.sha256(encoded).digest(),
        )
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _close_descriptors(directory_chain)


def rehearse_recovery_file(
    path: Any,
    recovery_key: bytes | bytearray | memoryview,
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
) -> VaultRecoveryFileRehearsal:
    """Read and rehearse one exact file without mutating either filesystem."""

    current = _verified_latest_vault(storage, latest)
    first = _read_recovery_path(path)
    result = rehearse_recovery(first.record, recovery_key, current)
    second = _read_recovery_path(path)
    confirmed = _verified_latest_vault(storage, latest)
    if (
        not hmac.compare_digest(confirmed, current)
        or first.directory_device != second.directory_device
        or first.directory_inode != second.directory_inode
        or first.file_device != second.file_device
        or first.file_inode != second.file_inode
        or first.encoded_size != second.encoded_size
        or not hmac.compare_digest(first.record_sha256, second.record_sha256)
        or not hmac.compare_digest(first.record, second.record)
    ):
        raise RecoverySourceChangedError(
            "Vault or recovery file changed during read-only rehearsal"
        )
    return VaultRecoveryFileRehearsal(
        recovery_id=result.recovery_id,
        vault_id=result.vault_id,
        source_revision=result.source_revision,
        source_vault_sha256=result.source_vault_sha256,
        created_utc=result.created_utc,
        keyring_sha256=result.keyring_sha256,
        active_key_version=result.active_key_version,
        key_count=result.key_count,
        record_sha256=first.record_sha256,
        file_device=first.file_device,
        file_inode=first.file_inode,
        encoded_size=first.encoded_size,
    )
