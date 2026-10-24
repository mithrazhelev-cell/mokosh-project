"""Strict offline storage for one human-readable MOKOSH-RP1 sheet.

The recovery phrase is the secret key for a separate encrypted ``.mokr``
record.  This POSIX-only module therefore requires an explicitly selected,
private directory on a filesystem different from every caller-supplied
forbidden device.  It never chooses a destination, overwrites a path, stores
inside the profile, uses a clipboard, logs a phrase, or weakens permissions.
"""

from __future__ import annotations

import ctypes
import enum
import hashlib
import hmac
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from typing import Any

from mokosh_recovery_phrase import (
    RECOVERY_PHRASE_FORMAT,
    RECOVERY_PHRASE_WORD_COUNT,
    RecoveryPhraseError,
    decode_recovery_phrase,
    encode_recovery_phrase,
)
from mokosh_vault_recovery import RECOVERY_ID_LEN


PRIVATE_RECOVERY_PHRASE_DIRECTORY_MODE = 0o700
PRIVATE_RECOVERY_PHRASE_FILE_MODE = 0o600
MAX_RECOVERY_PHRASE_SHEET_BYTES = 4096
RECOVERY_PHRASE_FILE_PREFIX = "mokosh-recovery-phrase-"
RECOVERY_PHRASE_FILE_SUFFIX = ".txt"
RECOVERY_DIRECTORY_PREFIX = "mokosh-recovery-"
LINUX_MSDOS_SUPER_MAGIC = 0x4D44
LINUX_EXFAT_SUPER_MAGIC = 0x2011BAB0
_UNSUITABLE_FILESYSTEM_MAGICS = frozenset(
    {LINUX_MSDOS_SUPER_MAGIC, LINUX_EXFAT_SUPER_MAGIC}
)
_SEPARATION_LINE = "secret=KEEP-SEPARATE-FROM-MOKR"
_WORD_COUNT_LINE = f"words={RECOVERY_PHRASE_WORD_COUNT}"
_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")
_PHRASE_FILE_RE = re.compile(
    rf"^{re.escape(RECOVERY_PHRASE_FILE_PREFIX)}([0-9a-f]{{32}})"
    rf"{re.escape(RECOVERY_PHRASE_FILE_SUFFIX)}$"
)


class RecoveryPhraseStorageError(RecoveryPhraseError):
    """Base class for strict recovery-phrase filesystem failures."""


class UnsafeRecoveryPhraseDirectoryError(RecoveryPhraseStorageError):
    """A directory path, identity, owner, mode, or device is unsafe."""


class RecoveryPhraseFileConflictError(RecoveryPhraseStorageError):
    """A phrase sheet is conflicting, non-canonical, or not private."""


class RecoveryPhraseSourceChangedError(RecoveryPhraseStorageError):
    """A phrase sheet or its directory changed during an operation."""


class RecoveryPhraseSeparationError(RecoveryPhraseStorageError):
    """The phrase destination is not separate from protected material."""


class RecoveryPhraseStorageLimitError(RecoveryPhraseStorageError):
    """A bounded path, file, or input exceeds its declared limit."""


class RecoveryPhraseExportUnsupportedError(RecoveryPhraseStorageError):
    """The platform or filesystem lacks a required durable primitive."""


class RecoveryPhraseExportUncertainError(RecoveryPhraseStorageError):
    """A newly created object may be durable and needs manual inspection."""


class RecoveryMaterialKind(str, enum.Enum):
    RECORD = "record"
    PHRASE = "phrase"


@dataclass(frozen=True, slots=True)
class RecoveryPrivateDirectoryReceipt:
    path: str
    kind: RecoveryMaterialKind
    recovery_id: bytes
    device: int
    inode: int
    durable: bool = True


@dataclass(frozen=True, slots=True)
class ParsedRecoveryPhraseSheet:
    recovery_id: bytes
    recovery_key: bytes = field(repr=False)
    words: tuple[str, ...] = field(repr=False)
    encoded: bytes = field(repr=False)
    directory_device: int = 0
    directory_inode: int = 0
    file_device: int = 0
    file_inode: int = 0

    def __copy__(self) -> None:
        raise TypeError("recovery phrase sheet cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("recovery phrase sheet cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("recovery phrase sheet cannot be serialized")


@dataclass(frozen=True, slots=True)
class RecoveryPhraseExportReceipt:
    recovery_id: bytes
    encoded_size: int
    sha256: bytes
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    durable: bool = True


def _exact_recovery_id(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryPhraseFileConflictError("recovery identifier must be bytes")
    result = bytes(value)
    if len(result) != RECOVERY_ID_LEN:
        raise RecoveryPhraseFileConflictError(
            f"recovery identifier must contain exactly {RECOVERY_ID_LEN} bytes"
        )
    return result


def recovery_phrase_file_name(recovery_id: Any) -> str:
    return (
        RECOVERY_PHRASE_FILE_PREFIX
        + _exact_recovery_id(recovery_id).hex()
        + RECOVERY_PHRASE_FILE_SUFFIX
    )


def recovery_private_directory_name(
    kind: RecoveryMaterialKind,
    recovery_id: Any,
) -> str:
    if not isinstance(kind, RecoveryMaterialKind):
        raise UnsafeRecoveryPhraseDirectoryError(
            "recovery material kind is invalid"
        )
    return RECOVERY_DIRECTORY_PREFIX + kind.value + "-" + _exact_recovery_id(
        recovery_id
    ).hex()


def _path_text(value: Any, label: str) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise UnsafeRecoveryPhraseDirectoryError(f"{label} must be a path") from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise UnsafeRecoveryPhraseDirectoryError(
            f"{label} must be non-empty text"
        )
    absolute = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(absolute) != absolute:
        raise UnsafeRecoveryPhraseDirectoryError(
            f"{label} must not contain symlinks"
        )
    return absolute


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise RecoveryPhraseExportUnsupportedError(
            f"required filesystem flag {name} is unavailable"
        )
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
    )


def _file_flags(*, write: bool = False) -> int:
    flags = os.O_RDWR if write else os.O_RDONLY
    return (
        flags
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
        | getattr(os, "O_BINARY", 0)
    )


def _read_file_flags() -> int:
    return _file_flags() | _required_flag("O_NONBLOCK")


def _create_flags() -> int:
    return _file_flags(write=True) | _required_flag("O_CREAT") | _required_flag(
        "O_EXCL"
    )


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _filesystem_magic(descriptor: int) -> int:
    """Return Linux ``f_type`` without resolving a second pathname."""

    if not sys.platform.startswith("linux"):
        raise RecoveryPhraseExportUnsupportedError(
            "recovery phrase storage requires Linux filesystem checks"
        )
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.fstatfs
        call.argtypes = (ctypes.c_int, ctypes.c_void_p)
        call.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(256)
        if call(descriptor, ctypes.byref(buffer)) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        return int(ctypes.c_ulong.from_buffer(buffer).value)
    except RecoveryPhraseStorageError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise RecoveryPhraseExportUnsupportedError(
            "filesystem type cannot be verified"
        ) from exc


def _require_supported_filesystem(descriptor: int) -> None:
    if _filesystem_magic(descriptor) in _UNSUITABLE_FILESYSTEM_MAGICS:
        raise RecoveryPhraseExportUnsupportedError(
            "FAT and exFAT cannot store a recovery phrase sheet safely"
        )


def _mutation_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _require_directory(value: os.stat_result, label: str, *, private: bool) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise UnsafeRecoveryPhraseDirectoryError(f"{label} must be a directory")
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise UnsafeRecoveryPhraseDirectoryError(
            f"{label} must be owned by the current user"
        )
    if private and stat.S_IMODE(value.st_mode) != PRIVATE_RECOVERY_PHRASE_DIRECTORY_MODE:
        raise UnsafeRecoveryPhraseDirectoryError(
            f"{label} mode must be exactly 0700"
        )


def _require_private_file(
    value: os.stat_result,
    label: str,
    *,
    allow_empty: bool = False,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise RecoveryPhraseFileConflictError(f"{label} must be a regular file")
    if stat.S_IMODE(value.st_mode) != PRIVATE_RECOVERY_PHRASE_FILE_MODE:
        raise RecoveryPhraseFileConflictError(f"{label} mode must be exactly 0600")
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise RecoveryPhraseFileConflictError(
            f"{label} must be owned by the current user"
        )
    if value.st_nlink != 1:
        raise RecoveryPhraseFileConflictError(f"{label} link count must be one")
    minimum = 0 if allow_empty else 1
    if not minimum <= value.st_size <= MAX_RECOVERY_PHRASE_SHEET_BYTES:
        raise RecoveryPhraseStorageLimitError(f"{label} size is outside its bound")


def _forbidden_devices(value: Any, *, required: bool) -> tuple[int, ...]:
    if type(value) not in (tuple, list):
        raise RecoveryPhraseSeparationError("forbidden devices must be a sequence")
    result = tuple(value)
    if required and not result:
        raise RecoveryPhraseSeparationError(
            "at least one protected device identity is required"
        )
    if any(type(item) is not int or item < 0 for item in result):
        raise RecoveryPhraseSeparationError(
            "forbidden device identities must be non-negative integers"
        )
    if len(set(result)) != len(result):
        raise RecoveryPhraseSeparationError(
            "forbidden device identities must be unique"
        )
    return result


def _require_separate_device(device: int, forbidden: tuple[int, ...]) -> None:
    if device in forbidden:
        raise RecoveryPhraseSeparationError(
            "recovery phrase must be stored on a separate filesystem device"
        )


def _open_directory(
    path: Any,
    label: str,
    *,
    private: bool,
) -> tuple[str, int, os.stat_result]:
    exact = _path_text(path, label)
    descriptor: int | None = None
    try:
        before = os.lstat(exact)
        descriptor = os.open(exact, _directory_flags())
        opened = os.fstat(descriptor)
        current = os.lstat(exact)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise UnsafeRecoveryPhraseDirectoryError(
            f"cannot securely open {label}"
        ) from exc
    try:
        if not _same_inode(before, opened) or not _same_inode(opened, current):
            raise UnsafeRecoveryPhraseDirectoryError(
                f"{label} changed while opening"
            )
        _require_directory(before, label, private=private)
        _require_directory(opened, f"opened {label}", private=private)
        _require_directory(current, label, private=private)
        _require_supported_filesystem(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return exact, descriptor, opened


def _verify_open_directory(
    path: str,
    descriptor: int,
    initial: os.stat_result,
    label: str,
    *,
    private: bool,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
    except OSError as exc:
        raise UnsafeRecoveryPhraseDirectoryError(
            f"{label} is unavailable"
        ) from exc
    if not _same_inode(initial, opened) or not _same_inode(opened, current):
        raise UnsafeRecoveryPhraseDirectoryError(f"{label} identity changed")
    _require_directory(opened, f"opened {label}", private=private)
    _require_directory(current, label, private=private)
    return opened


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise RecoveryPhraseExportUnsupportedError(
            "directory fsync is unavailable"
        ) from exc


def _sync_file(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise RecoveryPhraseExportUnsupportedError(
            "phrase sheet fsync is unavailable"
        ) from exc


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset : offset + 4096])
        except OSError as exc:
            raise RecoveryPhraseExportUnsupportedError(
                "phrase sheet write failed"
            ) from exc
        if not 1 <= written <= min(4096, len(data) - offset):
            raise RecoveryPhraseExportUnsupportedError(
                "phrase sheet write made invalid progress"
            )
        offset += written


def _read_exact(descriptor: int, expected_size: int) -> bytes:
    if type(expected_size) is not int or not 1 <= expected_size <= MAX_RECOVERY_PHRASE_SHEET_BYTES:
        raise RecoveryPhraseStorageLimitError("phrase sheet size is outside its bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        requested = min(4096, expected_size - offset)
        try:
            chunk = os.pread(descriptor, requested, offset)
        except (OSError, AttributeError) as exc:
            raise RecoveryPhraseExportUnsupportedError(
                "bounded phrase sheet read is unavailable"
            ) from exc
        if not chunk:
            raise RecoveryPhraseSourceChangedError("phrase sheet is truncated")
        chunks.append(chunk)
        offset += len(chunk)
    try:
        trailing = os.pread(descriptor, 1, expected_size)
    except (OSError, AttributeError) as exc:
        raise RecoveryPhraseExportUnsupportedError(
            "bounded phrase sheet read is unavailable"
        ) from exc
    if trailing:
        raise RecoveryPhraseSourceChangedError("phrase sheet has trailing bytes")
    return b"".join(chunks)


def _cleanup_owned_file(
    directory_descriptor: int,
    name: str,
    file_descriptor: int,
    created: os.stat_result,
) -> bool:
    try:
        current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
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


def create_private_recovery_directory(
    parent: Any,
    kind: RecoveryMaterialKind,
    recovery_id: Any,
    *,
    forbidden_devices: tuple[int, ...] | list[int] = (),
) -> RecoveryPrivateDirectoryReceipt:
    """Create one no-clobber 0700 child in an explicitly selected parent."""

    exact_id = _exact_recovery_id(recovery_id)
    forbidden = _forbidden_devices(forbidden_devices, required=False)
    name = recovery_private_directory_name(kind, exact_id)
    exact_parent, parent_fd, parent_info = _open_directory(
        parent, "selected recovery parent", private=False
    )
    created = False
    child_fd: int | None = None
    try:
        _require_separate_device(parent_info.st_dev, forbidden)
        _sync_directory(parent_fd)
        _verify_open_directory(
            exact_parent,
            parent_fd,
            parent_info,
            "selected recovery parent",
            private=False,
        )
        try:
            os.mkdir(
                name,
                PRIVATE_RECOVERY_PHRASE_DIRECTORY_MODE,
                dir_fd=parent_fd,
            )
            created = True
        except FileExistsError as exc:
            raise RecoveryPhraseFileConflictError(
                "recovery directory already exists"
            ) from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise RecoveryPhraseExportUnsupportedError(
                "private recovery directory creation is unavailable"
            ) from exc
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        os.fchmod(child_fd, PRIVATE_RECOVERY_PHRASE_DIRECTORY_MODE)
        child = os.fstat(child_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_inode(child, current):
            raise RecoveryPhraseSourceChangedError(
                "new recovery directory identity changed"
            )
        _require_directory(child, "new recovery directory", private=True)
        _require_separate_device(child.st_dev, forbidden)
        _sync_directory(child_fd)
        _sync_directory(parent_fd)
        final_child = os.fstat(child_fd)
        final_current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _verify_open_directory(
            exact_parent,
            parent_fd,
            parent_info,
            "selected recovery parent",
            private=False,
        )
        if (
            not _same_inode(child, final_child)
            or not _same_inode(final_child, final_current)
            or _mutation_signature(final_child) != _mutation_signature(final_current)
        ):
            raise RecoveryPhraseExportUncertainError(
                "new recovery directory final identity is uncertain"
            )
        _require_directory(final_child, "durable recovery directory", private=True)
        return RecoveryPrivateDirectoryReceipt(
            path=os.path.join(exact_parent, name),
            kind=kind,
            recovery_id=exact_id,
            device=final_child.st_dev,
            inode=final_child.st_ino,
        )
    except BaseException as exc:
        if created:
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                safe = child_fd is not None and _same_inode(current, os.fstat(child_fd))
                if safe and not os.listdir(child_fd):
                    os.rmdir(name, dir_fd=parent_fd)
                    _sync_directory(parent_fd)
                elif not isinstance(exc, RecoveryPhraseExportUncertainError):
                    raise RecoveryPhraseExportUncertainError(
                        "new recovery directory may remain; inspect it manually"
                    ) from exc
            except RecoveryPhraseExportUncertainError:
                raise
            except Exception as cleanup_exc:
                raise RecoveryPhraseExportUncertainError(
                    "new recovery directory cleanup is uncertain"
                ) from cleanup_exc
        if isinstance(exc, RecoveryPhraseStorageError):
            raise
        if isinstance(exc, (OSError, TypeError, NotImplementedError)):
            raise RecoveryPhraseExportUnsupportedError(
                "secure recovery directory operation failed"
            ) from exc
        raise
    finally:
        if child_fd is not None:
            try:
                os.close(child_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def remove_empty_private_recovery_directory(
    receipt: Any,
) -> bool:
    """Remove only one exact directory created by this module if still empty."""

    if not isinstance(receipt, RecoveryPrivateDirectoryReceipt):
        raise UnsafeRecoveryPhraseDirectoryError(
            "recovery directory receipt is invalid"
        )
    exact_path = _path_text(receipt.path, "recovery directory rollback target")
    parent = os.path.dirname(exact_path)
    name = os.path.basename(exact_path)
    expected_name = recovery_private_directory_name(
        receipt.kind, receipt.recovery_id
    )
    if name != expected_name:
        raise UnsafeRecoveryPhraseDirectoryError(
            "recovery directory receipt path is non-canonical"
        )
    exact_parent, parent_fd, parent_info = _open_directory(
        parent, "recovery directory rollback parent", private=False
    )
    child_fd: int | None = None
    removed = False
    try:
        _verify_open_directory(
            exact_parent,
            parent_fd,
            parent_info,
            "recovery directory rollback parent",
            private=False,
        )
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        opened = os.fstat(child_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _same_inode(before, opened)
            or not _same_inode(opened, current)
            or opened.st_dev != receipt.device
            or opened.st_ino != receipt.inode
        ):
            raise RecoveryPhraseSourceChangedError(
                "recovery directory rollback identity changed"
            )
        _require_directory(opened, "recovery directory rollback target", private=True)
        if os.listdir(child_fd):
            return False
        os.rmdir(name, dir_fd=parent_fd)
        removed = True
        _sync_directory(parent_fd)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RecoveryPhraseExportUncertainError(
                "recovery directory rollback target remains visible"
            )
        _verify_open_directory(
            exact_parent,
            parent_fd,
            parent_info,
            "recovery directory rollback parent",
            private=False,
        )
        return True
    except BaseException as exc:
        if removed and not isinstance(exc, RecoveryPhraseExportUncertainError):
            raise RecoveryPhraseExportUncertainError(
                "recovery directory was removed but durability is uncertain"
            ) from exc
        if isinstance(exc, (OSError, TypeError, NotImplementedError)):
            raise UnsafeRecoveryPhraseDirectoryError(
                "recovery directory rollback target is unavailable"
            ) from exc
        raise
    finally:
        if child_fd is not None:
            try:
                os.close(child_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def encode_recovery_phrase_sheet(recovery_id: Any, phrase: Any) -> bytes:
    exact_id = _exact_recovery_id(recovery_id)
    try:
        key = decode_recovery_phrase(phrase)
        words = encode_recovery_phrase(key)
    except RecoveryPhraseError as exc:
        raise RecoveryPhraseFileConflictError(
            "recovery phrase is invalid"
        ) from exc
    lines = [
        RECOVERY_PHRASE_FORMAT,
        "recovery-id=" + exact_id.hex(),
        _SEPARATION_LINE,
        _WORD_COUNT_LINE,
    ]
    lines.extend(f"{index:02d}={word}" for index, word in enumerate(words, 1))
    lines.append("END")
    encoded = ("\n".join(lines) + "\n").encode("ascii")
    if len(encoded) > MAX_RECOVERY_PHRASE_SHEET_BYTES:
        raise RecoveryPhraseStorageLimitError("phrase sheet exceeds its bound")
    return encoded


def parse_recovery_phrase_sheet(value: Any) -> ParsedRecoveryPhraseSheet:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryPhraseFileConflictError("phrase sheet must be bytes")
    encoded = bytes(value)
    if not 1 <= len(encoded) <= MAX_RECOVERY_PHRASE_SHEET_BYTES:
        raise RecoveryPhraseStorageLimitError("phrase sheet size is outside its bound")
    try:
        text = encoded.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RecoveryPhraseFileConflictError("phrase sheet must be ASCII") from exc
    lines = text.splitlines()
    if (
        len(lines) != 5 + RECOVERY_PHRASE_WORD_COUNT
        or not text.endswith("\n")
        or lines[0] != RECOVERY_PHRASE_FORMAT
        or lines[2] != _SEPARATION_LINE
        or lines[3] != _WORD_COUNT_LINE
        or lines[-1] != "END"
        or not lines[1].startswith("recovery-id=")
    ):
        raise RecoveryPhraseFileConflictError(
            "phrase sheet structure is non-canonical"
        )
    recovery_hex = lines[1][len("recovery-id=") :]
    if len(recovery_hex) != RECOVERY_ID_LEN * 2 or _LOWER_HEX_RE.fullmatch(
        recovery_hex
    ) is None:
        raise RecoveryPhraseFileConflictError(
            "phrase sheet recovery identifier is invalid"
        )
    words: list[str] = []
    for index, line in enumerate(lines[4:-1], 1):
        prefix = f"{index:02d}="
        if not line.startswith(prefix) or len(line) == len(prefix):
            raise RecoveryPhraseFileConflictError(
                "phrase sheet word numbering is non-canonical"
            )
        words.append(line[len(prefix) :])
    try:
        key = decode_recovery_phrase(tuple(words))
    except RecoveryPhraseError as exc:
        raise RecoveryPhraseFileConflictError(
            "phrase sheet words are invalid"
        ) from exc
    recovery_id = bytes.fromhex(recovery_hex)
    if encode_recovery_phrase_sheet(recovery_id, tuple(words)) != encoded:
        raise RecoveryPhraseFileConflictError("phrase sheet encoding is non-canonical")
    return ParsedRecoveryPhraseSheet(
        recovery_id=recovery_id,
        recovery_key=key,
        words=tuple(words),
        encoded=encoded,
    )


def export_recovery_phrase_sheet(
    recovery_id: Any,
    phrase: Any,
    directory: Any,
    *,
    forbidden_devices: tuple[int, ...] | list[int],
) -> RecoveryPhraseExportReceipt:
    """Durably write one private sheet, refusing the protected devices."""

    exact_id = _exact_recovery_id(recovery_id)
    encoded = encode_recovery_phrase_sheet(exact_id, phrase)
    parsed = parse_recovery_phrase_sheet(encoded)
    forbidden = _forbidden_devices(forbidden_devices, required=True)
    name = recovery_phrase_file_name(exact_id)
    exact_path, directory_fd, directory_info = _open_directory(
        directory, "recovery phrase directory", private=True
    )
    descriptor: int | None = None
    created: os.stat_result | None = None
    directory_synced = False
    try:
        _require_separate_device(directory_info.st_dev, forbidden)
        _sync_directory(directory_fd)
        _verify_open_directory(
            exact_path,
            directory_fd,
            directory_info,
            "recovery phrase directory",
            private=True,
        )
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RecoveryPhraseFileConflictError(
                "cannot inspect phrase sheet target"
            ) from exc
        else:
            raise RecoveryPhraseFileConflictError(
                "phrase sheet target already exists"
            )
        try:
            descriptor = os.open(
                name,
                _create_flags(),
                PRIVATE_RECOVERY_PHRASE_FILE_MODE,
                dir_fd=directory_fd,
            )
        except FileExistsError as exc:
            raise RecoveryPhraseFileConflictError(
                "phrase sheet target collided"
            ) from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise RecoveryPhraseExportUnsupportedError(
                "exclusive phrase sheet creation is unavailable"
            ) from exc
        created = os.fstat(descriptor)
        os.fchmod(descriptor, PRIVATE_RECOVERY_PHRASE_FILE_MODE)
        created = os.fstat(descriptor)
        _require_private_file(created, "new phrase sheet", allow_empty=True)
        _write_all(descriptor, encoded)
        _sync_file(descriptor)
        written = os.fstat(descriptor)
        _require_private_file(written, "sealed phrase sheet")
        if not _same_inode(created, written) or written.st_size != len(encoded):
            raise RecoveryPhraseSourceChangedError(
                "phrase sheet identity or size changed while writing"
            )
        readback = _read_exact(descriptor, written.st_size)
        confirmed = parse_recovery_phrase_sheet(readback)
        if (
            not hmac.compare_digest(readback, encoded)
            or not hmac.compare_digest(confirmed.recovery_id, parsed.recovery_id)
            or not hmac.compare_digest(confirmed.recovery_key, parsed.recovery_key)
        ):
            raise RecoveryPhraseSourceChangedError(
                "phrase sheet read-back verification failed"
            )
        _verify_open_directory(
            exact_path,
            directory_fd,
            directory_info,
            "recovery phrase directory",
            private=True,
        )
        _sync_directory(directory_fd)
        directory_synced = True
        final_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        final_opened = os.fstat(descriptor)
        _require_private_file(final_path, "durable phrase sheet")
        _require_private_file(final_opened, "opened durable phrase sheet")
        if (
            not _same_inode(final_path, written)
            or not _same_inode(final_opened, written)
            or _mutation_signature(final_path) != _mutation_signature(written)
            or _mutation_signature(final_opened) != _mutation_signature(written)
            or not hmac.compare_digest(_read_exact(descriptor, written.st_size), encoded)
        ):
            raise RecoveryPhraseExportUncertainError(
                "durable phrase sheet changed after verification"
            )
        _verify_open_directory(
            exact_path,
            directory_fd,
            directory_info,
            "recovery phrase directory",
            private=True,
        )
        return RecoveryPhraseExportReceipt(
            recovery_id=exact_id,
            encoded_size=len(encoded),
            sha256=hashlib.sha256(encoded).digest(),
            directory_device=directory_info.st_dev,
            directory_inode=directory_info.st_ino,
            file_device=final_path.st_dev,
            file_inode=final_path.st_ino,
        )
    except BaseException as exc:
        if descriptor is not None:
            if created is None:
                raise RecoveryPhraseExportUncertainError(
                    "phrase sheet was created but its identity is uncertain"
                ) from exc
            if directory_synced:
                if isinstance(exc, RecoveryPhraseExportUncertainError):
                    raise
                raise RecoveryPhraseExportUncertainError(
                    "phrase sheet may be durable; inspect it manually"
                ) from exc
            if not _cleanup_owned_file(directory_fd, name, descriptor, created):
                raise RecoveryPhraseExportUncertainError(
                    "phrase sheet cleanup is uncertain; inspect it manually"
                ) from exc
        if isinstance(exc, RecoveryPhraseStorageError):
            raise
        if isinstance(exc, (OSError, TypeError, NotImplementedError)):
            raise RecoveryPhraseExportUnsupportedError(
                "secure phrase sheet export failed"
            ) from exc
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass


def read_recovery_phrase_sheet(
    path: Any,
    *,
    expected_recovery_id: Any | None = None,
    forbidden_devices: tuple[int, ...] | list[int],
) -> ParsedRecoveryPhraseSheet:
    """Read one exact private sheet twice without modifying it."""

    forbidden = _forbidden_devices(forbidden_devices, required=True)
    exact_path = _path_text(path, "recovery phrase sheet path")
    name = os.path.basename(exact_path)
    match = _PHRASE_FILE_RE.fullmatch(name)
    if match is None:
        raise RecoveryPhraseFileConflictError(
            "phrase sheet filename is non-canonical"
        )
    filename_id = bytes.fromhex(match.group(1))
    requested_id = (
        None if expected_recovery_id is None else _exact_recovery_id(expected_recovery_id)
    )
    parent = os.path.dirname(exact_path)
    exact_parent, directory_fd, directory_info = _open_directory(
        parent, "recovery phrase directory", private=True
    )
    descriptor: int | None = None
    try:
        _require_separate_device(directory_info.st_dev, forbidden)
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require_private_file(before, "recovery phrase sheet")
            descriptor = os.open(name, _read_file_flags(), dir_fd=directory_fd)
            opened = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RecoveryPhraseFileConflictError(
                "cannot securely open recovery phrase sheet"
            ) from exc
        if not _same_inode(before, opened) or not _same_inode(opened, current):
            raise RecoveryPhraseSourceChangedError(
                "recovery phrase sheet changed while opening"
            )
        _require_private_file(opened, "opened recovery phrase sheet")
        signature = _mutation_signature(opened)
        first = _read_exact(descriptor, opened.st_size)
        middle = os.fstat(descriptor)
        current_middle = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if signature != _mutation_signature(middle) or signature != _mutation_signature(
            current_middle
        ):
            raise RecoveryPhraseSourceChangedError(
                "recovery phrase sheet changed during reading"
            )
        parsed = parse_recovery_phrase_sheet(first)
        second = _read_exact(descriptor, opened.st_size)
        after = os.fstat(descriptor)
        current_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _verify_open_directory(
            exact_parent,
            directory_fd,
            directory_info,
            "recovery phrase directory",
            private=True,
        )
        if (
            not hmac.compare_digest(first, second)
            or signature != _mutation_signature(after)
            or signature != _mutation_signature(current_after)
            or not hmac.compare_digest(parsed.recovery_id, filename_id)
            or (
                requested_id is not None
                and not hmac.compare_digest(parsed.recovery_id, requested_id)
            )
        ):
            raise RecoveryPhraseSourceChangedError(
                "recovery phrase sheet identity or binding changed"
            )
        return ParsedRecoveryPhraseSheet(
            recovery_id=parsed.recovery_id,
            recovery_key=parsed.recovery_key,
            words=parsed.words,
            encoded=parsed.encoded,
            directory_device=directory_info.st_dev,
            directory_inode=directory_info.st_ino,
            file_device=opened.st_dev,
            file_inode=opened.st_ino,
        )
    except RecoveryPhraseStorageError:
        raise
    except OSError as exc:
        raise RecoveryPhraseSourceChangedError(
            "recovery phrase sheet became unavailable while reading"
        ) from exc
    except (TypeError, NotImplementedError) as exc:
        raise RecoveryPhraseExportUnsupportedError(
            "secure phrase sheet reading is unavailable"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass


__all__ = [
    "MAX_RECOVERY_PHRASE_SHEET_BYTES",
    "LINUX_EXFAT_SUPER_MAGIC",
    "LINUX_MSDOS_SUPER_MAGIC",
    "PRIVATE_RECOVERY_PHRASE_DIRECTORY_MODE",
    "PRIVATE_RECOVERY_PHRASE_FILE_MODE",
    "ParsedRecoveryPhraseSheet",
    "RecoveryMaterialKind",
    "RecoveryPhraseExportReceipt",
    "RecoveryPhraseExportUncertainError",
    "RecoveryPhraseExportUnsupportedError",
    "RecoveryPhraseFileConflictError",
    "RecoveryPhraseSeparationError",
    "RecoveryPhraseSourceChangedError",
    "RecoveryPhraseStorageError",
    "RecoveryPhraseStorageLimitError",
    "RecoveryPrivateDirectoryReceipt",
    "UnsafeRecoveryPhraseDirectoryError",
    "create_private_recovery_directory",
    "encode_recovery_phrase_sheet",
    "export_recovery_phrase_sheet",
    "parse_recovery_phrase_sheet",
    "read_recovery_phrase_sheet",
    "remove_empty_private_recovery_directory",
    "recovery_phrase_file_name",
    "recovery_private_directory_name",
]
