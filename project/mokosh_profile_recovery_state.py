"""Fail-closed public lifecycle receipt for optional profile recovery.

The receipt contains identifiers, one Vault revision, and a bounded reminder
counter.  It never contains recovery words, passwords, keys, exported bytes,
or external paths.  It is only a UI/lifecycle hint: every real recovery still
authenticates the current Vault, the selected .mokr record, and the exact
25-word phrase in the cryptographic recovery core.
"""

from __future__ import annotations

import enum
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mokosh_profile_storage import (
    PROFILE_RECOVERY_STATE_DIRECTORY_NAME,
    ProfileSnapshot,
    load_profile,
)
from mokosh_vault_storage import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    VaultGenerationReceipt,
)


PROFILE_RECOVERY_STATE_FORMAT = "MOKOSH_PROFILE_RECOVERY_STATE"
PROFILE_RECOVERY_STATE_VERSION = 1
PROFILE_RECOVERY_STATE_NAME = "state.json"
MAX_PROFILE_RECOVERY_STATE_BYTES = 1024
MAX_PROFILE_RECOVERY_STATE_ENTRIES = 16
MAX_REPLACEMENT_REMINDERS = 2
_MAX_REVISION = (1 << 63) - 1
_STATE_FIELDS = frozenset(
    {
        "format",
        "version",
        "profile_id",
        "vault_id",
        "recovery_id",
        "source_revision",
        "replacement_reminders_shown",
    }
)
_TEMP_RE = re.compile(r"^\.recovery-state-([0-9a-f]{32})\.tmp$")


class ProfileRecoveryStateError(RuntimeError):
    """Base class for recovery lifecycle receipt failures."""


class ProfileRecoveryStateFormatError(ProfileRecoveryStateError, ValueError):
    """The bounded receipt is malformed or non-canonical."""


class ProfileRecoveryStateUnsafeError(ProfileRecoveryStateError):
    """A path, owner, mode, identity, or object kind is unsafe."""


class ProfileRecoveryStateConflictError(ProfileRecoveryStateError):
    """Observed state changed or contains an unresolved object."""


class ProfileRecoveryStatePublishUncertainError(ProfileRecoveryStateError):
    """The stable receipt may be visible but durability is uncertain."""


class ProfileRecoveryAvailability(str, enum.Enum):
    MISSING = "missing"
    CURRENT = "current"
    REPLACEMENT_REQUIRED = "replacement_required"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class ProfileRecoveryStateRecord:
    profile_id: str
    vault_id: str
    recovery_id: str
    source_revision: int
    replacement_reminders_shown: int = 0
    format: str = PROFILE_RECOVERY_STATE_FORMAT
    version: int = PROFILE_RECOVERY_STATE_VERSION


@dataclass(frozen=True, slots=True)
class ProfileRecoveryStateInspection:
    availability: ProfileRecoveryAvailability
    reason: str
    source_revision: int | None = None
    current_revision: int | None = None
    replacement_reminders_shown: int = 0
    _record: ProfileRecoveryStateRecord | None = field(
        default=None, repr=False, compare=False
    )

    @property
    def recovery_available(self) -> bool:
        return self.availability is ProfileRecoveryAvailability.CURRENT

    @property
    def replacement_required(self) -> bool:
        return self.availability is ProfileRecoveryAvailability.REPLACEMENT_REQUIRED


@dataclass(frozen=True, slots=True)
class ProfileRecoveryLoginNotice:
    inspection: ProfileRecoveryStateInspection
    show_reminder: bool
    reminder_number: int = 0


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags(*, write: bool = False, create: bool = False) -> int:
    flags = (
        (os.O_WRONLY if write else os.O_RDONLY)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    return flags


def _path_text(value: Any) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ProfileRecoveryStateUnsafeError("profile root must be a path") from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ProfileRecoveryStateUnsafeError("profile root must be non-empty text")
    exact = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(exact) != exact:
        raise ProfileRecoveryStateUnsafeError("profile root must not contain symlinks")
    return exact


def _require_directory(info: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ProfileRecoveryStateUnsafeError(f"{label} is not a directory")
    if stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise ProfileRecoveryStateUnsafeError(f"{label} permissions are unsafe")
    uid = _current_uid()
    if uid is not None and info.st_uid != uid:
        raise ProfileRecoveryStateUnsafeError(f"{label} owner is unsafe")


def _require_file(
    info: os.stat_result,
    label: str,
    *,
    allow_empty: bool = False,
) -> None:
    minimum = 0 if allow_empty else 1
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
        or info.st_nlink != 1
        or not minimum <= info.st_size <= MAX_PROFILE_RECOVERY_STATE_BYTES
    ):
        raise ProfileRecoveryStateUnsafeError(f"{label} object is unsafe")
    uid = _current_uid()
    if uid is not None and info.st_uid != uid:
        raise ProfileRecoveryStateUnsafeError(f"{label} owner is unsafe")


def _open_root(path: str) -> int:
    try:
        before = os.lstat(path)
        descriptor = os.open(path, _directory_flags())
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ProfileRecoveryStateUnsafeError(
            "profile root cannot be opened safely"
        ) from exc
    try:
        if not _same_inode(before, opened):
            raise ProfileRecoveryStateUnsafeError("profile root changed while opening")
        _require_directory(opened, "profile root")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_state_directory(root_fd: int, *, create: bool) -> int | None:
    try:
        before = os.stat(
            PROFILE_RECOVERY_STATE_DIRECTORY_NAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        if not create:
            return None
        try:
            os.mkdir(
                PROFILE_RECOVERY_STATE_DIRECTORY_NAME,
                PRIVATE_DIRECTORY_MODE,
                dir_fd=root_fd,
            )
            os.fsync(root_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise ProfileRecoveryStateUnsafeError(
                "recovery state directory cannot be created safely"
            ) from exc
        before = os.stat(
            PROFILE_RECOVERY_STATE_DIRECTORY_NAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    try:
        descriptor = os.open(
            PROFILE_RECOVERY_STATE_DIRECTORY_NAME,
            _directory_flags(),
            dir_fd=root_fd,
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ProfileRecoveryStateUnsafeError(
            "recovery state directory cannot be opened safely"
        ) from exc
    try:
        if not _same_inode(before, opened):
            raise ProfileRecoveryStateUnsafeError(
                "recovery state directory changed while opening"
            )
        _require_directory(opened, "recovery state directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileRecoveryStateFormatError("recovery state has duplicate keys")
        result[key] = value
    return result


def _hex_identifier(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProfileRecoveryStateFormatError(f"{label} is invalid")
    return value


def encode_profile_recovery_state(record: ProfileRecoveryStateRecord) -> bytes:
    if not isinstance(record, ProfileRecoveryStateRecord):
        raise ProfileRecoveryStateFormatError("recovery state type is invalid")
    _hex_identifier(record.profile_id, "profile identifier")
    _hex_identifier(record.vault_id, "Vault identifier")
    _hex_identifier(record.recovery_id, "recovery identifier")
    if (
        record.format != PROFILE_RECOVERY_STATE_FORMAT
        or record.version != PROFILE_RECOVERY_STATE_VERSION
        or type(record.source_revision) is not int
        or not 1 <= record.source_revision <= _MAX_REVISION
        or type(record.replacement_reminders_shown) is not int
        or not 0
        <= record.replacement_reminders_shown
        <= MAX_REPLACEMENT_REMINDERS
    ):
        raise ProfileRecoveryStateFormatError("recovery state values are invalid")
    mapping = {
        "format": record.format,
        "profile_id": record.profile_id,
        "recovery_id": record.recovery_id,
        "replacement_reminders_shown": record.replacement_reminders_shown,
        "source_revision": record.source_revision,
        "vault_id": record.vault_id,
        "version": record.version,
    }
    encoded = json.dumps(
        mapping,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if not 1 <= len(encoded) <= MAX_PROFILE_RECOVERY_STATE_BYTES:
        raise ProfileRecoveryStateFormatError("recovery state exceeds its bound")
    return encoded


def parse_profile_recovery_state(value: Any) -> ProfileRecoveryStateRecord:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProfileRecoveryStateFormatError("recovery state must be bytes")
    exact = bytes(value)
    if not 1 <= len(exact) <= MAX_PROFILE_RECOVERY_STATE_BYTES:
        raise ProfileRecoveryStateFormatError("recovery state size is invalid")
    try:
        mapping = json.loads(
            exact.decode("ascii", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProfileRecoveryStateFormatError("recovery state contains non-JSON numbers")
            ),
        )
    except ProfileRecoveryStateFormatError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProfileRecoveryStateFormatError("recovery state is malformed") from exc
    if type(mapping) is not dict or set(mapping) != _STATE_FIELDS:
        raise ProfileRecoveryStateFormatError("recovery state fields are invalid")
    result = ProfileRecoveryStateRecord(
        profile_id=_hex_identifier(mapping["profile_id"], "profile identifier"),
        vault_id=_hex_identifier(mapping["vault_id"], "Vault identifier"),
        recovery_id=_hex_identifier(mapping["recovery_id"], "recovery identifier"),
        source_revision=mapping["source_revision"],
        replacement_reminders_shown=mapping["replacement_reminders_shown"],
        format=mapping["format"],
        version=mapping["version"],
    )
    if encode_profile_recovery_state(result) != exact:
        raise ProfileRecoveryStateFormatError("recovery state is not canonical")
    return result


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise ProfileRecoveryStateFormatError("recovery state is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ProfileRecoveryStateFormatError("recovery state grew while reading")
    return b"".join(chunks)


def _read_state(directory_fd: int) -> tuple[ProfileRecoveryStateRecord, bytes]:
    try:
        descriptor = os.open(
            PROFILE_RECOVERY_STATE_NAME,
            _file_flags(),
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
        current = os.stat(
            PROFILE_RECOVERY_STATE_NAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ProfileRecoveryStateUnsafeError(
            "recovery state cannot be opened safely"
        ) from exc
    try:
        if not _same_inode(opened, current):
            raise ProfileRecoveryStateUnsafeError(
                "recovery state changed while opening"
            )
        _require_file(opened, "recovery state")
        encoded = _read_exact(descriptor, opened.st_size)
        return parse_profile_recovery_state(encoded), encoded
    finally:
        os.close(descriptor)


def _scan_state_directory(directory_fd: int) -> tuple[bool, int]:
    try:
        iterator = os.scandir(directory_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ProfileRecoveryStateUnsafeError(
            "recovery state directory cannot be scanned safely"
        ) from exc
    state_present = False
    temporary_count = 0
    try:
        for position, entry in enumerate(iterator):
            if position >= MAX_PROFILE_RECOVERY_STATE_ENTRIES:
                raise ProfileRecoveryStateConflictError(
                    "recovery state directory exceeds its bound"
                )
            if entry.name == PROFILE_RECOVERY_STATE_NAME:
                state_present = True
                continue
            if _TEMP_RE.fullmatch(entry.name) is None:
                raise ProfileRecoveryStateConflictError(
                    "recovery state directory contains an unknown object"
                )
            try:
                info = entry.stat(follow_symlinks=False)
                _require_file(info, "recovery state temporary", allow_empty=True)
            except (OSError, ProfileRecoveryStateError) as exc:
                raise ProfileRecoveryStateConflictError(
                    "recovery state directory contains an unsafe temporary"
                ) from exc
            temporary_count += 1
    finally:
        iterator.close()
    return state_present, temporary_count


def _bound_inspection(
    record: ProfileRecoveryStateRecord,
    snapshot: ProfileSnapshot,
) -> ProfileRecoveryStateInspection:
    revision = snapshot.receipt.revision
    if (
        record.profile_id != snapshot.descriptor.profile_id
        or record.vault_id != snapshot.descriptor.vault_id
        or record.source_revision > revision
    ):
        return ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.INVALID,
            "binding",
            record.source_revision,
            revision,
        )
    availability = (
        ProfileRecoveryAvailability.CURRENT
        if record.source_revision == revision
        else ProfileRecoveryAvailability.REPLACEMENT_REQUIRED
    )
    return ProfileRecoveryStateInspection(
        availability,
        "current" if availability is ProfileRecoveryAvailability.CURRENT else "stale",
        record.source_revision,
        revision,
        record.replacement_reminders_shown,
        record,
    )


def inspect_profile_recovery_state(
    profile_root: Any,
    *,
    snapshot: ProfileSnapshot | None = None,
) -> ProfileRecoveryStateInspection:
    try:
        exact_snapshot = load_profile(profile_root) if snapshot is None else snapshot
        if not isinstance(exact_snapshot, ProfileSnapshot):
            raise ProfileRecoveryStateUnsafeError("profile snapshot is invalid")
        path = _path_text(profile_root)
        root_fd = _open_root(path)
        try:
            directory_fd = _open_state_directory(root_fd, create=False)
        finally:
            os.close(root_fd)
        if directory_fd is None:
            return ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.MISSING,
                "missing",
                current_revision=exact_snapshot.receipt.revision,
            )
        try:
            state_present, temporary_count = _scan_state_directory(directory_fd)
            if not state_present:
                return ProfileRecoveryStateInspection(
                    ProfileRecoveryAvailability.MISSING,
                    "interrupted" if temporary_count else "missing",
                    current_revision=exact_snapshot.receipt.revision,
                )
            record, _encoded = _read_state(directory_fd)
        finally:
            os.close(directory_fd)
        return _bound_inspection(record, exact_snapshot)
    except Exception as exc:
        return ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.INVALID,
            type(exc).__name__,
        )


def _write_all(descriptor: int, encoded: bytes) -> None:
    offset = 0
    while offset < len(encoded):
        written = os.write(descriptor, encoded[offset:])
        if not 1 <= written <= len(encoded) - offset:
            raise ProfileRecoveryStateError("recovery state write made no progress")
        offset += written


def _publish_state(
    path: str,
    record: ProfileRecoveryStateRecord,
    *,
    expected_existing: bytes | None,
    allow_repair: bool,
) -> None:
    encoded = encode_profile_recovery_state(record)
    root_fd = _open_root(path)
    try:
        directory_fd = _open_state_directory(root_fd, create=True)
    finally:
        os.close(root_fd)
    assert directory_fd is not None
    temp_name = f".recovery-state-{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    renamed = False
    try:
        state_present, _temporary_count = _scan_state_directory(directory_fd)
        if state_present:
            try:
                _old_record, old_encoded = _read_state(directory_fd)
            except ProfileRecoveryStateError:
                if not allow_repair:
                    raise
                old_encoded = None
        else:
            old_encoded = None
        if expected_existing is not None and old_encoded != expected_existing:
            raise ProfileRecoveryStateConflictError(
                "recovery state changed before update"
            )
        descriptor = os.open(
            temp_name,
            _file_flags(write=True, create=True),
            PRIVATE_FILE_MODE,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        _require_file(os.fstat(descriptor), "new recovery state", allow_empty=True)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        _require_file(written, "sealed recovery state")
        os.lseek(descriptor, 0, os.SEEK_SET)
        # The write descriptor is intentionally not reused for readback.
        if expected_existing is not None:
            _current_record, current_encoded = _read_state(directory_fd)
            if current_encoded != expected_existing:
                raise ProfileRecoveryStateConflictError(
                    "recovery state changed during update"
                )
        try:
            os.replace(
                temp_name,
                PROFILE_RECOVERY_STATE_NAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        except (OSError, TypeError, NotImplementedError) as exc:
            raise ProfileRecoveryStateUnsafeError(
                "atomic recovery state replacement is unavailable"
            ) from exc
        renamed = True
        temp_name = ""
        os.fsync(directory_fd)
        final_record, final_encoded = _read_state(directory_fd)
        if final_record != record or final_encoded != encoded:
            raise ProfileRecoveryStatePublishUncertainError(
                "published recovery state differs from the intended receipt"
            )
    except BaseException as exc:
        if renamed and not isinstance(exc, ProfileRecoveryStatePublishUncertainError):
            raise ProfileRecoveryStatePublishUncertainError(
                "recovery state may be visible; read-only inspection is required"
            ) from exc
        if temp_name:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def publish_current_profile_recovery_state(
    profile_root: Any,
    recovery_id: Any,
    expected_vault_receipt: VaultGenerationReceipt,
) -> ProfileRecoveryStateInspection:
    if not isinstance(expected_vault_receipt, VaultGenerationReceipt):
        raise ProfileRecoveryStateConflictError("expected Vault receipt is invalid")
    if not isinstance(recovery_id, (bytes, bytearray, memoryview)):
        raise ProfileRecoveryStateFormatError("recovery identifier must be bytes")
    exact_recovery_id = bytes(recovery_id)
    if len(exact_recovery_id) != 16:
        raise ProfileRecoveryStateFormatError("recovery identifier size is invalid")
    snapshot = load_profile(profile_root)
    if snapshot.receipt != expected_vault_receipt:
        raise ProfileRecoveryStateConflictError(
            "current Vault revision changed before recovery setup completion"
        )
    record = ProfileRecoveryStateRecord(
        profile_id=snapshot.descriptor.profile_id,
        vault_id=snapshot.descriptor.vault_id,
        recovery_id=exact_recovery_id.hex(),
        source_revision=snapshot.receipt.revision,
    )
    path = _path_text(profile_root)
    _publish_state(path, record, expected_existing=None, allow_repair=True)
    inspection = inspect_profile_recovery_state(profile_root, snapshot=snapshot)
    if not inspection.recovery_available:
        raise ProfileRecoveryStatePublishUncertainError(
            "current recovery state could not be verified after publish"
        )
    return inspection


def note_successful_login_for_recovery(
    profile_root: Any,
) -> ProfileRecoveryLoginNotice:
    snapshot = load_profile(profile_root)
    inspection = inspect_profile_recovery_state(profile_root, snapshot=snapshot)
    if not inspection.replacement_required or inspection._record is None:
        return ProfileRecoveryLoginNotice(inspection, False)
    record = inspection._record
    if record.replacement_reminders_shown >= MAX_REPLACEMENT_REMINDERS:
        return ProfileRecoveryLoginNotice(inspection, False)
    updated = ProfileRecoveryStateRecord(
        profile_id=record.profile_id,
        vault_id=record.vault_id,
        recovery_id=record.recovery_id,
        source_revision=record.source_revision,
        replacement_reminders_shown=record.replacement_reminders_shown + 1,
    )
    old_encoded = encode_profile_recovery_state(record)
    path = _path_text(profile_root)
    _publish_state(
        path,
        updated,
        expected_existing=old_encoded,
        allow_repair=False,
    )
    refreshed = inspect_profile_recovery_state(profile_root, snapshot=snapshot)
    if not refreshed.replacement_required:
        raise ProfileRecoveryStatePublishUncertainError(
            "replacement reminder state could not be verified"
        )
    return ProfileRecoveryLoginNotice(
        refreshed,
        True,
        updated.replacement_reminders_shown,
    )


__all__ = [
    "MAX_PROFILE_RECOVERY_STATE_BYTES",
    "MAX_PROFILE_RECOVERY_STATE_ENTRIES",
    "MAX_REPLACEMENT_REMINDERS",
    "PROFILE_RECOVERY_STATE_FORMAT",
    "PROFILE_RECOVERY_STATE_NAME",
    "PROFILE_RECOVERY_STATE_VERSION",
    "ProfileRecoveryAvailability",
    "ProfileRecoveryLoginNotice",
    "ProfileRecoveryStateConflictError",
    "ProfileRecoveryStateError",
    "ProfileRecoveryStateFormatError",
    "ProfileRecoveryStateInspection",
    "ProfileRecoveryStatePublishUncertainError",
    "ProfileRecoveryStateRecord",
    "ProfileRecoveryStateUnsafeError",
    "encode_profile_recovery_state",
    "inspect_profile_recovery_state",
    "note_successful_login_for_recovery",
    "parse_profile_recovery_state",
    "publish_current_profile_recovery_state",
]
