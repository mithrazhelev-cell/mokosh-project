"""Fail-closed local storage for one Stage 2.46 protected profile.

The profile descriptor contains only bounded public UI metadata.  Secret key
material lives exclusively in the existing authenticated schema-two Key Vault
and is published through the existing immutable POSIX generation store.

Stage 2.46 deliberately supports the Linux/POSIX backend only.  Windows and
macOS packaging must not silently fall back to weaker filesystem semantics;
their native storage backends are later platform work.
"""

from __future__ import annotations

import enum
import json
import os
import secrets
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mokosh_vault_format import (
    MAX_PASSWORD_UTF8_LEN,
    VaultSession,
    VaultSessionState,
    create_keyring_vault,
    parse_vault,
    utc_now,
)
from mokosh_vault_storage import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    VaultGenerationReceipt,
    VaultStorage,
)


PROFILE_FORMAT = "MOKOSH_SECURE_PROFILE"
PROFILE_VERSION = 1
PROFILE_DESCRIPTOR_NAME = "profile.json"
PROFILE_VAULT_DIRECTORY_NAME = "key-vault"
PROFILE_RECOVERY_STATE_DIRECTORY_NAME = "recovery-state"
MAX_PROFILE_DESCRIPTOR_BYTES = 4096
MAX_PROFILE_ENTRIES = 8
MIN_PROFILE_PASSWORD_CHARACTERS = 15
MAX_NICKNAME_CHARACTERS = 64
DEFAULT_PROFILE_DIRECTORY_NAME = "profile-v1"
DEFAULT_APPLICATION_DIRECTORY_NAME = "mokosh"

_PROFILE_FIELDS = frozenset(
    {
        "format",
        "version",
        "profile_id",
        "nickname",
        "created_utc",
        "key_vault",
        "vault_id",
    }
)
_BIDI_FORBIDDEN = frozenset(
    {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
)


class ProfileStorageError(RuntimeError):
    """Base class for profile storage refusals."""


class ProfileUnsupportedPlatformError(ProfileStorageError):
    """The required native filesystem guarantees are unavailable."""


class ProfileUnsafePathError(ProfileStorageError):
    """A profile path, owner, permission, or object type is unsafe."""


class ProfileConflictError(ProfileStorageError):
    """Existing or partial profile state blocks mutation."""


class ProfileFormatError(ProfileStorageError, ValueError):
    """The bounded public descriptor is malformed or non-canonical."""


class ProfileValidationError(ProfileStorageError, ValueError):
    """A new nickname or password violates the explicit policy."""


class ProfileState(str, enum.Enum):
    ABSENT = "absent"
    READY = "ready"
    PARTIAL = "partial"
    CONFLICT = "conflict"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ProfileDescriptor:
    profile_id: str
    nickname: str
    created_utc: str
    vault_id: str
    key_vault: str = PROFILE_VAULT_DIRECTORY_NAME
    format: str = PROFILE_FORMAT
    version: int = PROFILE_VERSION


@dataclass(frozen=True, slots=True)
class ProfileInspection:
    state: ProfileState
    legacy_login_records_present: bool
    descriptor: ProfileDescriptor | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ProfileSnapshot:
    descriptor: ProfileDescriptor
    vault_bytes: bytes = field(repr=False)
    receipt: VaultGenerationReceipt


def _linux_supported() -> bool:
    required = (
        os.open,
        os.lstat,
        os.fstat,
        os.fsync,
        os.link,
        os.unlink,
    )
    return sys.platform.startswith("linux") and all(callable(item) for item in required)


def require_supported_platform() -> None:
    if not _linux_supported():
        raise ProfileUnsupportedPlatformError(
            "the Stage 2.46 protected-profile backend is unavailable"
        )


def _path_text(value: Any) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ProfileUnsafePathError("profile root must be a path") from exc
    if type(raw) is not str or not raw or "\x00" in raw:
        raise ProfileUnsafePathError("profile root must be non-empty text")
    result = os.path.abspath(os.path.expanduser(raw))
    if os.path.realpath(result) != result:
        raise ProfileUnsafePathError("profile root must not contain symlinks")
    return result


def default_profile_root() -> Path:
    configured = os.environ.get("MOKOSH_PROFILE_ROOT")
    if configured is not None:
        return Path(_path_text(configured))
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        base = Path(_path_text(xdg))
    else:
        base = Path.home() / ".local" / "share"
    return base / DEFAULT_APPLICATION_DIRECTORY_NAME / DEFAULT_PROFILE_DIRECTORY_NAME


def _root(value: Any | None) -> str:
    return _path_text(default_profile_root() if value is None else value)


def normalize_nickname(value: Any) -> str:
    if type(value) is not str:
        raise ProfileValidationError("nickname must be text")
    normalized = unicodedata.normalize("NFC", value)
    if not 1 <= len(normalized) <= MAX_NICKNAME_CHARACTERS:
        raise ProfileValidationError("nickname length is outside policy")
    if not normalized.strip():
        raise ProfileValidationError("nickname must contain a visible character")
    for character in normalized:
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            raise ProfileValidationError("nickname contains a forbidden character")
        if unicodedata.bidirectional(character) in _BIDI_FORBIDDEN:
            raise ProfileValidationError("nickname contains bidi formatting")
    return normalized


def normalize_password(value: Any) -> str:
    if type(value) is not str:
        raise ProfileValidationError("password must be text")
    normalized = unicodedata.normalize("NFC", value)
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProfileValidationError("password must be valid Unicode") from exc
    if (
        len(normalized) < MIN_PROFILE_PASSWORD_CHARACTERS
        or len(encoded) > MAX_PASSWORD_UTF8_LEN
    ):
        raise ProfileValidationError("password length is outside policy")
    return normalized


def _legacy_records_present(legacy_directory: Any | None) -> bool:
    if legacy_directory is None:
        configured = os.environ.get("MOKOSH_DATA_DIR")
        base = configured if configured else os.path.dirname(__file__)
    else:
        base = legacy_directory
    try:
        directory = _path_text(base)
    except ProfileStorageError:
        return False
    present = False
    for name in ("seed_store.enc", "seed_meta.json"):
        try:
            os.lstat(os.path.join(directory, name))
        except FileNotFoundError:
            continue
        except OSError:
            present = True
        else:
            present = True
    return present


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _require_private_directory(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ProfileUnsafePathError("profile root is not a directory")
    if stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise ProfileUnsafePathError("profile root permissions are unsafe")
    uid = _current_uid()
    if uid is not None and info.st_uid != uid:
        raise ProfileUnsafePathError("profile root owner is unsafe")


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _open_root(path: str) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
        descriptor = os.open(path, _directory_flags())
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ProfileUnsafePathError("cannot securely open profile root") from exc
    try:
        if not _same_inode(before, opened):
            raise ProfileUnsafePathError("profile root changed while opening")
        _require_private_directory(opened)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _create_private_directory(path: str) -> None:
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    if name in {"", ".", ".."}:
        raise ProfileUnsafePathError("profile root needs a valid basename")
    try:
        parent_before = os.lstat(parent)
        parent_fd = os.open(parent, _directory_flags())
        parent_opened = os.fstat(parent_fd)
    except OSError as exc:
        raise ProfileUnsafePathError("profile parent is unavailable") from exc
    try:
        if not _same_inode(parent_before, parent_opened) or not stat.S_ISDIR(
            parent_opened.st_mode
        ):
            raise ProfileUnsafePathError("profile parent changed while opening")
        if stat.S_IMODE(parent_opened.st_mode) & 0o022:
            raise ProfileUnsafePathError("profile parent is group/world writable")
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise ProfileConflictError("profile root already exists") from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise ProfileUnsupportedPlatformError(
                "relative no-clobber profile creation is unavailable"
            ) from exc
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        try:
            os.fchmod(child_fd, PRIVATE_DIRECTORY_MODE)
            _require_private_directory(os.fstat(child_fd))
            os.fsync(child_fd)
            os.fsync(parent_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)


def _ensure_direct_parent(path: str) -> None:
    parent = os.path.dirname(path)
    if os.path.lexists(parent):
        return
    grandparent = os.path.dirname(parent)
    name = os.path.basename(parent)
    try:
        grand_before = os.lstat(grandparent)
        grand_fd = os.open(grandparent, _directory_flags())
        grand_opened = os.fstat(grand_fd)
    except OSError as exc:
        raise ProfileUnsafePathError("profile parent cannot be prepared") from exc
    try:
        if not _same_inode(grand_before, grand_opened) or not stat.S_ISDIR(
            grand_opened.st_mode
        ):
            raise ProfileUnsafePathError("profile parent ancestor is unsafe")
        if stat.S_IMODE(grand_opened.st_mode) & 0o022:
            raise ProfileUnsafePathError("profile parent ancestor is writable")
        os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=grand_fd)
        parent_fd = os.open(name, _directory_flags(), dir_fd=grand_fd)
        try:
            os.fchmod(parent_fd, PRIVATE_DIRECTORY_MODE)
            _require_private_directory(os.fstat(parent_fd))
            os.fsync(parent_fd)
            os.fsync(grand_fd)
        finally:
            os.close(parent_fd)
    except FileExistsError:
        pass
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ProfileUnsupportedPlatformError(
            "private profile parent creation is unavailable"
        ) from exc
    finally:
        os.close(grand_fd)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileFormatError("profile descriptor has duplicate keys")
        result[key] = value
    return result


def encode_profile_descriptor(descriptor: ProfileDescriptor) -> bytes:
    if not isinstance(descriptor, ProfileDescriptor):
        raise ProfileFormatError("descriptor type is invalid")
    mapping = {
        "created_utc": descriptor.created_utc,
        "format": descriptor.format,
        "key_vault": descriptor.key_vault,
        "nickname": descriptor.nickname,
        "profile_id": descriptor.profile_id,
        "vault_id": descriptor.vault_id,
        "version": descriptor.version,
    }
    encoded = json.dumps(
        mapping,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if not 1 <= len(encoded) <= MAX_PROFILE_DESCRIPTOR_BYTES:
        raise ProfileFormatError("profile descriptor exceeds its bound")
    return encoded


def parse_profile_descriptor(data: Any) -> ProfileDescriptor:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ProfileFormatError("profile descriptor must be bytes")
    exact = bytes(data)
    if not 1 <= len(exact) <= MAX_PROFILE_DESCRIPTOR_BYTES:
        raise ProfileFormatError("profile descriptor size is invalid")
    try:
        mapping = json.loads(
            exact.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProfileFormatError("profile descriptor has non-JSON numbers")
            ),
        )
    except ProfileFormatError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProfileFormatError("profile descriptor is malformed") from exc
    if type(mapping) is not dict or set(mapping) != _PROFILE_FIELDS:
        raise ProfileFormatError("profile descriptor fields are invalid")
    if mapping["format"] != PROFILE_FORMAT or mapping["version"] != PROFILE_VERSION:
        raise ProfileFormatError("profile descriptor version is unsupported")
    if mapping["key_vault"] != PROFILE_VAULT_DIRECTORY_NAME:
        raise ProfileFormatError("profile Vault location is invalid")
    profile_id = mapping["profile_id"]
    vault_id = mapping["vault_id"]
    if (
        type(profile_id) is not str
        or len(profile_id) != 32
        or any(character not in "0123456789abcdef" for character in profile_id)
        or type(vault_id) is not str
        or len(vault_id) != 32
        or any(character not in "0123456789abcdef" for character in vault_id)
    ):
        raise ProfileFormatError("profile identifiers are invalid")
    nickname = normalize_nickname(mapping["nickname"])
    if nickname != mapping["nickname"]:
        raise ProfileFormatError("profile nickname is not canonical NFC")
    created = mapping["created_utc"]
    if type(created) is not str:
        raise ProfileFormatError("profile timestamp is invalid")
    # Reuse the Key Vault timestamp parser without exposing a new loose format.
    try:
        checked_time = utc_now() if created == "" else created
        if checked_time != created:
            raise ValueError
        from datetime import datetime

        parsed_time = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
        if parsed_time.strftime("%Y-%m-%dT%H:%M:%SZ") != created:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ProfileFormatError("profile timestamp is invalid") from exc
    result = ProfileDescriptor(
        profile_id=profile_id,
        nickname=nickname,
        created_utc=created,
        vault_id=vault_id,
    )
    if encode_profile_descriptor(result) != exact:
        raise ProfileFormatError("profile descriptor is not canonical")
    return result


def _read_descriptor(root_fd: int) -> ProfileDescriptor:
    try:
        descriptor_fd = os.open(PROFILE_DESCRIPTOR_NAME, _file_flags(), dir_fd=root_fd)
        info = os.fstat(descriptor_fd)
    except OSError as exc:
        raise ProfileFormatError("profile descriptor cannot be opened safely") from exc
    try:
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
            or info.st_nlink != 1
            or not 1 <= info.st_size <= MAX_PROFILE_DESCRIPTOR_BYTES
        ):
            raise ProfileFormatError("profile descriptor object is unsafe")
        uid = _current_uid()
        if uid is not None and info.st_uid != uid:
            raise ProfileFormatError("profile descriptor owner is unsafe")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor_fd, remaining)
            if not chunk:
                raise ProfileFormatError("profile descriptor is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor_fd, 1):
            raise ProfileFormatError("profile descriptor grew while reading")
        return parse_profile_descriptor(b"".join(chunks))
    finally:
        os.close(descriptor_fd)


def _publish_descriptor(root_fd: int, encoded: bytes) -> None:
    temp_name = f".profile-{secrets.token_hex(16)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor_fd: int | None = None
    linked = False
    try:
        descriptor_fd = os.open(temp_name, flags, PRIVATE_FILE_MODE, dir_fd=root_fd)
        os.fchmod(descriptor_fd, PRIVATE_FILE_MODE)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor_fd, encoded[offset:])
            if not 1 <= written <= len(encoded) - offset:
                raise ProfileStorageError("profile descriptor write made no progress")
            offset += written
        os.fsync(descriptor_fd)
        info = os.fstat(descriptor_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
            or info.st_nlink != 1
            or info.st_size != len(encoded)
        ):
            raise ProfileStorageError("profile descriptor temporary is unsafe")
        try:
            os.link(
                temp_name,
                PROFILE_DESCRIPTOR_NAME,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ProfileConflictError("profile descriptor already exists") from exc
        linked = True
        os.fsync(root_fd)
        os.unlink(temp_name, dir_fd=root_fd)
        temp_name = ""
        os.fsync(root_fd)
        final = os.stat(PROFILE_DESCRIPTOR_NAME, dir_fd=root_fd, follow_symlinks=False)
        if (
            not _same_inode(final, info)
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != PRIVATE_FILE_MODE
        ):
            raise ProfileStorageError("published profile descriptor is uncertain")
    except BaseException as exc:
        if linked:
            raise ProfileStorageError(
                "profile descriptor may be visible; read-only inspection is required"
            ) from exc
        if temp_name:
            try:
                os.unlink(temp_name, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor_fd is not None:
            os.close(descriptor_fd)


def inspect_profile(
    root: Any | None = None,
    *,
    legacy_directory: Any | None = None,
) -> ProfileInspection:
    legacy = _legacy_records_present(legacy_directory)
    if not _linux_supported():
        return ProfileInspection(ProfileState.UNSUPPORTED, legacy, reason="platform")
    try:
        path = _root(root)
    except ProfileStorageError:
        return ProfileInspection(ProfileState.CONFLICT, legacy, reason="path")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return ProfileInspection(ProfileState.ABSENT, legacy)
    except OSError:
        return ProfileInspection(ProfileState.CONFLICT, legacy, reason="root")
    try:
        root_fd, _ = _open_root(path)
    except ProfileStorageError:
        return ProfileInspection(ProfileState.CONFLICT, legacy, reason="root")
    try:
        try:
            entries = list(os.scandir(root_fd))
        except OSError:
            return ProfileInspection(ProfileState.CONFLICT, legacy, reason="scan")
        if len(entries) > MAX_PROFILE_ENTRIES:
            return ProfileInspection(ProfileState.CONFLICT, legacy, reason="entries")
        names = {entry.name for entry in entries}
        required = {PROFILE_DESCRIPTOR_NAME, PROFILE_VAULT_DIRECTORY_NAME}
        allowed = required | {PROFILE_RECOVERY_STATE_DIRECTORY_NAME}
        if names - allowed:
            state = ProfileState.PARTIAL if PROFILE_DESCRIPTOR_NAME not in names else ProfileState.CONFLICT
            return ProfileInspection(state, legacy, reason="objects")
        if not required.issubset(names):
            return ProfileInspection(ProfileState.PARTIAL, legacy, reason="incomplete")
        descriptor = _read_descriptor(root_fd)
    except ProfileStorageError:
        return ProfileInspection(ProfileState.CONFLICT, legacy, reason="descriptor")
    finally:
        os.close(root_fd)
    try:
        with VaultStorage(os.path.join(path, PROFILE_VAULT_DIRECTORY_NAME)) as store:
            report = store.scan()
            if report.has_conflict or not report.generations:
                return ProfileInspection(ProfileState.CONFLICT, legacy, reason="vault")
            latest = report.generations[-1]
            if latest.vault_id.hex() != descriptor.vault_id:
                return ProfileInspection(ProfileState.CONFLICT, legacy, reason="binding")
            store.verify_receipt(latest)
    except Exception:
        return ProfileInspection(ProfileState.CONFLICT, legacy, reason="vault")
    return ProfileInspection(ProfileState.READY, legacy, descriptor)


def load_profile(root: Any | None = None) -> ProfileSnapshot:
    path = _root(root)
    inspection = inspect_profile(path)
    if inspection.state is not ProfileState.READY or inspection.descriptor is None:
        raise ProfileConflictError("protected profile is not ready")
    with VaultStorage(os.path.join(path, PROFILE_VAULT_DIRECTORY_NAME)) as store:
        report = store.scan()
        if report.has_conflict or not report.generations:
            raise ProfileConflictError("protected profile Vault is not ready")
        latest = report.generations[-1]
        vault_bytes = store.verify_receipt(latest)
    parsed = parse_vault(vault_bytes)
    if parsed.header.vault_id.hex() != inspection.descriptor.vault_id:
        raise ProfileConflictError("protected profile binding is invalid")
    return ProfileSnapshot(inspection.descriptor, vault_bytes, latest)


def create_profile(
    nickname: Any,
    password: Any,
    root: Any | None = None,
    *,
    created_utc: str | None = None,
    time_cost: int | None = None,
    memory_kib: int | None = None,
    parallelism: int | None = None,
    vault_factory: Callable[..., bytes] = create_keyring_vault,
) -> ProfileDescriptor:
    """Create one profile without overwrite; publish public metadata last."""

    require_supported_platform()
    exact_nickname = normalize_nickname(nickname)
    exact_password = normalize_password(password)
    path = _root(root)
    if inspect_profile(path).state is not ProfileState.ABSENT:
        raise ProfileConflictError("profile creation requires an absent target")
    _ensure_direct_parent(path)
    _create_private_directory(path)
    timestamp = created_utc or utc_now()
    options: dict[str, Any] = {"created_utc": timestamp}
    if time_cost is not None:
        options["time_cost"] = time_cost
    if memory_kib is not None:
        options["memory_kib"] = memory_kib
    if parallelism is not None:
        options["parallelism"] = parallelism
    try:
        vault_bytes = vault_factory(exact_password, **options)
        parsed = parse_vault(vault_bytes)
        session = VaultSession(vault_bytes, inactivity_timeout=30.0)
        try:
            session.unlock(exact_password)
            session.keyring_copy()
            with VaultStorage.create(
                os.path.join(path, PROFILE_VAULT_DIRECTORY_NAME)
            ) as store:
                receipt = store.publish(session)
        finally:
            session.close()

        # Reopen from the published generation and authenticate again before
        # making the descriptor visible.  A failure leaves explicit PARTIAL
        # state and is never mistaken for a new first run.
        with VaultStorage(os.path.join(path, PROFILE_VAULT_DIRECTORY_NAME)) as store:
            report = store.scan()
            if report.has_conflict or len(report.generations) != 1:
                raise ProfileConflictError("fresh profile Vault is inconsistent")
            persisted = store.verify_receipt(receipt)
        confirmation = VaultSession(persisted, inactivity_timeout=30.0)
        try:
            confirmation.unlock(exact_password)
            confirmation.keyring_copy()
            if confirmation.state is not VaultSessionState.UNLOCKED:
                raise ProfileConflictError("fresh profile Vault did not unlock")
        finally:
            confirmation.close()
        descriptor = ProfileDescriptor(
            profile_id=secrets.token_hex(16),
            nickname=exact_nickname,
            created_utc=timestamp,
            vault_id=parsed.header.vault_id.hex(),
        )
        encoded = encode_profile_descriptor(descriptor)
        root_fd, _ = _open_root(path)
        try:
            _publish_descriptor(root_fd, encoded)
        finally:
            os.close(root_fd)
        final = inspect_profile(path)
        if final.state is not ProfileState.READY or final.descriptor != descriptor:
            raise ProfileConflictError("fresh profile verification failed")
        return descriptor
    finally:
        del exact_password


__all__ = [
    "DEFAULT_PROFILE_DIRECTORY_NAME",
    "MAX_NICKNAME_CHARACTERS",
    "MAX_PROFILE_DESCRIPTOR_BYTES",
    "MIN_PROFILE_PASSWORD_CHARACTERS",
    "PROFILE_DESCRIPTOR_NAME",
    "PROFILE_FORMAT",
    "PROFILE_RECOVERY_STATE_DIRECTORY_NAME",
    "PROFILE_VAULT_DIRECTORY_NAME",
    "PROFILE_VERSION",
    "ProfileConflictError",
    "ProfileDescriptor",
    "ProfileFormatError",
    "ProfileInspection",
    "ProfileSnapshot",
    "ProfileState",
    "ProfileStorageError",
    "ProfileUnsafePathError",
    "ProfileUnsupportedPlatformError",
    "ProfileValidationError",
    "create_profile",
    "default_profile_root",
    "encode_profile_descriptor",
    "inspect_profile",
    "load_profile",
    "normalize_nickname",
    "normalize_password",
    "parse_profile_descriptor",
    "require_supported_platform",
]
