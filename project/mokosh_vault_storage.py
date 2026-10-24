"""Crash-aware immutable storage for authenticated MOKOSH Vault generations.

This POSIX backend holds an exact directory descriptor, publishes one new
immutable generation through a same-directory hard link, and never replaces
or deletes a published generation.  Reconciliation is strictly read-only.
"""

from __future__ import annotations

import enum
import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from typing import Any

from mokosh_vault_format import (
    MAX_VAULT_CIPHERTEXT_LEN,
    MAX_VAULT_HEADER_LEN,
    VAULT_PREAMBLE_LEN,
    ParsedVault,
    VaultSession,
    VaultSessionState,
    parse_vault,
)


PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
MAX_STORAGE_ENTRIES = 512
MAX_GENERATION_BYTES = (
    VAULT_PREAMBLE_LEN + MAX_VAULT_HEADER_LEN + MAX_VAULT_CIPHERTEXT_LEN
)
TEMP_CREATE_ATTEMPTS = 32
GENERATION_NAME_WIDTH = 20

_GENERATION_RE = re.compile(r"^vault-r([0-9]{20})\.mokv$")
_TEMP_RE = re.compile(r"^\.mokosh-vault-([0-9a-f]{32})\.tmp$")


class VaultStorageError(RuntimeError):
    """Base class for Vault storage failures."""


class UnsafeVaultDirectoryError(VaultStorageError):
    """The directory path, ownership, mode, or identity is unsafe."""


class VaultStorageLimitError(VaultStorageError):
    """A bounded storage limit is exceeded."""


class VaultGenerationConflictError(VaultStorageError):
    """Generation history is missing, conflicting, or inconsistent."""


class VaultPublishUnsupportedError(VaultStorageError):
    """The platform cannot provide the required publish semantics."""


class VaultPublishUncertainError(VaultStorageError):
    """A generation may be visible but its durable state is uncertain."""


class VaultObjectKind(enum.Enum):
    GENERATION_VALID = "generation_valid"
    GENERATION_INVALID = "generation_invalid"
    TEMPORARY_UNLINKED = "temporary_unlinked"
    TEMPORARY_LINKED = "temporary_linked"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    uid: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            links=value.st_nlink,
            size=value.st_size,
            uid=getattr(value, "st_uid", 0),
        )


@dataclass(frozen=True, slots=True)
class VaultGenerationReceipt:
    directory_device: int
    directory_inode: int
    vault_id: bytes
    revision: int
    sha256: bytes
    file_device: int
    file_inode: int
    encoded_size: int
    durable: bool = True


@dataclass(frozen=True, slots=True)
class VaultStorageFinding:
    kind: VaultObjectKind
    object_token: str
    revision: int | None
    identity: FileIdentity | None


@dataclass(frozen=True, slots=True)
class VaultStorageReport:
    directory_device: int
    directory_inode: int
    findings: tuple[VaultStorageFinding, ...]
    generations: tuple[VaultGenerationReceipt, ...]
    omitted_entries: int
    complete: bool

    @property
    def has_conflict(self) -> bool:
        invalid = sum(
            finding.kind
            in {
                VaultObjectKind.GENERATION_INVALID,
                VaultObjectKind.TEMPORARY_UNLINKED,
                VaultObjectKind.TEMPORARY_LINKED,
                VaultObjectKind.UNKNOWN,
            }
            for finding in self.findings
        )
        if not self.complete or invalid > 0:
            return True
        if not self.generations:
            return False
        revisions = [item.revision for item in self.generations]
        if revisions != list(range(1, revisions[-1] + 1)):
            return True
        first_id = self.generations[0].vault_id
        return any(item.vault_id != first_id for item in self.generations)


def generation_name(revision: int) -> str:
    if type(revision) is not int or not 1 <= revision <= 10**GENERATION_NAME_WIDTH - 1:
        raise VaultGenerationConflictError("revision cannot be represented canonically")
    return f"vault-r{revision:0{GENERATION_NAME_WIDTH}d}.mokv"


def _path_text(value: Any, field: str) -> str:
    try:
        result = os.fspath(value)
    except TypeError as exc:
        raise UnsafeVaultDirectoryError(f"{field} must be a path") from exc
    if not isinstance(result, str) or not result or "\x00" in result:
        raise UnsafeVaultDirectoryError(f"{field} must be non-empty text")
    absolute = os.path.abspath(result)
    if os.path.realpath(absolute) != absolute:
        raise UnsafeVaultDirectoryError(f"{field} must not contain symlinks")
    return absolute


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _file_flags(*, write: bool = False) -> int:
    flags = os.O_RDWR if write else os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _create_flags() -> int:
    return _file_flags(write=True) | os.O_CREAT | os.O_EXCL


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _require_private_directory(value: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise UnsafeVaultDirectoryError(f"{label} must be a directory")
    if stat.S_IMODE(value.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise UnsafeVaultDirectoryError(f"{label} mode must be exactly 0700")
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise UnsafeVaultDirectoryError(f"{label} must be owned by the current user")


def _require_private_file(
    value: os.stat_result,
    label: str,
    *,
    links: set[int],
    allow_empty: bool = False,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise VaultGenerationConflictError(f"{label} must be a regular file")
    if stat.S_IMODE(value.st_mode) != PRIVATE_FILE_MODE:
        raise VaultGenerationConflictError(f"{label} mode must be exactly 0600")
    uid = _current_uid()
    if uid is not None and value.st_uid != uid:
        raise VaultGenerationConflictError(f"{label} owner is invalid")
    if value.st_nlink not in links:
        raise VaultGenerationConflictError(f"{label} link count is invalid")
    minimum_size = 0 if allow_empty else 1
    if not minimum_size <= value.st_size <= MAX_GENERATION_BYTES:
        raise VaultStorageLimitError(f"{label} size is outside its bound")


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except (OSError, NotImplementedError) as exc:
        raise VaultPublishUnsupportedError("directory fsync is unavailable") from exc


def _read_exact_descriptor(descriptor: int, expected_size: int) -> bytes:
    if type(expected_size) is not int or not 1 <= expected_size <= MAX_GENERATION_BYTES:
        raise VaultStorageLimitError("generation size is outside its bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        requested = min(64 * 1024, expected_size - offset)
        try:
            chunk = os.pread(descriptor, requested, offset)
        except (AttributeError, OSError) as exc:
            raise VaultPublishUnsupportedError("bounded descriptor read is unavailable") from exc
        if not chunk:
            raise VaultGenerationConflictError("generation became truncated while reading")
        if len(chunk) > requested:
            raise VaultGenerationConflictError("descriptor read exceeded its requested bound")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        raise VaultGenerationConflictError("generation grew while reading")
    return b"".join(chunks)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset : offset + 64 * 1024])
        except OSError as exc:
            raise VaultStorageError("Vault temporary write failed") from exc
        if not 1 <= written <= min(64 * 1024, len(data) - offset):
            raise VaultStorageError("Vault temporary write made invalid progress")
        offset += written


def _object_token(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8", errors="surrogateescape")).hexdigest()[:24]


def _validate_receipt(receipt: VaultGenerationReceipt) -> None:
    if not isinstance(receipt, VaultGenerationReceipt):
        raise VaultGenerationConflictError("previous must be VaultGenerationReceipt")
    integer_fields = (
        receipt.directory_device,
        receipt.directory_inode,
        receipt.revision,
        receipt.file_device,
        receipt.file_inode,
        receipt.encoded_size,
    )
    if any(type(value) is not int or value < 0 for value in integer_fields):
        raise VaultGenerationConflictError("receipt integer fields are invalid")
    if (
        type(receipt.vault_id) is not bytes
        or type(receipt.sha256) is not bytes
        or len(receipt.vault_id) != 16
        or len(receipt.sha256) != 32
    ):
        raise VaultGenerationConflictError("receipt binary fields are invalid")
    if receipt.revision < 1 or type(receipt.durable) is not bool or not receipt.durable:
        raise VaultGenerationConflictError("receipt is not a durable generation")


class VaultStorage:
    """Exact-descriptor storage for one Vault's immutable generations."""

    __slots__ = ("_path", "_descriptor", "_identity", "_closed")

    def __init__(self, path: Any) -> None:
        exact_path = _path_text(path, "Vault directory")
        try:
            before = os.lstat(exact_path)
            descriptor = os.open(exact_path, _directory_flags())
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise UnsafeVaultDirectoryError("cannot securely open Vault directory") from exc
        try:
            if not _same_inode(before, opened):
                raise UnsafeVaultDirectoryError("Vault directory changed while opening")
            _require_private_directory(before, "Vault directory")
            _require_private_directory(opened, "opened Vault directory")
            _sync_directory(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        self._path = exact_path
        self._descriptor = descriptor
        self._identity = FileIdentity.from_stat(opened)
        self._closed = False

    @classmethod
    def create(cls, path: Any) -> "VaultStorage":
        exact_path = _path_text(path, "Vault directory")
        parent = os.path.dirname(exact_path)
        name = os.path.basename(exact_path)
        if name in {"", ".", ".."}:
            raise UnsafeVaultDirectoryError("Vault directory needs one valid basename")
        try:
            parent_before = os.lstat(parent)
            parent_fd = os.open(parent, _directory_flags())
            parent_opened = os.fstat(parent_fd)
        except OSError as exc:
            raise UnsafeVaultDirectoryError("cannot securely open Vault parent") from exc
        created = False
        try:
            if not _same_inode(parent_before, parent_opened) or not stat.S_ISDIR(
                parent_opened.st_mode
            ):
                raise UnsafeVaultDirectoryError("Vault parent changed while opening")
            if stat.S_IMODE(parent_opened.st_mode) & 0o022:
                raise UnsafeVaultDirectoryError("Vault parent must not be group/world writable")
            _sync_directory(parent_fd)
            try:
                os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise UnsafeVaultDirectoryError("Vault directory already exists") from exc
            except (TypeError, NotImplementedError, OSError) as exc:
                raise VaultPublishUnsupportedError(
                    "relative no-clobber directory creation is unavailable"
                ) from exc
            created = True
            child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
            try:
                os.fchmod(child_fd, PRIVATE_DIRECTORY_MODE)
                _require_private_directory(os.fstat(child_fd), "new Vault directory")
                _sync_directory(child_fd)
                _sync_directory(parent_fd)
            finally:
                os.close(child_fd)
        except BaseException:
            if created:
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                    _sync_directory(parent_fd)
                except Exception:
                    pass
            raise
        finally:
            os.close(parent_fd)
        return cls(exact_path)

    def __repr__(self) -> str:
        return f"VaultStorage(closed={self._closed!r})"

    def __copy__(self) -> None:
        raise TypeError("VaultStorage cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultStorage cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultStorage cannot be pickled")

    def _require_open(self) -> None:
        if self._closed:
            raise VaultStorageError("Vault storage is closed")

    def _verify_directory(self) -> os.stat_result:
        self._require_open()
        try:
            opened = os.fstat(self._descriptor)
            current = os.lstat(self._path)
        except OSError as exc:
            raise UnsafeVaultDirectoryError("Vault directory is unavailable") from exc
        if not _same_inode(opened, current):
            raise UnsafeVaultDirectoryError("Vault directory identity changed")
        _require_private_directory(opened, "opened Vault directory")
        _require_private_directory(current, "Vault directory")
        return opened

    @property
    def directory_identity(self) -> FileIdentity:
        self._verify_directory()
        return self._identity

    def _open_generation(self, revision: int) -> tuple[int, os.stat_result, ParsedVault, bytes]:
        name = generation_name(revision)
        try:
            descriptor = os.open(name, _file_flags(), dir_fd=self._descriptor)
        except OSError as exc:
            raise VaultGenerationConflictError("required generation is unavailable") from exc
        try:
            opened = os.fstat(descriptor)
            current = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
            if not _same_inode(opened, current):
                raise VaultGenerationConflictError("generation changed while opening")
            _require_private_file(opened, "generation", links={1})
            encoded = _read_exact_descriptor(descriptor, opened.st_size)
            parsed = parse_vault(encoded)
            if parsed.header.revision != revision:
                raise VaultGenerationConflictError("filename revision does not match Vault")
            return descriptor, opened, parsed, encoded
        except BaseException:
            os.close(descriptor)
            raise

    def verify_receipt(self, receipt: VaultGenerationReceipt) -> bytes:
        self._verify_directory()
        _validate_receipt(receipt)
        if (
            receipt.directory_device != self._identity.device
            or receipt.directory_inode != self._identity.inode
        ):
            raise VaultGenerationConflictError("receipt belongs to another directory")
        descriptor, opened, parsed, encoded = self._open_generation(receipt.revision)
        try:
            if (
                opened.st_dev != receipt.file_device
                or opened.st_ino != receipt.file_inode
                or opened.st_size != receipt.encoded_size
                or parsed.header.vault_id != receipt.vault_id
                or hashlib.sha256(encoded).digest() != receipt.sha256
            ):
                raise VaultGenerationConflictError("generation no longer matches receipt")
            return encoded
        finally:
            os.close(descriptor)

    def scan(self, *, maximum_entries: int = MAX_STORAGE_ENTRIES) -> VaultStorageReport:
        directory = self._verify_directory()
        if type(maximum_entries) is not int or not 1 <= maximum_entries <= MAX_STORAGE_ENTRIES:
            raise VaultStorageLimitError("maximum_entries is outside its bound")
        findings: list[VaultStorageFinding] = []
        generations: list[VaultGenerationReceipt] = []
        omitted = 0
        try:
            iterator = os.scandir(self._descriptor)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise VaultPublishUnsupportedError("descriptor-relative scan is unavailable") from exc
        try:
            entries = enumerate(iterator)
            for position, entry in entries:
                if position >= maximum_entries:
                    omitted += 1
                    continue
                try:
                    token = _object_token(entry.name)
                    match = _GENERATION_RE.fullmatch(entry.name)
                    temp_match = _TEMP_RE.fullmatch(entry.name)
                    observed = entry.stat(follow_symlinks=False)
                    identity = FileIdentity.from_stat(observed)
                except OSError:
                    findings.append(
                        VaultStorageFinding(VaultObjectKind.UNKNOWN, token, None, None)
                    )
                    continue
                if match is not None:
                    revision = int(match.group(1))
                    try:
                        descriptor, opened, parsed, encoded = self._open_generation(revision)
                        try:
                            receipt = VaultGenerationReceipt(
                                directory_device=directory.st_dev,
                                directory_inode=directory.st_ino,
                                vault_id=parsed.header.vault_id,
                                revision=revision,
                                sha256=hashlib.sha256(encoded).digest(),
                                file_device=opened.st_dev,
                                file_inode=opened.st_ino,
                                encoded_size=opened.st_size,
                            )
                        finally:
                            os.close(descriptor)
                    except Exception:
                        findings.append(
                            VaultStorageFinding(
                                VaultObjectKind.GENERATION_INVALID,
                                token,
                                revision,
                                identity,
                            )
                        )
                    else:
                        findings.append(
                            VaultStorageFinding(
                                VaultObjectKind.GENERATION_VALID,
                                token,
                                revision,
                                identity,
                            )
                        )
                        generations.append(receipt)
                elif temp_match is not None:
                    uid = _current_uid()
                    valid_temp = (
                        stat.S_ISREG(observed.st_mode)
                        and identity.mode == PRIVATE_FILE_MODE
                        and identity.links in {1, 2}
                        and 0 <= identity.size <= MAX_GENERATION_BYTES
                        and (uid is None or identity.uid == uid)
                    )
                    if not valid_temp:
                        kind = VaultObjectKind.UNKNOWN
                    elif identity.links == 2:
                        kind = VaultObjectKind.TEMPORARY_LINKED
                    else:
                        kind = VaultObjectKind.TEMPORARY_UNLINKED
                    findings.append(VaultStorageFinding(kind, token, None, identity))
                else:
                    findings.append(
                        VaultStorageFinding(VaultObjectKind.UNKNOWN, token, None, identity)
                    )
        finally:
            iterator.close()
        generations.sort(key=lambda item: item.revision)
        return VaultStorageReport(
            directory_device=directory.st_dev,
            directory_inode=directory.st_ino,
            findings=tuple(findings),
            generations=tuple(generations),
            omitted_entries=omitted,
            complete=omitted == 0,
        )

    def _require_clean_history(
        self, report: VaultStorageReport, previous: VaultGenerationReceipt | None
    ) -> None:
        if not report.complete:
            raise VaultStorageLimitError("Vault directory scan is incomplete")
        if any(
            finding.kind is not VaultObjectKind.GENERATION_VALID
            for finding in report.findings
        ):
            raise VaultGenerationConflictError(
                "Vault directory contains unresolved or unknown objects"
            )
        if previous is None:
            if report.generations:
                raise VaultGenerationConflictError("initial publish requires empty history")
            return
        _validate_receipt(previous)
        if not report.generations or report.generations[-1] != previous:
            raise VaultGenerationConflictError("previous receipt is not the latest generation")
        expected = list(range(1, previous.revision + 1))
        actual = [item.revision for item in report.generations]
        if actual != expected:
            raise VaultGenerationConflictError("Vault revision history is not contiguous")
        if any(item.vault_id != previous.vault_id for item in report.generations):
            raise VaultGenerationConflictError("Vault history mixes identifiers")
        self.verify_receipt(previous)

    def _new_temp(self) -> tuple[int, str, os.stat_result]:
        for _ in range(TEMP_CREATE_ATTEMPTS):
            token = secrets.token_hex(16)
            if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
                raise VaultStorageError("secure token source returned invalid output")
            name = f".mokosh-vault-{token}.tmp"
            try:
                descriptor = os.open(
                    name,
                    _create_flags(),
                    PRIVATE_FILE_MODE,
                    dir_fd=self._descriptor,
                )
            except FileExistsError:
                continue
            except (OSError, TypeError, NotImplementedError) as exc:
                raise VaultPublishUnsupportedError(
                    "relative exclusive temporary creation is unavailable"
                ) from exc
            try:
                os.fchmod(descriptor, PRIVATE_FILE_MODE)
                opened = os.fstat(descriptor)
                _require_private_file(
                    opened, "new temporary", links={1}, allow_empty=True
                )
            except BaseException:
                os.close(descriptor)
                try:
                    os.unlink(name, dir_fd=self._descriptor)
                except OSError:
                    pass
                raise
            return descriptor, name, opened
        raise VaultStorageError("cannot allocate unique Vault temporary name")

    def publish(
        self,
        session: VaultSession,
        *,
        previous: VaultGenerationReceipt | None = None,
    ) -> VaultGenerationReceipt:
        directory = self._verify_directory()
        if not isinstance(session, VaultSession):
            raise VaultGenerationConflictError("publish requires VaultSession")
        if session.state is not VaultSessionState.UNLOCKED:
            raise VaultGenerationConflictError("publish requires an unlocked session")
        if session.check_inactivity():
            raise VaultGenerationConflictError("Vault session expired before publish")
        session.touch()
        encoded = session.encoded
        parsed = parse_vault(encoded)
        report = self.scan()
        self._require_clean_history(report, previous)
        if previous is None:
            if parsed.header.revision != 1:
                raise VaultGenerationConflictError("initial Vault revision must be one")
        else:
            if (
                parsed.header.vault_id != previous.vault_id
                or parsed.header.revision != previous.revision + 1
            ):
                raise VaultGenerationConflictError(
                    "new generation does not continue the previous Vault"
                )
        if not 1 <= len(encoded) <= MAX_GENERATION_BYTES:
            raise VaultStorageLimitError("encoded Vault exceeds storage bound")
        final_name = generation_name(parsed.header.revision)
        try:
            os.stat(final_name, dir_fd=self._descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise VaultGenerationConflictError("cannot inspect generation target") from exc
        else:
            raise VaultGenerationConflictError("generation target already exists")

        _sync_directory(self._descriptor)
        descriptor: int | None = None
        temp_name: str | None = None
        temp_identity: os.stat_result | None = None
        linked = False
        try:
            descriptor, temp_name, temp_identity = self._new_temp()
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            written = os.fstat(descriptor)
            _require_private_file(written, "sealed temporary", links={1})
            if not _same_inode(temp_identity, written) or written.st_size != len(encoded):
                raise VaultGenerationConflictError("temporary identity or size changed")
            readback = _read_exact_descriptor(descriptor, written.st_size)
            readback_parsed = parse_vault(readback)
            if (
                readback != encoded
                or readback_parsed.header.vault_id != parsed.header.vault_id
                or readback_parsed.header.revision != parsed.header.revision
            ):
                raise VaultGenerationConflictError("temporary verification failed")
            session.check_inactivity()
            session.touch()
            try:
                os.link(
                    temp_name,
                    final_name,
                    src_dir_fd=self._descriptor,
                    dst_dir_fd=self._descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise VaultGenerationConflictError("generation target collided") from exc
            except (OSError, TypeError, NotImplementedError) as exc:
                raise VaultPublishUnsupportedError(
                    "atomic no-clobber hard-link publish is unavailable"
                ) from exc
            linked = True
            _sync_directory(self._descriptor)
            final_stat = os.stat(
                final_name, dir_fd=self._descriptor, follow_symlinks=False
            )
            temp_stat = os.fstat(descriptor)
            if not _same_inode(final_stat, temp_stat) or temp_stat.st_nlink != 2:
                raise VaultPublishUncertainError(
                    "published generation identity is uncertain"
                )
            os.unlink(temp_name, dir_fd=self._descriptor)
            temp_name = None
            _sync_directory(self._descriptor)
            final_stat = os.stat(
                final_name, dir_fd=self._descriptor, follow_symlinks=False
            )
            _require_private_file(final_stat, "published generation", links={1})
            if not _same_inode(final_stat, temp_stat):
                raise VaultPublishUncertainError("published generation inode changed")
            receipt = VaultGenerationReceipt(
                directory_device=directory.st_dev,
                directory_inode=directory.st_ino,
                vault_id=parsed.header.vault_id,
                revision=parsed.header.revision,
                sha256=hashlib.sha256(encoded).digest(),
                file_device=final_stat.st_dev,
                file_inode=final_stat.st_ino,
                encoded_size=final_stat.st_size,
            )
            self.verify_receipt(receipt)
            return receipt
        except BaseException as exc:
            if linked:
                if isinstance(exc, VaultPublishUncertainError):
                    raise
                raise VaultPublishUncertainError(
                    "generation may be visible; read-only reconciliation is required"
                ) from exc
            if descriptor is not None and temp_name is not None and temp_identity is not None:
                try:
                    current = os.stat(
                        temp_name,
                        dir_fd=self._descriptor,
                        follow_symlinks=False,
                    )
                    opened = os.fstat(descriptor)
                    if (
                        _same_inode(current, opened)
                        and _same_inode(opened, temp_identity)
                        and current.st_nlink == 1
                        and opened.st_nlink == 1
                    ):
                        os.unlink(temp_name, dir_fd=self._descriptor)
                        _sync_directory(self._descriptor)
                except Exception:
                    pass
            raise
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def close(self) -> None:
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True

    def __enter__(self) -> "VaultStorage":
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
