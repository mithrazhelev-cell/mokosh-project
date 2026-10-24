"""Fail-closed local filesystem primitives for MOKOSH v2 streaming.

This module supplies a bounded regular-file source and a same-directory
transactional quarantine sink.  It does not choose user paths, encrypt,
decrypt, delete originals, apply trust, access a Vault, or activate the GUI.

Publishing uses an atomic hard link from the private temporary inode to a
previously absent final name.  Hard-link creation fails if the destination
already exists, so no fallback can silently overwrite data.  Filesystems that
cannot provide this guarantee are rejected.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
from dataclasses import dataclass
from typing import Any

from mokosh_v2_format import GCM_TAG_LEN, MAX_CHUNK_SIZE
from mokosh_v2_operation_journal import (
    PRIVATE_FILE_MODE,
    build_operation_journal,
    encode_operation_journal,
    journal_name_for,
    temporary_name_for,
)
from mokosh_v2_operation_lease import (
    HeldOperationLease,
    OperationLeaseError,
    acquire_writer_operation_lease,
)


MAX_SECURE_READ_SIZE = MAX_CHUNK_SIZE + GCM_TAG_LEN
TEMP_CREATE_ATTEMPTS = 128


class FilesystemSafetyError(OSError):
    """A filesystem operation cannot satisfy the required safety contract."""


class UnsafePathError(FilesystemSafetyError):
    """A path is a symlink, non-regular file, or unsafe directory."""


class SourceChangedError(FilesystemSafetyError):
    """The source identity or authenticated metadata changed while open."""


class OutputCollisionError(FilesystemSafetyError):
    """The requested final output name already exists."""


class AtomicPublishUnsupportedError(FilesystemSafetyError):
    """The filesystem cannot atomically publish without overwriting."""


class OwnedTemporaryFileError(FilesystemSafetyError):
    """The private temporary inode is missing, replaced, or unsafe to remove."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    uid: int
    gid: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
            uid=getattr(value, "st_uid", 0),
            gid=getattr(value, "st_gid", 0),
        )


@dataclass(frozen=True, slots=True)
class QuarantinePublishResult:
    """Irreversible publish result without paths or exception text.

    Once this object exists the final hard link was created.  Later cleanup,
    directory-sync, or descriptor-close trouble is represented only by the
    bounded flags below and can never turn the publish into a retryable
    failure.
    """

    output_identity: FileIdentity | None
    output_verified: bool
    publication_sync_complete: bool
    temporary_removed: bool
    journal_removed: bool
    cleanup_sync_complete: bool
    resources_closed: bool

    def __post_init__(self) -> None:
        for name in (
            "output_verified",
            "publication_sync_complete",
            "temporary_removed",
            "journal_removed",
            "cleanup_sync_complete",
            "resources_closed",
        ):
            if type(getattr(self, name)) is not bool:
                raise FilesystemSafetyError("publish result flags must be boolean")
        if self.output_verified != (self.output_identity is not None):
            raise FilesystemSafetyError("publish output identity flags are inconsistent")
        if not self.output_verified and (
            self.temporary_removed
            or self.journal_removed
            or self.cleanup_sync_complete
        ):
            raise FilesystemSafetyError(
                "unverified publication must preserve reconciliation residue"
            )
        if self.journal_removed and not self.temporary_removed:
            raise FilesystemSafetyError(
                "operation journal cannot be removed before its temporary file"
            )
        if self.cleanup_sync_complete and not (
            self.publication_sync_complete
            and self.temporary_removed
            and self.journal_removed
        ):
            raise FilesystemSafetyError(
                "cleanup sync cannot complete while residue remains"
            )

    @property
    def residue_requires_review(self) -> bool:
        return not (self.temporary_removed and self.journal_removed)

    @property
    def warning_required(self) -> bool:
        return not (
            self.output_verified
            and self.publication_sync_complete
            and self.temporary_removed
            and self.journal_removed
            and self.cleanup_sync_complete
            and self.resources_closed
        )


def _path_text(value: Any, field_name: str) -> str:
    try:
        path = os.fspath(value)
    except TypeError as exc:
        raise UnsafePathError(f"{field_name} must be path-like") from exc
    if isinstance(path, bytes):
        raise UnsafePathError(f"{field_name} must be a text path")
    if not isinstance(path, str) or not path or "\x00" in path:
        raise UnsafePathError(f"{field_name} must be non-empty text without NUL")
    return os.path.abspath(path)


def _lstat(path: str, field_name: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError as exc:
        raise UnsafePathError(f"cannot inspect {field_name}") from exc


def _require_regular(value: os.stat_result, field_name: str) -> None:
    if stat.S_ISLNK(value.st_mode):
        raise UnsafePathError(f"{field_name} must not be a symbolic link")
    if not stat.S_ISREG(value.st_mode):
        raise UnsafePathError(f"{field_name} must be a regular file")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _source_open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    # A regular path can be replaced with a FIFO between lstat and open.
    # Non-blocking open lets the post-open fstat reject that race instead of
    # leaving cancellation and the GUI worker blocked in the kernel.
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


class VerifiedFileSource:
    """Bounded binary source tied to one unchanged regular-file identity."""

    def __init__(
        self,
        path: Any,
        *,
        max_read_size: int = MAX_SECURE_READ_SIZE,
    ) -> None:
        if type(max_read_size) is not int or not 1 <= max_read_size <= MAX_SECURE_READ_SIZE:
            raise FilesystemSafetyError(
                f"max_read_size must be between 1 and {MAX_SECURE_READ_SIZE}"
            )
        self.path = _path_text(path, "source path")
        self.max_read_size = max_read_size
        before = _lstat(self.path, "source path")
        _require_regular(before, "source path")
        try:
            descriptor = os.open(self.path, _source_open_flags())
        except OSError as exc:
            raise UnsafePathError("cannot securely open source path") from exc
        try:
            opened = os.fstat(descriptor)
            current = os.lstat(self.path)
            _require_regular(opened, "opened source")
            _require_regular(current, "source path")
            before_identity = FileIdentity.from_stat(before)
            opened_identity = FileIdentity.from_stat(opened)
            current_identity = FileIdentity.from_stat(current)
            if not (
                before_identity == opened_identity == current_identity
            ):
                raise SourceChangedError(
                    "source identity or metadata changed while opening"
                )
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        self._identity = FileIdentity.from_stat(opened)
        self._closed = False
        self._verified = False
        self._bytes_read = 0

    @property
    def identity(self) -> FileIdentity:
        return self._identity

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    @property
    def closed(self) -> bool:
        return self._closed

    def read(self, size: int) -> bytes:
        if self._closed:
            raise FilesystemSafetyError("source is closed")
        if type(size) is not int or not 1 <= size <= self.max_read_size:
            raise FilesystemSafetyError(
                f"read size must be between 1 and {self.max_read_size}"
            )
        try:
            data = os.read(self._descriptor, size)
        except OSError as exc:
            raise FilesystemSafetyError("source read failed") from exc
        if len(data) > size:
            raise AssertionError("os.read returned more bytes than requested")
        self._bytes_read += len(data)
        return data

    def verify_unchanged(self) -> FileIdentity:
        if self._closed:
            raise FilesystemSafetyError("source is closed")
        try:
            opened = os.fstat(self._descriptor)
            current = os.lstat(self.path)
        except OSError as exc:
            raise SourceChangedError("source path or descriptor is unavailable") from exc
        _require_regular(opened, "opened source")
        _require_regular(current, "source path")
        opened_identity = FileIdentity.from_stat(opened)
        current_identity = FileIdentity.from_stat(current)
        if opened_identity != self._identity or current_identity != self._identity:
            raise SourceChangedError("source identity or metadata changed while open")
        self._verified = True
        return self._identity

    def verify_and_close(self) -> FileIdentity:
        identity = self.verify_unchanged()
        self.close()
        return identity

    def close(self) -> None:
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True

    def __enter__(self) -> "VerifiedFileSource":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        try:
            if exc_type is None:
                self.verify_unchanged()
        finally:
            self.close()
        return False


def _require_secure_parent(path: str) -> tuple[str, os.stat_result]:
    parent = os.path.dirname(path)
    if not parent:
        raise UnsafePathError("output requires a parent directory")
    parent_stat = _lstat(parent, "output parent directory")
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise UnsafePathError("output parent must be a real directory")
    if hasattr(os, "getuid"):
        if parent_stat.st_uid != os.getuid():
            raise UnsafePathError("output parent must be owned by the current user")
        if parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UnsafePathError(
                "output parent must not be group- or world-writable"
            )
    return parent, parent_stat


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _temporary_open_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        unsupported = {
            errno.EBADF,
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if exc.errno not in unsupported:
            raise FilesystemSafetyError("parent directory fsync failed") from exc


class ExclusiveFileQuarantineSink:
    """Same-directory 0600 temporary output with atomic no-clobber publish."""

    def __init__(self, final_path: Any) -> None:
        self.final_path = _path_text(final_path, "final output path")
        self._parent_path, parent_before = _require_secure_parent(self.final_path)
        self._final_name = os.path.basename(self.final_path)
        if self._final_name in {"", ".", ".."}:
            raise UnsafePathError("final output must have one valid basename")
        try:
            os.lstat(self.final_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise UnsafePathError("cannot inspect final output path") from exc
        else:
            raise OutputCollisionError("final output already exists")

        try:
            parent_descriptor = os.open(
                self._parent_path,
                _directory_open_flags(),
            )
        except OSError as exc:
            raise UnsafePathError("cannot securely open output parent") from exc
        try:
            parent_opened = os.fstat(parent_descriptor)
            if not _same_inode(parent_before, parent_opened):
                raise UnsafePathError("output parent changed while opening")
            (
                descriptor,
                temp_name,
                journal_name,
                journal_identity,
                journal_lease,
            ) = self._create_private_temp(parent_descriptor)
        except BaseException:
            os.close(parent_descriptor)
            raise

        self._parent_descriptor = parent_descriptor
        self._descriptor = descriptor
        self._temp_name = temp_name
        self.temp_path = os.path.join(self._parent_path, temp_name)
        self._temp_identity = FileIdentity.from_stat(os.fstat(descriptor))
        self._journal_name = journal_name
        self.journal_path = os.path.join(self._parent_path, journal_name)
        self._journal_identity = journal_identity
        self._journal_lease = journal_lease
        self._active = True
        self._published = False
        self._temp_exists = True
        self._journal_exists = True
        self._committed = False
        self._aborted = False
        self._sealed = False
        self._sealed_identity: FileIdentity | None = None
        self._publish_result: QuarantinePublishResult | None = None

    def _create_private_journal(
        self,
        parent_descriptor: int,
        operation_id: str,
        temp_stat: os.stat_result,
    ) -> tuple[str, FileIdentity, HeldOperationLease]:
        parent_stat = os.fstat(parent_descriptor)
        record = build_operation_journal(
            operation_id=operation_id,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
            temp_device=temp_stat.st_dev,
            temp_inode=temp_stat.st_ino,
            owner_uid=getattr(temp_stat, "st_uid", 0),
            owner_gid=getattr(temp_stat, "st_gid", 0),
        )
        data = encode_operation_journal(record)
        journal_name = journal_name_for(operation_id)
        descriptor = None
        created = False
        try:
            descriptor = os.open(
                journal_name,
                _temporary_open_flags(),
                PRIVATE_FILE_MODE,
                dir_fd=parent_descriptor,
            )
            created = True
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if not 1 <= written <= len(data) - offset:
                    raise FilesystemSafetyError(
                        "operation journal write made invalid progress"
                    )
                offset += written
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            _require_regular(opened, "operation journal")
            if (
                stat.S_IMODE(opened.st_mode) != PRIVATE_FILE_MODE
                or opened.st_nlink != 1
                or opened.st_size != len(data)
            ):
                raise OwnedTemporaryFileError(
                    "new operation journal metadata is invalid"
                )
            identity = FileIdentity.from_stat(opened)
            lease = acquire_writer_operation_lease(descriptor)
            descriptor = None
        except BaseException:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created:
                try:
                    os.unlink(journal_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            raise
        return journal_name, identity, lease

    def _create_private_temp(
        self,
        parent_descriptor: int,
    ) -> tuple[int, str, str, FileIdentity, HeldOperationLease]:
        for _ in range(TEMP_CREATE_ATTEMPTS):
            operation_id = secrets.token_hex(16)
            name = temporary_name_for(operation_id)
            journal_name = None
            journal_lease = None
            try:
                descriptor = os.open(
                    name,
                    _temporary_open_flags(),
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            except (NotImplementedError, TypeError) as exc:
                raise AtomicPublishUnsupportedError(
                    "platform cannot create quarantine files relative to a directory"
                ) from exc
            except OSError as exc:
                raise FilesystemSafetyError(
                    "cannot create private quarantine file"
                ) from exc
            try:
                os.fchmod(descriptor, 0o600)
                opened = os.fstat(descriptor)
                _require_regular(opened, "quarantine file")
                if opened.st_nlink != 1:
                    raise OwnedTemporaryFileError(
                        "new quarantine file must have exactly one link"
                    )
                (
                    journal_name,
                    journal_identity,
                    journal_lease,
                ) = self._create_private_journal(
                    parent_descriptor,
                    operation_id,
                    opened,
                )
                _sync_directory(parent_descriptor)
            except BaseException:
                if journal_lease is not None:
                    try:
                        journal_lease.close()
                    except OSError:
                        pass
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except OSError:
                    pass
                if journal_name is not None:
                    try:
                        os.unlink(journal_name, dir_fd=parent_descriptor)
                    except OSError:
                        pass
                raise
            return (
                descriptor,
                name,
                journal_name,
                journal_identity,
                journal_lease,
            )
        raise FilesystemSafetyError("cannot allocate a unique quarantine name")

    @property
    def committed(self) -> bool:
        return self._committed

    @property
    def aborted(self) -> bool:
        return self._aborted

    @property
    def sealed(self) -> bool:
        return self._sealed

    @property
    def publish_result(self) -> QuarantinePublishResult | None:
        return self._publish_result

    def _require_active(self) -> None:
        if not self._active:
            raise FilesystemSafetyError("quarantine transaction is not active")

    def _verify_parent(self) -> None:
        try:
            opened = os.fstat(self._parent_descriptor)
            current = os.lstat(self._parent_path)
        except OSError as exc:
            raise UnsafePathError("output parent is unavailable") from exc
        if not _same_inode(opened, current) or not stat.S_ISDIR(current.st_mode):
            raise UnsafePathError("output parent identity changed")

    def _verify_owned_temp(self) -> None:
        if not self._temp_exists:
            raise OwnedTemporaryFileError("quarantine file no longer exists")
        try:
            opened = os.fstat(self._descriptor)
            current = os.stat(
                self._temp_name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise OwnedTemporaryFileError("quarantine file is unavailable") from exc
        try:
            _require_regular(opened, "opened quarantine file")
            _require_regular(current, "quarantine path")
        except UnsafePathError as exc:
            raise OwnedTemporaryFileError(
                "quarantine path no longer names a regular file"
            ) from exc
        if (
            opened.st_dev != self._temp_identity.device
            or opened.st_ino != self._temp_identity.inode
            or not _same_inode(opened, current)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(current.st_mode) != 0o600
            or opened.st_nlink != 1
            or current.st_nlink != 1
        ):
            raise OwnedTemporaryFileError(
                "quarantine path no longer names the owned inode"
            )

    def _verify_owned_journal(self) -> None:
        if not self._journal_exists:
            raise OwnedTemporaryFileError("operation journal no longer exists")
        try:
            opened = os.fstat(self._journal_lease.fileno())
            current = os.stat(
                self._journal_name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except (OSError, OperationLeaseError) as exc:
            raise OwnedTemporaryFileError("operation journal is unavailable") from exc
        try:
            _require_regular(opened, "opened operation journal")
            _require_regular(current, "operation journal")
        except UnsafePathError as exc:
            raise OwnedTemporaryFileError(
                "operation journal no longer names a regular file"
            ) from exc
        if (
            FileIdentity.from_stat(opened) != self._journal_identity
            or FileIdentity.from_stat(current) != self._journal_identity
            or not _same_inode(opened, current)
            or stat.S_IMODE(current.st_mode) != PRIVATE_FILE_MODE
            or current.st_nlink != 1
        ):
            raise OwnedTemporaryFileError(
                "operation journal no longer names the recorded inode"
            )

    def _close_runtime_resources(self) -> BaseException | None:
        first_error: BaseException | None = None
        for close in (
            self._journal_lease.close,
            lambda: os.close(self._descriptor),
            lambda: os.close(self._parent_descriptor),
        ):
            try:
                close()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        self._active = False
        return first_error

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self._require_active()
        if self._sealed:
            raise FilesystemSafetyError("quarantine file is sealed")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise FilesystemSafetyError("quarantine write requires bytes")
        exact = bytes(data)
        if not exact:
            return 0
        try:
            written = os.write(self._descriptor, exact)
        except OSError as exc:
            raise FilesystemSafetyError("quarantine write failed") from exc
        if not 1 <= written <= len(exact):
            raise FilesystemSafetyError("quarantine write made invalid progress")
        return written

    def seal_for_verification(self) -> FileIdentity:
        """Flush and freeze the private inode without publishing its name."""

        self._require_active()
        if self._sealed:
            self._verify_sealed_unchanged()
            assert self._sealed_identity is not None
            return self._sealed_identity
        try:
            os.fsync(self._descriptor)
        except OSError as exc:
            raise FilesystemSafetyError("quarantine file fsync failed") from exc
        self._verify_parent()
        self._verify_owned_temp()
        self._verify_owned_journal()
        self._sealed_identity = FileIdentity.from_stat(os.fstat(self._descriptor))
        self._sealed = True
        return self._sealed_identity

    def _verify_sealed_unchanged(self) -> None:
        if not self._sealed or self._sealed_identity is None:
            raise FilesystemSafetyError("quarantine file is not sealed")
        self._verify_parent()
        self._verify_owned_temp()
        self._verify_owned_journal()
        try:
            opened = FileIdentity.from_stat(os.fstat(self._descriptor))
            current = FileIdentity.from_stat(
                os.stat(
                    self._temp_name,
                    dir_fd=self._parent_descriptor,
                    follow_symlinks=False,
                )
            )
        except OSError as exc:
            raise OwnedTemporaryFileError(
                "sealed quarantine file is unavailable"
            ) from exc
        if opened != self._sealed_identity or current != self._sealed_identity:
            raise OwnedTemporaryFileError(
                "sealed quarantine file changed before publish"
            )

    def commit(self) -> None:
        self._require_active()
        if not self._sealed:
            self.seal_for_verification()
        self._verify_sealed_unchanged()
        try:
            os.link(
                self._temp_name,
                self._final_name,
                src_dir_fd=self._parent_descriptor,
                dst_dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise OutputCollisionError("final output appeared before commit") from exc
        except (NotImplementedError, TypeError) as exc:
            raise AtomicPublishUnsupportedError(
                "platform cannot atomically publish relative to a directory"
            ) from exc
        except OSError as exc:
            raise AtomicPublishUnsupportedError(
                "filesystem cannot perform atomic no-clobber publish"
            ) from exc

        self._published = True
        self._committed = True

        output_identity: FileIdentity | None = None
        output_verified = False
        publication_sync_complete = False
        cleanup_sync_complete = False
        resources_closed = False
        try:
            try:
                published = os.stat(
                    self._final_name,
                    dir_fd=self._parent_descriptor,
                    follow_symlinks=False,
                )
                opened = os.fstat(self._descriptor)
                _require_regular(published, "published output")
                _require_regular(opened, "opened published output")
                published_identity = FileIdentity.from_stat(published)
                opened_identity = FileIdentity.from_stat(opened)
                if (
                    not _same_inode(published, opened)
                    or stat.S_IMODE(published.st_mode) != 0o600
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or published.st_nlink != 2
                    or opened.st_nlink != 2
                    or published_identity != opened_identity
                ):
                    raise OwnedTemporaryFileError(
                        "published output identity is inconsistent"
                    )
                output_identity = published_identity
                output_verified = True
            except BaseException:
                # The no-clobber link already exists.  Verification trouble is
                # an explicit post-publish warning, never a failed operation.
                pass

            try:
                _sync_directory(self._parent_descriptor)
                publication_sync_complete = True
                if output_verified:
                    os.unlink(self._temp_name, dir_fd=self._parent_descriptor)
                    self._temp_exists = False
                    os.unlink(self._journal_name, dir_fd=self._parent_descriptor)
                    self._journal_exists = False
                    _sync_directory(self._parent_descriptor)
                    cleanup_sync_complete = True
            except BaseException:
                # Leave every not-yet-removed object for reconciliation.  No
                # path is guessed and no second deletion strategy is attempted.
                pass
        finally:
            resources_closed = self._close_runtime_resources() is None

        self._publish_result = QuarantinePublishResult(
            output_identity=output_identity,
            output_verified=output_verified,
            publication_sync_complete=publication_sync_complete,
            temporary_removed=not self._temp_exists,
            journal_removed=not self._journal_exists,
            cleanup_sync_complete=cleanup_sync_complete,
            resources_closed=resources_closed,
        )

    def abort(self) -> None:
        if not self._active:
            return
        cleanup_error = None
        close_error = None
        try:
            if self._temp_exists:
                self._verify_owned_temp()
            if self._journal_exists:
                self._verify_owned_journal()
            if self._temp_exists:
                os.unlink(self._temp_name, dir_fd=self._parent_descriptor)
                self._temp_exists = False
            if self._journal_exists:
                os.unlink(self._journal_name, dir_fd=self._parent_descriptor)
                self._journal_exists = False
            if not self._temp_exists and not self._journal_exists:
                _sync_directory(self._parent_descriptor)
        except BaseException as exc:
            cleanup_error = exc
        finally:
            close_error = self._close_runtime_resources()
            self._aborted = not self._committed
        if cleanup_error is not None or close_error is not None:
            raise OwnedTemporaryFileError(
                "refusing to remove an unverified quarantine path"
            ) from (cleanup_error or close_error)

    def __enter__(self) -> "ExclusiveFileQuarantineSink":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self._active and not self._committed:
            self.abort()
        return False
