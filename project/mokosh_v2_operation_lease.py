"""Portable fail-closed activity leases for MOKOSH operation journals.

An active writer holds one OS-managed exclusive lease on the exact journal
descriptor.  A probe can distinguish a cooperating active writer from a
released-lock candidate, but it never authorizes cleanup.  The descriptor is
owned by the returned handle and is closed to release the lease.
"""

from __future__ import annotations

import errno
import importlib
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class OperationLeaseError(OSError):
    """The requested operation lease could not satisfy its safety contract."""


class OperationLeaseUnsupported(OperationLeaseError):
    """The platform or filesystem has no validated lease semantics."""


class OperationLeaseBusy(OperationLeaseError):
    """Another cooperating process already holds the operation lease."""


class OperationLeaseBackend(str, Enum):
    POSIX_FLOCK = "posix_flock"
    WINDOWS_MSVCRT = "windows_msvcrt"


class LeaseProbeStatus(str, Enum):
    ACQUIRED = "acquired"
    HELD_BY_OTHER = "held_by_other"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class _NativeBackend(Protocol):
    name: OperationLeaseBackend

    def acquire(self, descriptor: int) -> None: ...


class _PosixFlockBackend:
    name = OperationLeaseBackend.POSIX_FLOCK

    def __init__(self, module: Any) -> None:
        self._module = module

    def acquire(self, descriptor: int) -> None:
        self._module.flock(
            descriptor,
            self._module.LOCK_EX | self._module.LOCK_NB,
        )


class _WindowsMsvcrtBackend:
    name = OperationLeaseBackend.WINDOWS_MSVCRT

    def __init__(self, module: Any) -> None:
        self._module = module

    def acquire(self, descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        self._module.locking(descriptor, self._module.LK_NBLCK, 1)


@dataclass(slots=True)
class HeldOperationLease:
    """One acquired lease that owns and eventually closes its descriptor."""

    backend: OperationLeaseBackend
    _descriptor: int
    _closed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.backend, OperationLeaseBackend):
            raise OperationLeaseError("lease backend is invalid")
        _require_descriptor(self._descriptor)
        if type(self._closed) is not bool or self._closed:
            raise OperationLeaseError("new lease must be open")

    @property
    def closed(self) -> bool:
        return self._closed

    def fileno(self) -> int:
        if self._closed:
            raise OperationLeaseError("operation lease is closed")
        return self._descriptor

    def close(self) -> None:
        if self._closed:
            return
        descriptor = self._descriptor
        self._closed = True
        self._descriptor = -1
        try:
            os.close(descriptor)
        except OSError as exc:
            raise OperationLeaseError("operation lease descriptor close failed") from exc

    def __enter__(self) -> HeldOperationLease:
        self.fileno()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.close()
        return False


@dataclass(frozen=True, slots=True)
class OperationLeaseProbe:
    status: LeaseProbeStatus
    backend: OperationLeaseBackend | None
    lease: HeldOperationLease | None
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, LeaseProbeStatus):
            raise OperationLeaseError("lease probe status is invalid")
        if self.backend is not None and not isinstance(
            self.backend,
            OperationLeaseBackend,
        ):
            raise OperationLeaseError("lease probe backend is invalid")
        if self.status is LeaseProbeStatus.ACQUIRED:
            if self.lease is None or self.backend is None:
                raise OperationLeaseError("acquired probe must retain its lease")
            if self.lease.backend is not self.backend or self.lease.closed:
                raise OperationLeaseError("acquired probe lease is inconsistent")
        elif self.lease is not None:
            raise OperationLeaseError("non-acquired probe must not retain a lease")
        if self.mutation_permitted:
            raise OperationLeaseError("lease observation never permits mutation")


def _require_descriptor(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise OperationLeaseError("lease descriptor must be a non-negative integer")
    return value


def _close_unclaimed(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _load_backend() -> _NativeBackend:
    if os.name == "posix":
        try:
            module = importlib.import_module("fcntl")
        except (ImportError, AttributeError) as exc:
            raise OperationLeaseUnsupported("POSIX flock is unavailable") from exc
        required = ("flock", "LOCK_EX", "LOCK_NB")
        if any(not hasattr(module, name) for name in required):
            raise OperationLeaseUnsupported("POSIX flock API is incomplete")
        return _PosixFlockBackend(module)
    if os.name == "nt":
        try:
            module = importlib.import_module("msvcrt")
        except (ImportError, AttributeError) as exc:
            raise OperationLeaseUnsupported("Windows locking is unavailable") from exc
        required = ("locking", "LK_NBLCK")
        if any(not hasattr(module, name) for name in required):
            raise OperationLeaseUnsupported("Windows locking API is incomplete")
        return _WindowsMsvcrtBackend(module)
    raise OperationLeaseUnsupported("platform lease backend is unsupported")


def _is_busy_error(exc: OSError) -> bool:
    busy_errnos = {
        errno.EACCES,
        errno.EAGAIN,
        getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
        getattr(errno, "EDEADLK", errno.EACCES),
    }
    busy_winerrors = {33, 36}
    return exc.errno in busy_errnos or getattr(exc, "winerror", None) in busy_winerrors


def _is_unsupported_error(exc: OSError) -> bool:
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        getattr(errno, "ENOLCK", errno.EINVAL),
    }
    return exc.errno in unsupported


def probe_operation_lease(descriptor: int) -> OperationLeaseProbe:
    """Consume a descriptor and return a non-mutating lease observation."""

    exact = _require_descriptor(descriptor)
    try:
        backend = _load_backend()
    except OperationLeaseUnsupported:
        _close_unclaimed(exact)
        return OperationLeaseProbe(LeaseProbeStatus.UNSUPPORTED, None, None)
    try:
        backend.acquire(exact)
    except OSError as exc:
        _close_unclaimed(exact)
        if _is_busy_error(exc):
            return OperationLeaseProbe(
                LeaseProbeStatus.HELD_BY_OTHER,
                backend.name,
                None,
            )
        if _is_unsupported_error(exc):
            return OperationLeaseProbe(
                LeaseProbeStatus.UNSUPPORTED,
                backend.name,
                None,
            )
        return OperationLeaseProbe(LeaseProbeStatus.ERROR, backend.name, None)
    except BaseException:
        _close_unclaimed(exact)
        return OperationLeaseProbe(LeaseProbeStatus.ERROR, backend.name, None)
    lease = HeldOperationLease(backend.name, exact)
    return OperationLeaseProbe(LeaseProbeStatus.ACQUIRED, backend.name, lease)


def acquire_writer_operation_lease(descriptor: int) -> HeldOperationLease:
    """Consume a new journal descriptor and require an exclusive lease."""

    result = probe_operation_lease(descriptor)
    if result.status is LeaseProbeStatus.ACQUIRED:
        assert result.lease is not None
        return result.lease
    if result.status is LeaseProbeStatus.HELD_BY_OTHER:
        raise OperationLeaseBusy("new operation journal is unexpectedly locked")
    if result.status is LeaseProbeStatus.UNSUPPORTED:
        raise OperationLeaseUnsupported("validated operation lease is unavailable")
    raise OperationLeaseError("operation lease acquisition failed")
