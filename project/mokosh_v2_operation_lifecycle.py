"""Non-secret lifecycle, cancellation, and outcome contracts for MOKOSH v2.

The objects in this module deliberately carry no paths, file names, byte
counts, keys, exception text, or user content.  They are suitable for a
future GUI adapter, but this module performs no GUI, telemetry, network, file,
or deletion operation.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Generic, TypeVar


class OperationLifecycleError(RuntimeError):
    """The caller violated the fail-closed lifecycle contract."""


class OperationCancelled(OperationLifecycleError):
    """Cancellation was observed at a safe bounded-operation boundary."""


class OperationKind(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class OperationPhase(str, Enum):
    PREFLIGHT = "preflight"
    SCAN = "scan"
    VERIFY_INPUT = "verify_input"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    VERIFY_OUTPUT = "verify_output"
    PUBLISH = "publish"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ProgressState(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"


class OperationErrorCode(str, Enum):
    CANCELLED = "operation_cancelled"
    INTERRUPTED = "operation_interrupted"
    UNSAFE_PATH = "unsafe_path"
    SOURCE_CHANGED = "source_changed"
    OUTPUT_COLLISION = "output_collision"
    ATOMIC_PUBLISH_UNSUPPORTED = "atomic_publish_unsupported"
    AUTHENTICATION_FAILED = "authentication_failed"
    VERIFICATION_FAILED = "verification_failed"
    CLEANUP_FAILED = "cleanup_failed"
    INVALID_INPUT = "invalid_input"
    RESOURCE_LIMIT = "resource_limit"
    IO_FAILED = "io_failed"
    INTERNAL_ERROR = "internal_error"


class OperationWarningCode(str, Enum):
    PUBLISHED_CLEANUP_INCOMPLETE = "published_cleanup_incomplete"


@dataclass(frozen=True, slots=True)
class OperationProgressEvent:
    kind: OperationKind
    phase: OperationPhase
    state: ProgressState
    sequence: int


@dataclass(frozen=True, slots=True)
class SafeOperationFailure:
    code: OperationErrorCode
    phase: OperationPhase
    retryable: bool
    message_key: str


@dataclass(frozen=True, slots=True)
class SafeOperationWarning:
    code: OperationWarningCode
    message_key: str


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class OperationOutcome(Generic[T]):
    ok: bool
    result: T | None = None
    failure: SafeOperationFailure | None = None
    warning: SafeOperationWarning | None = None

    def __post_init__(self) -> None:
        if self.ok:
            valid = self.result is not None and self.failure is None
        else:
            valid = (
                self.result is None
                and self.failure is not None
                and self.warning is None
            )
        if not valid:
            raise OperationLifecycleError("outcome must contain exactly one result or failure")
        if self.warning is not None and not isinstance(
            self.warning, SafeOperationWarning
        ):
            raise OperationLifecycleError("operation warning type is invalid")


class CancellationToken:
    """Thread-safe, one-way cancellation signal with no secret reason text."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def checkpoint(self) -> None:
        if self.cancelled:
            raise OperationCancelled("operation cancelled at a safe boundary")


ProgressObserver = Callable[[OperationProgressEvent], None]


class OperationLifecycle:
    """Strict ordered phases and cancellation checks for one operation."""

    def __init__(
        self,
        kind: OperationKind,
        phases: tuple[OperationPhase, ...],
        *,
        cancellation: CancellationToken | None = None,
        observer: ProgressObserver | None = None,
    ) -> None:
        if not isinstance(kind, OperationKind):
            raise OperationLifecycleError("kind must be an OperationKind")
        if not phases or any(not isinstance(value, OperationPhase) for value in phases):
            raise OperationLifecycleError("phases must be a non-empty phase tuple")
        if len(set(phases)) != len(phases):
            raise OperationLifecycleError("operation phases must be unique")
        if any(value in {OperationPhase.COMPLETE, OperationPhase.CANCELLED, OperationPhase.FAILED} for value in phases):
            raise OperationLifecycleError("terminal phases are managed by the lifecycle")
        if observer is not None and not callable(observer):
            raise OperationLifecycleError("observer must be callable")
        self.kind = kind
        self.phases = phases
        self.cancellation = cancellation or CancellationToken()
        self.observer = observer
        self._next = 0
        self._active: OperationPhase | None = None
        self._terminal: OperationPhase | None = None
        self._sequence = 0

    @property
    def current_phase(self) -> OperationPhase:
        if self._active is not None:
            return self._active
        if self._terminal is not None:
            return self._terminal
        if self._next < len(self.phases):
            return self.phases[self._next]
        return self.phases[-1]

    def checkpoint(self) -> None:
        if self._terminal is not None:
            raise OperationLifecycleError("terminal lifecycle cannot continue")
        self.cancellation.checkpoint()

    def _emit(self, phase: OperationPhase, state: ProgressState) -> None:
        self._sequence += 1
        event = OperationProgressEvent(self.kind, phase, state, self._sequence)
        if self.observer is not None:
            self.observer(event)
        self.cancellation.checkpoint()

    def start(self, phase: OperationPhase) -> None:
        self.checkpoint()
        if self._active is not None or self._next >= len(self.phases):
            raise OperationLifecycleError("operation phase started out of order")
        if self.phases[self._next] is not phase:
            raise OperationLifecycleError("unexpected operation phase")
        self._active = phase
        self._emit(phase, ProgressState.STARTED)

    def finish(self, phase: OperationPhase) -> None:
        self.checkpoint()
        if self._active is not phase:
            raise OperationLifecycleError("operation phase completed out of order")
        self._emit(phase, ProgressState.COMPLETED)
        self._active = None
        self._next += 1

    def finish_published(self) -> None:
        """Record an irreversible publish without reclassifying later cancel."""

        if self._active is not OperationPhase.PUBLISH:
            raise OperationLifecycleError("publish completed out of order")
        self._sequence += 1
        event = OperationProgressEvent(
            self.kind,
            OperationPhase.PUBLISH,
            ProgressState.COMPLETED,
            self._sequence,
        )
        if self.observer is not None:
            try:
                self.observer(event)
            except BaseException:
                pass
        self._active = None
        self._next += 1

    def complete(self) -> None:
        if self._terminal is not None:
            raise OperationLifecycleError("terminal lifecycle cannot continue")
        if self._active is not None or self._next != len(self.phases):
            raise OperationLifecycleError("operation cannot complete before every phase")
        self._terminal = OperationPhase.COMPLETE
        self._sequence += 1
        event = OperationProgressEvent(
            self.kind,
            OperationPhase.COMPLETE,
            ProgressState.COMPLETED,
            self._sequence,
        )
        if self.observer is not None:
            try:
                self.observer(event)
            except BaseException:
                pass

    def terminate(self, phase: OperationPhase) -> None:
        if phase not in {OperationPhase.CANCELLED, OperationPhase.FAILED}:
            raise OperationLifecycleError("invalid terminal failure phase")
        if self._terminal is not None:
            return
        self._terminal = phase
        self._active = None
        self._sequence += 1
        event = OperationProgressEvent(self.kind, phase, ProgressState.COMPLETED, self._sequence)
        if self.observer is not None:
            try:
                self.observer(event)
            except BaseException:
                pass


class CancellableSource:
    """Check cancellation immediately around every bounded source read."""

    def __init__(self, source: Any, lifecycle: OperationLifecycle) -> None:
        self._source = source
        self._lifecycle = lifecycle

    def read(self, size: int) -> bytes:
        self._lifecycle.checkpoint()
        value = self._source.read(size)
        self._lifecycle.checkpoint()
        return value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._source, name)


def classify_operation_error(exc: BaseException) -> OperationErrorCode:
    """Map an exception type to a stable code without exposing its text."""

    from mokosh_v2_crypto import FrameAuthenticationError
    from mokosh_v2_file_pipeline import (
        FilePipelineCleanupError,
        FilePipelineVerificationError,
    )
    from mokosh_v2_filesystem import (
        AtomicPublishUnsupportedError,
        FilesystemSafetyError,
        OutputCollisionError,
        SourceChangedError,
        UnsafePathError,
    )
    from mokosh_v2_format import FormatLimitError, V2FormatError

    if isinstance(exc, OperationCancelled):
        return OperationErrorCode.CANCELLED
    if isinstance(exc, KeyboardInterrupt):
        return OperationErrorCode.INTERRUPTED
    if isinstance(exc, OutputCollisionError):
        return OperationErrorCode.OUTPUT_COLLISION
    if isinstance(exc, SourceChangedError):
        return OperationErrorCode.SOURCE_CHANGED
    if isinstance(exc, AtomicPublishUnsupportedError):
        return OperationErrorCode.ATOMIC_PUBLISH_UNSUPPORTED
    if isinstance(exc, UnsafePathError):
        return OperationErrorCode.UNSAFE_PATH
    if isinstance(exc, FrameAuthenticationError):
        return OperationErrorCode.AUTHENTICATION_FAILED
    if isinstance(exc, FilePipelineCleanupError):
        return OperationErrorCode.CLEANUP_FAILED
    if isinstance(exc, FilePipelineVerificationError):
        return OperationErrorCode.VERIFICATION_FAILED
    if isinstance(exc, FormatLimitError):
        return OperationErrorCode.RESOURCE_LIMIT
    if isinstance(exc, FilesystemSafetyError):
        return OperationErrorCode.IO_FAILED
    if isinstance(exc, (V2FormatError, TypeError, ValueError)):
        return OperationErrorCode.INVALID_INPUT
    return OperationErrorCode.INTERNAL_ERROR


def safe_failure(exc: BaseException, phase: OperationPhase) -> SafeOperationFailure:
    code = classify_operation_error(exc)
    retryable = code in {
        OperationErrorCode.CANCELLED,
        OperationErrorCode.INTERRUPTED,
        OperationErrorCode.SOURCE_CHANGED,
        OperationErrorCode.OUTPUT_COLLISION,
        OperationErrorCode.IO_FAILED,
    }
    return SafeOperationFailure(code, phase, retryable, f"operation.error.{code.value}")


def _safe_publish_warning(result: Any) -> SafeOperationWarning | None:
    publish = getattr(result, "publish", None)
    if publish is None or not bool(getattr(publish, "warning_required", False)):
        return None
    code = OperationWarningCode.PUBLISHED_CLEANUP_INCOMPLETE
    return SafeOperationWarning(code, f"operation.warning.{code.value}")


ENCRYPT_PHASES = (
    OperationPhase.PREFLIGHT,
    OperationPhase.SCAN,
    OperationPhase.ENCRYPT,
    OperationPhase.VERIFY_OUTPUT,
    OperationPhase.PUBLISH,
)

DECRYPT_PHASES = (
    OperationPhase.PREFLIGHT,
    OperationPhase.VERIFY_INPUT,
    OperationPhase.DECRYPT,
    OperationPhase.VERIFY_OUTPUT,
    OperationPhase.PUBLISH,
)


def run_encryption_operation(
    *,
    cancellation: CancellationToken | None = None,
    observer: ProgressObserver | None = None,
    **pipeline_arguments: Any,
) -> OperationOutcome[Any]:
    """Run the verified file encryptor and return only a safe failure code."""

    from mokosh_v2_file_pipeline import encrypt_file_to_v2

    lifecycle = OperationLifecycle(
        OperationKind.ENCRYPT,
        ENCRYPT_PHASES,
        cancellation=cancellation,
        observer=observer,
    )
    try:
        result = encrypt_file_to_v2(lifecycle=lifecycle, **pipeline_arguments)
    except (Exception, KeyboardInterrupt) as exc:
        terminal = (
            OperationPhase.CANCELLED
            if isinstance(exc, (OperationCancelled, KeyboardInterrupt))
            else OperationPhase.FAILED
        )
        phase = lifecycle.current_phase
        lifecycle.terminate(terminal)
        return OperationOutcome(ok=False, failure=safe_failure(exc, phase))
    return OperationOutcome(
        ok=True,
        result=result,
        warning=_safe_publish_warning(result),
    )


def run_decryption_operation(
    *,
    cancellation: CancellationToken | None = None,
    observer: ProgressObserver | None = None,
    **pipeline_arguments: Any,
) -> OperationOutcome[Any]:
    """Run the verified file decryptor and return only a safe failure code."""

    from mokosh_v2_file_pipeline import decrypt_v2_file_to_quarantine

    lifecycle = OperationLifecycle(
        OperationKind.DECRYPT,
        DECRYPT_PHASES,
        cancellation=cancellation,
        observer=observer,
    )
    try:
        result = decrypt_v2_file_to_quarantine(
            lifecycle=lifecycle,
            **pipeline_arguments,
        )
    except (Exception, KeyboardInterrupt) as exc:
        terminal = (
            OperationPhase.CANCELLED
            if isinstance(exc, (OperationCancelled, KeyboardInterrupt))
            else OperationPhase.FAILED
        )
        phase = lifecycle.current_phase
        lifecycle.terminate(terminal)
        return OperationOutcome(ok=False, failure=safe_failure(exc, phase))
    return OperationOutcome(
        ok=True,
        result=result,
        warning=_safe_publish_warning(result),
    )
