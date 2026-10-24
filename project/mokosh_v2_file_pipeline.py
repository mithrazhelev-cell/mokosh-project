"""Fail-closed end-to-end local file pipeline for MOKOSH v2.

This module composes the bounded streaming engine with verified filesystem
sources and a same-directory quarantine transaction.  A streaming ``commit``
only seals the private inode.  Publication happens later, after source
stability and the bytes actually stored on disk have both been re-verified.

It never deletes an original, chooses an output path, trusts a contact,
accesses a persistent Vault, logs sensitive paths, or activates the GUI.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

from mokosh_v2_complete_envelope import (
    Ed25519EnvelopeSigning,
    EnvelopeSigning,
    EnvelopeVerification,
    RequireEd25519Envelope,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_filesystem import (
    ExclusiveFileQuarantineSink,
    FileIdentity,
    QuarantinePublishResult,
    SourceChangedError,
    VerifiedFileSource,
)
from mokosh_v2_format import DEFAULT_CHUNK_SIZE, V2FormatError
from mokosh_v2_operation_lifecycle import (
    CancellableSource,
    OperationLifecycle,
    OperationPhase,
)
from mokosh_v2_slot_orchestration import (
    EnvelopeKeyPlan,
    SlotCredential,
)
from mokosh_v2_streaming import (
    PlaintextStreamPlan,
    StreamingDecryptionResult,
    StreamingEncryptionResult,
    StreamingEnvelopeVerificationResult,
    decrypt_stream_to_quarantine,
    encrypt_stream_to_quarantine,
    inspect_envelope_stream,
    scan_plaintext_stream,
    verify_envelope_stream_with_dek,
)


class FilePipelineError(V2FormatError):
    """The safe file pipeline cannot prove a required invariant."""


class FilePipelineStateError(FilePipelineError):
    """An internal transaction phase occurred out of order."""


class FilePipelineVerificationError(FilePipelineError):
    """The stored temporary output differs from the authenticated result."""


class FilePipelineCleanupError(FilePipelineError):
    """Failure cleanup could not prove ownership of its temporary object."""


@dataclass(frozen=True, slots=True)
class FileEncryptionPipelineResult:
    source_identity: FileIdentity
    output_identity: FileIdentity | None
    stream: StreamingEncryptionResult
    verification: StreamingEnvelopeVerificationResult
    publish: QuarantinePublishResult


@dataclass(frozen=True, slots=True)
class FileDecryptionPipelineResult:
    source_identity: FileIdentity
    output_identity: FileIdentity | None
    stream: StreamingDecryptionResult
    output_scan: PlaintextStreamPlan
    publish: QuarantinePublishResult


class _DeferredPublishSink:
    """Translate stream commit into seal; only the pipeline may publish."""

    def __init__(
        self,
        transaction: ExclusiveFileQuarantineSink,
        lifecycle: OperationLifecycle | None = None,
    ) -> None:
        self._transaction = transaction
        self._lifecycle = lifecycle
        self.ready = False
        self.aborted = False

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self.ready or self.aborted:
            raise FilePipelineStateError(
                "cannot write after deferred transaction completion"
            )
        if self._lifecycle is not None:
            self._lifecycle.checkpoint()
        written = self._transaction.write(data)
        if self._lifecycle is not None:
            self._lifecycle.checkpoint()
        return written

    def commit(self) -> None:
        if self.ready or self.aborted:
            raise FilePipelineStateError(
                "deferred transaction completed more than once"
            )
        self._transaction.seal_for_verification()
        self.ready = True

    def abort(self) -> None:
        if self.ready:
            raise FilePipelineStateError(
                "stream attempted to abort after successful sealing"
            )
        if not self.aborted:
            self._transaction.abort()
            self.aborted = True


def _abort_transaction(transaction: ExclusiveFileQuarantineSink) -> None:
    try:
        transaction.abort()
    except BaseException as exc:
        raise FilePipelineCleanupError(
            "failed to remove the verified private quarantine file"
        ) from exc


def _require_ready(value: _DeferredPublishSink) -> None:
    if not value.ready or value.aborted:
        raise FilePipelineStateError(
            "stream did not seal exactly one complete quarantine output"
        )


def _require_same_source(
    first: FileIdentity,
    second: FileIdentity,
) -> None:
    if first != second:
        raise SourceChangedError(
            "the second file pass did not open the first source identity"
        )


def _verification_policy(signing: EnvelopeSigning) -> EnvelopeVerification:
    if isinstance(signing, UnsignedEnvelopeSigning):
        return RequireUnsignedEnvelope()
    if isinstance(signing, Ed25519EnvelopeSigning):
        return RequireEd25519Envelope(signing.private_key.public_key())
    raise FilePipelineStateError("unsupported envelope signing policy")


def _phase_start(
    lifecycle: OperationLifecycle | None,
    phase: OperationPhase,
) -> None:
    if lifecycle is not None:
        lifecycle.start(phase)


def _phase_finish(
    lifecycle: OperationLifecycle | None,
    phase: OperationPhase,
) -> None:
    if lifecycle is not None:
        lifecycle.finish(phase)


def _source_for_lifecycle(
    source: VerifiedFileSource,
    lifecycle: OperationLifecycle | None,
) -> Any:
    if lifecycle is None:
        return source
    return CancellableSource(source, lifecycle)


def _compare_encryption_verification(
    stream: StreamingEncryptionResult,
    verification: StreamingEnvelopeVerificationResult,
    plan: PlaintextStreamPlan,
) -> None:
    if stream.manifest != verification.manifest:
        raise FilePipelineVerificationError(
            "stored envelope manifest differs from the writer result"
        )
    if stream.transcript != verification.transcript:
        raise FilePipelineVerificationError(
            "stored envelope transcript differs from the writer result"
        )
    if stream.trailer != verification.trailer:
        raise FilePipelineVerificationError(
            "stored envelope trailer differs from the writer result"
        )
    if verification.plaintext_size != plan.original_size:
        raise FilePipelineVerificationError(
            "stored envelope plaintext size differs from the source plan"
        )
    if not hmac.compare_digest(
        verification.plaintext_sha256,
        plan.plaintext_sha256,
    ):
        raise FilePipelineVerificationError(
            "stored envelope plaintext digest differs from the source plan"
        )


def encrypt_file_to_v2(
    *,
    source_path: Any,
    output_path: Any,
    key_plan: EnvelopeKeyPlan,
    original_name: str,
    signing: EnvelopeSigning,
    content_type: str | None = None,
    created_utc: str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_plaintext_size: int | None = None,
    lifecycle: OperationLifecycle | None = None,
) -> FileEncryptionPipelineResult:
    """Encrypt one explicit regular file and publish only a verified v2 file."""

    _phase_start(lifecycle, OperationPhase.PREFLIGHT)
    with VerifiedFileSource(source_path) as first_source:
        source_identity = first_source.identity
        _phase_finish(lifecycle, OperationPhase.PREFLIGHT)
        _phase_start(lifecycle, OperationPhase.SCAN)
        plan = scan_plaintext_stream(
            _source_for_lifecycle(first_source, lifecycle),
            chunk_size=chunk_size,
            max_plaintext_size=max_plaintext_size,
        )
        _phase_finish(lifecycle, OperationPhase.SCAN)

    transaction = ExclusiveFileQuarantineSink(output_path)
    deferred = _DeferredPublishSink(transaction, lifecycle)
    try:
        _phase_start(lifecycle, OperationPhase.ENCRYPT)
        with VerifiedFileSource(source_path) as second_source:
            _require_same_source(source_identity, second_source.identity)
            stream_result = encrypt_stream_to_quarantine(
                key_plan=key_plan,
                plaintext_source=_source_for_lifecycle(second_source, lifecycle),
                sink=deferred,
                stream_plan=plan,
                original_name=original_name,
                signing=signing,
                content_type=content_type,
                created_utc=created_utc,
            )
            second_source.verify_unchanged()
        _require_ready(deferred)
        _phase_finish(lifecycle, OperationPhase.ENCRYPT)

        _phase_start(lifecycle, OperationPhase.VERIFY_OUTPUT)
        policy = _verification_policy(signing)
        with VerifiedFileSource(transaction.temp_path) as public_source:
            inspection = inspect_envelope_stream(
                _source_for_lifecycle(public_source, lifecycle),
                verification=policy,
            )
        with VerifiedFileSource(transaction.temp_path) as secret_source:
            verification = verify_envelope_stream_with_dek(
                _source_for_lifecycle(secret_source, lifecycle),
                inspection=inspection,
                dek=key_plan.dek,
            )
        _compare_encryption_verification(stream_result, verification, plan)
        if stream_result.encoded_size != transaction.seal_for_verification().size:
            raise FilePipelineVerificationError(
                "stored envelope size differs from the writer result"
            )
        _phase_finish(lifecycle, OperationPhase.VERIFY_OUTPUT)

        _phase_start(lifecycle, OperationPhase.PUBLISH)
        if lifecycle is not None:
            lifecycle.checkpoint()
        transaction.commit()
        if lifecycle is not None:
            lifecycle.finish_published()
        publish = transaction.publish_result
        if publish is None:
            raise FilePipelineStateError("publish result is unavailable")
        result = FileEncryptionPipelineResult(
            source_identity=source_identity,
            output_identity=publish.output_identity,
            stream=stream_result,
            verification=verification,
            publish=publish,
        )
        if lifecycle is not None:
            lifecycle.complete()
        return result
    except BaseException:
        _abort_transaction(transaction)
        raise


def _compare_plaintext_output(
    stream: StreamingDecryptionResult,
    output_scan: PlaintextStreamPlan,
) -> None:
    if output_scan.original_size != stream.plaintext_size:
        raise FilePipelineVerificationError(
            "stored plaintext size differs from the authenticated manifest"
        )
    if not hmac.compare_digest(
        output_scan.plaintext_sha256,
        stream.plaintext_sha256,
    ):
        raise FilePipelineVerificationError(
            "stored plaintext digest differs from the authenticated manifest"
        )
    if output_scan.data_frames != stream.manifest.data_frames:
        raise FilePipelineVerificationError(
            "stored plaintext frame plan differs from the authenticated manifest"
        )


def decrypt_v2_file_to_quarantine(
    *,
    source_path: Any,
    output_path: Any,
    verification: EnvelopeVerification,
    selected_slot_id: bytes | bytearray | memoryview,
    credential: SlotCredential,
    expected_source_identity: FileIdentity | None = None,
    lifecycle: OperationLifecycle | None = None,
) -> FileDecryptionPipelineResult:
    """Decrypt one v2 regular file and publish only verified plaintext."""

    _phase_start(lifecycle, OperationPhase.PREFLIGHT)
    with VerifiedFileSource(source_path) as first_source:
        source_identity = first_source.identity
        if expected_source_identity is not None:
            _require_same_source(expected_source_identity, source_identity)
        _phase_finish(lifecycle, OperationPhase.PREFLIGHT)
        _phase_start(lifecycle, OperationPhase.VERIFY_INPUT)
        inspection = inspect_envelope_stream(
            _source_for_lifecycle(first_source, lifecycle),
            verification=verification,
        )
        _phase_finish(lifecycle, OperationPhase.VERIFY_INPUT)

    transaction = ExclusiveFileQuarantineSink(output_path)
    deferred = _DeferredPublishSink(transaction, lifecycle)
    try:
        _phase_start(lifecycle, OperationPhase.DECRYPT)
        with VerifiedFileSource(source_path) as second_source:
            _require_same_source(source_identity, second_source.identity)
            stream_result = decrypt_stream_to_quarantine(
                envelope_source=_source_for_lifecycle(second_source, lifecycle),
                sink=deferred,
                inspection=inspection,
                selected_slot_id=selected_slot_id,
                credential=credential,
            )
            second_source.verify_unchanged()
        _require_ready(deferred)
        _phase_finish(lifecycle, OperationPhase.DECRYPT)

        _phase_start(lifecycle, OperationPhase.VERIFY_OUTPUT)
        with VerifiedFileSource(transaction.temp_path) as plaintext_source:
            output_scan = scan_plaintext_stream(
                _source_for_lifecycle(plaintext_source, lifecycle),
                chunk_size=inspection.prefix.preamble.chunk_size,
                max_plaintext_size=stream_result.plaintext_size,
            )
        _compare_plaintext_output(stream_result, output_scan)
        if output_scan.original_size != transaction.seal_for_verification().size:
            raise FilePipelineVerificationError(
                "stored plaintext size differs from the sealed inode"
            )
        _phase_finish(lifecycle, OperationPhase.VERIFY_OUTPUT)

        _phase_start(lifecycle, OperationPhase.PUBLISH)
        if lifecycle is not None:
            lifecycle.checkpoint()
        transaction.commit()
        if lifecycle is not None:
            lifecycle.finish_published()
        publish = transaction.publish_result
        if publish is None:
            raise FilePipelineStateError("publish result is unavailable")
        result = FileDecryptionPipelineResult(
            source_identity=source_identity,
            output_identity=publish.output_identity,
            stream=stream_result,
            output_scan=output_scan,
            publish=publish,
        )
        if lifecycle is not None:
            lifecycle.complete()
        return result
    except BaseException:
        _abort_transaction(transaction)
        raise
