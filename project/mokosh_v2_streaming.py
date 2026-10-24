"""Bounded two-pass streaming integration for MOKOSH v2 envelopes.

The manifest is encrypted frame 0 and contains the final plaintext size and
digest.  Contact signature policy must also be verified before a secret slot
is opened.  Those format rules require two bounded passes:

* encryption scans plaintext, then encrypts a fresh second source;
* decryption inspects and verifies public ciphertext, then decrypts an exact
  second source into a quarantine sink.

This module performs no path, filesystem, network, GUI, trust, recovery, or
license operation.  A quarantine sink is a caller-supplied transaction whose
``write`` data is not public until ``commit`` succeeds.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from mokosh_v2_complete_envelope import (
    Ed25519EnvelopeSigning,
    EnvelopeSigning,
    EnvelopeVerification,
    WRITER_NAME,
    build_complete_envelope_prefix,
    decode_complete_envelope_file_id,
    verify_complete_envelope_signature_policy,
)
from mokosh_v2_crypto import V2FrameDecryptor, V2FrameEncryptor
from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    FRAME_HEADER_LEN,
    FRAME_HEADER_STRUCT,
    GCM_TAG_LEN,
    PREAMBLE_LEN,
    EnvelopePrefix,
    FrameRecord,
    FrameSequenceValidator,
    FormatLimitError,
    TruncatedDataError,
    V2FormatError,
    parse_envelope_prefix,
    parse_frame,
    parse_preamble,
)
from mokosh_v2_key_slots import ContactHybridSlot, KeySlot, parse_key_slots
from mokosh_v2_manifest import (
    Manifest,
    build_manifest,
    encode_manifest,
    expected_data_frames,
    parse_manifest,
)
from mokosh_v2_signatures import (
    VerifiedEd25519Signature,
    sign_transcript_info,
)
from mokosh_v2_slot_orchestration import (
    DEK_LEN,
    EnvelopeKeyPlan,
    SlotCredential,
    unwrap_selected_slot,
)
from mokosh_v2_trailer import (
    MAX_SIGNATURE_LEN,
    MAX_TRAILER_FRAME_COUNT,
    TRAILER_FIXED_LEN,
    TRAILER_STRUCT,
    TRANSCRIPT_DOMAIN,
    TranscriptInfo,
    Trailer,
    build_unsigned_trailer,
    parse_trailer,
    validate_trailer_against_transcript,
)


_INSPECTION_PROOF = object()


class StreamingEnvelopeError(V2FormatError):
    """A bounded stream, its plan, or its transaction is invalid."""


class StreamSourceError(StreamingEnvelopeError):
    """A source violated the blocking binary-source contract."""


class StreamPlanMismatchError(StreamingEnvelopeError):
    """The second plaintext pass differs from the first scan."""


class QuarantineSinkError(StreamingEnvelopeError):
    """The quarantine sink could not write, commit, or abort safely."""


class StreamPassMismatchError(StreamingEnvelopeError):
    """The second ciphertext pass differs from verified inspection."""


@dataclass(frozen=True, slots=True)
class PlaintextStreamPlan:
    original_size: int
    plaintext_sha256: bytes
    data_frames: int
    chunk_size: int

    def __post_init__(self) -> None:
        if type(self.original_size) is not int or self.original_size < 0:
            raise StreamingEnvelopeError("original_size must be a non-negative integer")
        if not isinstance(self.plaintext_sha256, (bytes, bytearray, memoryview)):
            raise StreamingEnvelopeError("plaintext_sha256 must be bytes")
        digest = bytes(self.plaintext_sha256)
        if len(digest) != 32:
            raise StreamingEnvelopeError("plaintext_sha256 must contain 32 bytes")
        expected = expected_data_frames(
            self.original_size,
            chunk_size=self.chunk_size,
        )
        if type(self.data_frames) is not int or self.data_frames != expected:
            raise StreamingEnvelopeError(
                f"data_frames must be exactly {expected} for original_size"
            )
        if self.data_frames + 1 > MAX_TRAILER_FRAME_COUNT:
            raise FormatLimitError(
                "manifest plus data frames exceed the trailer frame-count limit"
            )
        object.__setattr__(self, "plaintext_sha256", digest)


@dataclass(frozen=True, slots=True)
class InspectedStreamEnvelope:
    prefix: EnvelopePrefix
    prefix_bytes: bytes
    slots: tuple[KeySlot, ...]
    transcript: TranscriptInfo
    trailer: Trailer
    verified_signature: VerifiedEd25519Signature | None
    _proof: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._proof is not _INSPECTION_PROOF:
            raise StreamingEnvelopeError(
                "inspection must be created by inspect_envelope_stream"
            )


@dataclass(frozen=True, slots=True)
class StreamingEncryptionResult:
    manifest: Manifest
    transcript: TranscriptInfo
    trailer: Trailer
    encoded_size: int


@dataclass(frozen=True, slots=True)
class StreamingDecryptionResult:
    manifest: Manifest
    transcript: TranscriptInfo
    trailer: Trailer
    selected_slot_id: bytes
    verified_signature: VerifiedEd25519Signature | None
    plaintext_size: int
    plaintext_sha256: bytes


@dataclass(frozen=True, slots=True)
class StreamingEnvelopeVerificationResult:
    """Authenticated verification using an already-held exact envelope DEK."""

    manifest: Manifest
    transcript: TranscriptInfo
    trailer: Trailer
    verified_signature: VerifiedEd25519Signature | None
    plaintext_size: int
    plaintext_sha256: bytes


class _TranscriptAccumulator:
    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._digest.update(TRANSCRIPT_DOMAIN)
        self.length = 0
        self.frame_count = 0

    def add_prefix(self, prefix_bytes: bytes) -> None:
        self._digest.update(prefix_bytes)
        self.length += len(prefix_bytes)

    def add_frame(self, frame_bytes: bytes) -> None:
        self._digest.update(frame_bytes)
        self.length += len(frame_bytes)
        self.frame_count += 1

    def info(self) -> TranscriptInfo:
        return TranscriptInfo(
            frame_count=self.frame_count,
            digest=self._digest.digest(),
            transcript_len=self.length,
        )


def _require_source(source: Any) -> Any:
    if not callable(getattr(source, "read", None)):
        raise StreamSourceError("source must provide a callable read(size)")
    return source


def _read_some(source: Any, size: int) -> bytes:
    if type(size) is not int or size <= 0:
        raise AssertionError("internal stream read size must be positive")
    try:
        value = source.read(size)
    except Exception as exc:
        raise StreamSourceError("source read failed") from exc
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise StreamSourceError("source read(size) must return bytes")
    data = bytes(value)
    if len(data) > size:
        raise StreamSourceError("source returned more bytes than requested")
    return data


def _read_exact(source: Any, size: int, field_name: str) -> bytes:
    if type(size) is not int or size < 0:
        raise AssertionError("internal exact read size is invalid")
    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = _read_some(source, remaining)
        if not part:
            received = size - remaining
            raise TruncatedDataError(
                f"{field_name} requires {size} bytes; received {received}"
            )
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _require_eof(source: Any, field_name: str) -> None:
    if _read_some(source, 1):
        raise StreamingEnvelopeError(f"{field_name} contains undeclared trailing bytes")


def _require_sink(sink: Any) -> Any:
    for method in ("write", "commit", "abort"):
        if not callable(getattr(sink, method, None)):
            raise QuarantineSinkError(
                "sink must provide callable write, commit, and abort methods"
            )
    return sink


def _write_all(sink: Any, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = sink.write(view[offset:])
        except Exception as exc:
            raise QuarantineSinkError("quarantine write failed") from exc
        if type(written) is not int or not 1 <= written <= len(view) - offset:
            raise QuarantineSinkError(
                "quarantine write must report positive bounded progress"
            )
        offset += written


def _commit_sink(sink: Any) -> None:
    try:
        result = sink.commit()
    except Exception as exc:
        raise QuarantineSinkError("quarantine commit failed") from exc
    if result is not None:
        raise QuarantineSinkError("quarantine commit must return None")


def _abort_sink(sink: Any) -> None:
    try:
        result = sink.abort()
    except Exception as exc:
        raise QuarantineSinkError("quarantine abort failed") from exc
    if result is not None:
        raise QuarantineSinkError("quarantine abort must return None")


def _abort_after_failure(sink: Any) -> None:
    try:
        _abort_sink(sink)
    except Exception as abort_error:
        raise QuarantineSinkError(
            "stream operation failed and quarantine abort also failed"
        ) from abort_error


def _validate_max_plaintext_size(value: int | None, chunk_size: int) -> int:
    expected_data_frames(0, chunk_size=chunk_size)
    format_max = (MAX_TRAILER_FRAME_COUNT - 1) * chunk_size
    if value is None:
        return format_max
    if type(value) is not int or not 0 <= value <= format_max:
        raise FormatLimitError(
            f"max_plaintext_size must be between 0 and {format_max}"
        )
    return value


def scan_plaintext_stream(
    source: Any,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_plaintext_size: int | None = None,
) -> PlaintextStreamPlan:
    """Consume one plaintext pass using only bounded reads."""

    stream = _require_source(source)
    limit = _validate_max_plaintext_size(max_plaintext_size, chunk_size)
    digest = hashlib.sha256()
    total = 0
    while True:
        request = min(chunk_size, limit - total + 1)
        if request <= 0:
            raise FormatLimitError("plaintext exceeds max_plaintext_size")
        part = _read_some(stream, request)
        if not part:
            break
        total += len(part)
        if total > limit:
            raise FormatLimitError("plaintext exceeds max_plaintext_size")
        digest.update(part)
    frames = expected_data_frames(total, chunk_size=chunk_size)
    return PlaintextStreamPlan(total, digest.digest(), frames, chunk_size)


def _read_prefix(source: Any) -> tuple[EnvelopePrefix, bytes]:
    preamble_bytes = _read_exact(source, PREAMBLE_LEN, "preamble")
    preamble = parse_preamble(preamble_bytes)
    header_bytes = _read_exact(source, preamble.header_len, "header")
    exact_prefix = preamble_bytes + header_bytes
    prefix, remainder = parse_envelope_prefix(exact_prefix)
    if remainder:
        raise AssertionError("internal streaming prefix invariant failed")
    return prefix, exact_prefix


def _read_frame(source: Any, *, chunk_size: int) -> tuple[FrameRecord, bytes]:
    header_bytes = _read_exact(source, FRAME_HEADER_LEN, "frame header")
    _, plaintext_len, _ = FRAME_HEADER_STRUCT.unpack(header_bytes)
    if plaintext_len > chunk_size:
        raise FormatLimitError("frame plaintext_len exceeds chunk_size")
    payload = _read_exact(
        source,
        plaintext_len + GCM_TAG_LEN,
        "frame ciphertext and tag",
    )
    encoded = header_bytes + payload
    record, remainder = parse_frame(encoded, chunk_size=chunk_size)
    if remainder:
        raise AssertionError("internal streaming frame invariant failed")
    return record, encoded


def _read_trailer(source: Any) -> tuple[Trailer, bytes]:
    fixed = _read_exact(source, TRAILER_FIXED_LEN, "trailer")
    fields = TRAILER_STRUCT.unpack(fixed)
    fingerprint_len = fields[-2]
    signature_len = fields[-1]
    if signature_len > MAX_SIGNATURE_LEN:
        raise FormatLimitError(
            f"signature exceeds the limit of {MAX_SIGNATURE_LEN} bytes"
        )
    variable = _read_exact(
        source,
        fingerprint_len + signature_len,
        "trailer signature fields",
    )
    encoded = fixed + variable
    trailer = parse_trailer(encoded)
    _require_eof(source, "complete v2 envelope")
    return trailer, encoded


def _contains_contact(slots: tuple[KeySlot, ...]) -> bool:
    return any(isinstance(slot, ContactHybridSlot) for slot in slots)


def inspect_envelope_stream(
    source: Any,
    *,
    verification: EnvelopeVerification,
) -> InspectedStreamEnvelope:
    """Boundedly verify public structure and signature without opening a slot."""

    stream = _require_source(source)
    prefix, prefix_bytes = _read_prefix(stream)
    slots = parse_key_slots(prefix.header["key_slots"])
    sequence = FrameSequenceValidator(chunk_size=prefix.preamble.chunk_size)
    accumulator = _TranscriptAccumulator()
    accumulator.add_prefix(prefix_bytes)

    while True:
        record, encoded = _read_frame(
            stream,
            chunk_size=prefix.preamble.chunk_size,
        )
        sequence.accept(record.header)
        accumulator.add_frame(encoded)
        if accumulator.frame_count == 1 and record.header.is_final:
            raise StreamingEnvelopeError("manifest frame must not carry FINAL")
        if record.header.is_final:
            break
    sequence.finish()
    if accumulator.frame_count < 2:
        raise StreamingEnvelopeError(
            "complete envelope requires manifest and data frames"
        )

    trailer, _ = _read_trailer(stream)
    transcript = accumulator.info()
    validate_trailer_against_transcript(trailer, transcript)
    verified = verify_complete_envelope_signature_policy(
        trailer=trailer,
        transcript=transcript,
        verification=verification,
        contains_contact=_contains_contact(slots),
    )
    return InspectedStreamEnvelope(
        prefix=prefix,
        prefix_bytes=prefix_bytes,
        slots=slots,
        transcript=transcript,
        trailer=trailer,
        verified_signature=verified,
        _proof=_INSPECTION_PROOF,
    )


def _build_stream_trailer(
    signing: EnvelopeSigning,
    transcript: TranscriptInfo,
) -> Trailer:
    if isinstance(signing, Ed25519EnvelopeSigning):
        return sign_transcript_info(
            transcript,
            private_key=signing.private_key,
            signer_key_version=signing.signer_key_version,
        )
    return build_unsigned_trailer(
        frame_count=transcript.frame_count,
        transcript_sha256=transcript.digest,
    )


def encrypt_stream_to_quarantine(
    *,
    key_plan: EnvelopeKeyPlan,
    plaintext_source: Any,
    sink: Any,
    stream_plan: PlaintextStreamPlan,
    original_name: str,
    signing: EnvelopeSigning,
    content_type: str | None = None,
    created_utc: str | None = None,
    writer: str = WRITER_NAME,
) -> StreamingEncryptionResult:
    """Encrypt a verified second plaintext pass into a transactional sink."""

    if not isinstance(stream_plan, PlaintextStreamPlan):
        raise StreamingEnvelopeError(
            "stream_plan must be created by scan_plaintext_stream"
        )
    stream = _require_source(plaintext_source)
    transaction = _require_sink(sink)
    try:
        prefix_bytes = build_complete_envelope_prefix(
            key_plan=key_plan,
            signing=signing,
            chunk_size=stream_plan.chunk_size,
            created_utc=created_utc,
            writer=writer,
        )
        manifest = build_manifest(
            original_name=original_name,
            original_size=stream_plan.original_size,
            plaintext_sha256=stream_plan.plaintext_sha256,
            chunk_size=stream_plan.chunk_size,
            content_type=content_type,
        )
        manifest_bytes = encode_manifest(
            manifest,
            chunk_size=stream_plan.chunk_size,
        )
        encryptor = V2FrameEncryptor(key_plan.dek, prefix_bytes)
        accumulator = _TranscriptAccumulator()
        accumulator.add_prefix(prefix_bytes)
        _write_all(transaction, prefix_bytes)

        manifest_frame = encryptor.encrypt_frame(manifest_bytes)
        accumulator.add_frame(manifest_frame)
        _write_all(transaction, manifest_frame)

        plaintext_digest = hashlib.sha256()
        plaintext_size = 0
        for position in range(stream_plan.data_frames):
            remaining = stream_plan.original_size - plaintext_size
            expected_len = min(stream_plan.chunk_size, remaining)
            data = _read_exact(stream, expected_len, "plaintext data")
            plaintext_size += len(data)
            plaintext_digest.update(data)
            final = position == stream_plan.data_frames - 1
            encoded_frame = encryptor.encrypt_frame(data, final=final)
            accumulator.add_frame(encoded_frame)
            _write_all(transaction, encoded_frame)
        _require_eof(stream, "plaintext second pass")
        encryptor.finish()

        if plaintext_size != stream_plan.original_size or not hmac.compare_digest(
            plaintext_digest.digest(),
            stream_plan.plaintext_sha256,
        ):
            raise StreamPlanMismatchError(
                "plaintext second pass differs from the scanned plan"
            )

        transcript = accumulator.info()
        trailer = _build_stream_trailer(signing, transcript)
        trailer_bytes = trailer.to_bytes()
        _write_all(transaction, trailer_bytes)
        _commit_sink(transaction)
        return StreamingEncryptionResult(
            manifest=manifest,
            transcript=transcript,
            trailer=trailer,
            encoded_size=transcript.transcript_len + len(trailer_bytes),
        )
    except BaseException:
        _abort_after_failure(transaction)
        raise


def _require_inspection(value: Any) -> InspectedStreamEnvelope:
    if not isinstance(value, InspectedStreamEnvelope) or value._proof is not _INSPECTION_PROOF:
        raise StreamingEnvelopeError(
            "inspection must come from inspect_envelope_stream"
        )
    return value


def decrypt_stream_to_quarantine(
    *,
    envelope_source: Any,
    sink: Any,
    inspection: InspectedStreamEnvelope,
    selected_slot_id: bytes | bytearray | memoryview,
    credential: SlotCredential,
) -> StreamingDecryptionResult:
    """Decrypt an exact second ciphertext pass and commit only after all checks."""

    checked = _require_inspection(inspection)
    stream = _require_source(envelope_source)
    transaction = _require_sink(sink)
    if not isinstance(selected_slot_id, (bytes, bytearray, memoryview)):
        raise StreamingEnvelopeError("selected_slot_id must be bytes")
    exact_slot_id = bytes(selected_slot_id)
    try:
        file_id = decode_complete_envelope_file_id(
            checked.prefix.header["file_id"]
        )
        dek = unwrap_selected_slot(
            checked.slots,
            file_id,
            exact_slot_id,
            credential,
        )
        prefix, prefix_bytes = _read_prefix(stream)
        if not hmac.compare_digest(prefix_bytes, checked.prefix_bytes):
            raise StreamPassMismatchError(
                "second-pass prefix differs from verified inspection"
            )
        decryptor = V2FrameDecryptor(dek, prefix_bytes)
        del dek
        accumulator = _TranscriptAccumulator()
        accumulator.add_prefix(prefix_bytes)

        manifest_record, manifest_encoded = _read_frame(
            stream,
            chunk_size=prefix.preamble.chunk_size,
        )
        accumulator.add_frame(manifest_encoded)
        manifest_frame = decryptor.decrypt_frame(manifest_encoded)
        if manifest_record.header.index != 0 or manifest_record.header.is_final:
            raise StreamingEnvelopeError(
                "frame 0 must be a non-final encrypted manifest"
            )
        manifest = parse_manifest(
            manifest_frame.plaintext,
            chunk_size=prefix.preamble.chunk_size,
        )

        plaintext_digest = hashlib.sha256()
        plaintext_size = 0
        data_frames = 0
        while True:
            record, encoded = _read_frame(
                stream,
                chunk_size=prefix.preamble.chunk_size,
            )
            accumulator.add_frame(encoded)
            decrypted = decryptor.decrypt_frame(encoded)
            data_frames += 1
            next_size = plaintext_size + len(decrypted.plaintext)
            if next_size > manifest.original_size:
                raise StreamingEnvelopeError(
                    "plaintext exceeds the authenticated manifest size"
                )
            plaintext_digest.update(decrypted.plaintext)
            plaintext_size = next_size
            _write_all(transaction, decrypted.plaintext)
            if record.header.is_final:
                break
        decryptor.finish()

        trailer, trailer_bytes = _read_trailer(stream)
        transcript = accumulator.info()
        validate_trailer_against_transcript(trailer, transcript)
        if not hmac.compare_digest(trailer_bytes, checked.trailer.to_bytes()):
            raise StreamPassMismatchError(
                "second-pass trailer differs from verified inspection"
            )
        if (
            transcript.frame_count != checked.transcript.frame_count
            or transcript.transcript_len != checked.transcript.transcript_len
            or not hmac.compare_digest(
                transcript.digest,
                checked.transcript.digest,
            )
        ):
            raise StreamPassMismatchError(
                "second-pass ciphertext differs from verified inspection"
            )
        if data_frames != manifest.data_frames:
            raise StreamingEnvelopeError(
                "data frame count differs from the authenticated manifest"
            )
        if plaintext_size != manifest.original_size:
            raise StreamingEnvelopeError(
                "plaintext size differs from the authenticated manifest"
            )
        actual_digest = plaintext_digest.digest()
        if not hmac.compare_digest(actual_digest, manifest.plaintext_sha256):
            raise StreamingEnvelopeError(
                "plaintext digest differs from the authenticated manifest"
            )

        _commit_sink(transaction)
        return StreamingDecryptionResult(
            manifest=manifest,
            transcript=transcript,
            trailer=trailer,
            selected_slot_id=exact_slot_id,
            verified_signature=checked.verified_signature,
            plaintext_size=plaintext_size,
            plaintext_sha256=actual_digest,
        )
    except BaseException:
        _abort_after_failure(transaction)
        raise


def verify_envelope_stream_with_dek(
    source: Any,
    *,
    inspection: InspectedStreamEnvelope,
    dek: bytes | bytearray | memoryview,
) -> StreamingEnvelopeVerificationResult:
    """Verify a second exact envelope pass without publishing plaintext.

    This is intended for post-write verification while the writer already
    holds the freshly generated DEK.  It does not open a key slot, write
    plaintext, alter trust, or commit a filesystem transaction.
    """

    checked = _require_inspection(inspection)
    stream = _require_source(source)
    if not isinstance(dek, (bytes, bytearray, memoryview)):
        raise StreamingEnvelopeError("dek must be bytes")
    exact_dek = bytes(dek)
    if len(exact_dek) != DEK_LEN:
        raise StreamingEnvelopeError(
            f"dek must contain exactly {DEK_LEN} bytes"
        )

    prefix, prefix_bytes = _read_prefix(stream)
    if not hmac.compare_digest(prefix_bytes, checked.prefix_bytes):
        raise StreamPassMismatchError(
            "verification prefix differs from verified inspection"
        )
    decryptor = V2FrameDecryptor(exact_dek, prefix_bytes)
    del exact_dek
    accumulator = _TranscriptAccumulator()
    accumulator.add_prefix(prefix_bytes)

    manifest_record, manifest_encoded = _read_frame(
        stream,
        chunk_size=prefix.preamble.chunk_size,
    )
    accumulator.add_frame(manifest_encoded)
    manifest_frame = decryptor.decrypt_frame(manifest_encoded)
    if manifest_record.header.index != 0 or manifest_record.header.is_final:
        raise StreamingEnvelopeError(
            "frame 0 must be a non-final encrypted manifest"
        )
    manifest = parse_manifest(
        manifest_frame.plaintext,
        chunk_size=prefix.preamble.chunk_size,
    )

    plaintext_digest = hashlib.sha256()
    plaintext_size = 0
    data_frames = 0
    while True:
        record, encoded = _read_frame(
            stream,
            chunk_size=prefix.preamble.chunk_size,
        )
        accumulator.add_frame(encoded)
        decrypted = decryptor.decrypt_frame(encoded)
        data_frames += 1
        next_size = plaintext_size + len(decrypted.plaintext)
        if next_size > manifest.original_size:
            raise StreamingEnvelopeError(
                "plaintext exceeds the authenticated manifest size"
            )
        plaintext_digest.update(decrypted.plaintext)
        plaintext_size = next_size
        if record.header.is_final:
            break
    decryptor.finish()

    trailer, trailer_bytes = _read_trailer(stream)
    transcript = accumulator.info()
    validate_trailer_against_transcript(trailer, transcript)
    if not hmac.compare_digest(trailer_bytes, checked.trailer.to_bytes()):
        raise StreamPassMismatchError(
            "verification trailer differs from verified inspection"
        )
    if (
        transcript.frame_count != checked.transcript.frame_count
        or transcript.transcript_len != checked.transcript.transcript_len
        or not hmac.compare_digest(transcript.digest, checked.transcript.digest)
    ):
        raise StreamPassMismatchError(
            "verification ciphertext differs from verified inspection"
        )
    if data_frames != manifest.data_frames:
        raise StreamingEnvelopeError(
            "data frame count differs from the authenticated manifest"
        )
    if plaintext_size != manifest.original_size:
        raise StreamingEnvelopeError(
            "plaintext size differs from the authenticated manifest"
        )
    actual_digest = plaintext_digest.digest()
    if not hmac.compare_digest(actual_digest, manifest.plaintext_sha256):
        raise StreamingEnvelopeError(
            "plaintext digest differs from the authenticated manifest"
        )
    return StreamingEnvelopeVerificationResult(
        manifest=manifest,
        transcript=transcript,
        trailer=trailer,
        verified_signature=checked.verified_signature,
        plaintext_size=plaintext_size,
        plaintext_sha256=actual_digest,
    )
