"""Complete in-memory MOKOSH v2 envelope integration.

This module is the fail-closed composition boundary for the already verified
Stage 1 codecs and cryptographic primitives.  It builds one authenticated
header from one finalized key-slot plan, encrypts the manifest and payload
frames, appends an unsigned or Ed25519 trailer, and reverses that process only
with an explicitly selected slot and an explicit signature policy.

It performs no filesystem, Key Vault storage, contact trust, recovery,
network, licensing, logging, or GUI operation.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mokosh_v2_envelope import (
    DecryptedPayload,
    decrypt_payload_bytes,
    encrypt_payload_bytes,
)
from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    NONCE_PREFIX_LEN,
    PREAMBLE_LEN,
    EnvelopePrefix,
    FrameSequenceValidator,
    TruncatedDataError,
    V2FormatError,
    build_envelope_prefix,
    parse_envelope_prefix,
    parse_frame,
)
from mokosh_v2_key_slots import ContactHybridSlot, parse_key_slots
from mokosh_v2_manifest import Manifest
from mokosh_v2_signatures import (
    VerifiedEd25519Signature,
    sign_ciphertext_transcript,
    verify_ciphertext_transcript_signature,
    verify_transcript_info_signature,
)
from mokosh_v2_slot_orchestration import (
    FILE_ID_LEN,
    EnvelopeKeyPlan,
    SlotCredential,
    unwrap_selected_slot,
)
from mokosh_v2_trailer import (
    TranscriptInfo,
    Trailer,
    build_unsigned_trailer,
    parse_trailer,
    scan_ciphertext_transcript,
    validate_trailer_against_transcript,
)


WRITER_NAME = "MOKOSH Agent"


class CompleteEnvelopeError(V2FormatError):
    """A complete envelope or its integration policy is invalid."""


class CompleteEnvelopePolicyError(CompleteEnvelopeError):
    """The requested slot or signature policy would be ambiguous or unsafe."""


@dataclass(frozen=True, slots=True)
class UnsignedEnvelopeSigning:
    """Explicitly request an unsigned local envelope."""


@dataclass(frozen=True, slots=True)
class Ed25519EnvelopeSigning:
    """Sign the exact public ciphertext transcript with one Ed25519 key."""

    private_key: Ed25519PrivateKey = field(repr=False)
    signer_key_version: int


EnvelopeSigning = UnsignedEnvelopeSigning | Ed25519EnvelopeSigning


@dataclass(frozen=True, slots=True)
class RequireUnsignedEnvelope:
    """Accept only the explicitly unsigned local-envelope mode."""


@dataclass(frozen=True, slots=True)
class RequireEd25519Envelope:
    """Require and verify one exact Ed25519 signer key.

    Successful verification proves key possession only.  It does not mark the
    key or contact as trusted.
    """

    public_key: Ed25519PublicKey | bytes = field(repr=False)


EnvelopeVerification = RequireUnsignedEnvelope | RequireEd25519Envelope


@dataclass(frozen=True, slots=True)
class CompleteEnvelopeParts:
    """Strictly split public structure; no payload has been decrypted."""

    prefix: EnvelopePrefix
    ciphertext_transcript: bytes
    transcript: TranscriptInfo
    trailer: Trailer


@dataclass(frozen=True, slots=True)
class DecryptedCompleteEnvelope:
    """Authenticated plaintext plus cryptographic signature result.

    ``verified_signature`` intentionally conveys no contact-trust decision.
    """

    manifest: Manifest
    plaintext: bytes = field(repr=False)
    trailer: Trailer
    selected_slot_id: bytes
    verified_signature: VerifiedEd25519Signature | None


def _require_bytes(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CompleteEnvelopeError(f"{field_name} must be bytes")
    return bytes(value)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_complete_envelope_file_id(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise CompleteEnvelopeError("header file_id must be unpadded base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise CompleteEnvelopeError("header file_id is invalid base64url") from exc
    if len(decoded) != FILE_ID_LEN:
        raise CompleteEnvelopeError(
            f"header file_id must decode to exactly {FILE_ID_LEN} bytes"
        )
    return decoded


def _created_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_nonce_prefix() -> bytes:
    value = os.urandom(NONCE_PREFIX_LEN)
    if not isinstance(value, bytes) or len(value) != NONCE_PREFIX_LEN:
        raise CompleteEnvelopeError(
            "secure random source returned an invalid nonce_prefix"
        )
    return value


def _validate_signing(signing: Any, *, contains_contact: bool) -> None:
    if isinstance(signing, UnsignedEnvelopeSigning):
        if contains_contact:
            raise CompleteEnvelopePolicyError(
                "CONTACT_HYBRID envelopes require Ed25519 signing"
            )
        return
    if not isinstance(signing, Ed25519EnvelopeSigning):
        raise CompleteEnvelopePolicyError(
            "signing must explicitly select unsigned or Ed25519 mode"
        )
    if not isinstance(signing.private_key, Ed25519PrivateKey):
        raise CompleteEnvelopePolicyError(
            "Ed25519 signing requires an Ed25519PrivateKey"
        )
    if (
        type(signing.signer_key_version) is not int
        or not 1 <= signing.signer_key_version <= 0xFFFFFFFF
    ):
        raise CompleteEnvelopePolicyError(
            "signer_key_version must be a positive uint32"
        )


def _contains_contact_slots(slots: tuple[object, ...]) -> bool:
    return any(isinstance(slot, ContactHybridSlot) for slot in slots)


def build_complete_envelope_prefix(
    *,
    key_plan: EnvelopeKeyPlan,
    signing: EnvelopeSigning,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    created_utc: str | None = None,
    writer: str = WRITER_NAME,
) -> bytes:
    """Build the strict public prefix shared by in-memory and stream writers."""

    if not isinstance(key_plan, EnvelopeKeyPlan):
        raise CompleteEnvelopePolicyError(
            "key_plan must be finalized by KeySlotPlanBuilder"
        )
    slots = parse_key_slots(key_plan.header_key_slots())
    _validate_signing(
        signing,
        contains_contact=_contains_contact_slots(slots),
    )
    nonce_prefix = _random_nonce_prefix()
    header = {
        "format": "MOKOSH",
        "version": 2,
        "file_id": _b64url(key_plan.file_id),
        "content_aead": "AES-256-GCM-CHUNKED",
        "nonce_prefix": _b64url(nonce_prefix),
        "chunk_size": chunk_size,
        "key_slots": key_plan.header_key_slots(),
        "created_utc": _created_utc_now() if created_utc is None else created_utc,
        "writer": writer,
    }
    return build_envelope_prefix(header, chunk_size=chunk_size)


def encrypt_complete_envelope(
    *,
    key_plan: EnvelopeKeyPlan,
    plaintext: bytes | bytearray | memoryview,
    original_name: str,
    signing: EnvelopeSigning,
    content_type: str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    created_utc: str | None = None,
    writer: str = WRITER_NAME,
) -> bytes:
    """Build one complete ``PREFIX || FRAMES || TRAILER`` envelope.

    A finalized plan is mandatory so every public slot wraps the one DEK used
    by all frames.  CONTACT_HYBRID presence always requires Ed25519 signing.
    """

    cleartext = _require_bytes(plaintext, "plaintext")
    prefix = build_complete_envelope_prefix(
        key_plan=key_plan,
        signing=signing,
        chunk_size=chunk_size,
        created_utc=created_utc,
        writer=writer,
    )
    transcript_bytes = encrypt_payload_bytes(
        dek=key_plan.dek,
        prefix_bytes=prefix,
        plaintext=cleartext,
        original_name=original_name,
        content_type=content_type,
    )

    if isinstance(signing, UnsignedEnvelopeSigning):
        transcript = scan_ciphertext_transcript(transcript_bytes)
        trailer = build_unsigned_trailer(
            frame_count=transcript.frame_count,
            transcript_sha256=transcript.digest,
        )
    else:
        trailer = sign_ciphertext_transcript(
            transcript_bytes,
            private_key=signing.private_key,
            signer_key_version=signing.signer_key_version,
        )
    return transcript_bytes + trailer.to_bytes()


def split_complete_envelope(
    envelope_bytes: bytes | bytearray | memoryview,
) -> CompleteEnvelopeParts:
    """Split and validate exact transcript and trailer boundaries."""

    encoded = _require_bytes(envelope_bytes, "envelope_bytes")
    prefix, remaining = parse_envelope_prefix(encoded)
    prefix_len = PREAMBLE_LEN + prefix.preamble.header_len
    transcript_end = prefix_len
    sequence = FrameSequenceValidator(chunk_size=prefix.preamble.chunk_size)

    if not remaining:
        raise TruncatedDataError("complete v2 envelope contains no frames")
    while True:
        record, after = parse_frame(
            remaining,
            chunk_size=prefix.preamble.chunk_size,
        )
        frame_len = len(remaining) - len(after)
        if frame_len <= 0:
            raise AssertionError("internal complete-envelope frame invariant failed")
        sequence.accept(record.header)
        transcript_end += frame_len
        remaining = after
        if record.header.is_final:
            break
        if not remaining:
            raise TruncatedDataError(
                "complete v2 envelope ends before FINAL and trailer"
            )
    sequence.finish()
    if not remaining:
        raise TruncatedDataError("complete v2 envelope contains no trailer")

    transcript_bytes = encoded[:transcript_end]
    trailer = parse_trailer(remaining)
    transcript = scan_ciphertext_transcript(transcript_bytes)
    validate_trailer_against_transcript(trailer, transcript)
    return CompleteEnvelopeParts(
        prefix=prefix,
        ciphertext_transcript=transcript_bytes,
        transcript=transcript,
        trailer=trailer,
    )


def _verify_signature_policy(
    parts: CompleteEnvelopeParts,
    verification: Any,
    *,
    contains_contact: bool,
) -> VerifiedEd25519Signature | None:
    return verify_complete_envelope_signature_policy(
        trailer=parts.trailer,
        transcript=parts.transcript,
        verification=verification,
        contains_contact=contains_contact,
        ciphertext_transcript=parts.ciphertext_transcript,
    )


def verify_complete_envelope_signature_policy(
    *,
    trailer: Trailer,
    transcript: TranscriptInfo,
    verification: EnvelopeVerification,
    contains_contact: bool,
    ciphertext_transcript: bytes | None = None,
) -> VerifiedEd25519Signature | None:
    """Apply explicit unsigned/signed policy to bytes or stream transcript data."""

    if isinstance(verification, RequireUnsignedEnvelope):
        if contains_contact:
            raise CompleteEnvelopePolicyError(
                "CONTACT_HYBRID envelopes cannot use unsigned verification"
            )
        if trailer.is_signed:
            raise CompleteEnvelopePolicyError(
                "signed envelope was supplied where unsigned mode was required"
            )
        return None
    if not isinstance(verification, RequireEd25519Envelope):
        raise CompleteEnvelopePolicyError(
            "verification must explicitly require unsigned or Ed25519 mode"
        )
    if not trailer.is_signed:
        raise CompleteEnvelopePolicyError(
            "unsigned envelope was supplied where Ed25519 was required"
        )
    if ciphertext_transcript is not None:
        return verify_ciphertext_transcript_signature(
            trailer,
            ciphertext_transcript,
            public_key=verification.public_key,
        )
    return verify_transcript_info_signature(
        trailer,
        transcript,
        public_key=verification.public_key,
    )


def decrypt_complete_envelope(
    *,
    envelope_bytes: bytes | bytearray | memoryview,
    selected_slot_id: bytes | bytearray | memoryview,
    credential: SlotCredential,
    verification: EnvelopeVerification,
) -> DecryptedCompleteEnvelope:
    """Verify, explicitly unwrap one slot, and decrypt one complete envelope.

    Public trailer/signature policy is checked before a password KDF or secret
    key operation.  No other slot is searched after selection or failure.
    """

    exact_slot_id = _require_bytes(selected_slot_id, "selected_slot_id")
    parts = split_complete_envelope(envelope_bytes)
    slots = parse_key_slots(parts.prefix.header["key_slots"])
    contains_contact = _contains_contact_slots(slots)
    verified_signature = _verify_signature_policy(
        parts,
        verification,
        contains_contact=contains_contact,
    )

    file_id = decode_complete_envelope_file_id(parts.prefix.header["file_id"])
    dek = unwrap_selected_slot(
        slots,
        file_id,
        exact_slot_id,
        credential,
    )
    try:
        payload: DecryptedPayload = decrypt_payload_bytes(
            dek=dek,
            envelope_bytes=parts.ciphertext_transcript,
        )
    finally:
        del dek
    return DecryptedCompleteEnvelope(
        manifest=payload.manifest,
        plaintext=payload.plaintext,
        trailer=parts.trailer,
        selected_slot_id=exact_slot_id,
        verified_signature=verified_signature,
    )
