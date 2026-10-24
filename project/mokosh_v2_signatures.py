"""In-memory Ed25519 signing and verification for MOKOSH v2 trailers.

This module proves that a trailer was signed by the private key corresponding
to a supplied Ed25519 public key. It deliberately does not decide whether
that key belongs to a trusted contact and performs no filesystem I/O.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mokosh_v2_trailer import (
    TranscriptInfo,
    Trailer,
    TrailerError,
    build_ed25519_signing_bytes,
    build_ed25519_trailer,
    scan_ciphertext_transcript,
    validate_trailer,
    validate_trailer_against_transcript,
)


ED25519_PUBLIC_KEY_LEN = 32
SIGNER_FINGERPRINT_LEN = 32
SIGNER_FINGERPRINT_DOMAIN = b"MOKOSH2\x00ED25519-PUBLIC-KEY\x00"


class V2SignatureError(TrailerError):
    """The v2 Ed25519 signing or verification operation is invalid."""


class UnsignedTrailerError(V2SignatureError):
    """Signature verification was requested for an unsigned trailer."""


class SignerFingerprintMismatchError(V2SignatureError):
    """The supplied public key does not match the signed fingerprint."""


class InvalidTrailerSignatureError(V2SignatureError):
    """The Ed25519 signature is not valid for the exact trailer input."""


@dataclass(frozen=True, slots=True)
class VerifiedEd25519Signature:
    """Cryptographic result only; this object never conveys contact trust."""

    signer_fingerprint: bytes
    signer_key_version: int
    public_key_bytes: bytes


def _require_private_key(private_key: Any) -> Ed25519PrivateKey:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise V2SignatureError("private_key must be an Ed25519PrivateKey")
    return private_key


def ed25519_public_key_bytes(public_key: Any) -> bytes:
    if not isinstance(public_key, Ed25519PublicKey):
        raise V2SignatureError("public_key must be an Ed25519PublicKey")
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if len(encoded) != ED25519_PUBLIC_KEY_LEN:
        raise AssertionError("internal Ed25519 public-key length invariant failed")
    return encoded


def load_ed25519_public_key(
    encoded: bytes | bytearray | memoryview,
) -> Ed25519PublicKey:
    if not isinstance(encoded, (bytes, bytearray, memoryview)):
        raise V2SignatureError("encoded public key must be bytes")
    raw = bytes(encoded)
    if len(raw) != ED25519_PUBLIC_KEY_LEN:
        raise V2SignatureError(
            f"encoded Ed25519 public key must contain {ED25519_PUBLIC_KEY_LEN} bytes"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise V2SignatureError("invalid encoded Ed25519 public key") from exc


def _coerce_public_key(
    public_key: Ed25519PublicKey | bytes | bytearray | memoryview,
) -> Ed25519PublicKey:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    return load_ed25519_public_key(public_key)


def derive_ed25519_fingerprint(public_key: Any) -> bytes:
    raw = ed25519_public_key_bytes(public_key)
    fingerprint = hashlib.sha256(SIGNER_FINGERPRINT_DOMAIN + raw).digest()
    if len(fingerprint) != SIGNER_FINGERPRINT_LEN:
        raise AssertionError("internal signer-fingerprint length invariant failed")
    return fingerprint


def sign_ciphertext_transcript(
    ciphertext_transcript: bytes | bytearray | memoryview,
    *,
    private_key: Ed25519PrivateKey,
    signer_key_version: int,
) -> Trailer:
    """Scan and sign an exact PREAMBLE || HEADER || FRAMES transcript."""

    transcript = scan_ciphertext_transcript(ciphertext_transcript)
    return sign_transcript_info(
        transcript,
        private_key=private_key,
        signer_key_version=signer_key_version,
    )


def sign_transcript_info(
    transcript: TranscriptInfo,
    *,
    private_key: Ed25519PrivateKey,
    signer_key_version: int,
) -> Trailer:
    """Sign already computed bounded-stream transcript information."""

    if not isinstance(transcript, TranscriptInfo):
        raise V2SignatureError("transcript must be TranscriptInfo")
    key = _require_private_key(private_key)
    fingerprint = derive_ed25519_fingerprint(key.public_key())
    signing_input = build_ed25519_signing_bytes(
        frame_count=transcript.frame_count,
        transcript_sha256=transcript.digest,
        signer_key_version=signer_key_version,
        signer_fingerprint=fingerprint,
    )
    signature = key.sign(signing_input)
    return build_ed25519_trailer(
        frame_count=transcript.frame_count,
        transcript_sha256=transcript.digest,
        signer_key_version=signer_key_version,
        signer_fingerprint=fingerprint,
        signature=signature,
    )


def verify_ciphertext_transcript_signature(
    trailer: Trailer,
    ciphertext_transcript: bytes | bytearray | memoryview,
    *,
    public_key: Ed25519PublicKey | bytes | bytearray | memoryview,
) -> VerifiedEd25519Signature:
    """Verify structure, transcript binding, key binding, and Ed25519 proof.

    A successful result says nothing about whether the caller trusts the key.
    """

    transcript = scan_ciphertext_transcript(ciphertext_transcript)
    return verify_transcript_info_signature(
        trailer,
        transcript,
        public_key=public_key,
    )


def verify_transcript_info_signature(
    trailer: Trailer,
    transcript: TranscriptInfo,
    *,
    public_key: Ed25519PublicKey | bytes | bytearray | memoryview,
) -> VerifiedEd25519Signature:
    """Verify an Ed25519 trailer against bounded-stream transcript data."""

    validate_trailer(trailer)
    if not trailer.is_signed:
        raise UnsignedTrailerError("signed contact trailer is required")
    if not isinstance(transcript, TranscriptInfo):
        raise V2SignatureError("transcript must be TranscriptInfo")
    validate_trailer_against_transcript(trailer, transcript)

    key = _coerce_public_key(public_key)
    raw_public_key = ed25519_public_key_bytes(key)
    actual_fingerprint = derive_ed25519_fingerprint(key)
    if not hmac.compare_digest(trailer.signer_fingerprint, actual_fingerprint):
        raise SignerFingerprintMismatchError(
            "supplied Ed25519 public key does not match signer fingerprint"
        )

    try:
        key.verify(trailer.signature, trailer.signing_bytes())
    except InvalidSignature as exc:
        raise InvalidTrailerSignatureError(
            "invalid Ed25519 trailer signature"
        ) from exc

    return VerifiedEd25519Signature(
        signer_fingerprint=actual_fingerprint,
        signer_key_version=trailer.signer_key_version,
        public_key_bytes=raw_public_key,
    )
