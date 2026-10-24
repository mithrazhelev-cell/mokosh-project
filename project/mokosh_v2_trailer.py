"""Strict MOKOSH v2 ciphertext-transcript and trailer codec.

This module hashes and validates public envelope structure.  It does not sign,
verify signatures, decrypt frames, apply trust policy, or perform filesystem I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Any

from mokosh_v2_format import (
    MAJOR_VERSION,
    MINOR_VERSION,
    PREAMBLE_LEN,
    FormatLimitError,
    FrameSequenceValidator,
    TruncatedDataError,
    UnknownFlagsError,
    UnsupportedVersionError,
    V2FormatError,
    parse_envelope_prefix,
    parse_frame,
)


TRAILER_MAGIC = b"MOKTRL2\x00"
TRAILER_STRUCT = struct.Struct(">8sBBHI32sBIBH")
TRAILER_FIXED_LEN = TRAILER_STRUCT.size

TRANSCRIPT_DOMAIN = b"MOKOSH2\x00CIPHERTEXT-TRANSCRIPT\x00"
TRAILER_SIGNATURE_DOMAIN = b"MOKOSH2\x00TRAILER-SIGNATURE\x00"

SIGNATURE_NONE = 0
SIGNATURE_ED25519 = 1
SUPPORTED_TRAILER_FLAGS = 0
TRANSCRIPT_DIGEST_LEN = 32
ED25519_FINGERPRINT_LEN = 32
ED25519_SIGNATURE_LEN = 64
MAX_SIGNATURE_LEN = 128
MAX_TRAILER_FRAME_COUNT = 0xFFFFFFFF


class TrailerError(V2FormatError):
    """The v2 trailer is malformed, unsupported, or inconsistent."""


class TranscriptMismatchError(TrailerError):
    """Trailer frame count or digest does not match the ciphertext transcript."""


@dataclass(frozen=True, slots=True)
class TranscriptInfo:
    frame_count: int
    digest: bytes
    transcript_len: int


@dataclass(frozen=True, slots=True)
class Trailer:
    frame_count: int
    transcript_sha256: bytes
    signature_algorithm: int = SIGNATURE_NONE
    signer_key_version: int = 0
    signer_fingerprint: bytes = b""
    signature: bytes = b""
    flags: int = 0
    major: int = MAJOR_VERSION
    minor: int = MINOR_VERSION

    @property
    def is_signed(self) -> bool:
        return self.signature_algorithm == SIGNATURE_ED25519

    def _fixed_bytes(self) -> bytes:
        validate_trailer(self)
        return TRAILER_STRUCT.pack(
            TRAILER_MAGIC,
            self.major,
            self.minor,
            self.flags,
            self.frame_count,
            self.transcript_sha256,
            self.signature_algorithm,
            self.signer_key_version,
            len(self.signer_fingerprint),
            len(self.signature),
        )

    def to_bytes(self) -> bytes:
        return self._fixed_bytes() + self.signer_fingerprint + self.signature

    def signing_bytes(self) -> bytes:
        if not self.is_signed:
            raise TrailerError("unsigned trailer has no Ed25519 signing input")
        return TRAILER_SIGNATURE_DOMAIN + self._fixed_bytes() + self.signer_fingerprint


def _require_plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise TrailerError(f"{field} must be an integer")
    return value


def _require_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TrailerError(f"{field} must be bytes")
    return bytes(value)


def validate_trailer(trailer: Trailer) -> None:
    if not isinstance(trailer, Trailer):
        raise TrailerError("trailer must be a Trailer instance")
    for value, field in (
        (trailer.major, "trailer.major"),
        (trailer.minor, "trailer.minor"),
        (trailer.flags, "trailer.flags"),
        (trailer.frame_count, "trailer.frame_count"),
        (trailer.signature_algorithm, "trailer.signature_algorithm"),
        (trailer.signer_key_version, "trailer.signer_key_version"),
    ):
        _require_plain_int(value, field)

    if trailer.major != MAJOR_VERSION or trailer.minor != MINOR_VERSION:
        raise UnsupportedVersionError(
            f"unsupported trailer version {trailer.major}.{trailer.minor}"
        )
    if not 0 <= trailer.flags <= 0xFFFF:
        raise FormatLimitError("trailer flags must fit in uint16")
    unknown = trailer.flags & ~SUPPORTED_TRAILER_FLAGS
    if unknown:
        raise UnknownFlagsError(f"unknown trailer flags: 0x{unknown:04x}")
    if not 1 <= trailer.frame_count <= MAX_TRAILER_FRAME_COUNT:
        raise FormatLimitError(
            "trailer frame_count must be between 1 and "
            f"{MAX_TRAILER_FRAME_COUNT}"
        )
    digest = _require_bytes(trailer.transcript_sha256, "transcript_sha256")
    if len(digest) != TRANSCRIPT_DIGEST_LEN:
        raise TrailerError(
            f"transcript_sha256 must contain exactly {TRANSCRIPT_DIGEST_LEN} bytes"
        )
    fingerprint = _require_bytes(
        trailer.signer_fingerprint, "signer_fingerprint"
    )
    signature = _require_bytes(trailer.signature, "signature")
    if len(signature) > MAX_SIGNATURE_LEN:
        raise FormatLimitError(
            f"signature exceeds the limit of {MAX_SIGNATURE_LEN} bytes"
        )
    if not 0 <= trailer.signer_key_version <= 0xFFFFFFFF:
        raise FormatLimitError("signer_key_version must fit in uint32")

    if trailer.signature_algorithm == SIGNATURE_NONE:
        if trailer.signer_key_version != 0 or fingerprint or signature:
            raise TrailerError(
                "unsigned trailer requires zero key version and empty signature fields"
            )
    elif trailer.signature_algorithm == SIGNATURE_ED25519:
        if trailer.signer_key_version == 0:
            raise TrailerError("signed trailer requires a positive key version")
        if len(fingerprint) != ED25519_FINGERPRINT_LEN:
            raise TrailerError(
                f"Ed25519 fingerprint must contain {ED25519_FINGERPRINT_LEN} bytes"
            )
        if len(signature) != ED25519_SIGNATURE_LEN:
            raise TrailerError(
                f"Ed25519 signature must contain {ED25519_SIGNATURE_LEN} bytes"
            )
    else:
        raise TrailerError(
            f"unsupported signature algorithm: {trailer.signature_algorithm}"
        )


def build_unsigned_trailer(
    *, frame_count: int, transcript_sha256: bytes | bytearray | memoryview
) -> Trailer:
    trailer = Trailer(
        frame_count=frame_count,
        transcript_sha256=_require_bytes(
            transcript_sha256, "transcript_sha256"
        ),
    )
    validate_trailer(trailer)
    return trailer


def build_ed25519_trailer(
    *,
    frame_count: int,
    transcript_sha256: bytes | bytearray | memoryview,
    signer_key_version: int,
    signer_fingerprint: bytes | bytearray | memoryview,
    signature: bytes | bytearray | memoryview,
) -> Trailer:
    trailer = Trailer(
        frame_count=frame_count,
        transcript_sha256=_require_bytes(
            transcript_sha256, "transcript_sha256"
        ),
        signature_algorithm=SIGNATURE_ED25519,
        signer_key_version=signer_key_version,
        signer_fingerprint=_require_bytes(
            signer_fingerprint, "signer_fingerprint"
        ),
        signature=_require_bytes(signature, "signature"),
    )
    validate_trailer(trailer)
    return trailer


def build_ed25519_signing_bytes(
    *,
    frame_count: int,
    transcript_sha256: bytes | bytearray | memoryview,
    signer_key_version: int,
    signer_fingerprint: bytes | bytearray | memoryview,
) -> bytes:
    placeholder = build_ed25519_trailer(
        frame_count=frame_count,
        transcript_sha256=transcript_sha256,
        signer_key_version=signer_key_version,
        signer_fingerprint=signer_fingerprint,
        signature=b"\x00" * ED25519_SIGNATURE_LEN,
    )
    return placeholder.signing_bytes()


def parse_trailer(data: bytes | bytearray | memoryview) -> Trailer:
    encoded = _require_bytes(data, "trailer input")
    if len(encoded) < TRAILER_FIXED_LEN:
        raise TruncatedDataError(
            f"trailer requires at least {TRAILER_FIXED_LEN} bytes; received {len(encoded)}"
        )
    (
        magic,
        major,
        minor,
        flags,
        frame_count,
        transcript_sha256,
        signature_algorithm,
        signer_key_version,
        fingerprint_len,
        signature_len,
    ) = TRAILER_STRUCT.unpack(encoded[:TRAILER_FIXED_LEN])
    if magic != TRAILER_MAGIC:
        raise TrailerError("invalid MOKOSH v2 trailer magic")
    if signature_len > MAX_SIGNATURE_LEN:
        raise FormatLimitError(
            f"signature exceeds the limit of {MAX_SIGNATURE_LEN} bytes"
        )
    expected_len = TRAILER_FIXED_LEN + fingerprint_len + signature_len
    if len(encoded) < expected_len:
        raise TruncatedDataError(
            f"declared trailer requires {expected_len} bytes; received {len(encoded)}"
        )
    if len(encoded) != expected_len:
        raise TrailerError("trailer contains undeclared trailing bytes")
    fingerprint_end = TRAILER_FIXED_LEN + fingerprint_len
    trailer = Trailer(
        frame_count=frame_count,
        transcript_sha256=transcript_sha256,
        signature_algorithm=signature_algorithm,
        signer_key_version=signer_key_version,
        signer_fingerprint=encoded[TRAILER_FIXED_LEN:fingerprint_end],
        signature=encoded[fingerprint_end:expected_len],
        flags=flags,
        major=major,
        minor=minor,
    )
    validate_trailer(trailer)
    return trailer


def scan_ciphertext_transcript(
    data: bytes | bytearray | memoryview,
) -> TranscriptInfo:
    encoded = _require_bytes(data, "ciphertext transcript")
    prefix, remaining = parse_envelope_prefix(encoded)
    prefix_len = PREAMBLE_LEN + prefix.preamble.header_len
    digest = hashlib.sha256()
    digest.update(TRANSCRIPT_DOMAIN)
    digest.update(encoded[:prefix_len])
    sequence = FrameSequenceValidator(chunk_size=prefix.preamble.chunk_size)
    frame_count = 0

    while remaining:
        record, after = parse_frame(
            remaining,
            chunk_size=prefix.preamble.chunk_size,
        )
        frame_len = len(remaining) - len(after)
        sequence.accept(record.header)
        digest.update(remaining[:frame_len])
        frame_count += 1
        remaining = after
        if record.header.is_final:
            if remaining:
                raise TrailerError(
                    "ciphertext transcript contains bytes after FINAL"
                )
            break

    sequence.finish()
    if frame_count > MAX_TRAILER_FRAME_COUNT:
        raise FormatLimitError("ciphertext transcript exceeds frame-count limit")
    return TranscriptInfo(
        frame_count=frame_count,
        digest=digest.digest(),
        transcript_len=len(encoded),
    )


def validate_trailer_against_transcript(
    trailer: Trailer, transcript: TranscriptInfo
) -> None:
    validate_trailer(trailer)
    if not isinstance(transcript, TranscriptInfo):
        raise TrailerError("transcript must be TranscriptInfo")
    if trailer.frame_count != transcript.frame_count:
        raise TranscriptMismatchError(
            "trailer frame_count does not match the ciphertext transcript"
        )
    if not hmac.compare_digest(trailer.transcript_sha256, transcript.digest):
        raise TranscriptMismatchError(
            "trailer digest does not match the ciphertext transcript"
        )
