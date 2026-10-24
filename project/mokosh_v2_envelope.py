"""In-memory MOKOSH v2 manifest/frame integration.

This stage connects the already validated prefix, manifest and AES-GCM frame
components.  It performs no filesystem I/O, no password KDF, no DEK wrapping,
and no trailer or signature processing.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from mokosh_v2_crypto import V2FrameDecryptor, V2FrameEncryptor
from mokosh_v2_format import (
    PREAMBLE_LEN,
    FrameSequenceError,
    TruncatedDataError,
    V2FormatError,
    parse_envelope_prefix,
    parse_frame,
)
from mokosh_v2_manifest import (
    Manifest,
    build_manifest,
    encode_manifest,
    parse_manifest,
)


class EnvelopeIntegrationError(V2FormatError):
    """The authenticated manifest and data frames are inconsistent."""


@dataclass(frozen=True, slots=True)
class DecryptedPayload:
    manifest: Manifest
    plaintext: bytes


def _require_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise EnvelopeIntegrationError(f"{field} must be bytes")
    return bytes(value)


def _split_data_frames(plaintext: bytes, chunk_size: int) -> list[bytes]:
    if not plaintext:
        return [b""]
    return [
        plaintext[offset : offset + chunk_size]
        for offset in range(0, len(plaintext), chunk_size)
    ]


def encrypt_payload_bytes(
    *,
    dek: bytes | bytearray | memoryview,
    prefix_bytes: bytes | bytearray | memoryview,
    plaintext: bytes | bytearray | memoryview,
    original_name: str,
    content_type: str | None = None,
) -> bytes:
    cleartext = _require_bytes(plaintext, "plaintext")
    exact_prefix = _require_bytes(prefix_bytes, "prefix_bytes")
    prefix, remainder = parse_envelope_prefix(exact_prefix)
    if remainder:
        raise EnvelopeIntegrationError(
            "prefix_bytes must not contain frame or trailer bytes"
        )

    manifest = build_manifest(
        original_name=original_name,
        original_size=len(cleartext),
        plaintext_sha256=hashlib.sha256(cleartext).digest(),
        chunk_size=prefix.preamble.chunk_size,
        content_type=content_type,
    )
    manifest_bytes = encode_manifest(
        manifest,
        chunk_size=prefix.preamble.chunk_size,
    )
    encryptor = V2FrameEncryptor(dek, exact_prefix)
    encoded_frames = [encryptor.encrypt_frame(manifest_bytes)]
    data_frames = _split_data_frames(cleartext, prefix.preamble.chunk_size)
    for position, data in enumerate(data_frames):
        encoded_frames.append(
            encryptor.encrypt_frame(
                data,
                final=position == len(data_frames) - 1,
            )
        )
    encryptor.finish()
    return exact_prefix + b"".join(encoded_frames)


def _take_one_frame(
    remaining: bytes, *, chunk_size: int
) -> tuple[bytes, bytes]:
    record, after = parse_frame(remaining, chunk_size=chunk_size)
    encoded_len = len(remaining) - len(after)
    if encoded_len <= 0:
        raise AssertionError("internal frame length invariant failed")
    encoded_frame = remaining[:encoded_len]
    if len(record.ciphertext_and_tag) != record.header.plaintext_len + 16:
        raise AssertionError("internal parsed frame invariant failed")
    return encoded_frame, after


def decrypt_payload_bytes(
    *,
    dek: bytes | bytearray | memoryview,
    envelope_bytes: bytes | bytearray | memoryview,
) -> DecryptedPayload:
    encoded = _require_bytes(envelope_bytes, "envelope_bytes")
    prefix, remaining = parse_envelope_prefix(encoded)
    prefix_len = PREAMBLE_LEN + prefix.preamble.header_len
    exact_prefix = encoded[:prefix_len]
    if not remaining:
        raise TruncatedDataError("v2 envelope contains no manifest frame")

    decryptor = V2FrameDecryptor(dek, exact_prefix)
    manifest_frame_bytes, remaining = _take_one_frame(
        remaining,
        chunk_size=prefix.preamble.chunk_size,
    )
    manifest_frame = decryptor.decrypt_frame(manifest_frame_bytes)
    if manifest_frame.header.index != 0:
        raise EnvelopeIntegrationError("manifest must be frame 0")
    if manifest_frame.header.is_final:
        raise EnvelopeIntegrationError("manifest frame must not carry FINAL")
    manifest = parse_manifest(
        manifest_frame.plaintext,
        chunk_size=prefix.preamble.chunk_size,
    )

    plaintext_parts: list[bytes] = []
    data_frame_count = 0
    final_seen = False
    while remaining:
        frame_bytes, after = _take_one_frame(
            remaining,
            chunk_size=prefix.preamble.chunk_size,
        )
        decrypted = decryptor.decrypt_frame(frame_bytes)
        data_frame_count += 1
        plaintext_parts.append(decrypted.plaintext)
        remaining = after
        if decrypted.header.is_final:
            final_seen = True
            if remaining:
                raise EnvelopeIntegrationError(
                    "authenticated bytes appear after the FINAL frame"
                )
            break

    try:
        decryptor.finish()
    except FrameSequenceError as exc:
        raise EnvelopeIntegrationError("data frame sequence is missing FINAL") from exc
    if not final_seen:
        raise EnvelopeIntegrationError("data frame sequence is missing FINAL")
    if data_frame_count != manifest.data_frames:
        raise EnvelopeIntegrationError(
            "authenticated data frame count does not match the manifest"
        )

    plaintext = b"".join(plaintext_parts)
    if len(plaintext) != manifest.original_size:
        raise EnvelopeIntegrationError(
            "authenticated plaintext size does not match the manifest"
        )
    actual_digest = hashlib.sha256(plaintext).digest()
    if not hmac.compare_digest(actual_digest, manifest.plaintext_sha256):
        raise EnvelopeIntegrationError(
            "authenticated plaintext SHA-256 does not match the manifest"
        )
    return DecryptedPayload(manifest=manifest, plaintext=plaintext)
