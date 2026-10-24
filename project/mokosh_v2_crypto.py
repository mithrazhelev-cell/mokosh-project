"""Stateful in-memory AES-256-GCM frame protection for MOKOSH v2.

This stage deliberately performs no filesystem operations and no password or
key-slot processing.  A fresh 32-byte DEK must be supplied for one envelope.
The stateful API prevents frame-index reuse inside one encryptor instance.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mokosh_v2_format import (
    FRAME_FLAG_FINAL,
    FrameHeader,
    FrameSequenceValidator,
    V2FormatError,
    build_frame,
    build_frame_aad,
    derive_frame_nonce,
    hash_envelope_prefix,
    parse_envelope_prefix,
    parse_frame,
)


DEK_LEN = 32


class V2CryptoError(ValueError):
    """Base class for misuse of the v2 frame-crypto API."""


class FrameAuthenticationError(V2CryptoError):
    """A frame failed AES-GCM authentication."""


@dataclass(frozen=True, slots=True)
class V2FrameContext:
    prefix_digest: bytes
    nonce_prefix: bytes
    chunk_size: int

    @classmethod
    def from_prefix(
        cls, prefix_bytes: bytes | bytearray | memoryview
    ) -> "V2FrameContext":
        if not isinstance(prefix_bytes, (bytes, bytearray, memoryview)):
            raise V2CryptoError("envelope prefix must be bytes")
        exact_prefix = bytes(prefix_bytes)
        prefix, remainder = parse_envelope_prefix(exact_prefix)
        if remainder:
            raise V2FormatError(
                "frame context prefix must not contain frame or trailer bytes"
            )
        encoded_nonce_prefix = prefix.header["nonce_prefix"]
        padding = "=" * ((4 - len(encoded_nonce_prefix) % 4) % 4)
        nonce_prefix = base64.urlsafe_b64decode(encoded_nonce_prefix + padding)
        return cls(
            prefix_digest=hash_envelope_prefix(exact_prefix),
            nonce_prefix=nonce_prefix,
            chunk_size=prefix.preamble.chunk_size,
        )


@dataclass(frozen=True, slots=True)
class DecryptedFrame:
    header: FrameHeader
    plaintext: bytes


def generate_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _require_dek(dek: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(dek, (bytes, bytearray, memoryview)):
        raise V2CryptoError("DEK must be bytes")
    key = bytes(dek)
    if len(key) != DEK_LEN:
        raise V2CryptoError(f"DEK must contain exactly {DEK_LEN} bytes")
    return key


def _candidate_sequence(
    current: FrameSequenceValidator, header: FrameHeader
) -> FrameSequenceValidator:
    candidate = FrameSequenceValidator(
        chunk_size=current.chunk_size,
        next_index=current.next_index,
        final_seen=current.final_seen,
    )
    candidate.accept(header)
    return candidate


class V2FrameEncryptor:
    def __init__(
        self,
        dek: bytes | bytearray | memoryview,
        prefix_bytes: bytes | bytearray | memoryview,
    ) -> None:
        self._context = V2FrameContext.from_prefix(prefix_bytes)
        self._aead = AESGCM(_require_dek(dek))
        self._sequence = FrameSequenceValidator(
            chunk_size=self._context.chunk_size
        )

    @property
    def next_index(self) -> int:
        return self._sequence.next_index

    @property
    def finalized(self) -> bool:
        return self._sequence.final_seen

    def encrypt_frame(
        self,
        plaintext: bytes | bytearray | memoryview,
        *,
        final: bool = False,
    ) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise V2CryptoError("frame plaintext must be bytes")
        if type(final) is not bool:
            raise V2CryptoError("final must be a boolean")
        cleartext = bytes(plaintext)
        flags = FRAME_FLAG_FINAL if final else 0
        header = FrameHeader(self._sequence.next_index, len(cleartext), flags)
        candidate = _candidate_sequence(self._sequence, header)
        nonce = derive_frame_nonce(self._context.nonce_prefix, header.index)
        aad = build_frame_aad(
            self._context.prefix_digest,
            header,
            chunk_size=self._context.chunk_size,
        )
        ciphertext_and_tag = self._aead.encrypt(nonce, cleartext, aad)
        encoded = build_frame(
            index=header.index,
            plaintext_len=header.plaintext_len,
            flags=header.flags,
            ciphertext_and_tag=ciphertext_and_tag,
            chunk_size=self._context.chunk_size,
        )
        self._sequence = candidate
        return encoded

    def finish(self) -> None:
        self._sequence.finish()


class V2FrameDecryptor:
    def __init__(
        self,
        dek: bytes | bytearray | memoryview,
        prefix_bytes: bytes | bytearray | memoryview,
    ) -> None:
        self._context = V2FrameContext.from_prefix(prefix_bytes)
        self._aead = AESGCM(_require_dek(dek))
        self._sequence = FrameSequenceValidator(
            chunk_size=self._context.chunk_size
        )

    @property
    def next_index(self) -> int:
        return self._sequence.next_index

    @property
    def finalized(self) -> bool:
        return self._sequence.final_seen

    def decrypt_frame(
        self, encoded_frame: bytes | bytearray | memoryview
    ) -> DecryptedFrame:
        if not isinstance(encoded_frame, (bytes, bytearray, memoryview)):
            raise V2CryptoError("encoded frame must be bytes")
        record, remainder = parse_frame(
            encoded_frame,
            chunk_size=self._context.chunk_size,
        )
        if remainder:
            raise V2FormatError("decrypt_frame requires exactly one encoded frame")
        candidate = _candidate_sequence(self._sequence, record.header)
        nonce = derive_frame_nonce(
            self._context.nonce_prefix,
            record.header.index,
        )
        aad = build_frame_aad(
            self._context.prefix_digest,
            record.header,
            chunk_size=self._context.chunk_size,
        )
        try:
            plaintext = self._aead.decrypt(
                nonce,
                record.ciphertext_and_tag,
                aad,
            )
        except InvalidTag:
            raise FrameAuthenticationError(
                "frame authentication failed"
            ) from None
        self._sequence = candidate
        return DecryptedFrame(record.header, plaintext)

    def finish(self) -> None:
        self._sequence.finish()
