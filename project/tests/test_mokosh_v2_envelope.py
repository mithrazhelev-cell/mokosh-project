import base64
import hashlib
import unittest

from mokosh_v2_crypto import (
    FrameAuthenticationError,
    V2FrameEncryptor,
)
from mokosh_v2_envelope import (
    EnvelopeIntegrationError,
    decrypt_payload_bytes,
    encrypt_payload_bytes,
)
from mokosh_v2_format import (
    MIN_CHUNK_SIZE,
    FrameSequenceError,
    TruncatedDataError,
    V2FormatError,
    build_envelope_prefix,
    parse_envelope_prefix,
    parse_frame,
)
from mokosh_v2_manifest import build_manifest, encode_manifest


DEK = bytes(range(32))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_prefix(*, writer="MOKOSH Agent") -> bytes:
    return build_envelope_prefix(
        {
            "format": "MOKOSH",
            "version": 2,
            "file_id": b64url(bytes(range(16))),
            "content_aead": "AES-256-GCM-CHUNKED",
            "nonce_prefix": b64url(bytes(range(8))),
            "chunk_size": MIN_CHUNK_SIZE,
            "key_slots": [],
            "created_utc": "2026-08-07T16:00:00Z",
            "writer": writer,
        },
        chunk_size=MIN_CHUNK_SIZE,
    )


PREFIX = valid_prefix()


def manual_envelope(manifest, data_frames):
    encryptor = V2FrameEncryptor(DEK, PREFIX)
    parts = [
        encryptor.encrypt_frame(
            encode_manifest(manifest, chunk_size=MIN_CHUNK_SIZE)
        )
    ]
    for plaintext, final in data_frames:
        parts.append(encryptor.encrypt_frame(plaintext, final=final))
    return PREFIX + b"".join(parts)


def split_frames(envelope: bytes):
    prefix, remaining = parse_envelope_prefix(envelope)
    prefix_len = len(envelope) - len(remaining)
    frames = []
    while remaining:
        _, after = parse_frame(remaining, chunk_size=prefix.preamble.chunk_size)
        frame_len = len(remaining) - len(after)
        frames.append(remaining[:frame_len])
        remaining = after
    return envelope[:prefix_len], frames


class EnvelopeRoundtripTests(unittest.TestCase):
    def test_empty_payload_roundtrip(self):
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=b"",
            original_name="empty.txt",
        )
        result = decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)
        self.assertEqual(result.plaintext, b"")
        self.assertEqual(result.manifest.original_size, 0)
        self.assertEqual(result.manifest.data_frames, 1)

    def test_small_unicode_payload_roundtrip(self):
        plaintext = "Сигурен документ 测试".encode("utf-8")
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=plaintext,
            original_name="документ-测试.txt",
            content_type="text/plain",
        )
        result = decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)
        self.assertEqual(result.plaintext, plaintext)
        self.assertEqual(result.manifest.original_name, "документ-测试.txt")
        self.assertEqual(result.manifest.content_type, "text/plain")

    def test_exact_chunk_boundary_roundtrip(self):
        plaintext = b"A" * MIN_CHUNK_SIZE
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=plaintext,
            original_name="boundary.bin",
        )
        result = decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)
        self.assertEqual(result.plaintext, plaintext)
        self.assertEqual(result.manifest.data_frames, 1)

    def test_multi_frame_roundtrip(self):
        plaintext = b"A" * (MIN_CHUNK_SIZE + 17)
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=plaintext,
            original_name="large.bin",
        )
        result = decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)
        self.assertEqual(result.plaintext, plaintext)
        self.assertEqual(result.manifest.data_frames, 2)

    def test_non_bytes_plaintext_or_envelope_is_rejected(self):
        with self.assertRaises(EnvelopeIntegrationError):
            encrypt_payload_bytes(
                dek=DEK,
                prefix_bytes=PREFIX,
                plaintext="not-bytes",
                original_name="file.txt",
            )
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes="not-bytes")

    def test_encrypt_rejects_prefix_with_remainder(self):
        with self.assertRaises(EnvelopeIntegrationError):
            encrypt_payload_bytes(
                dek=DEK,
                prefix_bytes=PREFIX + b"extra",
                plaintext=b"data",
                original_name="file.txt",
            )


class EnvelopeTamperTests(unittest.TestCase):
    def setUp(self):
        self.envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=b"important data",
            original_name="report.txt",
        )

    def test_wrong_key_is_rejected(self):
        with self.assertRaises(FrameAuthenticationError):
            decrypt_payload_bytes(
                dek=b"W" * 32,
                envelope_bytes=self.envelope,
            )

    def test_manifest_ciphertext_tamper_is_rejected(self):
        prefix, frames = split_frames(self.envelope)
        damaged = bytearray(frames[0])
        damaged[-1] ^= 1
        with self.assertRaises(FrameAuthenticationError):
            decrypt_payload_bytes(
                dek=DEK,
                envelope_bytes=prefix + bytes(damaged) + b"".join(frames[1:]),
            )

    def test_data_ciphertext_tamper_is_rejected(self):
        prefix, frames = split_frames(self.envelope)
        damaged = bytearray(frames[1])
        damaged[-1] ^= 1
        with self.assertRaises(FrameAuthenticationError):
            decrypt_payload_bytes(
                dek=DEK,
                envelope_bytes=prefix + frames[0] + bytes(damaged),
            )

    def test_truncated_frame_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=self.envelope[:-1])

    def test_bytes_after_final_are_rejected(self):
        with self.assertRaises((EnvelopeIntegrationError, TruncatedDataError)):
            decrypt_payload_bytes(
                dek=DEK,
                envelope_bytes=self.envelope + b"unexpected",
            )

    def test_changed_valid_prefix_is_rejected(self):
        _, frames = split_frames(self.envelope)
        with self.assertRaises(FrameAuthenticationError):
            decrypt_payload_bytes(
                dek=DEK,
                envelope_bytes=valid_prefix(writer="Changed") + b"".join(frames),
            )


class EnvelopeConsistencyTests(unittest.TestCase):
    def test_missing_manifest_frame_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=PREFIX)

    def test_manifest_frame_must_not_be_final(self):
        manifest = build_manifest(
            original_name="empty.txt",
            original_size=0,
            plaintext_sha256=hashlib.sha256(b"").digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        encryptor = V2FrameEncryptor(DEK, PREFIX)
        envelope = PREFIX + encryptor.encrypt_frame(
            encode_manifest(manifest, chunk_size=MIN_CHUNK_SIZE),
            final=True,
        )
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_invalid_encrypted_manifest_plaintext_is_rejected(self):
        encryptor = V2FrameEncryptor(DEK, PREFIX)
        envelope = (
            PREFIX
            + encryptor.encrypt_frame(b"not-json")
            + encryptor.encrypt_frame(b"data", final=True)
        )
        with self.assertRaises(V2FormatError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_missing_final_is_rejected(self):
        manifest = build_manifest(
            original_name="file.txt",
            original_size=4,
            plaintext_sha256=hashlib.sha256(b"data").digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        envelope = manual_envelope(manifest, [(b"data", False)])
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_extra_authenticated_data_frame_is_rejected(self):
        manifest = build_manifest(
            original_name="file.txt",
            original_size=4,
            plaintext_sha256=hashlib.sha256(b"data").digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        envelope = manual_envelope(
            manifest,
            [(b"data", False), (b"extra", True)],
        )
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_missing_data_frame_is_rejected(self):
        declared_size = MIN_CHUNK_SIZE + 1
        manifest = build_manifest(
            original_name="large.bin",
            original_size=declared_size,
            plaintext_sha256=hashlib.sha256(b"A" * declared_size).digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        envelope = manual_envelope(manifest, [(b"A" * MIN_CHUNK_SIZE, True)])
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_plaintext_size_mismatch_is_rejected(self):
        manifest = build_manifest(
            original_name="file.txt",
            original_size=4,
            plaintext_sha256=hashlib.sha256(b"data").digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        envelope = manual_envelope(manifest, [(b"bad", True)])
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_plaintext_hash_mismatch_is_rejected(self):
        manifest = build_manifest(
            original_name="file.txt",
            original_size=4,
            plaintext_sha256=hashlib.sha256(b"good").digest(),
            chunk_size=MIN_CHUNK_SIZE,
        )
        envelope = manual_envelope(manifest, [(b"evil", True)])
        with self.assertRaises(EnvelopeIntegrationError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=envelope)

    def test_reordered_data_frames_are_rejected(self):
        plaintext = b"A" * (MIN_CHUNK_SIZE + 1)
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=plaintext,
            original_name="large.bin",
        )
        prefix, frames = split_frames(envelope)
        reordered = prefix + frames[0] + frames[2] + frames[1]
        with self.assertRaises(FrameSequenceError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=reordered)

    def test_duplicate_data_frame_is_rejected(self):
        plaintext = b"A" * (MIN_CHUNK_SIZE + 1)
        envelope = encrypt_payload_bytes(
            dek=DEK,
            prefix_bytes=PREFIX,
            plaintext=plaintext,
            original_name="large.bin",
        )
        prefix, frames = split_frames(envelope)
        duplicated = prefix + frames[0] + frames[1] + frames[1]
        with self.assertRaises(FrameSequenceError):
            decrypt_payload_bytes(dek=DEK, envelope_bytes=duplicated)


if __name__ == "__main__":
    unittest.main()
