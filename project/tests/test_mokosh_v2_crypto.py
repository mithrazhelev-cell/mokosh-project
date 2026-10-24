import base64
import unittest

from mokosh_v2_crypto import (
    DEK_LEN,
    FrameAuthenticationError,
    V2CryptoError,
    V2FrameDecryptor,
    V2FrameEncryptor,
    generate_dek,
)
from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    FRAME_HEADER_LEN,
    FrameSequenceError,
    TruncatedDataError,
    V2FormatError,
    build_envelope_prefix,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_prefix(*, nonce_prefix: bytes = bytes(range(8)), writer="MOKOSH Agent"):
    return build_envelope_prefix(
        {
            "format": "MOKOSH",
            "version": 2,
            "file_id": b64url(bytes(range(16))),
            "content_aead": "AES-256-GCM-CHUNKED",
            "nonce_prefix": b64url(nonce_prefix),
            "chunk_size": DEFAULT_CHUNK_SIZE,
            "key_slots": [],
            "created_utc": "2026-08-06T20:00:00Z",
            "writer": writer,
        }
    )


class KeyAndContextTests(unittest.TestCase):
    def test_generated_dek_is_256_bits(self):
        self.assertEqual(len(generate_dek()), DEK_LEN)

    def test_invalid_dek_length_or_type_is_rejected(self):
        for invalid in (b"short", b"L" * 31, b"L" * 33, "not-bytes"):
            with self.subTest(invalid=invalid), self.assertRaises(V2CryptoError):
                V2FrameEncryptor(invalid, valid_prefix())

    def test_context_rejects_prefix_with_remainder(self):
        with self.assertRaises(V2FormatError):
            V2FrameEncryptor(generate_dek(), valid_prefix() + b"extra")

    def test_context_rejects_truncated_prefix(self):
        with self.assertRaises(TruncatedDataError):
            V2FrameEncryptor(generate_dek(), valid_prefix()[:-1])


class FrameCryptoTests(unittest.TestCase):
    def setUp(self):
        self.dek = bytes(range(DEK_LEN))
        self.prefix = valid_prefix()

    def test_three_frame_roundtrip_and_finalization(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        encoded = [
            encryptor.encrypt_frame(b"manifest"),
            encryptor.encrypt_frame(b"first data"),
            encryptor.encrypt_frame(b"last data", final=True),
        ]
        encryptor.finish()

        decryptor = V2FrameDecryptor(self.dek, self.prefix)
        decoded = [decryptor.decrypt_frame(frame) for frame in encoded]
        decryptor.finish()
        self.assertEqual(
            [frame.plaintext for frame in decoded],
            [b"manifest", b"first data", b"last data"],
        )
        self.assertEqual([frame.header.index for frame in decoded], [0, 1, 2])
        self.assertTrue(decoded[-1].header.is_final)

    def test_empty_final_frame_roundtrip(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"", final=True
        )
        decrypted = V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted)
        self.assertEqual(decrypted.plaintext, b"")

    def test_exact_chunk_boundary_roundtrip(self):
        plaintext = b"A" * DEFAULT_CHUNK_SIZE
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            plaintext, final=True
        )
        decrypted = V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted)
        self.assertEqual(decrypted.plaintext, plaintext)

    def test_oversized_plaintext_is_rejected(self):
        with self.assertRaises(V2FormatError):
            V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
                b"A" * (DEFAULT_CHUNK_SIZE + 1), final=True
            )

    def test_wrong_key_is_rejected(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        with self.assertRaises(FrameAuthenticationError):
            V2FrameDecryptor(b"W" * DEK_LEN, self.prefix).decrypt_frame(encrypted)

    def test_modified_ciphertext_or_tag_is_rejected(self):
        encrypted = bytearray(
            V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
                b"secret", final=True
            )
        )
        encrypted[-1] ^= 1
        with self.assertRaises(FrameAuthenticationError):
            V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted)

    def test_changed_valid_header_prefix_is_rejected(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        changed_prefix = valid_prefix(writer="Different writer")
        with self.assertRaises(FrameAuthenticationError):
            V2FrameDecryptor(self.dek, changed_prefix).decrypt_frame(encrypted)

    def test_changed_nonce_prefix_is_rejected(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        changed_prefix = valid_prefix(nonce_prefix=b"Z" * 8)
        with self.assertRaises(FrameAuthenticationError):
            V2FrameDecryptor(self.dek, changed_prefix).decrypt_frame(encrypted)

    def test_changed_final_flag_is_rejected_by_authentication(self):
        encrypted = bytearray(
            V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
                b"secret", final=True
            )
        )
        encrypted[8] = 0
        with self.assertRaises(FrameAuthenticationError):
            V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted)

    def test_authentication_failure_does_not_advance_decryptor(self):
        valid = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        damaged = bytearray(valid)
        damaged[-1] ^= 1
        decryptor = V2FrameDecryptor(self.dek, self.prefix)
        with self.assertRaises(FrameAuthenticationError):
            decryptor.decrypt_frame(damaged)
        self.assertEqual(decryptor.next_index, 0)
        self.assertEqual(decryptor.decrypt_frame(valid).plaintext, b"secret")

    def test_decrypt_frame_rejects_appended_remainder(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        with self.assertRaises(V2FormatError):
            V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted + b"x")

    def test_truncated_tag_is_rejected_before_plaintext(self):
        encrypted = V2FrameEncryptor(self.dek, self.prefix).encrypt_frame(
            b"secret", final=True
        )
        with self.assertRaises(TruncatedDataError):
            V2FrameDecryptor(self.dek, self.prefix).decrypt_frame(encrypted[:-1])

    def test_encryptor_rejects_frame_after_final(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        encryptor.encrypt_frame(b"done", final=True)
        with self.assertRaises(FrameSequenceError):
            encryptor.encrypt_frame(b"extra", final=True)

    def test_finish_rejects_missing_final(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        encryptor.encrypt_frame(b"not final")
        with self.assertRaises(FrameSequenceError):
            encryptor.finish()

    def test_reordered_frame_is_rejected(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        first = encryptor.encrypt_frame(b"first")
        second = encryptor.encrypt_frame(b"second", final=True)
        decryptor = V2FrameDecryptor(self.dek, self.prefix)
        with self.assertRaises(FrameSequenceError):
            decryptor.decrypt_frame(second)
        self.assertEqual(decryptor.decrypt_frame(first).plaintext, b"first")

    def test_equal_plaintexts_at_different_indexes_encrypt_differently(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        first = encryptor.encrypt_frame(b"same")
        second = encryptor.encrypt_frame(b"same", final=True)
        self.assertNotEqual(first[FRAME_HEADER_LEN:], second[FRAME_HEADER_LEN:])

    def test_plaintext_and_final_types_are_strict(self):
        encryptor = V2FrameEncryptor(self.dek, self.prefix)
        with self.assertRaises(V2CryptoError):
            encryptor.encrypt_frame("not-bytes", final=True)
        with self.assertRaises(V2CryptoError):
            encryptor.encrypt_frame(b"bytes", final=1)


if __name__ == "__main__":
    unittest.main()
