import base64
import hashlib
import struct
import unittest

from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    FRAME_AAD_DOMAIN,
    FRAME_FLAG_FINAL,
    FRAME_NONCE_LEN,
    MAX_FRAME_INDEX,
    NONCE_PREFIX_LEN,
    PREFIX_DIGEST_LEN,
    FormatLimitError,
    FrameHeader,
    TruncatedDataError,
    UnknownFlagsError,
    V2FormatError,
    build_envelope_prefix,
    build_frame_aad,
    build_frame_aad_from_prefix,
    derive_frame_nonce,
    hash_envelope_prefix,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_prefix(**updates) -> bytes:
    header = {
        "format": "MOKOSH",
        "version": 2,
        "file_id": b64url(bytes(range(16))),
        "content_aead": "AES-256-GCM-CHUNKED",
        "nonce_prefix": b64url(bytes(range(NONCE_PREFIX_LEN))),
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "key_slots": [],
        "created_utc": "2026-08-06T19:00:00Z",
        "writer": "MOKOSH Agent",
    }
    header.update(updates)
    return build_envelope_prefix(header)


class FrameNonceTests(unittest.TestCase):
    def test_nonce_is_prefix_plus_big_endian_index(self):
        prefix = bytes.fromhex("0011223344556677")
        nonce = derive_frame_nonce(prefix, 0x01020304)
        self.assertEqual(nonce, prefix + b"\x01\x02\x03\x04")
        self.assertEqual(len(nonce), FRAME_NONCE_LEN)

    def test_maximum_frame_index_is_supported(self):
        prefix = b"N" * NONCE_PREFIX_LEN
        self.assertEqual(
            derive_frame_nonce(prefix, MAX_FRAME_INDEX),
            prefix + b"\xff\xff\xff\xff",
        )

    def test_distinct_indexes_produce_distinct_nonces(self):
        prefix = b"N" * NONCE_PREFIX_LEN
        nonces = {derive_frame_nonce(prefix, index) for index in range(1000)}
        self.assertEqual(len(nonces), 1000)

    def test_nonce_prefix_length_is_exact(self):
        for size in (NONCE_PREFIX_LEN - 1, NONCE_PREFIX_LEN + 1):
            with self.subTest(size=size), self.assertRaises(V2FormatError):
                derive_frame_nonce(b"N" * size, 0)

    def test_invalid_frame_index_is_rejected(self):
        for invalid in (-1, MAX_FRAME_INDEX + 1):
            with self.subTest(invalid=invalid), self.assertRaises(FormatLimitError):
                derive_frame_nonce(b"N" * NONCE_PREFIX_LEN, invalid)
        with self.assertRaises(V2FormatError):
            derive_frame_nonce(b"N" * NONCE_PREFIX_LEN, True)


class PrefixDigestTests(unittest.TestCase):
    def test_digest_is_sha256_of_exact_prefix_bytes(self):
        prefix = valid_prefix()
        digest = hash_envelope_prefix(prefix)
        self.assertEqual(digest, hashlib.sha256(prefix).digest())
        self.assertEqual(len(digest), PREFIX_DIGEST_LEN)

    def test_frame_or_trailer_remainder_is_rejected(self):
        with self.assertRaises(V2FormatError):
            hash_envelope_prefix(valid_prefix() + b"not-prefix")

    def test_one_byte_header_change_changes_digest(self):
        first = valid_prefix(writer="MOKOSH Agent")
        second = valid_prefix(writer="MOKOSH Agent 2")
        self.assertNotEqual(hash_envelope_prefix(first), hash_envelope_prefix(second))

    def test_truncated_prefix_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            hash_envelope_prefix(valid_prefix()[:-1])


class FrameAADTests(unittest.TestCase):
    def test_aad_has_domain_digest_and_exact_frame_header(self):
        digest = bytes(range(PREFIX_DIGEST_LEN))
        header = FrameHeader(7, 1234, FRAME_FLAG_FINAL)
        aad = build_frame_aad(digest, header)
        expected = FRAME_AAD_DOMAIN + digest + struct.pack(">IIB", 7, 1234, 1)
        self.assertEqual(aad, expected)

    def test_aad_is_deterministic(self):
        digest = b"D" * PREFIX_DIGEST_LEN
        header = FrameHeader(4, 99, 0)
        self.assertEqual(build_frame_aad(digest, header), build_frame_aad(digest, header))

    def test_each_frame_header_field_changes_aad(self):
        digest = b"D" * PREFIX_DIGEST_LEN
        baseline = build_frame_aad(digest, FrameHeader(1, 10, 0))
        variants = (
            FrameHeader(2, 10, 0),
            FrameHeader(1, 11, 0),
            FrameHeader(1, 10, FRAME_FLAG_FINAL),
        )
        for header in variants:
            with self.subTest(header=header):
                self.assertNotEqual(build_frame_aad(digest, header), baseline)

    def test_prefix_digest_length_is_exact(self):
        header = FrameHeader(0, 0, FRAME_FLAG_FINAL)
        for size in (PREFIX_DIGEST_LEN - 1, PREFIX_DIGEST_LEN + 1):
            with self.subTest(size=size), self.assertRaises(V2FormatError):
                build_frame_aad(b"D" * size, header)

    def test_non_bytes_digest_is_rejected(self):
        with self.assertRaises(V2FormatError):
            build_frame_aad("not-bytes", FrameHeader(0, 0, FRAME_FLAG_FINAL))

    def test_frame_header_object_is_required(self):
        with self.assertRaises(V2FormatError):
            build_frame_aad(b"D" * PREFIX_DIGEST_LEN, (0, 0, 1))

    def test_invalid_frame_header_is_rejected(self):
        with self.assertRaises(UnknownFlagsError):
            build_frame_aad(
                b"D" * PREFIX_DIGEST_LEN,
                FrameHeader(0, 0, 0x02),
            )

    def test_aad_from_prefix_matches_two_step_api(self):
        prefix = valid_prefix()
        header = FrameHeader(9, 42, 0)
        self.assertEqual(
            build_frame_aad_from_prefix(prefix, header),
            build_frame_aad(hash_envelope_prefix(prefix), header),
        )


if __name__ == "__main__":
    unittest.main()
