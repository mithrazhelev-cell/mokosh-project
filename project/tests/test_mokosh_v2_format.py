import base64
import json
import unittest

from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    MAGIC,
    MAJOR_VERSION,
    MAX_HEADER_LEN,
    MAX_KEY_SLOTS,
    MIN_CHUNK_SIZE,
    PREAMBLE_LEN,
    DuplicateHeaderKeyError,
    FormatLimitError,
    TruncatedDataError,
    UnknownFlagsError,
    UnsupportedVersionError,
    V2FormatError,
    build_envelope_prefix,
    build_preamble,
    encode_header,
    parse_envelope_prefix,
    parse_header_bytes,
    parse_preamble,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_header(**updates):
    header = {
        "format": "MOKOSH",
        "version": 2,
        "file_id": b64url(bytes(range(16))),
        "content_aead": "AES-256-GCM-CHUNKED",
        "nonce_prefix": b64url(bytes(range(8))),
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "key_slots": [],
        "created_utc": "2026-08-06T18:00:00Z",
        "writer": "MOKOSH Agent",
    }
    header.update(updates)
    return header


class PreambleTests(unittest.TestCase):
    def test_preamble_roundtrip(self):
        encoded = build_preamble(123, DEFAULT_CHUNK_SIZE)
        self.assertEqual(len(encoded), PREAMBLE_LEN)
        parsed = parse_preamble(encoded)
        self.assertEqual(parsed.major, 2)
        self.assertEqual(parsed.minor, 0)
        self.assertEqual(parsed.flags, 0)
        self.assertEqual(parsed.header_len, 123)
        self.assertEqual(parsed.chunk_size, DEFAULT_CHUNK_SIZE)

    def test_truncated_preamble_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            parse_preamble(MAGIC)

    def test_invalid_magic_is_rejected(self):
        data = bytearray(build_preamble(10))
        data[0] ^= 1
        with self.assertRaises(V2FormatError):
            parse_preamble(data)

    def test_unsupported_major_is_rejected(self):
        data = bytearray(build_preamble(10))
        data[8] = MAJOR_VERSION + 1
        with self.assertRaises(UnsupportedVersionError):
            parse_preamble(data)

    def test_unsupported_minor_is_rejected(self):
        data = bytearray(build_preamble(10))
        data[9] = 1
        with self.assertRaises(UnsupportedVersionError):
            parse_preamble(data)

    def test_unknown_flags_are_rejected(self):
        data = bytearray(build_preamble(10))
        data[10:12] = (1).to_bytes(2, "big")
        with self.assertRaises(UnknownFlagsError):
            parse_preamble(data)

    def test_header_length_limits_are_enforced(self):
        with self.assertRaises(FormatLimitError):
            build_preamble(0)
        with self.assertRaises(FormatLimitError):
            build_preamble(MAX_HEADER_LEN + 1)

    def test_chunk_size_limits_are_enforced(self):
        with self.assertRaises(FormatLimitError):
            build_preamble(10, MIN_CHUNK_SIZE - 1)


class HeaderTests(unittest.TestCase):
    def test_header_encoding_is_deterministic(self):
        first = encode_header(valid_header(), chunk_size=DEFAULT_CHUNK_SIZE)
        second = encode_header(
            dict(reversed(list(valid_header().items()))),
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self.assertEqual(first, second)

    def test_duplicate_json_keys_are_rejected(self):
        raw = encode_header(valid_header(), chunk_size=DEFAULT_CHUNK_SIZE)
        parsed = json.loads(raw)
        pairs = list(parsed.items())
        duplicate = "{" + ",".join(
            [json.dumps(key) + ":" + json.dumps(value) for key, value in pairs]
            + ['"writer":"duplicate"']
        ) + "}"
        with self.assertRaises(DuplicateHeaderKeyError):
            parse_header_bytes(duplicate.encode(), chunk_size=DEFAULT_CHUNK_SIZE)

    def test_missing_required_field_is_rejected(self):
        header = valid_header()
        del header["file_id"]
        with self.assertRaises(V2FormatError):
            encode_header(header, chunk_size=DEFAULT_CHUNK_SIZE)

    def test_exact_binary_identifier_lengths_are_enforced(self):
        with self.assertRaises(V2FormatError):
            encode_header(
                valid_header(file_id=b64url(b"too-short")),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )
        with self.assertRaises(V2FormatError):
            encode_header(
                valid_header(nonce_prefix=b64url(b"short")),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_key_slot_limit_is_enforced(self):
        with self.assertRaises(FormatLimitError):
            encode_header(
                valid_header(key_slots=[{}] * (MAX_KEY_SLOTS + 1)),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_header_api_enforces_chunk_size_range(self):
        with self.assertRaises(FormatLimitError):
            encode_header(
                valid_header(chunk_size=1),
                chunk_size=1,
            )

    def test_non_standard_json_constants_are_rejected(self):
        raw = json.dumps(valid_header(), separators=(",", ":"))
        raw = raw[:-1] + ',"forbidden":NaN}'
        with self.assertRaises(V2FormatError):
            parse_header_bytes(raw.encode(), chunk_size=DEFAULT_CHUNK_SIZE)

    def test_created_utc_must_be_strict_utc(self):
        with self.assertRaises(V2FormatError):
            encode_header(
                valid_header(created_utc="2026-08-06 18:00:00"),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )


class EnvelopePrefixTests(unittest.TestCase):
    def test_prefix_roundtrip_preserves_exact_header_and_remainder(self):
        header = valid_header()
        encoded = build_envelope_prefix(header) + b"future-frame-bytes"
        prefix, remainder = parse_envelope_prefix(encoded)
        self.assertEqual(prefix.header, header)
        self.assertEqual(prefix.preamble.chunk_size, DEFAULT_CHUNK_SIZE)
        self.assertEqual(remainder, b"future-frame-bytes")

    def test_truncated_declared_header_is_rejected(self):
        header = encode_header(valid_header(), chunk_size=DEFAULT_CHUNK_SIZE)
        data = build_preamble(len(header)) + header[:-1]
        with self.assertRaises(TruncatedDataError):
            parse_envelope_prefix(data)

    def test_header_and_preamble_chunk_size_must_match(self):
        header = encode_header(valid_header(), chunk_size=DEFAULT_CHUNK_SIZE)
        data = build_preamble(len(header), MIN_CHUNK_SIZE) + header
        with self.assertRaises(V2FormatError):
            parse_envelope_prefix(data)


if __name__ == "__main__":
    unittest.main()
