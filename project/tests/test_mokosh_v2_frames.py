import struct
import unittest

from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    FRAME_FLAG_FINAL,
    FRAME_HEADER_LEN,
    GCM_TAG_LEN,
    MAX_FRAME_INDEX,
    FormatLimitError,
    FrameHeader,
    FrameSequenceError,
    FrameSequenceValidator,
    TruncatedDataError,
    UnknownFlagsError,
    V2FormatError,
    build_frame,
    parse_frame,
)


def opaque_payload(plaintext_len: int, fill: int = 0xA5) -> bytes:
    return bytes([fill]) * (plaintext_len + GCM_TAG_LEN)


class FrameCodecTests(unittest.TestCase):
    def test_frame_roundtrip_preserves_payload_and_remainder(self):
        payload = opaque_payload(27)
        encoded = build_frame(
            index=3,
            plaintext_len=27,
            flags=FRAME_FLAG_FINAL,
            ciphertext_and_tag=payload,
        )
        frame, remainder = parse_frame(encoded + b"trailer")
        self.assertEqual(frame.header.index, 3)
        self.assertEqual(frame.header.plaintext_len, 27)
        self.assertTrue(frame.header.is_final)
        self.assertEqual(frame.ciphertext_and_tag, payload)
        self.assertEqual(remainder, b"trailer")

    def test_empty_plaintext_still_requires_full_tag(self):
        encoded = build_frame(
            index=0,
            plaintext_len=0,
            flags=FRAME_FLAG_FINAL,
            ciphertext_and_tag=b"T" * GCM_TAG_LEN,
        )
        frame, remainder = parse_frame(encoded)
        self.assertEqual(frame.header.encoded_len, FRAME_HEADER_LEN + GCM_TAG_LEN)
        self.assertEqual(remainder, b"")

    def test_exact_chunk_boundary_is_accepted(self):
        encoded = build_frame(
            index=1,
            plaintext_len=DEFAULT_CHUNK_SIZE,
            flags=0,
            ciphertext_and_tag=opaque_payload(DEFAULT_CHUNK_SIZE),
        )
        frame, remainder = parse_frame(encoded)
        self.assertEqual(frame.header.plaintext_len, DEFAULT_CHUNK_SIZE)
        self.assertEqual(remainder, b"")

    def test_truncated_frame_header_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            parse_frame(b"\x00" * (FRAME_HEADER_LEN - 1))

    def test_truncated_ciphertext_or_tag_is_rejected(self):
        encoded = build_frame(
            index=0,
            plaintext_len=8,
            flags=FRAME_FLAG_FINAL,
            ciphertext_and_tag=opaque_payload(8),
        )
        with self.assertRaises(TruncatedDataError):
            parse_frame(encoded[:-1])

    def test_declared_plaintext_over_chunk_size_is_rejected_before_payload(self):
        header = struct.pack(">IIB", 0, DEFAULT_CHUNK_SIZE + 1, 0)
        with self.assertRaises(FormatLimitError):
            parse_frame(header)

    def test_unknown_frame_flag_is_rejected(self):
        header = struct.pack(">IIB", 0, 0, 0x02)
        with self.assertRaises(UnknownFlagsError):
            parse_frame(header + b"T" * GCM_TAG_LEN)

    def test_builder_rejects_payload_length_mismatch(self):
        with self.assertRaises(V2FormatError):
            build_frame(
                index=0,
                plaintext_len=5,
                flags=FRAME_FLAG_FINAL,
                ciphertext_and_tag=b"short",
            )

    def test_frame_index_must_fit_uint32(self):
        for invalid in (-1, MAX_FRAME_INDEX + 1):
            with self.subTest(invalid=invalid), self.assertRaises(FormatLimitError):
                build_frame(
                    index=invalid,
                    plaintext_len=0,
                    flags=FRAME_FLAG_FINAL,
                    ciphertext_and_tag=b"T" * GCM_TAG_LEN,
                )

    def test_boolean_is_not_accepted_as_integer_field(self):
        with self.assertRaises(V2FormatError):
            build_frame(
                index=True,
                plaintext_len=0,
                flags=FRAME_FLAG_FINAL,
                ciphertext_and_tag=b"T" * GCM_TAG_LEN,
            )


class FrameSequenceTests(unittest.TestCase):
    def test_contiguous_sequence_with_final_is_accepted(self):
        validator = FrameSequenceValidator()
        validator.accept(FrameHeader(0, 12, 0))
        validator.accept(FrameHeader(1, 20, 0))
        validator.accept(FrameHeader(2, 7, FRAME_FLAG_FINAL))
        validator.finish()
        self.assertTrue(validator.final_seen)

    def test_duplicate_index_is_rejected(self):
        validator = FrameSequenceValidator()
        validator.accept(FrameHeader(0, 1, 0))
        with self.assertRaises(FrameSequenceError):
            validator.accept(FrameHeader(0, 1, FRAME_FLAG_FINAL))

    def test_skipped_or_reordered_index_is_rejected(self):
        validator = FrameSequenceValidator()
        validator.accept(FrameHeader(0, 1, 0))
        with self.assertRaises(FrameSequenceError):
            validator.accept(FrameHeader(2, 1, FRAME_FLAG_FINAL))

    def test_frame_after_final_is_rejected(self):
        validator = FrameSequenceValidator()
        validator.accept(FrameHeader(0, 1, FRAME_FLAG_FINAL))
        with self.assertRaises(FrameSequenceError):
            validator.accept(FrameHeader(1, 1, FRAME_FLAG_FINAL))

    def test_finish_rejects_missing_final(self):
        validator = FrameSequenceValidator()
        validator.accept(FrameHeader(0, 1, 0))
        with self.assertRaises(FrameSequenceError):
            validator.finish()

    def test_empty_sequence_is_rejected(self):
        with self.assertRaises(FrameSequenceError):
            FrameSequenceValidator().finish()

    def test_counter_exhaustion_without_final_is_rejected(self):
        validator = FrameSequenceValidator(next_index=MAX_FRAME_INDEX)
        with self.assertRaises(FrameSequenceError):
            validator.accept(FrameHeader(MAX_FRAME_INDEX, 1, 0))

    def test_final_frame_at_maximum_index_is_accepted(self):
        validator = FrameSequenceValidator(next_index=MAX_FRAME_INDEX)
        validator.accept(FrameHeader(MAX_FRAME_INDEX, 1, FRAME_FLAG_FINAL))
        validator.finish()


if __name__ == "__main__":
    unittest.main()
