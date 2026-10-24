import base64
import hashlib
import unittest

from mokosh_v2_crypto import V2FrameEncryptor
from mokosh_v2_format import (
    MIN_CHUNK_SIZE,
    MAX_FRAME_INDEX,
    FormatLimitError,
    FrameHeader,
    FrameSequenceError,
    FrameSequenceValidator,
    TruncatedDataError,
    UnknownFlagsError,
    UnsupportedVersionError,
    V2FormatError,
    build_envelope_prefix,
    build_frame,
    parse_envelope_prefix,
    parse_frame,
)
from mokosh_v2_trailer import (
    ED25519_FINGERPRINT_LEN,
    ED25519_SIGNATURE_LEN,
    SIGNATURE_ED25519,
    TRAILER_FIXED_LEN,
    TRANSCRIPT_DOMAIN,
    Trailer,
    TrailerError,
    TranscriptInfo,
    TranscriptMismatchError,
    build_ed25519_signing_bytes,
    build_ed25519_trailer,
    build_unsigned_trailer,
    parse_trailer,
    scan_ciphertext_transcript,
    validate_trailer,
    validate_trailer_against_transcript,
)


DEK = bytes(range(32))
DIGEST = bytes(range(32))
FINGERPRINT = b"F" * ED25519_FINGERPRINT_LEN
SIGNATURE = b"S" * ED25519_SIGNATURE_LEN


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_prefix() -> bytes:
    return build_envelope_prefix(
        {
            "format": "MOKOSH",
            "version": 2,
            "file_id": b64url(bytes(range(16))),
            "content_aead": "AES-256-GCM-CHUNKED",
            "nonce_prefix": b64url(bytes(range(8))),
            "chunk_size": MIN_CHUNK_SIZE,
            "key_slots": [],
            "created_utc": "2026-08-07T17:00:00Z",
            "writer": "MOKOSH Agent",
        },
        chunk_size=MIN_CHUNK_SIZE,
    )


PREFIX = valid_prefix()


def valid_transcript() -> bytes:
    encryptor = V2FrameEncryptor(DEK, PREFIX)
    return (
        PREFIX
        + encryptor.encrypt_frame(b"manifest")
        + encryptor.encrypt_frame(b"data-1")
        + encryptor.encrypt_frame(b"data-2", final=True)
    )


def split_frames(transcript: bytes):
    prefix, remaining = parse_envelope_prefix(transcript)
    prefix_len = len(transcript) - len(remaining)
    frames = []
    while remaining:
        _, after = parse_frame(remaining, chunk_size=prefix.preamble.chunk_size)
        frame_len = len(remaining) - len(after)
        frames.append(remaining[:frame_len])
        remaining = after
    return transcript[:prefix_len], frames


class TrailerCodecTests(unittest.TestCase):
    def test_fixed_trailer_size_is_56_bytes(self):
        self.assertEqual(TRAILER_FIXED_LEN, 56)

    def test_unsigned_trailer_roundtrip(self):
        trailer = build_unsigned_trailer(
            frame_count=3,
            transcript_sha256=DIGEST,
        )
        encoded = trailer.to_bytes()
        self.assertEqual(len(encoded), TRAILER_FIXED_LEN)
        self.assertEqual(parse_trailer(encoded), trailer)
        self.assertFalse(trailer.is_signed)

    def test_ed25519_trailer_roundtrip(self):
        trailer = build_ed25519_trailer(
            frame_count=3,
            transcript_sha256=DIGEST,
            signer_key_version=7,
            signer_fingerprint=FINGERPRINT,
            signature=SIGNATURE,
        )
        encoded = trailer.to_bytes()
        self.assertEqual(
            len(encoded),
            TRAILER_FIXED_LEN + ED25519_FINGERPRINT_LEN + ED25519_SIGNATURE_LEN,
        )
        self.assertEqual(parse_trailer(encoded), trailer)
        self.assertTrue(trailer.is_signed)

    def test_signing_bytes_are_deterministic_and_exclude_signature(self):
        trailer = build_ed25519_trailer(
            frame_count=3,
            transcript_sha256=DIGEST,
            signer_key_version=7,
            signer_fingerprint=FINGERPRINT,
            signature=SIGNATURE,
        )
        expected = build_ed25519_signing_bytes(
            frame_count=3,
            transcript_sha256=DIGEST,
            signer_key_version=7,
            signer_fingerprint=FINGERPRINT,
        )
        self.assertEqual(trailer.signing_bytes(), expected)
        self.assertFalse(expected.endswith(SIGNATURE))

    def test_unsigned_trailer_has_no_signing_input(self):
        trailer = build_unsigned_trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
        )
        with self.assertRaises(TrailerError):
            trailer.signing_bytes()

    def test_invalid_magic_is_rejected(self):
        encoded = bytearray(
            build_unsigned_trailer(
                frame_count=1,
                transcript_sha256=DIGEST,
            ).to_bytes()
        )
        encoded[0] ^= 1
        with self.assertRaises(TrailerError):
            parse_trailer(encoded)

    def test_truncated_fixed_or_variable_trailer_is_rejected(self):
        with self.assertRaises(TruncatedDataError):
            parse_trailer(b"x" * (TRAILER_FIXED_LEN - 1))
        signed = build_ed25519_trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
            signer_key_version=1,
            signer_fingerprint=FINGERPRINT,
            signature=SIGNATURE,
        ).to_bytes()
        with self.assertRaises(TruncatedDataError):
            parse_trailer(signed[:-1])

    def test_undeclared_trailing_bytes_are_rejected(self):
        encoded = build_unsigned_trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
        ).to_bytes()
        with self.assertRaises(TrailerError):
            parse_trailer(encoded + b"extra")

    def test_unsupported_version_is_rejected(self):
        encoded = bytearray(
            build_unsigned_trailer(
                frame_count=1,
                transcript_sha256=DIGEST,
            ).to_bytes()
        )
        encoded[8] = 3
        with self.assertRaises(UnsupportedVersionError):
            parse_trailer(encoded)

    def test_unknown_flags_are_rejected(self):
        encoded = bytearray(
            build_unsigned_trailer(
                frame_count=1,
                transcript_sha256=DIGEST,
            ).to_bytes()
        )
        encoded[10:12] = (1).to_bytes(2, "big")
        with self.assertRaises(UnknownFlagsError):
            parse_trailer(encoded)

    def test_zero_or_boolean_frame_count_is_rejected(self):
        for count in (0, True):
            with self.subTest(count=count), self.assertRaises(V2FormatError):
                build_unsigned_trailer(
                    frame_count=count,
                    transcript_sha256=DIGEST,
                )

    def test_digest_length_is_exact(self):
        with self.assertRaises(TrailerError):
            build_unsigned_trailer(
                frame_count=1,
                transcript_sha256=b"short",
            )

    def test_unsigned_mixed_signature_fields_are_rejected(self):
        trailer = Trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
            signer_key_version=1,
        )
        with self.assertRaises(TrailerError):
            validate_trailer(trailer)

    def test_unknown_signature_algorithm_is_rejected(self):
        trailer = Trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
            signature_algorithm=99,
        )
        with self.assertRaises(TrailerError):
            validate_trailer(trailer)

    def test_signed_key_version_fingerprint_and_signature_are_strict(self):
        invalid_values = (
            {"signer_key_version": 0},
            {"signer_fingerprint": b"short"},
            {"signature": b"short"},
        )
        defaults = {
            "signer_key_version": 1,
            "signer_fingerprint": FINGERPRINT,
            "signature": SIGNATURE,
        }
        for update in invalid_values:
            values = defaults | update
            with self.subTest(update=update), self.assertRaises(TrailerError):
                build_ed25519_trailer(
                    frame_count=1,
                    transcript_sha256=DIGEST,
                    **values,
                )

    def test_declared_oversized_signature_is_rejected_before_slicing(self):
        encoded = bytearray(
            build_unsigned_trailer(
                frame_count=1,
                transcript_sha256=DIGEST,
            ).to_bytes()
        )
        encoded[54:56] = (129).to_bytes(2, "big")
        with self.assertRaises(FormatLimitError):
            parse_trailer(encoded)


class TranscriptTests(unittest.TestCase):
    def test_valid_transcript_count_and_domain_separated_digest(self):
        transcript = valid_transcript()
        info = scan_ciphertext_transcript(transcript)
        self.assertEqual(info.frame_count, 3)
        self.assertEqual(info.transcript_len, len(transcript))
        self.assertEqual(
            info.digest,
            hashlib.sha256(TRANSCRIPT_DOMAIN + transcript).digest(),
        )

    def test_ciphertext_tamper_changes_transcript_digest(self):
        transcript = valid_transcript()
        prefix, frames = split_frames(transcript)
        changed = bytearray(frames[1])
        changed[-1] ^= 1
        changed_transcript = prefix + frames[0] + bytes(changed) + frames[2]
        self.assertNotEqual(
            scan_ciphertext_transcript(transcript).digest,
            scan_ciphertext_transcript(changed_transcript).digest,
        )

    def test_missing_final_is_rejected(self):
        encryptor = V2FrameEncryptor(DEK, PREFIX)
        transcript = PREFIX + encryptor.encrypt_frame(b"manifest")
        with self.assertRaises(FrameSequenceError):
            scan_ciphertext_transcript(transcript)

    def test_bytes_after_final_are_rejected(self):
        with self.assertRaises(TrailerError):
            scan_ciphertext_transcript(valid_transcript() + b"extra")

    def test_reordered_or_duplicate_frame_is_rejected(self):
        prefix, frames = split_frames(valid_transcript())
        for bad in (
            prefix + frames[0] + frames[2] + frames[1],
            prefix + frames[0] + frames[1] + frames[1],
        ):
            with self.subTest(), self.assertRaises(FrameSequenceError):
                scan_ciphertext_transcript(bad)

    def test_uint32_maximum_frame_index_remains_supported(self):
        self.assertEqual(MAX_FRAME_INDEX, 0xFFFFFFFF)
        validator = FrameSequenceValidator(next_index=MAX_FRAME_INDEX)
        validator.accept(FrameHeader(MAX_FRAME_INDEX, 0, 1))
        validator.finish()
        with self.assertRaises(FormatLimitError):
            build_frame(
                index=MAX_FRAME_INDEX + 1,
                plaintext_len=0,
                flags=1,
                ciphertext_and_tag=b"T" * 16,
            )


class TrailerTranscriptValidationTests(unittest.TestCase):
    def test_matching_unsigned_trailer_is_accepted(self):
        info = scan_ciphertext_transcript(valid_transcript())
        trailer = build_unsigned_trailer(
            frame_count=info.frame_count,
            transcript_sha256=info.digest,
        )
        validate_trailer_against_transcript(trailer, info)

    def test_frame_count_mismatch_is_rejected(self):
        info = scan_ciphertext_transcript(valid_transcript())
        trailer = build_unsigned_trailer(
            frame_count=info.frame_count + 1,
            transcript_sha256=info.digest,
        )
        with self.assertRaises(TranscriptMismatchError):
            validate_trailer_against_transcript(trailer, info)

    def test_digest_mismatch_is_rejected(self):
        info = scan_ciphertext_transcript(valid_transcript())
        trailer = build_unsigned_trailer(
            frame_count=info.frame_count,
            transcript_sha256=b"W" * 32,
        )
        with self.assertRaises(TranscriptMismatchError):
            validate_trailer_against_transcript(trailer, info)

    def test_transcript_info_type_is_strict(self):
        trailer = build_unsigned_trailer(
            frame_count=1,
            transcript_sha256=DIGEST,
        )
        with self.assertRaises(TrailerError):
            validate_trailer_against_transcript(trailer, (1, DIGEST))


if __name__ == "__main__":
    unittest.main()
