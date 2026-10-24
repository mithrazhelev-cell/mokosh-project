import base64
import hashlib
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mokosh_v2_crypto import V2FrameEncryptor
from mokosh_v2_format import MIN_CHUNK_SIZE, V2FormatError, build_envelope_prefix
from mokosh_v2_signatures import (
    ED25519_PUBLIC_KEY_LEN,
    SIGNER_FINGERPRINT_DOMAIN,
    InvalidTrailerSignatureError,
    SignerFingerprintMismatchError,
    UnsignedTrailerError,
    V2SignatureError,
    derive_ed25519_fingerprint,
    ed25519_public_key_bytes,
    load_ed25519_public_key,
    sign_ciphertext_transcript,
    verify_ciphertext_transcript_signature,
)
from mokosh_v2_trailer import (
    TranscriptMismatchError,
    build_unsigned_trailer,
    parse_trailer,
    scan_ciphertext_transcript,
)


DEK = bytes(range(32))
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_prefix(*, file_id_byte: int = 0) -> bytes:
    return build_envelope_prefix(
        {
            "format": "MOKOSH",
            "version": 2,
            "file_id": b64url(bytes([file_id_byte]) * 16),
            "content_aead": "AES-256-GCM-CHUNKED",
            "nonce_prefix": b64url(bytes(range(8))),
            "chunk_size": MIN_CHUNK_SIZE,
            "key_slots": [],
            "created_utc": "2026-08-08T10:00:00Z",
            "writer": "MOKOSH Agent",
        },
        chunk_size=MIN_CHUNK_SIZE,
    )


def valid_transcript(*, file_id_byte: int = 0, payload: bytes = b"data") -> bytes:
    prefix = valid_prefix(file_id_byte=file_id_byte)
    encryptor = V2FrameEncryptor(DEK, prefix)
    return (
        prefix
        + encryptor.encrypt_frame(b"manifest")
        + encryptor.encrypt_frame(payload, final=True)
    )


class PublicKeyAndFingerprintTests(unittest.TestCase):
    def test_raw_public_key_roundtrip(self):
        public_key = PRIVATE_KEY.public_key()
        encoded = ed25519_public_key_bytes(public_key)
        self.assertEqual(len(encoded), ED25519_PUBLIC_KEY_LEN)
        self.assertEqual(
            ed25519_public_key_bytes(load_ed25519_public_key(encoded)),
            encoded,
        )

    def test_public_key_type_and_encoded_length_are_strict(self):
        with self.assertRaises(V2SignatureError):
            ed25519_public_key_bytes(b"not-an-object")
        for invalid in (b"short", b"x" * 33, "not-bytes"):
            with self.subTest(invalid=invalid), self.assertRaises(V2SignatureError):
                load_ed25519_public_key(invalid)

    def test_fingerprint_is_domain_separated_sha256(self):
        public_key = PRIVATE_KEY.public_key()
        raw = ed25519_public_key_bytes(public_key)
        self.assertEqual(
            derive_ed25519_fingerprint(public_key),
            hashlib.sha256(SIGNER_FINGERPRINT_DOMAIN + raw).digest(),
        )

    def test_distinct_public_keys_have_distinct_fingerprints(self):
        self.assertNotEqual(
            derive_ed25519_fingerprint(PRIVATE_KEY.public_key()),
            derive_ed25519_fingerprint(OTHER_PRIVATE_KEY.public_key()),
        )


class SigningTests(unittest.TestCase):
    def test_signing_builds_parseable_bound_trailer(self):
        transcript_bytes = valid_transcript()
        transcript = scan_ciphertext_transcript(transcript_bytes)
        trailer = sign_ciphertext_transcript(
            transcript_bytes,
            private_key=PRIVATE_KEY,
            signer_key_version=7,
        )
        self.assertTrue(trailer.is_signed)
        self.assertEqual(trailer.frame_count, transcript.frame_count)
        self.assertEqual(trailer.transcript_sha256, transcript.digest)
        self.assertEqual(trailer.signer_key_version, 7)
        self.assertEqual(
            trailer.signer_fingerprint,
            derive_ed25519_fingerprint(PRIVATE_KEY.public_key()),
        )
        self.assertEqual(parse_trailer(trailer.to_bytes()), trailer)

    def test_ed25519_signing_is_deterministic_for_same_input(self):
        transcript = valid_transcript()
        first = sign_ciphertext_transcript(
            transcript,
            private_key=PRIVATE_KEY,
            signer_key_version=1,
        )
        second = sign_ciphertext_transcript(
            transcript,
            private_key=PRIVATE_KEY,
            signer_key_version=1,
        )
        self.assertEqual(first, second)

    def test_key_version_is_cryptographically_bound(self):
        transcript = valid_transcript()
        first = sign_ciphertext_transcript(
            transcript,
            private_key=PRIVATE_KEY,
            signer_key_version=1,
        )
        second = sign_ciphertext_transcript(
            transcript,
            private_key=PRIVATE_KEY,
            signer_key_version=2,
        )
        self.assertNotEqual(first.signature, second.signature)

    def test_private_key_type_is_strict(self):
        with self.assertRaises(V2SignatureError):
            sign_ciphertext_transcript(
                valid_transcript(),
                private_key=b"not-a-private-key",
                signer_key_version=1,
            )

    def test_key_version_is_strict(self):
        for invalid in (0, -1, True):
            with self.subTest(invalid=invalid), self.assertRaises(V2FormatError):
                sign_ciphertext_transcript(
                    valid_transcript(),
                    private_key=PRIVATE_KEY,
                    signer_key_version=invalid,
                )

    def test_malformed_transcript_is_rejected_before_signing(self):
        with self.assertRaises(V2FormatError):
            sign_ciphertext_transcript(
                b"not-a-v2-transcript",
                private_key=PRIVATE_KEY,
                signer_key_version=1,
            )


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.transcript = valid_transcript()
        self.trailer = sign_ciphertext_transcript(
            self.transcript,
            private_key=PRIVATE_KEY,
            signer_key_version=9,
        )

    def test_valid_signature_returns_identity_without_trust_decision(self):
        result = verify_ciphertext_transcript_signature(
            self.trailer,
            self.transcript,
            public_key=PRIVATE_KEY.public_key(),
        )
        self.assertEqual(result.signer_key_version, 9)
        self.assertEqual(
            result.signer_fingerprint,
            derive_ed25519_fingerprint(PRIVATE_KEY.public_key()),
        )
        self.assertEqual(
            result.public_key_bytes,
            ed25519_public_key_bytes(PRIVATE_KEY.public_key()),
        )
        self.assertFalse(hasattr(result, "trusted"))

    def test_raw_public_key_bytes_are_accepted(self):
        result = verify_ciphertext_transcript_signature(
            self.trailer,
            self.transcript,
            public_key=ed25519_public_key_bytes(PRIVATE_KEY.public_key()),
        )
        self.assertEqual(result.signer_key_version, 9)

    def test_wrong_public_key_is_rejected_by_fingerprint(self):
        with self.assertRaises(SignerFingerprintMismatchError):
            verify_ciphertext_transcript_signature(
                self.trailer,
                self.transcript,
                public_key=OTHER_PRIVATE_KEY.public_key(),
            )

    def test_modified_signature_is_rejected(self):
        changed = bytearray(self.trailer.signature)
        changed[-1] ^= 1
        tampered = replace(self.trailer, signature=bytes(changed))
        with self.assertRaises(InvalidTrailerSignatureError):
            verify_ciphertext_transcript_signature(
                tampered,
                self.transcript,
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_modified_key_version_is_rejected(self):
        tampered = replace(
            self.trailer,
            signer_key_version=self.trailer.signer_key_version + 1,
        )
        with self.assertRaises(InvalidTrailerSignatureError):
            verify_ciphertext_transcript_signature(
                tampered,
                self.transcript,
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_modified_fingerprint_is_rejected(self):
        changed = bytearray(self.trailer.signer_fingerprint)
        changed[0] ^= 1
        tampered = replace(self.trailer, signer_fingerprint=bytes(changed))
        with self.assertRaises(SignerFingerprintMismatchError):
            verify_ciphertext_transcript_signature(
                tampered,
                self.transcript,
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_different_valid_transcript_is_rejected(self):
        different = valid_transcript(file_id_byte=1, payload=b"other")
        with self.assertRaises(TranscriptMismatchError):
            verify_ciphertext_transcript_signature(
                self.trailer,
                different,
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_ciphertext_tamper_is_rejected(self):
        changed = bytearray(self.transcript)
        changed[-1] ^= 1
        with self.assertRaises(TranscriptMismatchError):
            verify_ciphertext_transcript_signature(
                self.trailer,
                bytes(changed),
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_unsigned_trailer_is_rejected(self):
        transcript = scan_ciphertext_transcript(self.transcript)
        unsigned = build_unsigned_trailer(
            frame_count=transcript.frame_count,
            transcript_sha256=transcript.digest,
        )
        with self.assertRaises(UnsignedTrailerError):
            verify_ciphertext_transcript_signature(
                unsigned,
                self.transcript,
                public_key=PRIVATE_KEY.public_key(),
            )

    def test_invalid_public_key_input_is_rejected(self):
        for invalid in (b"short", "not-a-key"):
            with self.subTest(invalid=invalid), self.assertRaises(V2SignatureError):
                verify_ciphertext_transcript_signature(
                    self.trailer,
                    self.transcript,
                    public_key=invalid,
                )


if __name__ == "__main__":
    unittest.main()
