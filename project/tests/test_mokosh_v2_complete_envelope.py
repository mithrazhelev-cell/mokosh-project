import inspect
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from mokosh_v2_complete_envelope import (
    CompleteEnvelopeError,
    CompleteEnvelopePolicyError,
    Ed25519EnvelopeSigning,
    RequireEd25519Envelope,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
    decrypt_complete_envelope,
    encrypt_complete_envelope,
    split_complete_envelope,
)
from mokosh_v2_format import MIN_CHUNK_SIZE, TruncatedDataError, parse_envelope_prefix
from mokosh_v2_key_slots import ContactHybridSlot
from mokosh_v2_signatures import (
    InvalidTrailerSignatureError,
    SignerFingerprintMismatchError,
)
from mokosh_v2_slot_orchestration import (
    ContactCredential,
    KeySlotPlanBuilder,
    PasswordCredential,
    SlotCredentialMismatchError,
    SlotSelectionError,
    VaultCredential,
)
from mokosh_v2_trailer import (
    TrailerError,
    TranscriptMismatchError,
    build_unsigned_trailer,
)


try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as real_mlkem
except ImportError:
    real_mlkem = None


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
VAULT_KEY = b"V" * 32
PASSWORD = "correct horse battery staple"
PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes(range(1, 33))
)
CREATED_UTC = "2026-08-09T10:00:00Z"


def vault_plan(*, include_password=False):
    builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
    password_slot = None
    if include_password:
        password_slot = builder.add_password(
            PASSWORD,
            time_cost=2,
            parallelism=1,
        )
    vault_slot = builder.add_vault(VAULT_KEY, 4)
    return builder.finish(), password_slot, vault_slot


def unsigned_vault_envelope(payload=b"important data", *, include_password=False):
    plan, password_slot, vault_slot = vault_plan(
        include_password=include_password
    )
    envelope = encrypt_complete_envelope(
        key_plan=plan,
        plaintext=payload,
        original_name="report.txt",
        content_type="text/plain",
        signing=UnsignedEnvelopeSigning(),
        chunk_size=MIN_CHUNK_SIZE,
        created_utc=CREATED_UTC,
    )
    return envelope, password_slot, vault_slot


def signed_vault_envelope(payload=b"important data"):
    plan, _, vault_slot = vault_plan()
    envelope = encrypt_complete_envelope(
        key_plan=plan,
        plaintext=payload,
        original_name="report.txt",
        signing=Ed25519EnvelopeSigning(PRIVATE_KEY, 7),
        chunk_size=MIN_CHUNK_SIZE,
        created_utc=CREATED_UTC,
    )
    return envelope, vault_slot


def fixed_contact_slot():
    return ContactHybridSlot(
        slot_id=b"C" * 16,
        recipient_key_version=8,
        ephemeral_x25519_public_key=b"E" * 32,
        mlkem_ciphertext=b"K" * 1088,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )


def fake_contact_plan():
    builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
    with patch(
        "mokosh_v2_slot_orchestration.create_contact_slot",
        return_value=fixed_contact_slot(),
    ):
        slot = builder.add_contact(b"X" * 32, b"M" * 1184, 8)
    return builder.finish(), slot


class CompleteEnvelopeConstructionTests(unittest.TestCase):
    def test_unsigned_vault_roundtrip(self):
        envelope, _, slot = unsigned_vault_envelope()
        result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireUnsignedEnvelope(),
        )
        self.assertEqual(result.plaintext, b"important data")
        self.assertEqual(result.manifest.original_name, "report.txt")
        self.assertEqual(result.manifest.content_type, "text/plain")
        self.assertIsNone(result.verified_signature)
        self.assertFalse(result.trailer.is_signed)

    def test_signed_vault_roundtrip_returns_proof_not_trust(self):
        envelope, slot = signed_vault_envelope()
        result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireEd25519Envelope(PRIVATE_KEY.public_key()),
        )
        self.assertEqual(result.plaintext, b"important data")
        self.assertEqual(result.verified_signature.signer_key_version, 7)
        self.assertFalse(hasattr(result.verified_signature, "trusted"))
        self.assertNotIn(DEK.hex(), repr(result))

    def test_password_and_vault_slots_restore_the_same_payload(self):
        envelope, password_slot, vault_slot = unsigned_vault_envelope(
            include_password=True
        )
        password_result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=password_slot.slot_id,
            credential=PasswordCredential(PASSWORD),
            verification=RequireUnsignedEnvelope(),
        )
        vault_result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=vault_slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireUnsignedEnvelope(),
        )
        self.assertEqual(password_result.plaintext, vault_result.plaintext)

    def test_empty_boundary_and_multiframe_payloads_roundtrip(self):
        for payload in (
            b"",
            b"A" * MIN_CHUNK_SIZE,
            b"B" * (MIN_CHUNK_SIZE + 1),
        ):
            with self.subTest(size=len(payload)):
                envelope, _, slot = unsigned_vault_envelope(payload)
                result = decrypt_complete_envelope(
                    envelope_bytes=envelope,
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                    verification=RequireUnsignedEnvelope(),
                )
                self.assertEqual(result.plaintext, payload)
                expected_frames = max(
                    1,
                    (len(payload) + MIN_CHUNK_SIZE - 1) // MIN_CHUNK_SIZE,
                )
                self.assertEqual(result.manifest.data_frames, expected_frames)

    def test_header_uses_exact_plan_identity_slots_and_fresh_nonce(self):
        plan, _, _ = vault_plan()
        kwargs = dict(
            key_plan=plan,
            plaintext=b"data",
            original_name="data.bin",
            signing=UnsignedEnvelopeSigning(),
            chunk_size=MIN_CHUNK_SIZE,
            created_utc=CREATED_UTC,
        )
        first = encrypt_complete_envelope(**kwargs)
        second = encrypt_complete_envelope(**kwargs)
        first_prefix, _ = parse_envelope_prefix(first)
        second_prefix, _ = parse_envelope_prefix(second)
        self.assertEqual(first_prefix.header["file_id"], "ABEiM0RVZneImaq7zN3u_w")
        self.assertEqual(first_prefix.header["key_slots"], plan.header_key_slots())
        self.assertNotEqual(
            first_prefix.header["nonce_prefix"],
            second_prefix.header["nonce_prefix"],
        )
        self.assertNotIn(DEK, first)

    def test_unfinalized_or_wrong_plan_is_rejected(self):
        for invalid in (None, object(), KeySlotPlanBuilder()):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(CompleteEnvelopePolicyError):
                    encrypt_complete_envelope(
                        key_plan=invalid,
                        plaintext=b"data",
                        original_name="x",
                        signing=UnsignedEnvelopeSigning(),
                    )

    def test_signing_mode_key_and_version_are_strict(self):
        plan, _, _ = vault_plan()
        invalid_modes = (
            None,
            "unsigned",
            Ed25519EnvelopeSigning(b"not-a-key", 1),
            Ed25519EnvelopeSigning(PRIVATE_KEY, 0),
            Ed25519EnvelopeSigning(PRIVATE_KEY, True),
        )
        for signing in invalid_modes:
            with self.subTest(signing=signing):
                with self.assertRaises(CompleteEnvelopePolicyError):
                    encrypt_complete_envelope(
                        key_plan=plan,
                        plaintext=b"data",
                        original_name="x",
                        signing=signing,
                    )

    def test_invalid_random_nonce_source_is_rejected(self):
        plan, _, _ = vault_plan()
        with patch("mokosh_v2_complete_envelope.os.urandom", return_value=b"short"):
            with self.assertRaises(CompleteEnvelopeError):
                encrypt_complete_envelope(
                    key_plan=plan,
                    plaintext=b"data",
                    original_name="x",
                    signing=UnsignedEnvelopeSigning(),
                )

    def test_contact_slot_cannot_be_encrypted_unsigned(self):
        plan, _ = fake_contact_plan()
        with self.assertRaises(CompleteEnvelopePolicyError):
            encrypt_complete_envelope(
                key_plan=plan,
                plaintext=b"contact data",
                original_name="message.txt",
                signing=UnsignedEnvelopeSigning(),
            )


class CompleteEnvelopeSplitTests(unittest.TestCase):
    def test_split_preserves_exact_transcript_and_trailer(self):
        envelope, _, _ = unsigned_vault_envelope()
        parts = split_complete_envelope(envelope)
        self.assertEqual(
            parts.ciphertext_transcript + parts.trailer.to_bytes(),
            envelope,
        )
        self.assertEqual(parts.transcript.frame_count, 2)
        self.assertEqual(parts.transcript.digest, parts.trailer.transcript_sha256)

    def test_non_bytes_and_missing_frames_are_rejected(self):
        envelope, _, _ = unsigned_vault_envelope()
        prefix, _ = parse_envelope_prefix(envelope)
        prefix_len = 20 + prefix.preamble.header_len
        with self.assertRaises(CompleteEnvelopeError):
            split_complete_envelope("not-bytes")
        with self.assertRaises(TruncatedDataError):
            split_complete_envelope(envelope[:prefix_len])

    def test_missing_or_truncated_trailer_is_rejected(self):
        envelope, _, _ = unsigned_vault_envelope()
        parts = split_complete_envelope(envelope)
        with self.assertRaises(TruncatedDataError):
            split_complete_envelope(parts.ciphertext_transcript)
        with self.assertRaises(TruncatedDataError):
            split_complete_envelope(envelope[:-1])

    def test_trailing_bytes_after_trailer_are_rejected(self):
        envelope, _, _ = unsigned_vault_envelope()
        with self.assertRaises(TrailerError):
            split_complete_envelope(envelope + b"extra")

    def test_ciphertext_tamper_is_rejected_by_transcript(self):
        envelope, _, _ = unsigned_vault_envelope()
        parts = split_complete_envelope(envelope)
        changed = bytearray(parts.ciphertext_transcript)
        changed[-1] ^= 1
        with self.assertRaises(TranscriptMismatchError):
            split_complete_envelope(bytes(changed) + parts.trailer.to_bytes())

    def test_trailer_frame_count_mismatch_is_rejected(self):
        envelope, _, _ = unsigned_vault_envelope()
        parts = split_complete_envelope(envelope)
        changed = replace(
            parts.trailer,
            frame_count=parts.trailer.frame_count + 1,
        )
        with self.assertRaises(TranscriptMismatchError):
            split_complete_envelope(
                parts.ciphertext_transcript + changed.to_bytes()
            )


class CompleteEnvelopeVerificationTests(unittest.TestCase):
    def test_signed_envelope_is_rejected_by_unsigned_policy(self):
        envelope, slot = signed_vault_envelope()
        with self.assertRaises(CompleteEnvelopePolicyError):
            decrypt_complete_envelope(
                envelope_bytes=envelope,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
                verification=RequireUnsignedEnvelope(),
            )

    def test_unsigned_envelope_is_rejected_by_signed_policy(self):
        envelope, _, slot = unsigned_vault_envelope()
        with self.assertRaises(CompleteEnvelopePolicyError):
            decrypt_complete_envelope(
                envelope_bytes=envelope,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
                verification=RequireEd25519Envelope(PRIVATE_KEY.public_key()),
            )

    def test_wrong_signer_key_is_rejected_before_slot_unwrap(self):
        envelope, slot = signed_vault_envelope()
        with patch("mokosh_v2_complete_envelope.unwrap_selected_slot") as unwrap:
            with self.assertRaises(SignerFingerprintMismatchError):
                decrypt_complete_envelope(
                    envelope_bytes=envelope,
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                    verification=RequireEd25519Envelope(
                        OTHER_PRIVATE_KEY.public_key()
                    ),
                )
        unwrap.assert_not_called()

    def test_modified_signature_is_rejected_before_slot_unwrap(self):
        envelope, slot = signed_vault_envelope()
        parts = split_complete_envelope(envelope)
        signature = bytearray(parts.trailer.signature)
        signature[-1] ^= 1
        changed = replace(parts.trailer, signature=bytes(signature))
        with patch("mokosh_v2_complete_envelope.unwrap_selected_slot") as unwrap:
            with self.assertRaises(InvalidTrailerSignatureError):
                decrypt_complete_envelope(
                    envelope_bytes=parts.ciphertext_transcript + changed.to_bytes(),
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                    verification=RequireEd25519Envelope(PRIVATE_KEY.public_key()),
                )
        unwrap.assert_not_called()

    def test_invalid_verification_object_is_rejected_before_unwrap(self):
        envelope, _, slot = unsigned_vault_envelope()
        with patch("mokosh_v2_complete_envelope.unwrap_selected_slot") as unwrap:
            with self.assertRaises(CompleteEnvelopePolicyError):
                decrypt_complete_envelope(
                    envelope_bytes=envelope,
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                    verification=None,
                )
        unwrap.assert_not_called()

    def test_missing_slot_does_not_fallback(self):
        envelope, _, _ = unsigned_vault_envelope(include_password=True)
        with self.assertRaises(SlotSelectionError):
            decrypt_complete_envelope(
                envelope_bytes=envelope,
                selected_slot_id=b"Z" * 16,
                credential=PasswordCredential(PASSWORD),
                verification=RequireUnsignedEnvelope(),
            )

    def test_wrong_credential_type_does_not_fallback(self):
        envelope, _, slot = unsigned_vault_envelope(include_password=True)
        with self.assertRaises(SlotCredentialMismatchError):
            decrypt_complete_envelope(
                envelope_bytes=envelope,
                selected_slot_id=slot.slot_id,
                credential=PasswordCredential(PASSWORD),
                verification=RequireUnsignedEnvelope(),
            )

    def test_valid_header_tamper_is_rejected_before_unwrap(self):
        envelope, _, slot = unsigned_vault_envelope()
        parts = split_complete_envelope(envelope)
        changed = bytearray(parts.ciphertext_transcript)
        marker = changed.find(b"MOKOSH Agent")
        self.assertGreater(marker, 0)
        changed[marker] = ord("N")
        with patch("mokosh_v2_complete_envelope.unwrap_selected_slot") as unwrap:
            with self.assertRaises(TranscriptMismatchError):
                decrypt_complete_envelope(
                    envelope_bytes=bytes(changed) + parts.trailer.to_bytes(),
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                    verification=RequireUnsignedEnvelope(),
                )
        unwrap.assert_not_called()

    def test_contact_envelope_cannot_be_downgraded_to_unsigned(self):
        plan, slot = fake_contact_plan()
        signed = encrypt_complete_envelope(
            key_plan=plan,
            plaintext=b"contact data",
            original_name="message.txt",
            signing=Ed25519EnvelopeSigning(PRIVATE_KEY, 2),
            chunk_size=MIN_CHUNK_SIZE,
            created_utc=CREATED_UTC,
        )
        parts = split_complete_envelope(signed)
        unsigned = build_unsigned_trailer(
            frame_count=parts.transcript.frame_count,
            transcript_sha256=parts.transcript.digest,
        )
        downgraded = parts.ciphertext_transcript + unsigned.to_bytes()
        with patch("mokosh_v2_complete_envelope.unwrap_selected_slot") as unwrap:
            with self.assertRaises(CompleteEnvelopePolicyError):
                decrypt_complete_envelope(
                    envelope_bytes=downgraded,
                    selected_slot_id=slot.slot_id,
                    credential=ContactCredential(b"X" * 32, b"M" * 64),
                    verification=RequireUnsignedEnvelope(),
                )
        unwrap.assert_not_called()


@unittest.skipIf(real_mlkem is None, "ML-KEM requires cryptography >= 47")
class RealHybridCompleteEnvelopeTests(unittest.TestCase):
    def test_real_hybrid_signed_roundtrip(self):
        x_private = x25519.X25519PrivateKey.generate()
        pq_private = real_mlkem.MLKEM768PrivateKey.generate()
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        slot = builder.add_contact(
            x_private.public_key().public_bytes_raw(),
            pq_private.public_key().public_bytes_raw(),
            11,
        )
        envelope = encrypt_complete_envelope(
            key_plan=builder.finish(),
            plaintext=b"hybrid contact payload",
            original_name="contact.bin",
            signing=Ed25519EnvelopeSigning(PRIVATE_KEY, 5),
            chunk_size=MIN_CHUNK_SIZE,
            created_utc=CREATED_UTC,
        )
        result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=ContactCredential(
                x_private.private_bytes_raw(),
                pq_private.private_bytes_raw(),
            ),
            verification=RequireEd25519Envelope(PRIVATE_KEY.public_key()),
        )
        self.assertEqual(result.plaintext, b"hybrid contact payload")
        self.assertTrue(result.trailer.is_signed)


class CompleteEnvelopeScopeTests(unittest.TestCase):
    def test_module_has_no_filesystem_network_gui_or_trust_operations(self):
        import mokosh_v2_complete_envelope as module

        source = inspect.getsource(module)
        for forbidden in (
            "open(",
            "Path(",
            "socket",
            "requests",
            "tkinter",
            "subprocess",
            "trusted =",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
