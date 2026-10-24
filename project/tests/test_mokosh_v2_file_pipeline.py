import inspect
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from mokosh_v2_complete_envelope import (
    Ed25519EnvelopeSigning,
    RequireEd25519Envelope,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_crypto import FrameAuthenticationError
from mokosh_v2_file_pipeline import (
    FilePipelineVerificationError,
    decrypt_v2_file_to_quarantine,
    encrypt_file_to_v2,
)
from mokosh_v2_filesystem import (
    ExclusiveFileQuarantineSink,
    FilesystemSafetyError,
    OutputCollisionError,
    OwnedTemporaryFileError,
    SourceChangedError,
    UnsafePathError,
    VerifiedFileSource,
)
from mokosh_v2_format import MIN_CHUNK_SIZE, FormatLimitError, V2FormatError
from mokosh_v2_slot_orchestration import (
    ContactCredential,
    KeySlotPlanBuilder,
    VaultCredential,
)
from mokosh_v2_streaming import (
    StreamPassMismatchError,
    StreamingEnvelopeError,
    inspect_envelope_stream,
    verify_envelope_stream_with_dek,
)


try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as real_mlkem
except ImportError:
    real_mlkem = None


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
VAULT_KEY = b"V" * 32
OTHER_VAULT_KEY = b"W" * 32
SIGNER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SIGNER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
CREATED_UTC = "2026-08-09T12:00:00Z"


class PrivateDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)
        os.chmod(self.directory, 0o700)

    def tearDown(self):
        self._temporary.cleanup()

    def write_file(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def vault_plan(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        slot = builder.add_vault(VAULT_KEY, 7)
        return builder.finish(), slot

    def encrypt_vault(self, payload, *, name="source.bin", signed=False):
        source = self.write_file(name, payload)
        encrypted = self.directory / f"{name}.mok"
        plan, slot = self.vault_plan()
        signing = (
            Ed25519EnvelopeSigning(SIGNER, 9)
            if signed
            else UnsignedEnvelopeSigning()
        )
        result = encrypt_file_to_v2(
            source_path=source,
            output_path=encrypted,
            key_plan=plan,
            original_name=name,
            signing=signing,
            created_utc=CREATED_UTC,
            chunk_size=MIN_CHUNK_SIZE,
        )
        return source, encrypted, plan, slot, result


class SealedQuarantineTests(PrivateDirectoryTestCase):
    def test_seal_flushes_without_publishing_and_commit_publishes(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"ciphertext")
        identity = sink.seal_for_verification()
        self.assertTrue(sink.sealed)
        self.assertEqual(identity.size, 10)
        self.assertFalse(final.exists())
        self.assertTrue(Path(sink.temp_path).exists())
        sink.commit()
        self.assertEqual(final.read_bytes(), b"ciphertext")

    def test_seal_is_idempotent_but_write_after_seal_is_rejected(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        sink.write(b"data")
        first = sink.seal_for_verification()
        self.assertEqual(sink.seal_for_verification(), first)
        with self.assertRaises(FilesystemSafetyError):
            sink.write(b"late")
        sink.abort()

    def test_sealed_inode_content_change_blocks_publish(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"data")
        sink.seal_for_verification()
        with Path(sink.temp_path).open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(OwnedTemporaryFileError):
            sink.commit()
        sink.abort()
        self.assertFalse(final.exists())

    def test_abort_after_seal_removes_private_inode(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        sink.write(b"data")
        sink.seal_for_verification()
        sink.abort()
        self.assertFalse(temp.exists())
        self.assertFalse(final.exists())


class StreamingDEKVerificationTests(PrivateDirectoryTestCase):
    def setUp(self):
        super().setUp()
        _, self.encrypted, self.plan, _, _ = self.encrypt_vault(
            b"verify with held DEK" * 500,
        )

    def inspect(self):
        with VerifiedFileSource(self.encrypted) as source:
            return inspect_envelope_stream(
                source,
                verification=RequireUnsignedEnvelope(),
            )

    def test_exact_dek_verifies_without_writing_plaintext(self):
        inspection = self.inspect()
        with VerifiedFileSource(self.encrypted) as source:
            result = verify_envelope_stream_with_dek(
                source,
                inspection=inspection,
                dek=self.plan.dek,
            )
        self.assertEqual(result.plaintext_size, len(b"verify with held DEK" * 500))

    def test_wrong_dek_is_rejected(self):
        inspection = self.inspect()
        with VerifiedFileSource(self.encrypted) as source:
            with self.assertRaises(FrameAuthenticationError):
                verify_envelope_stream_with_dek(
                    source,
                    inspection=inspection,
                    dek=b"X" * 32,
                )

    def test_invalid_dek_values_are_rejected_before_read(self):
        inspection = self.inspect()
        for value in ("not bytes", b"short", b"long" * 20):
            with self.subTest(value=type(value).__name__):
                with VerifiedFileSource(self.encrypted) as source:
                    with self.assertRaises(StreamingEnvelopeError):
                        verify_envelope_stream_with_dek(
                            source,
                            inspection=inspection,
                            dek=value,
                        )

    def test_second_pass_difference_is_rejected(self):
        inspection = self.inspect()
        changed = bytearray(self.encrypted.read_bytes())
        changed[0] ^= 1
        other = self.write_file("changed.mok", bytes(changed))
        with VerifiedFileSource(other) as source:
            with self.assertRaises(
                (StreamPassMismatchError, StreamingEnvelopeError, V2FormatError)
            ):
                verify_envelope_stream_with_dek(
                    source,
                    inspection=inspection,
                    dek=self.plan.dek,
                )


class FilePipelineTests(PrivateDirectoryTestCase):
    def test_empty_boundary_and_multiframe_roundtrips(self):
        payloads = (
            b"",
            b"B" * MIN_CHUNK_SIZE,
            bytes(range(251)) * 80,
        )
        for index, payload in enumerate(payloads):
            with self.subTest(size=len(payload)):
                source, encrypted, _, slot, enc_result = self.encrypt_vault(
                    payload,
                    name=f"source-{index}.bin",
                )
                restored = self.directory / f"restored-{index}.bin"
                dec_result = decrypt_v2_file_to_quarantine(
                    source_path=encrypted,
                    output_path=restored,
                    verification=RequireUnsignedEnvelope(),
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                )
                self.assertEqual(restored.read_bytes(), payload)
                self.assertEqual(source.read_bytes(), payload)
                self.assertIsNotNone(enc_result.output_identity)
                self.assertIsNotNone(dec_result.output_identity)
                self.assertEqual(enc_result.output_identity.size, encrypted.stat().st_size)
                self.assertEqual(dec_result.output_identity.size, len(payload))
                self.assertFalse(enc_result.publish.warning_required)
                self.assertFalse(dec_result.publish.warning_required)

    def test_post_publish_cleanup_fault_returns_result_without_retry_signal(self):
        source = self.write_file("source.bin", b"published once" * 1000)
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-operation-"):
                raise OSError("forced after publish")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            result = encrypt_file_to_v2(
                source_path=source,
                output_path=final,
                key_plan=plan,
                original_name="source.bin",
                signing=UnsignedEnvelopeSigning(),
                created_utc=CREATED_UTC,
                chunk_size=MIN_CHUNK_SIZE,
            )
        self.assertTrue(final.exists())
        self.assertTrue(result.publish.warning_required)
        self.assertTrue(result.publish.temporary_removed)
        self.assertFalse(result.publish.journal_removed)

    def test_signed_vault_roundtrip_proves_but_does_not_assign_trust(self):
        payload = b"signed file pipeline" * 700
        source, encrypted, _, slot, _ = self.encrypt_vault(payload, signed=True)
        restored = self.directory / "restored.bin"
        result = decrypt_v2_file_to_quarantine(
            source_path=encrypted,
            output_path=restored,
            verification=RequireEd25519Envelope(SIGNER.public_key()),
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
        )
        self.assertEqual(restored.read_bytes(), payload)
        self.assertIsNotNone(result.stream.verified_signature)
        self.assertNotIn("trust", repr(result).lower())
        self.assertEqual(source.read_bytes(), payload)

    def test_final_name_is_absent_during_post_write_crypto_verification(self):
        source = self.write_file("source.bin", b"deferred publish" * 1000)
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        from mokosh_v2_file_pipeline import verify_envelope_stream_with_dek as real

        def observe(*args, **kwargs):
            self.assertFalse(final.exists())
            self.assertEqual(len(list(self.directory.glob(".mokosh-quarantine-*"))), 1)
            return real(*args, **kwargs)

        with patch(
            "mokosh_v2_file_pipeline.verify_envelope_stream_with_dek",
            side_effect=observe,
        ):
            encrypt_file_to_v2(
                source_path=source,
                output_path=final,
                key_plan=plan,
                original_name="source.bin",
                signing=UnsignedEnvelopeSigning(),
                created_utc=CREATED_UTC,
                chunk_size=MIN_CHUNK_SIZE,
            )
        self.assertTrue(final.exists())

    def test_encryption_verification_failure_aborts_without_public_output(self):
        source = self.write_file("source.bin", b"secret")
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        with patch(
            "mokosh_v2_file_pipeline.verify_envelope_stream_with_dek",
            side_effect=FilePipelineVerificationError("forced"),
        ):
            with self.assertRaises(FilePipelineVerificationError):
                encrypt_file_to_v2(
                    source_path=source,
                    output_path=final,
                    key_plan=plan,
                    original_name="source.bin",
                    signing=UnsignedEnvelopeSigning(),
                    chunk_size=MIN_CHUNK_SIZE,
                )
        self.assertFalse(final.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])
        self.assertEqual(source.read_bytes(), b"secret")

    def test_source_change_during_second_pass_aborts_encryption(self):
        source = self.write_file("source.bin", b"A" * (MIN_CHUNK_SIZE * 2))
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        from mokosh_v2_file_pipeline import encrypt_stream_to_quarantine as real

        def mutate_then_encrypt(**kwargs):
            with source.open("ab") as handle:
                handle.write(b"changed")
            return real(**kwargs)

        with patch(
            "mokosh_v2_file_pipeline.encrypt_stream_to_quarantine",
            side_effect=mutate_then_encrypt,
        ):
            with self.assertRaises(Exception):
                encrypt_file_to_v2(
                    source_path=source,
                    output_path=final,
                    key_plan=plan,
                    original_name="source.bin",
                    signing=UnsignedEnvelopeSigning(),
                    chunk_size=MIN_CHUNK_SIZE,
                )
        self.assertFalse(final.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_source_replacement_between_passes_is_rejected(self):
        original = b"same bytes but different inode"
        source = self.write_file("source.bin", original)
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        from mokosh_v2_file_pipeline import ExclusiveFileQuarantineSink as real

        def replace_then_create(output_path):
            source.rename(self.directory / "old-source.bin")
            source.write_bytes(original)
            return real(output_path)

        with patch(
            "mokosh_v2_file_pipeline.ExclusiveFileQuarantineSink",
            side_effect=replace_then_create,
        ):
            with self.assertRaises(SourceChangedError):
                encrypt_file_to_v2(
                    source_path=source,
                    output_path=final,
                    key_plan=plan,
                    original_name="source.bin",
                    signing=UnsignedEnvelopeSigning(),
                    chunk_size=MIN_CHUNK_SIZE,
                )
        self.assertFalse(final.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_keyboard_interrupt_during_verification_cleans_quarantine(self):
        source = self.write_file("source.bin", b"interrupt secret")
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        with patch(
            "mokosh_v2_file_pipeline.verify_envelope_stream_with_dek",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                encrypt_file_to_v2(
                    source_path=source,
                    output_path=final,
                    key_plan=plan,
                    original_name="source.bin",
                    signing=UnsignedEnvelopeSigning(),
                    chunk_size=MIN_CHUNK_SIZE,
                )
        self.assertFalse(final.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_existing_output_and_output_symlink_are_never_overwritten(self):
        source = self.write_file("source.bin", b"secret")
        plan, _ = self.vault_plan()
        existing = self.write_file("existing.mok", b"keep")
        for output in (existing, self.directory / "link.mok"):
            if output.name == "link.mok":
                output.symlink_to(existing)
            with self.subTest(output=output.name):
                with self.assertRaises(OutputCollisionError):
                    encrypt_file_to_v2(
                        source_path=source,
                        output_path=output,
                        key_plan=plan,
                        original_name="source.bin",
                        signing=UnsignedEnvelopeSigning(),
                        chunk_size=MIN_CHUNK_SIZE,
                    )
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_late_output_collision_preserves_foreign_file(self):
        source = self.write_file("source.bin", b"secret" * 1000)
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        from mokosh_v2_file_pipeline import verify_envelope_stream_with_dek as real

        def collide(*args, **kwargs):
            result = real(*args, **kwargs)
            final.write_bytes(b"foreign")
            return result

        with patch(
            "mokosh_v2_file_pipeline.verify_envelope_stream_with_dek",
            side_effect=collide,
        ):
            with self.assertRaises(OutputCollisionError):
                encrypt_file_to_v2(
                    source_path=source,
                    output_path=final,
                    key_plan=plan,
                    original_name="source.bin",
                    signing=UnsignedEnvelopeSigning(),
                    chunk_size=MIN_CHUNK_SIZE,
                )
        self.assertEqual(final.read_bytes(), b"foreign")
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_plaintext_verification_failure_aborts_decryption(self):
        payload = b"plaintext verification" * 900
        _, encrypted, _, slot, _ = self.encrypt_vault(payload)
        restored = self.directory / "restored.bin"
        with patch(
            "mokosh_v2_file_pipeline._compare_plaintext_output",
            side_effect=FilePipelineVerificationError("forced"),
        ):
            with self.assertRaises(FilePipelineVerificationError):
                decrypt_v2_file_to_quarantine(
                    source_path=encrypted,
                    output_path=restored,
                    verification=RequireUnsignedEnvelope(),
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                )
        self.assertFalse(restored.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_wrong_credential_never_publishes_plaintext(self):
        _, encrypted, _, slot, _ = self.encrypt_vault(b"credential secret")
        restored = self.directory / "restored.bin"
        with self.assertRaises(Exception):
            decrypt_v2_file_to_quarantine(
                source_path=encrypted,
                output_path=restored,
                verification=RequireUnsignedEnvelope(),
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(OTHER_VAULT_KEY),
            )
        self.assertFalse(restored.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_wrong_signer_is_rejected_before_plaintext_transaction(self):
        _, encrypted, _, slot, _ = self.encrypt_vault(b"signed", signed=True)
        restored = self.directory / "restored.bin"
        with self.assertRaises(Exception):
            decrypt_v2_file_to_quarantine(
                source_path=encrypted,
                output_path=restored,
                verification=RequireEd25519Envelope(OTHER_SIGNER.public_key()),
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertFalse(restored.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_tampered_envelope_never_creates_plaintext(self):
        _, encrypted, _, slot, _ = self.encrypt_vault(b"tamper secret" * 500)
        changed = bytearray(encrypted.read_bytes())
        changed[len(changed) // 2] ^= 1
        encrypted.write_bytes(changed)
        restored = self.directory / "restored.bin"
        with self.assertRaises(Exception):
            decrypt_v2_file_to_quarantine(
                source_path=encrypted,
                output_path=restored,
                verification=RequireUnsignedEnvelope(),
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertFalse(restored.exists())

    def test_size_limit_rejects_before_output_transaction(self):
        source = self.write_file("source.bin", b"too large")
        final = self.directory / "source.bin.mok"
        plan, _ = self.vault_plan()
        with self.assertRaises(FormatLimitError):
            encrypt_file_to_v2(
                source_path=source,
                output_path=final,
                key_plan=plan,
                original_name="source.bin",
                signing=UnsignedEnvelopeSigning(),
                chunk_size=MIN_CHUNK_SIZE,
                max_plaintext_size=3,
            )
        self.assertFalse(final.exists())

    def test_source_and_output_symlink_or_public_parent_are_rejected(self):
        source = self.write_file("source.bin", b"secret")
        link = self.directory / "source-link.bin"
        link.symlink_to(source)
        plan, _ = self.vault_plan()
        with self.assertRaises(UnsafePathError):
            encrypt_file_to_v2(
                source_path=link,
                output_path=self.directory / "linked.mok",
                key_plan=plan,
                original_name="source.bin",
                signing=UnsignedEnvelopeSigning(),
            )
        public = self.directory / "public"
        public.mkdir(mode=0o777)
        os.chmod(public, 0o777)
        with self.assertRaises(UnsafePathError):
            encrypt_file_to_v2(
                source_path=source,
                output_path=public / "result.mok",
                key_plan=plan,
                original_name="source.bin",
                signing=UnsignedEnvelopeSigning(),
            )

    def test_published_outputs_are_private_and_original_is_untouched(self):
        payload = b"private output" * 800
        source, encrypted, _, slot, _ = self.encrypt_vault(payload)
        restored = self.directory / "restored.bin"
        decrypt_v2_file_to_quarantine(
            source_path=encrypted,
            output_path=restored,
            verification=RequireUnsignedEnvelope(),
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
        )
        self.assertEqual(stat.S_IMODE(encrypted.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
        self.assertEqual(source.read_bytes(), payload)
        self.assertEqual(restored.read_bytes(), payload)


class FilePipelineScopeTests(unittest.TestCase):
    def test_pipeline_has_no_delete_gui_network_logging_or_path_autoselection(self):
        import mokosh_v2_file_pipeline

        source = inspect.getsource(mokosh_v2_file_pipeline)
        for forbidden in (
            "os.unlink",
            "os.remove",
            "os.replace",
            "Path(",
            "tkinter",
            "socket",
            "requests",
            "logging",
            "print(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


@unittest.skipUnless(real_mlkem is not None, "ML-KEM requires cryptography >= 47")
class RealHybridFilePipelineTests(PrivateDirectoryTestCase):
    def test_signed_hybrid_contact_file_roundtrip(self):
        payload = b"hybrid contact file pipeline" * 1000
        source = self.write_file("contact.bin", payload)
        encrypted = self.directory / "contact.bin.mok"
        restored = self.directory / "contact-restored.bin"
        x_private = x25519.X25519PrivateKey.generate()
        pq_private = real_mlkem.MLKEM768PrivateKey.generate()
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        slot = builder.add_contact(
            x_private.public_key().public_bytes_raw(),
            pq_private.public_key().public_bytes_raw(),
            11,
        )
        plan = builder.finish()
        encrypt_file_to_v2(
            source_path=source,
            output_path=encrypted,
            key_plan=plan,
            original_name="contact.bin",
            signing=Ed25519EnvelopeSigning(SIGNER, 11),
            created_utc=CREATED_UTC,
            chunk_size=MIN_CHUNK_SIZE,
        )
        decrypt_v2_file_to_quarantine(
            source_path=encrypted,
            output_path=restored,
            verification=RequireEd25519Envelope(SIGNER.public_key()),
            selected_slot_id=slot.slot_id,
            credential=ContactCredential(
                x_private.private_bytes_raw(),
                pq_private.private_bytes_raw(),
            ),
        )
        self.assertEqual(restored.read_bytes(), payload)
        self.assertEqual(source.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
