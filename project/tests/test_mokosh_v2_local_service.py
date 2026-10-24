import errno
import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import mokosh_profile_storage as storage
import mokosh_v2_local_service as local
from mokosh_profile_session import ProfileSessionState, SecureProfileSession
from mokosh_v2_cleanup_authorization import CleanupUserDecision
from mokosh_v2_complete_envelope import (
    Ed25519EnvelopeSigning,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_file_pipeline import encrypt_file_to_v2
from mokosh_v2_filesystem import ExclusiveFileQuarantineSink, VerifiedFileSource
from mokosh_v2_format import MAGIC, MIN_CHUNK_SIZE
from mokosh_v2_key_slots import KeyVaultSlot
from mokosh_v2_operation_journal import operation_id_from_temporary_name
from mokosh_v2_operation_lifecycle import (
    CancellationToken,
    OperationPhase,
    ProgressState,
)
from mokosh_v2_slot_orchestration import KeySlotPlanBuilder
from mokosh_v2_streaming import inspect_envelope_stream


PASSWORD = "Stage 2.48 primary password"
NICKNAME = "Local service primary"
OTHER_PASSWORD = "Stage 2.48 other password"
OTHER_NICKNAME = "Local service other"
CREATED = "2026-09-18T10:00:00Z"
ROTATED = "2026-09-18T10:01:00Z"


class LocalV2ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._profiles = tempfile.TemporaryDirectory(prefix="mokosh-local-service-")
        parent = Path(cls._profiles.name)
        os.chmod(parent, 0o700)
        cls.primary_root = parent / "primary"
        cls.other_root = parent / "other"
        storage.create_profile(
            NICKNAME,
            PASSWORD,
            cls.primary_root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        storage.create_profile(
            OTHER_NICKNAME,
            OTHER_PASSWORD,
            cls.other_root,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        cls.primary_snapshot = storage.load_profile(cls.primary_root)
        cls.other_snapshot = storage.load_profile(cls.other_root)

    @classmethod
    def tearDownClass(cls):
        cls._profiles.cleanup()

    def setUp(self):
        self._files = tempfile.TemporaryDirectory(prefix="mokosh-local-files-")
        self.directory = Path(self._files.name)
        os.chmod(self.directory, 0o700)
        self.session = SecureProfileSession(self.primary_snapshot)
        self.assertTrue(self.session.unlock(NICKNAME, PASSWORD).unlocked)
        self.service = local.LocalV2Service(self.session)

    def tearDown(self):
        self.session.close()
        self._files.cleanup()

    def write(self, name, data=b"local payload"):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def encrypt(self, payload=b"local payload", name="source.bin"):
        source = self.write(name, payload)
        encrypted = self.directory / "encrypted.mok2"
        result = self.service.encrypt(source_path=source, output_path=encrypted)
        self.assertTrue(result.ok, result.failure)
        return source, encrypted, result

    @staticmethod
    def abandon(sink):
        sink._journal_lease.close()
        os.close(sink._descriptor)
        os.close(sink._parent_descriptor)
        sink._active = False

    def test_encrypt_and_extension_agnostic_decrypt_roundtrip(self):
        payload = bytes(range(251)) * 100
        source, encrypted, encrypted_result = self.encrypt(payload)
        self.assertEqual(encrypted.read_bytes()[: len(MAGIC)], MAGIC)
        self.assertEqual(source.read_bytes(), payload)
        self.assertIsNone(encrypted_result.warning)
        self.assertIs(encrypted_result.residue.state, local.ResidueReviewState.CLEAR)

        disguised = self.directory / "opaque.data"
        encrypted.rename(disguised)
        restored = self.directory / "restored-without-extension"
        decrypted = self.service.decrypt(
            source_path=disguised,
            output_path=restored,
        )
        self.assertTrue(decrypted.ok, decrypted.failure)
        self.assertEqual(restored.read_bytes(), payload)
        self.assertTrue(disguised.exists())
        self.assertTrue(source.exists())

    def test_new_envelope_is_unsigned_with_exactly_one_active_vault_slot(self):
        _, encrypted, _ = self.encrypt()
        with VerifiedFileSource(encrypted) as source:
            inspected = inspect_envelope_stream(
                source,
                verification=RequireUnsignedEnvelope(),
            )
        self.assertEqual(len(inspected.slots), 1)
        self.assertIsInstance(inspected.slots[0], KeyVaultSlot)
        self.assertEqual(inspected.slots[0].vault_key_version, 1)
        self.assertIsNone(inspected.verified_signature)

    def test_rotated_keyring_encrypts_with_active_and_decrypts_retired_version(self):
        old_source, old_encrypted, _ = self.encrypt(b"before rotation")
        self.session._vault.rotate_keyring(
            PASSWORD,
            rotated_utc=ROTATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        new_source = self.write("new-source.bin", b"after rotation")
        new_encrypted = self.directory / "new-encrypted.mok2"
        self.assertTrue(
            self.service.encrypt(
                source_path=new_source,
                output_path=new_encrypted,
            ).ok
        )

        versions = []
        for path in (old_encrypted, new_encrypted):
            with VerifiedFileSource(path) as source:
                inspected = inspect_envelope_stream(
                    source,
                    verification=RequireUnsignedEnvelope(),
                )
            versions.append(inspected.slots[0].vault_key_version)
        self.assertEqual(versions, [1, 2])

        old_restored = self.directory / "old-restored"
        new_restored = self.directory / "new-restored"
        self.assertTrue(
            self.service.decrypt(
                source_path=old_encrypted,
                output_path=old_restored,
            ).ok
        )
        self.assertTrue(
            self.service.decrypt(
                source_path=new_encrypted,
                output_path=new_restored,
            ).ok
        )
        self.assertEqual(old_restored.read_bytes(), old_source.read_bytes())
        self.assertEqual(new_restored.read_bytes(), new_source.read_bytes())

    def test_wrong_profile_and_tamper_share_generic_authentication_failure(self):
        _, encrypted, _ = self.encrypt(b"private content" * 100)
        other_session = SecureProfileSession(self.other_snapshot)
        self.addCleanup(other_session.close)
        self.assertTrue(
            other_session.unlock(OTHER_NICKNAME, OTHER_PASSWORD).unlocked
        )
        wrong_profile = local.LocalV2Service(other_session).decrypt(
            source_path=encrypted,
            output_path=self.directory / "wrong-profile-output",
        )
        self.assertFalse(wrong_profile.ok)
        self.assertIs(
            wrong_profile.failure.code,
            local.LocalV2ErrorCode.AUTHENTICATION_FAILED,
        )

        changed = bytearray(encrypted.read_bytes())
        changed[len(changed) // 2] ^= 1
        encrypted.write_bytes(changed)
        tampered = self.service.decrypt(
            source_path=encrypted,
            output_path=self.directory / "tampered-output",
        )
        self.assertFalse(tampered.ok)
        self.assertIs(
            tampered.failure.code,
            local.LocalV2ErrorCode.AUTHENTICATION_FAILED,
        )
        self.assertEqual(wrong_profile.failure.message_key, tampered.failure.message_key)

    def test_non_v2_file_never_falls_back_to_legacy(self):
        source = self.write("looks-encrypted.mok2", b"MOK1 or arbitrary bytes")
        output = self.directory / "must-not-exist"
        result = self.service.decrypt(source_path=source, output_path=output)
        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.NOT_MOKOSH2)
        self.assertFalse(output.exists())

    def test_multiple_slots_and_signed_envelope_are_refused(self):
        source = self.write("direct-source.bin", b"unsupported policy")
        multiple = self.directory / "multiple.mok2"
        builder = KeySlotPlanBuilder()
        builder.add_vault(b"A" * 32, 1)
        builder.add_vault(b"B" * 32, 2)
        encrypt_file_to_v2(
            source_path=source,
            output_path=multiple,
            key_plan=builder.finish(),
            original_name=source.name,
            signing=UnsignedEnvelopeSigning(),
            created_utc=CREATED,
            chunk_size=MIN_CHUNK_SIZE,
        )
        multiple_result = self.service.decrypt(
            source_path=multiple,
            output_path=self.directory / "multiple-output",
        )
        self.assertFalse(multiple_result.ok)
        self.assertIs(
            multiple_result.failure.code,
            local.LocalV2ErrorCode.UNSUPPORTED_ENVELOPE,
        )

        signed = self.directory / "signed.mok2"
        signed_builder = KeySlotPlanBuilder()
        signed_builder.add_vault(b"C" * 32, 1)
        private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        encrypt_file_to_v2(
            source_path=source,
            output_path=signed,
            key_plan=signed_builder.finish(),
            original_name=source.name,
            signing=Ed25519EnvelopeSigning(private, 1),
            created_utc=CREATED,
            chunk_size=MIN_CHUNK_SIZE,
        )
        signed_result = self.service.decrypt(
            source_path=signed,
            output_path=self.directory / "signed-output",
        )
        self.assertFalse(signed_result.ok)
        self.assertIs(
            signed_result.failure.code,
            local.LocalV2ErrorCode.UNSUPPORTED_ENVELOPE,
        )

    def test_no_overwrite_and_encrypt_suffix_is_mandatory(self):
        source = self.write("source.bin", b"new")
        existing = self.write("existing.mok2", b"keep")
        collision = self.service.encrypt(
            source_path=source,
            output_path=existing,
        )
        self.assertFalse(collision.ok)
        self.assertIs(
            collision.failure.code,
            local.LocalV2ErrorCode.OUTPUT_COLLISION,
        )
        self.assertEqual(existing.read_bytes(), b"keep")

        missing_suffix = self.service.encrypt(
            source_path=source,
            output_path=self.directory / "no-suffix",
        )
        self.assertFalse(missing_suffix.ok)
        self.assertIs(
            missing_suffix.failure.code,
            local.LocalV2ErrorCode.INVALID_SELECTION,
        )

    def test_locked_session_refuses_before_creating_output(self):
        self.session.lock()
        source = self.write("source.bin", b"secret")
        output = self.directory / "locked.mok2"
        result = self.service.encrypt(source_path=source, output_path=output)
        self.assertFalse(result.ok)
        self.assertIs(
            result.failure.code,
            local.LocalV2ErrorCode.SESSION_UNAVAILABLE,
        )
        self.assertFalse(output.exists())

    def test_panic_during_worker_cancels_and_removes_quarantine(self):
        source = self.write("source.bin", b"secret" * 10000)
        output = self.directory / "cancelled.mok2"

        def observer(event):
            if (
                event.phase is OperationPhase.ENCRYPT
                and event.state is ProgressState.STARTED
            ):
                self.session.panic_lock()

        result = self.service.encrypt(
            source_path=source,
            output_path=output,
            observer=observer,
        )
        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.CANCELLED)
        self.assertIs(self.session.state, ProfileSessionState.LOCKED)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])
        self.assertEqual(list(self.directory.glob(".mokosh-operation-*")), [])
        self.assertTrue(source.exists())

    def test_decrypt_binds_the_public_inspection_to_exact_source_identity(self):
        _, encrypted, _ = self.encrypt(b"identity bound")
        output = self.directory / "identity-output"
        real_run = local.run_decryption_operation

        def change_then_run(**kwargs):
            current = encrypted.stat()
            os.utime(
                encrypted,
                ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000),
            )
            return real_run(**kwargs)

        with patch.object(
            local,
            "run_decryption_operation",
            side_effect=change_then_run,
        ):
            result = self.service.decrypt(
                source_path=encrypted,
                output_path=output,
            )
        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.SOURCE_CHANGED)
        self.assertFalse(output.exists())

    def test_decrypt_binds_magic_probe_to_public_inspection_identity(self):
        _, encrypted, _ = self.encrypt(b"magic identity bound")
        replacement = self.directory / "replacement.mok2"
        replacement.write_bytes(encrypted.read_bytes())
        output = self.directory / "magic-identity-output"
        real_source = local.VerifiedFileSource
        opens = 0

        def replace_after_magic(path, *args, **kwargs):
            nonlocal opens
            opens += 1
            if opens == 2:
                encrypted.unlink()
                replacement.rename(encrypted)
            return real_source(path, *args, **kwargs)

        with patch.object(
            local,
            "VerifiedFileSource",
            side_effect=replace_after_magic,
        ):
            result = self.service.decrypt(
                source_path=encrypted,
                output_path=output,
            )

        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.SOURCE_CHANGED)
        self.assertFalse(output.exists())

    def test_exact_abandoned_pair_requires_review_and_explicit_cleanup(self):
        unrelated = self.write("unrelated.txt", b"preserve")
        source = self.write("source.bin", b"blocked until review")
        sink = ExclusiveFileQuarantineSink(self.directory / "unused.mok2")
        sink.write(b"abandoned")
        operation_id = operation_id_from_temporary_name(Path(sink.temp_path).name)
        self.abandon(sink)

        review = self.service.review_directory(self.directory)
        self.assertIs(review.state, local.ResidueReviewState.CLEANABLE)
        self.assertEqual(review.cleanup_operation_ids, (operation_id,))
        refused = self.service.encrypt(
            source_path=source,
            output_path=self.directory / "blocked.mok2",
        )
        self.assertFalse(refused.ok)
        self.assertIs(
            refused.failure.code,
            local.LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
        )

        preserved = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=review,
            operation_id=operation_id,
            decision=CleanupUserDecision.PRESERVE,
        )
        self.assertFalse(preserved.ok)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

        cleaned = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=review,
            operation_id=operation_id,
            decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertTrue(cleaned.ok)
        self.assertIs(cleaned.residue.state, local.ResidueReviewState.CLEAR)
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertFalse(Path(sink.journal_path).exists())
        self.assertEqual(unrelated.read_bytes(), b"preserve")

    def test_second_residue_scan_closes_preflight_to_key_lease_race(self):
        source = self.write("source.bin", b"race must stop")
        output = self.directory / "must-not-publish.mok2"
        real_review = local._review
        injected = []

        def inject_before_second_review(directory, cancellation=None):
            if not injected:
                injected.append(real_review(directory, cancellation))
                return injected[0]
            if len(injected) == 1:
                sink = ExclusiveFileQuarantineSink(
                    self.directory / "synthetic-unused.mok2"
                )
                sink.write(b"private abandoned bytes")
                self.abandon(sink)
                injected.append(sink)
            return real_review(directory, cancellation)

        with patch.object(local, "_review", side_effect=inject_before_second_review):
            result = self.service.encrypt(
                source_path=source,
                output_path=output,
            )

        self.assertFalse(result.ok)
        self.assertIs(
            result.failure.code,
            local.LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
        )
        self.assertFalse(output.exists())
        self.assertTrue(source.exists())
        self.assertIs(
            result.residue.state,
            local.ResidueReviewState.CLEANABLE,
        )

        # The refused attempt must have released the sole session key lease.
        reviewed = real_review(self.directory)
        cleaned = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=reviewed,
            operation_id=reviewed.cleanup_operation_ids[0],
            decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertTrue(cleaned.ok)
        second = self.service.encrypt(
            source_path=source,
            output_path=output,
        )
        self.assertTrue(second.ok, second.failure)

    def test_oversized_output_directory_is_blocked_before_full_listing(self):
        source = self.write("source.bin", b"bounded directory review")
        output = self.directory / "bounded.mok2"

        class OversizedDirectory:
            def __enter__(self):
                return iter(range(local.MAX_LOCAL_V2_DIRECTORY_ENTRIES + 1))

            def __exit__(self, exc_type, exc, traceback):
                return False

        with (
            patch.object(local.os, "scandir", return_value=OversizedDirectory()),
            patch.object(local, "scan_quarantine_directory") as full_scan,
        ):
            result = self.service.encrypt(
                source_path=source,
                output_path=output,
            )

        self.assertFalse(result.ok)
        self.assertIs(
            result.failure.code,
            local.LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
        )
        self.assertIs(result.residue.state, local.ResidueReviewState.BLOCKED)
        self.assertFalse(result.residue.scan_complete)
        full_scan.assert_not_called()
        self.assertFalse(output.exists())

    def test_link_count_conflict_is_blocked_and_never_cleanup_eligible(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "unused.mok2")
        sink.write(b"possible published inode")
        extra = self.directory / "possible-final"
        os.link(sink.temp_path, extra)
        operation_id = operation_id_from_temporary_name(Path(sink.temp_path).name)
        self.abandon(sink)

        review = self.service.review_directory(self.directory)
        self.assertIs(review.state, local.ResidueReviewState.BLOCKED)
        self.assertEqual(review.cleanup_operation_ids, ())
        result = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=review,
            operation_id=operation_id,
            decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertFalse(result.ok)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())
        self.assertEqual(extra.read_bytes(), b"possible published inode")

    def test_cleanup_is_session_bound_and_panic_cancels_before_unlink(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "unused.mok2")
        sink.write(b"cleanup cancellation")
        operation_id = operation_id_from_temporary_name(Path(sink.temp_path).name)
        self.abandon(sink)
        review = self.service.review_directory(self.directory)
        token = CancellationToken()
        real_prepare = local.prepare_cleanup_authorization

        def prepare_then_panic(*args, **kwargs):
            prepared = real_prepare(*args, **kwargs)
            self.session.panic_lock()
            return prepared

        with (
            patch.object(
                local,
                "prepare_cleanup_authorization",
                side_effect=prepare_then_panic,
            ),
            patch.object(local, "execute_cleanup") as execute,
        ):
            result = self.service.cleanup_reviewed_residue(
                directory=self.directory,
                reviewed=review,
                operation_id=operation_id,
                decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
                cancellation=token,
            )

        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.CANCELLED)
        self.assertTrue(token.cancelled)
        execute.assert_not_called()
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

        # The cleanup lease drained on return, so an explicit login can resume.
        self.assertTrue(self.session.unlock(NICKNAME, PASSWORD).unlocked)
        cleaned = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=review,
            operation_id=operation_id,
            decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertTrue(cleaned.ok)

    def test_cleanup_and_key_operation_share_one_session_slot(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "unused.mok2")
        sink.write(b"busy cleanup")
        operation_id = operation_id_from_temporary_name(Path(sink.temp_path).name)
        self.abandon(sink)
        review = self.service.review_directory(self.directory)
        lease = self.session._begin_local_v2_operation()
        try:
            result = self.service.cleanup_reviewed_residue(
                directory=self.directory,
                reviewed=review,
                operation_id=operation_id,
                decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
            )
        finally:
            lease.close()
        self.assertFalse(result.ok)
        self.assertIs(result.failure.code, local.LocalV2ErrorCode.OPERATION_BUSY)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())

        cleaned = self.service.cleanup_reviewed_residue(
            directory=self.directory,
            reviewed=review,
            operation_id=operation_id,
            decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
        )
        self.assertTrue(cleaned.ok)

    def test_cancellation_token_subclasses_are_refused(self):
        class TokenSubclass(CancellationToken):
            def __bool__(self):
                return False

        source = self.write("source.bin", b"token type")
        result = self.service.encrypt(
            source_path=source,
            output_path=self.directory / "token.mok2",
            cancellation=TokenSubclass(),
        )
        self.assertFalse(result.ok)
        self.assertIs(
            result.failure.code,
            local.LocalV2ErrorCode.INVALID_SELECTION,
        )

    def test_post_publish_cleanup_fault_is_success_warning_and_not_retry(self):
        source = self.write("source.bin", b"publish exactly once" * 100)
        output = self.directory / "published.mok2"
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-operation-"):
                raise OSError(errno.EIO, "secret injected text")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            result = self.service.encrypt(
                source_path=source,
                output_path=output,
            )
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.warning)
        self.assertIs(
            result.warning.code,
            local.LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED,
        )
        self.assertNotIn("secret", repr(result).lower())
        self.assertTrue(output.exists())
        self.assertIs(result.residue.state, local.ResidueReviewState.BLOCKED)

    def test_generic_suggested_names_never_include_source_information(self):
        with patch.object(local.secrets, "token_hex", return_value="0123abcd"):
            self.assertEqual(
                local.propose_encrypted_name(),
                "MOKOSH-encrypted-0123abcd.mok2",
            )
            self.assertEqual(
                local.propose_decrypted_name(),
                "MOKOSH-decrypted-0123abcd",
            )


class LocalV2ServiceScopeTests(unittest.TestCase):
    def test_public_result_dtos_reject_inconsistent_or_forged_state(self):
        with self.assertRaises(local.LocalV2ServiceError):
            local.SafeLocalV2Failure(
                local.LocalV2ErrorCode.IO_FAILED,
                1,
                "local_v2.error.io_failed",
            )
        with self.assertRaises(local.LocalV2ServiceError):
            local.SafeLocalV2Warning(
                local.LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED,
                "local_v2.warning.cleanup_review_required",
            )
        with self.assertRaises(local.LocalV2ServiceError):
            local.ResidueReview(
                local.ResidueReviewState.BLOCKED,
                1,
                1,
                (),
                True,
                None,
            )
        with self.assertRaises(local.LocalV2ServiceError):
            local.LocalV2Result(ok=True, residue=object())

        warning = local.SafeLocalV2Warning(
            local.LocalV2WarningCode.CLEANUP_REVIEW_REQUIRED,
            "local_v2.warning.cleanup_review_required",
        )
        with self.assertRaises(local.LocalV2ServiceError):
            local.LocalV2Result(
                ok=True,
                warning=warning,
                residue=local.ResidueReview(
                    local.ResidueReviewState.CLEAR,
                    0,
                    0,
                    (),
                    True,
                ),
            )

    def test_service_has_no_legacy_network_logging_or_gui_dependency(self):
        source = inspect.getsource(local)
        for forbidden in (
            "mokosh_legacy",
            "legacy_decrypt",
            "tkinter",
            "socket",
            "requests",
            "logging",
            "print(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
