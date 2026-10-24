import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mokosh_v2_complete_envelope import (
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_filesystem import (
    MAX_SECURE_READ_SIZE,
    AtomicPublishUnsupportedError,
    ExclusiveFileQuarantineSink,
    FilesystemSafetyError,
    OutputCollisionError,
    OwnedTemporaryFileError,
    SourceChangedError,
    UnsafePathError,
    VerifiedFileSource,
)
from mokosh_v2_format import MIN_CHUNK_SIZE
from mokosh_v2_slot_orchestration import KeySlotPlanBuilder, VaultCredential
from mokosh_v2_streaming import (
    decrypt_stream_to_quarantine,
    encrypt_stream_to_quarantine,
    inspect_envelope_stream,
    scan_plaintext_stream,
)


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
VAULT_KEY = b"V" * 32
CREATED_UTC = "2026-08-09T12:00:00Z"


class PrivateDirectoryTestCase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)
        os.chmod(self.directory, 0o700)

    def tearDown(self):
        self._temporary.cleanup()

    def write_file(self, name, data=b"payload"):
        path = self.directory / name
        path.write_bytes(data)
        return path


class VerifiedFileSourceTests(PrivateDirectoryTestCase):
    def test_regular_file_is_read_bounded_and_verified(self):
        path = self.write_file("source.bin", b"abcdefgh")
        source = VerifiedFileSource(path, max_read_size=3)
        self.assertEqual(source.read(3), b"abc")
        self.assertEqual(source.read(3), b"def")
        self.assertEqual(source.read(3), b"gh")
        self.assertEqual(source.read(3), b"")
        self.assertEqual(source.bytes_read, 8)
        identity = source.verify_and_close()
        self.assertEqual(identity.size, 8)
        self.assertTrue(source.closed)

    def test_context_manager_verifies_and_closes(self):
        path = self.write_file("source.bin", b"data")
        with VerifiedFileSource(path) as source:
            self.assertEqual(source.read(4), b"data")
        self.assertTrue(source.closed)

    def test_invalid_read_limits_are_rejected(self):
        path = self.write_file("source.bin")
        for value in (True, 0, -1, MAX_SECURE_READ_SIZE + 1):
            with self.subTest(value=value):
                with self.assertRaises(FilesystemSafetyError):
                    VerifiedFileSource(path, max_read_size=value)
        source = VerifiedFileSource(path, max_read_size=4)
        for value in (True, 0, -1, 5):
            with self.subTest(value=value):
                with self.assertRaises(FilesystemSafetyError):
                    source.read(value)
        source.close()

    def test_read_after_close_is_rejected(self):
        source = VerifiedFileSource(self.write_file("source.bin"))
        source.close()
        source.close()
        with self.assertRaises(FilesystemSafetyError):
            source.read(1)

    def test_symlink_and_directory_sources_are_rejected(self):
        target = self.write_file("target.bin")
        link = self.directory / "link.bin"
        link.symlink_to(target)
        for path in (link, self.directory):
            with self.subTest(path=path):
                with self.assertRaises(UnsafePathError):
                    VerifiedFileSource(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_fifo_source_is_rejected_without_blocking(self):
        fifo = self.directory / "source.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(UnsafePathError):
            VerifiedFileSource(fifo)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and bool(getattr(os, "O_NONBLOCK", 0)),
        "regular-to-FIFO race requires POSIX non-blocking open",
    )
    def test_regular_to_fifo_open_race_is_rejected_without_blocking(self):
        source = self.write_file("source.bin", b"replace before open")
        real_open = os.open

        def replace_then_open(path, flags, *args, **kwargs):
            if os.path.abspath(os.fspath(path)) == os.path.abspath(source):
                source.unlink()
                os.mkfifo(source, 0o600)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)

        with patch(
            "mokosh_v2_filesystem.os.open",
            side_effect=replace_then_open,
        ):
            with self.assertRaises(UnsafePathError):
                VerifiedFileSource(source)

    def test_missing_bytes_and_nul_paths_are_rejected(self):
        values = (
            self.directory / "missing.bin",
            os.fsencode(self.directory / "source.bin"),
            "bad\x00path",
            "",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(UnsafePathError):
                    VerifiedFileSource(value)

    def test_content_mutation_is_detected(self):
        path = self.write_file("source.bin", b"before")
        source = VerifiedFileSource(path)
        with path.open("ab") as handle:
            handle.write(b"after")
        with self.assertRaises(SourceChangedError):
            source.verify_unchanged()
        source.close()

    def test_path_replacement_is_detected(self):
        path = self.write_file("source.bin", b"before")
        source = VerifiedFileSource(path)
        path.rename(self.directory / "old.bin")
        self.write_file("source.bin", b"replacement")
        with self.assertRaises(SourceChangedError):
            source.verify_unchanged()
        source.close()

    def test_metadata_mutation_is_detected(self):
        path = self.write_file("source.bin")
        os.chmod(path, 0o600)
        source = VerifiedFileSource(path)
        os.chmod(path, 0o400)
        with self.assertRaises(SourceChangedError):
            source.verify_unchanged()
        source.close()

    def test_stream_scan_uses_verified_source(self):
        payload = bytes(range(251)) * 40
        path = self.write_file("source.bin", payload)
        with VerifiedFileSource(path) as source:
            plan = scan_plaintext_stream(
                source,
                chunk_size=MIN_CHUNK_SIZE,
            )
        self.assertEqual(plan.original_size, len(payload))


class ExclusiveFileQuarantineSinkTests(PrivateDirectoryTestCase):
    def test_private_journal_is_created_and_bound_without_user_names(self):
        final = self.directory / "highly-sensitive-output-name.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        journal = Path(sink.journal_path)
        self.assertTrue(journal.exists())
        self.assertEqual(journal.parent, final.parent)
        self.assertTrue(journal.name.startswith(".mokosh-operation-"))
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
        self.assertEqual(journal.stat().st_nlink, 1)
        self.assertEqual(
            journal.name.removeprefix(".mokosh-operation-").removesuffix(".json"),
            temp.name.removeprefix(".mokosh-quarantine-"),
        )
        data = journal.read_bytes().lower()
        self.assertNotIn(b"highly-sensitive-output-name", data)
        self.assertNotIn(b"output", data)
        self.assertNotIn(b"source", data)
        sink.abort()

    def test_commit_and_abort_remove_their_exact_journal(self):
        committed = ExclusiveFileQuarantineSink(self.directory / "done.mok")
        committed_journal = Path(committed.journal_path)
        committed.write(b"done")
        committed.commit()
        self.assertFalse(committed_journal.exists())
        aborted = ExclusiveFileQuarantineSink(self.directory / "cancelled.mok")
        aborted_journal = Path(aborted.journal_path)
        aborted.abort()
        self.assertFalse(aborted_journal.exists())

    def test_replaced_journal_blocks_publish_and_abort_deletes_nothing(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        journal = Path(sink.journal_path)
        moved = self.directory / "original-journal"
        journal.rename(moved)
        journal.write_bytes(b"foreign")
        os.chmod(journal, 0o600)
        with self.assertRaises(OwnedTemporaryFileError):
            sink.commit()
        with self.assertRaises(OwnedTemporaryFileError):
            sink.abort()
        self.assertTrue(temp.exists())
        self.assertEqual(journal.read_bytes(), b"foreign")
        self.assertTrue(moved.exists())
        self.assertFalse(final.exists())

    def test_modified_journal_blocks_publish_and_preserves_evidence(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        journal = Path(sink.journal_path)
        journal.write_bytes(journal.read_bytes() + b"\n")
        with self.assertRaises(OwnedTemporaryFileError):
            sink.commit()
        with self.assertRaises(OwnedTemporaryFileError):
            sink.abort()
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(journal.exists())
        self.assertFalse(final.exists())

    def test_journal_creation_failure_removes_allocated_temporary(self):
        final = self.directory / "result.mok"
        with patch.object(
            ExclusiveFileQuarantineSink,
            "_create_private_journal",
            side_effect=FilesystemSafetyError("forced"),
        ):
            with self.assertRaises(FilesystemSafetyError):
                ExclusiveFileQuarantineSink(final)
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])
        self.assertEqual(list(self.directory.glob(".mokosh-operation-*")), [])

    def test_directory_sync_failure_during_creation_removes_both_artifacts(self):
        final = self.directory / "result.mok"
        with patch(
            "mokosh_v2_filesystem._sync_directory",
            side_effect=FilesystemSafetyError("forced"),
        ):
            with self.assertRaises(FilesystemSafetyError):
                ExclusiveFileQuarantineSink(final)
        self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])
        self.assertEqual(list(self.directory.glob(".mokosh-operation-*")), [])

    def test_abort_journal_unlink_failure_is_loud_and_leaves_journal(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        journal = Path(sink.journal_path)
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-operation-"):
                raise OSError(errno.EIO, "forced")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            with self.assertRaises(OwnedTemporaryFileError):
                sink.abort()
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertTrue(journal.exists())
        self.assertFalse(final.exists())

    def test_commit_cleanup_failure_never_hides_published_output(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        journal = Path(sink.journal_path)
        sink.write(b"published")
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-operation-"):
                raise OSError(errno.EIO, "forced")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertEqual(final.read_bytes(), b"published")
        self.assertFalse(Path(sink.temp_path).exists())
        self.assertTrue(journal.exists())
        self.assertTrue(result.output_verified)
        self.assertTrue(result.publication_sync_complete)
        self.assertTrue(result.temporary_removed)
        self.assertFalse(result.journal_removed)
        self.assertFalse(result.cleanup_sync_complete)
        self.assertTrue(result.resources_closed)
        self.assertTrue(result.residue_requires_review)
        self.assertTrue(result.warning_required)

    def test_commit_temp_unlink_failure_returns_published_warning(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        journal = Path(sink.journal_path)
        sink.write(b"published")
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-quarantine-"):
                raise OSError(errno.EIO, "forced")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertEqual(final.read_bytes(), b"published")
        self.assertTrue(temp.exists())
        self.assertTrue(journal.exists())
        self.assertFalse(result.temporary_removed)
        self.assertFalse(result.journal_removed)
        self.assertTrue(result.residue_requires_review)
        self.assertTrue(result.warning_required)

    def test_commit_post_link_verification_failure_is_not_retryable_failure(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"published")
        real_stat = os.stat

        def selective_stat(path, *args, **kwargs):
            if path == final.name:
                raise OSError(errno.EIO, "forced")
            return real_stat(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.stat", side_effect=selective_stat):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertEqual(final.read_bytes(), b"published")
        self.assertIsNone(result.output_identity)
        self.assertFalse(result.output_verified)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())
        self.assertTrue(result.residue_requires_review)
        self.assertTrue(result.warning_required)

    def test_commit_unexpected_post_link_count_preserves_exact_residue(self):
        final = self.directory / "result.mok"
        extra = self.directory / "unexpected-link"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"published")
        real_link = os.link

        def link_then_duplicate(*args, **kwargs):
            result = real_link(*args, **kwargs)
            real_link(sink.temp_path, extra)
            return result

        with patch("mokosh_v2_filesystem.os.link", side_effect=link_then_duplicate):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertFalse(result.output_verified)
        self.assertTrue(result.residue_requires_review)
        self.assertTrue(Path(sink.temp_path).exists())
        self.assertTrue(Path(sink.journal_path).exists())
        self.assertEqual(final.read_bytes(), b"published")
        self.assertEqual(extra.read_bytes(), b"published")

    def test_clean_commit_returns_fully_verified_result(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"published")
        sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.output_identity)
        self.assertEqual(result.output_identity.device, sink._sealed_identity.device)
        self.assertEqual(result.output_identity.inode, sink._sealed_identity.inode)
        self.assertEqual(result.output_identity.size, sink._sealed_identity.size)
        self.assertTrue(result.output_verified)
        self.assertTrue(result.publication_sync_complete)
        self.assertTrue(result.temporary_removed)
        self.assertTrue(result.journal_removed)
        self.assertTrue(result.cleanup_sync_complete)
        self.assertTrue(result.resources_closed)
        self.assertFalse(result.residue_requires_review)
        self.assertFalse(result.warning_required)

    def test_commit_resource_close_failure_is_a_post_publish_warning(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"published")
        real_close = sink._close_runtime_resources

        def close_with_reported_failure():
            real_close()
            return OSError(errno.EIO, "forced")

        with patch.object(
            sink,
            "_close_runtime_resources",
            side_effect=close_with_reported_failure,
        ):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertEqual(final.read_bytes(), b"published")
        self.assertFalse(result.resources_closed)
        self.assertFalse(result.residue_requires_review)
        self.assertTrue(result.warning_required)

    def test_commit_publish_sync_failure_preserves_exact_residue(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        journal = Path(sink.journal_path)
        sink.write(b"published")

        with patch(
            "mokosh_v2_filesystem._sync_directory",
            side_effect=FilesystemSafetyError("forced"),
        ):
            sink.commit()
        result = sink.publish_result
        self.assertIsNotNone(result)
        self.assertEqual(final.read_bytes(), b"published")
        self.assertFalse(result.publication_sync_complete)
        self.assertTrue(temp.exists())
        self.assertTrue(journal.exists())
        self.assertTrue(result.residue_requires_review)
        self.assertTrue(result.warning_required)

    def test_private_same_directory_temp_is_not_public_until_commit(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        self.assertEqual(temp.parent, final.parent)
        self.assertTrue(temp.name.startswith(".mokosh-quarantine-"))
        self.assertEqual(stat.S_IMODE(temp.stat().st_mode), 0o600)
        self.assertFalse(final.exists())
        self.assertEqual(sink.write(b"ciphertext"), 10)
        self.assertFalse(final.exists())
        sink.commit()
        self.assertEqual(final.read_bytes(), b"ciphertext")
        self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o600)
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertFalse(temp.exists())
        self.assertTrue(sink.committed)

    def test_abort_removes_only_temp_and_is_idempotent(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        sink.write(b"secret")
        sink.abort()
        sink.abort()
        self.assertFalse(temp.exists())
        self.assertFalse(final.exists())
        self.assertTrue(sink.aborted)

    def test_context_manager_aborts_uncommitted_output(self):
        final = self.directory / "result.mok"
        with ExclusiveFileQuarantineSink(final) as sink:
            temp = Path(sink.temp_path)
            sink.write(b"secret")
        self.assertFalse(temp.exists())
        self.assertFalse(final.exists())

    def test_existing_final_regular_file_and_symlink_are_rejected(self):
        existing = self.write_file("existing.mok", b"keep")
        with self.assertRaises(OutputCollisionError):
            ExclusiveFileQuarantineSink(existing)
        target = self.write_file("target.mok", b"keep")
        link = self.directory / "linked.mok"
        link.symlink_to(target)
        with self.assertRaises(OutputCollisionError):
            ExclusiveFileQuarantineSink(link)

    def test_late_output_collision_does_not_overwrite(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"new")
        final.write_bytes(b"existing")
        with self.assertRaises(OutputCollisionError):
            sink.commit()
        sink.abort()
        self.assertEqual(final.read_bytes(), b"existing")

    def test_symlink_and_public_parent_directories_are_rejected(self):
        real = self.directory / "real"
        real.mkdir(mode=0o700)
        link = self.directory / "linked"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(UnsafePathError):
            ExclusiveFileQuarantineSink(link / "out.mok")
        os.chmod(real, 0o777)
        with self.assertRaises(UnsafePathError):
            ExclusiveFileQuarantineSink(real / "out.mok")

    def test_replaced_temp_is_not_deleted_by_abort(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        moved = self.directory / "owned-moved-aside"
        temp.rename(moved)
        temp.write_bytes(b"foreign")
        with self.assertRaises(OwnedTemporaryFileError):
            sink.abort()
        self.assertEqual(temp.read_bytes(), b"foreign")
        self.assertTrue(moved.exists())
        self.assertFalse(final.exists())

    def test_replaced_temp_is_not_published(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        temp = Path(sink.temp_path)
        moved = self.directory / "owned-moved-aside"
        temp.rename(moved)
        temp.symlink_to(self.write_file("foreign", b"foreign"))
        with self.assertRaises(OwnedTemporaryFileError):
            sink.commit()
        with self.assertRaises(OwnedTemporaryFileError):
            sink.abort()
        self.assertFalse(final.exists())

    def test_added_hardlink_or_changed_mode_blocks_publish(self):
        for attack in ("hardlink", "mode"):
            with self.subTest(attack=attack):
                final = self.directory / f"{attack}.mok"
                sink = ExclusiveFileQuarantineSink(final)
                temp = Path(sink.temp_path)
                if attack == "hardlink":
                    os.link(temp, self.directory / "attacker-link")
                else:
                    os.chmod(temp, 0o644)
                with self.assertRaises(OwnedTemporaryFileError):
                    sink.commit()
                with self.assertRaises(OwnedTemporaryFileError):
                    sink.abort()

    def test_replaced_parent_path_blocks_commit(self):
        parent = self.directory / "private"
        parent.mkdir(mode=0o700)
        final = parent / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"ciphertext")
        parent.rename(self.directory / "private-moved")
        parent.mkdir(mode=0o700)
        with self.assertRaises(UnsafePathError):
            sink.commit()
        sink.abort()
        self.assertFalse(final.exists())

    def test_unsupported_atomic_link_fails_closed(self):
        final = self.directory / "result.mok"
        sink = ExclusiveFileQuarantineSink(final)
        sink.write(b"ciphertext")
        with patch(
            "mokosh_v2_filesystem.os.link",
            side_effect=OSError(errno.EPERM, "not supported"),
        ):
            with self.assertRaises(AtomicPublishUnsupportedError):
                sink.commit()
        sink.abort()
        self.assertFalse(final.exists())

    def test_file_and_directory_sync_are_requested(self):
        final = self.directory / "result.mok"
        real_fsync = os.fsync
        calls = []

        def recording_fsync(descriptor):
            calls.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
            return real_fsync(descriptor)

        with patch("mokosh_v2_filesystem.os.fsync", side_effect=recording_fsync):
            sink = ExclusiveFileQuarantineSink(final)
            sink.write(b"ciphertext")
            sink.commit()
        self.assertIn(stat.S_IFREG, calls)
        self.assertIn(stat.S_IFDIR, calls)

    def test_unsupported_directory_sync_is_tolerated(self):
        final = self.directory / "result.mok"
        real_fsync = os.fsync

        def selective_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EINVAL, "directory fsync unsupported")
            return real_fsync(descriptor)

        with patch("mokosh_v2_filesystem.os.fsync", side_effect=selective_fsync):
            sink = ExclusiveFileQuarantineSink(final)
            sink.write(b"ciphertext")
            sink.commit()
        self.assertEqual(final.read_bytes(), b"ciphertext")

    def test_invalid_writes_and_writes_after_end_are_rejected(self):
        sink = ExclusiveFileQuarantineSink(self.directory / "result.mok")
        with self.assertRaises(FilesystemSafetyError):
            sink.write("not bytes")
        self.assertEqual(sink.write(b""), 0)
        sink.abort()
        with self.assertRaises(FilesystemSafetyError):
            sink.write(b"late")


class FilesystemStreamingIntegrationTests(PrivateDirectoryTestCase):
    def build_plan(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        slot = builder.add_vault(VAULT_KEY, 4)
        return builder.finish(), slot

    def test_encrypt_and_decrypt_via_verified_quarantine_files(self):
        payload = (bytes(range(251)) * 70) + b"final"
        plaintext = self.write_file("plain.bin", payload)
        encrypted = self.directory / "plain.bin.mok"
        restored = self.directory / "restored.bin"
        key_plan, slot = self.build_plan()

        with VerifiedFileSource(plaintext) as first_plaintext:
            stream_plan = scan_plaintext_stream(
                first_plaintext,
                chunk_size=MIN_CHUNK_SIZE,
            )
        with VerifiedFileSource(plaintext) as second_plaintext:
            with ExclusiveFileQuarantineSink(encrypted) as encrypted_sink:
                encrypt_stream_to_quarantine(
                    key_plan=key_plan,
                    plaintext_source=second_plaintext,
                    sink=encrypted_sink,
                    stream_plan=stream_plan,
                    original_name="plain.bin",
                    signing=UnsignedEnvelopeSigning(),
                    created_utc=CREATED_UTC,
                )
        self.assertEqual(plaintext.read_bytes(), payload)

        with VerifiedFileSource(encrypted) as first_envelope:
            inspection = inspect_envelope_stream(
                first_envelope,
                verification=RequireUnsignedEnvelope(),
            )
        with VerifiedFileSource(encrypted) as second_envelope:
            with ExclusiveFileQuarantineSink(restored) as restored_sink:
                result = decrypt_stream_to_quarantine(
                    envelope_source=second_envelope,
                    sink=restored_sink,
                    inspection=inspection,
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                )
        self.assertEqual(result.plaintext_size, len(payload))
        self.assertEqual(restored.read_bytes(), payload)
        self.assertEqual(plaintext.read_bytes(), payload)
        self.assertTrue(encrypted.exists())

    def test_second_pass_source_change_is_detected_after_stream_operation(self):
        path = self.write_file("source.bin", b"A" * MIN_CHUNK_SIZE)
        source = VerifiedFileSource(path)
        with path.open("ab") as handle:
            handle.write(b"changed")
        with self.assertRaises(SourceChangedError):
            source.verify_and_close()


if __name__ == "__main__":
    unittest.main()
