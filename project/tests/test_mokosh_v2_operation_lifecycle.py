import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from mokosh_v2_complete_envelope import (
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
)
from mokosh_v2_format import MIN_CHUNK_SIZE
from mokosh_v2_operation_lifecycle import (
    CancellationToken,
    DECRYPT_PHASES,
    ENCRYPT_PHASES,
    OperationErrorCode,
    OperationKind,
    OperationLifecycle,
    OperationLifecycleError,
    OperationPhase,
    OperationWarningCode,
    ProgressState,
    run_decryption_operation,
    run_encryption_operation,
)
from mokosh_v2_slot_orchestration import KeySlotPlanBuilder, VaultCredential


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
VAULT_KEY = b"V" * 32
CREATED_UTC = "2026-08-09T12:00:00Z"


class LifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)
        os.chmod(self.directory, 0o700)
        self.source = self.directory / "private-name.bin"
        self.source.write_bytes(bytes(range(251)) * 100)
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        self.slot = builder.add_vault(VAULT_KEY, 7)
        self.plan = builder.finish()

    def tearDown(self):
        self._temporary.cleanup()

    def encrypt_arguments(self, output=None):
        return dict(
            source_path=self.source,
            output_path=output or self.directory / "private-name.bin.mok",
            key_plan=self.plan,
            original_name="private-name.bin",
            signing=UnsignedEnvelopeSigning(),
            created_utc=CREATED_UTC,
            chunk_size=MIN_CHUNK_SIZE,
        )

    def encrypted_file(self):
        outcome = run_encryption_operation(**self.encrypt_arguments())
        self.assertTrue(outcome.ok)
        return self.directory / "private-name.bin.mok"


class LifecycleContractTests(LifecycleTestCase):
    def test_encryption_emits_exact_order_and_success_only_after_publish(self):
        events = []
        output = self.directory / "result.mok"

        def observer(event):
            if event.phase is OperationPhase.COMPLETE:
                self.assertTrue(output.exists())
            events.append(event)

        outcome = run_encryption_operation(
            observer=observer,
            **self.encrypt_arguments(output),
        )
        self.assertTrue(outcome.ok)
        expected = []
        for phase in ENCRYPT_PHASES:
            expected.extend(((phase, ProgressState.STARTED), (phase, ProgressState.COMPLETED)))
        expected.append((OperationPhase.COMPLETE, ProgressState.COMPLETED))
        self.assertEqual([(e.phase, e.state) for e in events], expected)
        self.assertEqual([e.sequence for e in events], list(range(1, 12)))

    def test_decryption_emits_exact_order(self):
        encrypted = self.encrypted_file()
        events = []
        restored = self.directory / "restored.bin"
        outcome = run_decryption_operation(
            source_path=encrypted,
            output_path=restored,
            verification=RequireUnsignedEnvelope(),
            selected_slot_id=self.slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            observer=events.append,
        )
        self.assertTrue(outcome.ok)
        expected = []
        for phase in DECRYPT_PHASES:
            expected.extend(((phase, ProgressState.STARTED), (phase, ProgressState.COMPLETED)))
        expected.append((OperationPhase.COMPLETE, ProgressState.COMPLETED))
        self.assertEqual([(e.phase, e.state) for e in events], expected)
        self.assertEqual(restored.read_bytes(), self.source.read_bytes())

    def test_events_contain_no_names_paths_sizes_keys_or_free_text(self):
        events = []
        outcome = run_encryption_operation(
            observer=events.append,
            **self.encrypt_arguments(self.directory / "safe.mok"),
        )
        self.assertTrue(outcome.ok)
        for event in events:
            self.assertEqual(
                set(event.__slots__),
                {"kind", "phase", "state", "sequence"},
            )
            rendered = repr(event)
            for secret in ("private-name", str(self.directory), "VVVV", "001122"):
                self.assertNotIn(secret, rendered)

    def test_lifecycle_rejects_duplicate_and_out_of_order_phases(self):
        with self.assertRaises(OperationLifecycleError):
            OperationLifecycle(
                OperationKind.ENCRYPT,
                (OperationPhase.SCAN, OperationPhase.SCAN),
            )
        lifecycle = OperationLifecycle(OperationKind.ENCRYPT, ENCRYPT_PHASES)
        with self.assertRaises(OperationLifecycleError):
            lifecycle.start(OperationPhase.SCAN)

    def test_cancel_before_start_returns_stable_code_without_output(self):
        token = CancellationToken()
        token.cancel()
        output = self.directory / "cancelled.mok"
        outcome = run_encryption_operation(
            cancellation=token,
            **self.encrypt_arguments(output),
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.code, OperationErrorCode.CANCELLED)
        self.assertFalse(output.exists())
        self.assertEqual(self.source.read_bytes(), bytes(range(251)) * 100)

    def test_cancel_at_every_pre_publish_phase_aborts_quarantine(self):
        for target in ENCRYPT_PHASES[:-1] + (OperationPhase.PUBLISH,):
            with self.subTest(phase=target.value):
                output = self.directory / f"cancel-{target.value}.mok"
                token = CancellationToken()

                def observer(event):
                    if event.phase is target and event.state is ProgressState.STARTED:
                        token.cancel()

                outcome = run_encryption_operation(
                    cancellation=token,
                    observer=observer,
                    **self.encrypt_arguments(output),
                )
                self.assertFalse(outcome.ok)
                self.assertEqual(outcome.failure.code, OperationErrorCode.CANCELLED)
                self.assertFalse(output.exists())
                self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_fault_injection_at_every_pre_publish_phase_fails_closed(self):
        for target in ENCRYPT_PHASES:
            with self.subTest(phase=target.value):
                output = self.directory / f"fault-{target.value}.mok"

                def observer(event):
                    if event.phase is target and event.state is ProgressState.STARTED:
                        raise RuntimeError("injected secret text")

                outcome = run_encryption_operation(
                    observer=observer,
                    **self.encrypt_arguments(output),
                )
                self.assertFalse(outcome.ok)
                self.assertEqual(outcome.failure.code, OperationErrorCode.INTERNAL_ERROR)
                self.assertNotIn("secret", repr(outcome.failure).lower())
                self.assertFalse(output.exists())
                self.assertEqual(list(self.directory.glob(".mokosh-quarantine-*")), [])

    def test_decryption_cancel_and_fault_injection_cover_every_phase(self):
        encrypted = self.encrypted_file()
        for target in DECRYPT_PHASES:
            for mode in ("cancel", "fault"):
                with self.subTest(phase=target.value, mode=mode):
                    output = self.directory / f"dec-{target.value}-{mode}.bin"
                    token = CancellationToken()

                    def observer(event):
                        if event.phase is target and event.state is ProgressState.STARTED:
                            if mode == "cancel":
                                token.cancel()
                            else:
                                raise RuntimeError("injected")

                    outcome = run_decryption_operation(
                        source_path=encrypted,
                        output_path=output,
                        verification=RequireUnsignedEnvelope(),
                        selected_slot_id=self.slot.slot_id,
                        credential=VaultCredential(VAULT_KEY),
                        cancellation=token,
                        observer=observer,
                    )
                    self.assertFalse(outcome.ok)
                    expected = (
                        OperationErrorCode.CANCELLED
                        if mode == "cancel"
                        else OperationErrorCode.INTERNAL_ERROR
                    )
                    self.assertEqual(outcome.failure.code, expected)
                    self.assertFalse(output.exists())
                    self.assertEqual(
                        list(self.directory.glob(".mokosh-quarantine-*")),
                        [],
                    )

    def test_late_output_collision_has_specific_safe_code(self):
        output = self.directory / "exists.mok"
        output.write_bytes(b"foreign")
        outcome = run_encryption_operation(**self.encrypt_arguments(output))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.code, OperationErrorCode.OUTPUT_COLLISION)
        self.assertEqual(output.read_bytes(), b"foreign")

    def test_wrong_credential_never_publishes_and_has_no_exception_text(self):
        encrypted = self.encrypted_file()
        restored = self.directory / "wrong.bin"
        outcome = run_decryption_operation(
            source_path=encrypted,
            output_path=restored,
            verification=RequireUnsignedEnvelope(),
            selected_slot_id=self.slot.slot_id,
            credential=VaultCredential(b"W" * 32),
        )
        self.assertFalse(outcome.ok)
        self.assertFalse(restored.exists())
        self.assertNotIn("wrong", repr(outcome.failure).lower())
        self.assertTrue(outcome.failure.message_key.startswith("operation.error."))

    def test_cancel_after_complete_does_not_retract_published_success(self):
        token = CancellationToken()
        output = self.directory / "published.mok"

        def observer(event):
            if event.phase is OperationPhase.COMPLETE:
                token.cancel()

        outcome = run_encryption_operation(
            cancellation=token,
            observer=observer,
            **self.encrypt_arguments(output),
        )
        self.assertTrue(outcome.ok)
        self.assertTrue(output.exists())

    def test_post_publish_observer_fault_never_reclassifies_success(self):
        for target in (OperationPhase.PUBLISH, OperationPhase.COMPLETE):
            for fault in (RuntimeError, KeyboardInterrupt):
                with self.subTest(target=target.value, fault=fault.__name__):
                    output = self.directory / (
                        f"observer-{target.value}-{fault.__name__}.mok"
                    )

                    def observer(event):
                        if (
                            event.phase is target
                            and event.state is ProgressState.COMPLETED
                        ):
                            raise fault("private observer text")

                    outcome = run_encryption_operation(
                        observer=observer,
                        **self.encrypt_arguments(output),
                    )
                    self.assertTrue(outcome.ok)
                    self.assertIsNone(outcome.failure)
                    self.assertTrue(output.exists())

    def test_post_publish_cleanup_fault_is_success_with_nonretry_warning(self):
        output = self.directory / "published-once.mok"
        events = []
        real_unlink = os.unlink

        def selective_unlink(path, *args, **kwargs):
            if str(path).startswith(".mokosh-operation-"):
                raise OSError("secret injected text")
            return real_unlink(path, *args, **kwargs)

        with patch("mokosh_v2_filesystem.os.unlink", side_effect=selective_unlink):
            outcome = run_encryption_operation(
                observer=events.append,
                **self.encrypt_arguments(output),
            )
        self.assertTrue(outcome.ok)
        self.assertIsNone(outcome.failure)
        self.assertIsNotNone(outcome.warning)
        self.assertEqual(
            outcome.warning.code,
            OperationWarningCode.PUBLISHED_CLEANUP_INCOMPLETE,
        )
        self.assertNotIn("secret", repr(outcome.warning).lower())
        self.assertTrue(output.exists())
        self.assertIn(
            (OperationPhase.PUBLISH, ProgressState.COMPLETED),
            [(event.phase, event.state) for event in events],
        )
        self.assertEqual(events[-1].phase, OperationPhase.COMPLETE)


class LifecycleScopeTests(unittest.TestCase):
    def test_module_has_no_gui_network_logging_paths_or_secret_fields(self):
        import mokosh_v2_operation_lifecycle

        source = inspect.getsource(mokosh_v2_operation_lifecycle)
        for forbidden in (
            "tkinter",
            "socket",
            "requests",
            "logging",
            "print(",
            "os.remove",
            "os.unlink",
            "source_path",
            "output_path",
            "file_name",
            "byte_count",
            "private_key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
