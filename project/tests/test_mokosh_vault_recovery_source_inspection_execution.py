import ast
import copy
from dataclasses import fields
import hashlib
import inspect
import os
from pathlib import Path
import pickle
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import mokosh_vault_recovery as recovery
import mokosh_vault_recovery_entry_request as entry
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_preparation_request as preparation
import mokosh_vault_recovery_source_inspection_request as request
import mokosh_vault_recovery_source_selection as selection
import mokosh_vault_recovery_storage as storage


ROOT = Path(__file__).resolve().parents[1]
RECOVERY_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_RECOVERY_ID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
VAULT_ID = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
SOURCE_HASH = hashlib.sha256(b"synthetic source Vault").digest()
CREATED = "2026-08-27T12:00:00Z"


def stage31_outcome(locale="bg-BG", *, requested=True, path=None):
    first = entry.prepare_recovery_entry_request(locale).decide_once(
        entry.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    moved = transition.prepare_recovery_entry_transition(first).decide_once(
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )
    chosen_path = path or (
        "/private/mokosh-vault-recovery-00112233445566778899aabbccddeeff.mokr"
        if locale == "bg-BG"
        else "/private/възстановяване/mokosh-vault-recovery-00112233445566778899aabbccddeeff.mokr"
    )
    chosen = selection.prepare_recovery_source_selection(moved).decide_once(
        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        chosen_path,
    )
    inspection = request.prepare_recovery_source_inspection_request(chosen).decide_once(
        request.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
    )
    prepared = preparation.prepare_recovery_source_inspection_preparation_request(
        inspection
    )
    decision = (
        preparation.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        if requested
        else preparation.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
    )
    return prepared.decide_once(decision)


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


def synthetic_record(recovery_id=RECOVERY_ID):
    header = recovery._canonical_json(
        recovery._header_mapping(
            recovery_id=recovery_id,
            vault_id=VAULT_ID,
            source_revision=7,
            source_vault_sha256=SOURCE_HASH,
            created_utc=CREATED,
            nonce=b"N" * recovery.RECOVERY_NONCE_LEN,
        ),
        "test recovery header",
    )
    ciphertext = b"unauthenticated" + b"X" * recovery.RECOVERY_GCM_TAG_LEN
    preamble = recovery.RECOVERY_PREAMBLE_STRUCT.pack(
        recovery.RECOVERY_MAGIC,
        recovery.RECOVERY_MAJOR_VERSION,
        recovery.RECOVERY_MINOR_VERSION,
        recovery.RECOVERY_FLAGS,
        len(header),
        len(ciphertext),
    )
    return preamble + header + ciphertext


def evidence_imported(record=None):
    encoded = record or synthetic_record()
    return SimpleNamespace(
        record=encoded,
        parsed=recovery.parse_recovery_record(encoded),
        directory_device=1,
        directory_inode=2,
        file_device=3,
        file_inode=4,
        encoded_size=len(encoded),
        record_sha256=hashlib.sha256(encoded).digest(),
    )


class ExecutionUnitTests(unittest.TestCase):
    def positive(self, locale="bg-BG"):
        return execution.prepare_recovery_source_inspection_execution(
            stage31_outcome(locale)
        )

    def inspect_with_mock(self, locale="bg-BG"):
        with mock.patch.object(
            execution, "_read_source_once", return_value=evidence_imported()
        ):
            return self.positive(locale).decide_once(
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
            )

    def test_01_bulgarian_preserve_returns_bounded_stop(self):
        result = self.positive().decide_once(
            execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
        )
        self.assertEqual(result.locale.value, "bg-BG")
        self.assertTrue(result.preserved_and_stopped)
        self.assertFalse(result.secure_source_inspection_performed)

    def test_02_english_preserve_returns_bounded_stop(self):
        result = self.positive("en-GB").decide_once(
            execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
        )
        self.assertEqual(result.locale.value, "en-GB")
        self.assertIsNone(result.recovery_id)
        self.assertFalse(result.header_structurally_validated)

    def test_03_bulgarian_positive_returns_exact_inspection_evidence(self):
        result = self.inspect_with_mock()
        self.assertEqual(result.recovery_id, RECOVERY_ID)
        self.assertEqual(result.vault_id, VAULT_ID)
        self.assertEqual(result.source_revision, 7)
        self.assertEqual(result.source_vault_sha256, SOURCE_HASH)

    def test_04_english_positive_preserves_locale_not_path(self):
        result = self.inspect_with_mock("en-GB")
        self.assertEqual(result.locale.value, "en-GB")
        self.assertFalse(result.source_path_metadata_retained)

    def test_05_source_requires_exact_stage31_outcome_type(self):
        exact = stage31_outcome()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, "source", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    execution.VaultRecoverySourceInspectionExecutionSourceError
                ):
                    execution.prepare_recovery_source_inspection_execution(invalid)

    def test_06_preserved_stage31_outcome_is_rejected(self):
        with self.assertRaises(
            execution.VaultRecoverySourceInspectionExecutionSourceError
        ):
            execution.prepare_recovery_source_inspection_execution(
                stage31_outcome(requested=False)
            )

    def test_07_forged_stage31_claims_are_revalidated(self):
        exact = stage31_outcome()
        for change in (
            {"future_secure_source_inspection_preparation_requested": False},
            {"selected_path": "/tmp/../record.mokr"},
            {"source_opened": True},
            {"operation_authorized": True},
            {"format": "WRONG"},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    execution.VaultRecoverySourceInspectionExecutionSourceError
                ):
                    execution.prepare_recovery_source_inspection_execution(
                        forged_copy(exact, **change)
                    )

    def test_08_prepared_retains_path_but_not_original_outcome(self):
        source = stage31_outcome()
        prepared = execution.prepare_recovery_source_inspection_execution(source)
        self.assertTrue(prepared.retains_source_path_metadata)
        self.assertIsNone(prepared.outcome)
        self.assertNotIn(
            source,
            (getattr(prepared, name) for name in prepared.__slots__ if name != "_lock"),
        )

    def test_09_public_constants_enums_and_signatures_are_exact(self):
        self.assertEqual(
            execution.RECOVERY_SOURCE_INSPECTION_EXECUTION_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_EXECUTION",
        )
        self.assertEqual(execution.RECOVERY_SOURCE_INSPECTION_EXECUTION_VERSION, 1)
        self.assertEqual(execution.RECOVERY_SOURCE_INSPECTION_EXECUTION_SEQUENCE, 1)
        self.assertEqual(
            tuple(execution.RecoverySourceInspectionExecutionDecision),
            (
                execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP,
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION,
            ),
        )
        self.assertEqual(
            tuple(inspect.signature(execution.prepare_recovery_source_inspection_execution).parameters),
            ("preparation_request_outcome",),
        )

    def test_10_invalid_decision_does_not_consume_fresh_object(self):
        prepared = self.positive()
        for invalid in (None, "authorize_one_secure_source_inspection", 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    execution.VaultRecoverySourceInspectionExecutionDecisionError
                ):
                    prepared.decide_once(invalid)
                self.assertTrue(prepared.retains_source_path_metadata)

    def test_11_preserve_never_loads_or_calls_secure_reader(self):
        prepared = self.positive()
        with mock.patch.object(execution, "_read_source_once") as reader:
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
            )
        reader.assert_not_called()

    def test_12_positive_calls_secure_reader_exactly_once(self):
        prepared = self.positive()
        with mock.patch.object(
            execution, "_read_source_once", return_value=evidence_imported()
        ) as reader:
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
            )
        reader.assert_called_once()

    def test_13_success_is_terminal_against_replay(self):
        prepared = self.positive()
        with mock.patch.object(
            execution, "_read_source_once", return_value=evidence_imported()
        ):
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
            )
        with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionReplayError):
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
            )

    def test_14_preserve_is_terminal_against_replay(self):
        prepared = self.positive()
        prepared.decide_once(
            execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
        )
        with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionReplayError):
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
            )

    def test_15_concurrency_has_exactly_one_success(self):
        prepared = self.positive()
        barrier = threading.Barrier(8)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                successes.append(
                    prepared.decide_once(
                        execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
                    )
                )
            except execution.VaultRecoverySourceInspectionExecutionReplayError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(successes), len(failures)), (1, 7))

    def test_16_ordinary_reader_failure_is_terminal(self):
        prepared = self.positive()
        with mock.patch.object(execution, "_read_source_once", side_effect=ValueError("fail")):
            with self.assertRaises(ValueError):
                prepared.decide_once(
                    execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                )
        self.assertIs(prepared.current_state, execution.RecoverySourceInspectionExecutionState.FAILED)
        with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionReplayError):
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP
            )

    def test_17_baseexception_reader_failure_is_terminal(self):
        prepared = self.positive()
        with mock.patch.object(execution, "_read_source_once", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                prepared.decide_once(
                    execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                )
        self.assertIs(prepared.current_state, execution.RecoverySourceInspectionExecutionState.FAILED)
        self.assertFalse(prepared.retains_source_path_metadata)

    def test_18_path_is_cleared_before_secure_reader_begins(self):
        prepared = self.positive()

        def assert_cleared(path):
            self.assertIsInstance(path, str)
            self.assertFalse(prepared.retains_source_path_metadata)
            self.assertIs(prepared.current_state, execution.RecoverySourceInspectionExecutionState.FAILED)
            return evidence_imported()

        with mock.patch.object(execution, "_read_source_once", side_effect=assert_cleared):
            prepared.decide_once(
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
            )

    def test_19_failure_retains_no_path_and_publishes_no_outcome(self):
        prepared = self.positive()
        with mock.patch.object(execution, "_read_source_once", side_effect=OSError("fail")):
            with self.assertRaises(OSError):
                prepared.decide_once(
                    execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                )
        self.assertFalse(prepared.retains_source_path_metadata)
        self.assertIsNone(prepared.outcome)

    def test_20_prepared_repr_hides_selected_path(self):
        source = stage31_outcome()
        prepared = execution.prepare_recovery_source_inspection_execution(source)
        self.assertNotIn(source.selected_path, repr(prepared))
        self.assertNotIn(RECOVERY_ID.hex(), repr(prepared))

    def test_21_prepared_refuses_copy_deepcopy_and_pickle(self):
        prepared = self.positive()
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionReplayError):
                operation()

    def test_22_outcome_repr_hides_all_evidence_values(self):
        result = self.inspect_with_mock()
        rendered = repr(result)
        for hidden in (RECOVERY_ID.hex(), VAULT_ID.hex(), SOURCE_HASH.hex(), str(result.encoded_size)):
            self.assertNotIn(hidden, rendered)

    def test_23_outcome_refuses_copy_deepcopy_and_pickle(self):
        result = self.inspect_with_mock()
        for operation in (
            lambda: copy.copy(result),
            lambda: copy.deepcopy(result),
            lambda: pickle.dumps(result),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_24_schema_contains_no_path_descriptor_or_content_field(self):
        names = {item.name for item in fields(execution.VaultRecoverySourceInspectionExecutionOutcome)}
        self.assertTrue(
            names.isdisjoint(
                {"path", "selected_path", "descriptor", "record", "header_bytes", "preamble_bytes", "nonce", "ciphertext", "recovery_key", "password", "plaintext"}
            )
        )

    def test_25_success_evidence_hash_and_size_are_exact(self):
        encoded = synthetic_record()
        with mock.patch.object(
            execution, "_read_source_once", return_value=evidence_imported(encoded)
        ):
            result = self.positive().decide_once(
                execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
            )
        self.assertEqual(result.record_sha256, hashlib.sha256(encoded).digest())
        self.assertEqual(result.encoded_size, len(encoded))

    def test_26_success_states_honest_unauthenticated_non_authority_semantics(self):
        result = self.inspect_with_mock()
        self.assertTrue(result.header_structurally_validated)
        for name in (
            "cryptographically_authenticated", "recovery_secret_received", "recovery_performed",
            "rehearsal_performed", "stage2_8_used", "review_session_prepared",
            "operation_authorized", "operation_performed", "filesystem_mutation_performed",
            "network_used", "logging_used", "gui_used", "memory_zeroization_proven",
            "filesystem_identity_future_validity_claimed",
        ):
            self.assertIs(getattr(result, name), False, name)

    def test_27_forged_outcome_evidence_is_rejected(self):
        exact = self.inspect_with_mock()
        for change in (
            {"recovery_id": b"short"}, {"vault_id": None}, {"source_revision": 0},
            {"source_vault_sha256": b"x" * 31}, {"record_sha256": b"x" * 33},
            {"encoded_size": execution.RECOVERY_SOURCE_INSPECTION_MAX_ENCODED_SIZE + 1},
        ):
            with self.subTest(change=change):
                with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionFormatError):
                    execution._validate_source_inspection_execution_outcome(forged_copy(exact, **change))

    def test_28_forged_outcome_boolean_types_and_claims_are_rejected(self):
        exact = self.inspect_with_mock()
        for change in (
            {"secure_source_inspection_performed": 1},
            {"header_structurally_validated": 1},
            {"cryptographically_authenticated": True},
            {"operation_authorized": True},
            {"memory_zeroization_proven": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionFormatError):
                    execution._validate_source_inspection_execution_outcome(forged_copy(exact, **change))

    def test_29_forged_outcome_sequences_and_schema_are_rejected(self):
        exact = self.inspect_with_mock()
        for change in (
            {"preparation_request_sequence": 2}, {"execution_sequence": 2},
            {"exact_preparation_request_outcome_validated": False},
            {"one_shot": False}, {"format": "WRONG"}, {"version": 2},
        ):
            with self.subTest(change=change):
                with self.assertRaises(execution.VaultRecoverySourceInspectionExecutionFormatError):
                    execution._validate_source_inspection_execution_outcome(forged_copy(exact, **change))

    def test_30_fresh_import_does_not_load_privileged_storage(self):
        code = (
            "import sys; import mokosh_vault_recovery_source_inspection_execution; "
            "print('mokosh_vault_recovery_storage' in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        self.assertEqual(result.stdout.strip(), "False")

    def test_31_import_closure_keeps_storage_import_conditional(self):
        tree = ast.parse((ROOT / "mokosh_vault_recovery_source_inspection_execution.py").read_text(encoding="utf-8"))
        top = set()
        nested_storage = []
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                top.add(node.module)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "mokosh_vault_recovery_storage":
                nested_storage.append(node)
        self.assertNotIn("mokosh_vault_recovery_storage", top)
        self.assertEqual(len(nested_storage), 1)
        self.assertIsInstance(getattr(nested_storage[0], "parent", None), type(None))

    def test_32_module_has_no_gui_network_logging_or_mutation_capability(self):
        source = (ROOT / "mokosh_vault_recovery_source_inspection_execution.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            node.module for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(imports.isdisjoint({"mokosh_gui", "socket", "subprocess", "logging", "mokosh_vault_recovery_reconciliation"}))
        called = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(called.isdisjoint({"write", "unlink", "remove", "replace", "rename"}))


class ExecutionFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix="mokosh-stage2-32-")
        self.directory = Path(self.context.name)
        os.chmod(self.directory, 0o700)
        self.record = synthetic_record()
        self.path = self.directory / storage.recovery_record_name(RECOVERY_ID)
        self.path.write_bytes(self.record)
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self.context.cleanup()

    def prepared(self, path=None):
        return execution.prepare_recovery_source_inspection_execution(
            stage31_outcome(path=str(path or self.path))
        )

    def inspect(self, path=None):
        return self.prepared(path).decide_once(
            execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
        )

    def test_33_real_private_0700_0600_record_inspects_successfully(self):
        result = self.inspect()
        self.assertEqual(result.recovery_id, RECOVERY_ID)
        self.assertEqual(result.record_sha256, hashlib.sha256(self.record).digest())
        self.assertEqual(result.encoded_size, len(self.record))
        self.assertFalse(result.cryptographically_authenticated)

    def test_34_parent_mode_and_owner_mismatch_are_rejected(self):
        os.chmod(self.directory, 0o755)
        with self.assertRaises(storage.UnsafeRecoveryDirectoryError):
            self.inspect()
        os.chmod(self.directory, 0o700)
        with mock.patch.object(storage, "_current_uid", return_value=os.getuid() + 1):
            with self.assertRaises(storage.UnsafeRecoveryDirectoryError):
                self.inspect()

    def test_35_file_mode_and_owner_mismatch_are_rejected(self):
        os.chmod(self.path, 0o644)
        with self.assertRaises(storage.RecoveryFileConflictError):
            self.inspect()
        os.chmod(self.path, 0o600)
        current = os.getuid()
        with mock.patch.object(
            storage,
            "_current_uid",
            side_effect=[current, current + 1],
        ):
            with self.assertRaises(storage.RecoveryFileConflictError):
                self.inspect()

    def test_36_symlink_source_is_rejected(self):
        held = self.directory / "held.mokr"
        self.path.rename(held)
        self.path.symlink_to(held.name)
        with self.assertRaises(storage.UnsafeRecoveryDirectoryError):
            self.inspect()

    def test_37_hardlinked_source_is_rejected(self):
        alias = self.directory / "alias"
        os.link(self.path, alias)
        with self.assertRaises(storage.RecoveryFileConflictError):
            self.inspect()

    def test_38_noncanonical_filename_is_rejected(self):
        wrong = self.directory / "recovery.mokr"
        self.path.rename(wrong)
        with self.assertRaises(storage.RecoveryFileConflictError):
            self.inspect(wrong)

    def test_39_filename_identifier_mismatch_and_malformed_record_are_rejected(self):
        wrong = self.directory / storage.recovery_record_name(OTHER_RECOVERY_ID)
        self.path.rename(wrong)
        with self.assertRaises(storage.RecoveryFileConflictError) as caught:
            self.inspect(wrong)
        self.assertIn("structurally observed identifier", str(caught.exception))
        self.assertNotIn("authenticated identifier", str(caught.exception))
        wrong.rename(self.path)
        self.path.write_bytes(b"not-a-recovery-record")
        os.chmod(self.path, 0o600)
        with self.assertRaises(recovery.VaultRecoveryError):
            self.inspect()

    def test_40_source_change_during_bounded_read_is_rejected_and_terminal(self):
        prepared = self.prepared()
        real_read = storage._read_exact_descriptor

        def read_then_change(descriptor, expected_size):
            result = real_read(descriptor, expected_size)
            os.utime(self.path, ns=(self.path.stat().st_atime_ns, self.path.stat().st_mtime_ns + 1_000_000))
            return result

        with mock.patch.object(storage, "_read_exact_descriptor", side_effect=read_then_change):
            with self.assertRaises(storage.RecoverySourceChangedError):
                prepared.decide_once(
                    execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                )
        self.assertIs(prepared.current_state, execution.RecoverySourceInspectionExecutionState.FAILED)
        self.assertFalse(prepared.retains_source_path_metadata)

    def test_41_success_is_read_only_for_directory_and_record(self):
        def snapshot():
            parent = self.directory.stat()
            target = self.path.stat()
            return (
                parent.st_dev, parent.st_ino, parent.st_mode, parent.st_nlink,
                target.st_dev, target.st_ino, target.st_mode, target.st_nlink,
                target.st_size, hashlib.sha256(self.path.read_bytes()).digest(),
            )

        before = snapshot()
        self.inspect()
        self.assertEqual(snapshot(), before)

    def test_42_ancestor_swap_after_path_validation_is_terminal(self):
        prepared = self.prepared()
        moved = self.directory.parent / (self.directory.name + "-moved")
        real_path_text = storage._path_text
        swapped = False

        def validate_then_swap(value, field_name):
            nonlocal swapped
            result = real_path_text(value, field_name)
            if not swapped:
                swapped = True
                self.directory.rename(moved)
                self.directory.symlink_to(moved.name, target_is_directory=True)
            return result

        try:
            with mock.patch.object(
                storage,
                "_path_text",
                side_effect=validate_then_swap,
            ):
                with self.assertRaises(storage.UnsafeRecoveryDirectoryError):
                    prepared.decide_once(
                        execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                    )
        finally:
            if self.directory.is_symlink():
                self.directory.unlink()
                moved.rename(self.directory)
        self.assertTrue(swapped)
        self.assertIs(
            prepared.current_state,
            execution.RecoverySourceInspectionExecutionState.FAILED,
        )
        self.assertFalse(prepared.retains_source_path_metadata)

    def test_43_fifo_replacement_is_nonblocking_and_terminal(self):
        prepared = self.prepared()
        held = self.directory / "held-regular-record"
        real_open = os.open
        swapped = False

        def open_after_fifo_swap(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == self.path.name and not flags & os.O_DIRECTORY and not swapped:
                swapped = True
                self.path.rename(held)
                os.mkfifo(self.path, 0o600)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(storage.os, "open", side_effect=open_after_fifo_swap):
            with self.assertRaises(storage.RecoverySourceChangedError):
                prepared.decide_once(
                    execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
                )
        self.assertTrue(swapped)
        self.assertIs(
            prepared.current_state,
            execution.RecoverySourceInspectionExecutionState.FAILED,
        )
        self.assertFalse(prepared.retains_source_path_metadata)

    def test_44_critical_existing_files_remain_byte_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
