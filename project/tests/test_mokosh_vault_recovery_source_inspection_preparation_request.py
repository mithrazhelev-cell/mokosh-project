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
import threading
import unittest

import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_source_inspection_request as inspection_request
import mokosh_vault_recovery_source_inspection_preparation_request as inspection
import mokosh_vault_recovery_source_selection as selection


ROOT = Path(__file__).resolve().parents[1]
BG_PATH = "/home/mitra/recovery/mokosh-vault-recovery-00112233445566778899aabbccddeeff.mokr"
EN_PATH = "/srv/private/възстановяване/mokosh-vault-recovery-ffeeddccbbaa99887766554433221100.mokr"


def inspection_request_outcome(locale="bg-BG", *, requested=True):
    entry = request.prepare_recovery_entry_request(locale).decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    moved = transition.prepare_recovery_entry_transition(entry).decide_once(
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )
    prepared = selection.prepare_recovery_source_selection(moved)
    selected = prepared.decide_once(
        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        BG_PATH if locale == "bg-BG" else EN_PATH,
    )
    prepared_request = inspection_request.prepare_recovery_source_inspection_request(
        selected
    )
    if not requested:
        return prepared_request.decide_once(
            inspection_request.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
    return prepared_request.decide_once(
        inspection_request.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
    )


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class VaultRecoverySourceInspectionPreparationRequestTests(unittest.TestCase):
    def test_01_bulgarian_positive_request_retains_only_bounded_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertEqual(outcome.selected_path, BG_PATH)
        self.assertTrue(outcome.future_secure_source_inspection_preparation_requested)
        self.assertTrue(outcome.source_path_metadata_retained)
        self.assertTrue(outcome.contains_sensitive_path_metadata)

    def test_02_english_positive_request_preserves_exact_unicode_path(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome("en-GB")
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertEqual(outcome.selected_path, EN_PATH)
        self.assertIs(
            outcome.state,
            inspection.RecoverySourceInspectionPreparationRequestState.COMPLETED,
        )

    def test_03_bulgarian_preserve_discards_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIsNone(outcome.selected_path)
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertFalse(outcome.future_secure_source_inspection_preparation_requested)
        self.assertFalse(outcome.source_path_metadata_retained)
        self.assertFalse(outcome.contains_sensitive_path_metadata)

    def test_04_english_preserve_discards_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome("en-GB")
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertIsNone(outcome.selected_path)
        self.assertTrue(outcome.preserved_and_stopped)

    def test_05_inspection_request_source_requires_exact_outcome_type(self):
        exact = inspection_request_outcome()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, (), "source", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestSourceError
                ):
                    inspection.prepare_recovery_source_inspection_preparation_request(invalid)

    def test_06_preserved_inspection_request_cannot_prepare_preparation_request(self):
        with self.assertRaises(
            inspection.VaultRecoverySourceInspectionPreparationRequestSourceError
        ):
            inspection.prepare_recovery_source_inspection_preparation_request(
                inspection_request_outcome(requested=False)
            )

    def test_07_forged_inspection_request_claims_are_fully_revalidated(self):
        exact = inspection_request_outcome()
        changes = (
            {"future_secure_source_inspection_requested": False},
            {"selected_path": "/tmp/../record.mokr"},
            {"source_opened": True},
            {"source_identity_validated": True},
            {"source_access_authorized": True},
            {"source_preparation_performed": True},
            {"recovery_secret_received": True},
            {"operation_authorized": True},
            {"recovery_source_filesystem_access_performed": True},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestSourceError
                ):
                    inspection.prepare_recovery_source_inspection_preparation_request(
                        forged_copy(exact, **change)
                    )

    def test_08_prepared_object_retains_path_but_not_original_outcome(self):
        source = inspection_request_outcome()
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(source)
        self.assertTrue(prepared.retains_source_path_metadata)
        self.assertIsNone(prepared.outcome)
        self.assertNotIn(
            source,
            (
                getattr(prepared, name)
                for name in prepared.__slots__
                if name != "_lock"
            ),
        )

    def test_09_public_constants_enums_and_signatures_are_exact(self):
        self.assertEqual(
            inspection.RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST",
        )
        self.assertEqual(inspection.RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_VERSION, 1)
        self.assertEqual(inspection.RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_SEQUENCE, 1)
        self.assertEqual(
            tuple(inspection.RecoverySourceInspectionPreparationRequestDecision),
            (
                inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP,
                inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION,
            ),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    inspection.prepare_recovery_source_inspection_preparation_request
                ).parameters
            ),
            ("inspection_request_outcome",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    inspection.PreparedVaultRecoverySourceInspectionPreparationRequest.decide_once
                ).parameters
            ),
            ("self", "decision"),
        )

    def test_10_invalid_decision_type_does_not_consume_fresh_object(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        for invalid in (None, "request_future_secure_source_inspection_preparation", 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestDecisionError
                ):
                    prepared.decide_once(invalid)
                self.assertIs(
                    prepared.current_state,
                    inspection.RecoverySourceInspectionPreparationRequestState.AWAITING_PREPARATION_DECISION,
                )
                self.assertTrue(prepared.retains_source_path_metadata)

    def test_11_positive_request_consumes_prepared_path_once(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertIs(prepared.outcome, outcome)
        self.assertFalse(prepared.retains_source_path_metadata)
        self.assertIs(
            prepared.current_state,
            inspection.RecoverySourceInspectionPreparationRequestState.COMPLETED,
        )

    def test_12_preserve_consumes_and_discards_prepared_path_once(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIs(prepared.outcome, outcome)
        self.assertFalse(prepared.retains_source_path_metadata)
        self.assertIsNone(outcome.selected_path)

    def test_13_replay_is_rejected_after_either_terminal_decision(self):
        for first in tuple(inspection.RecoverySourceInspectionPreparationRequestDecision):
            with self.subTest(first=first):
                prepared = inspection.prepare_recovery_source_inspection_preparation_request(
                    inspection_request_outcome()
                )
                prepared.decide_once(first)
                for replay in tuple(
                    inspection.RecoverySourceInspectionPreparationRequestDecision
                ):
                    with self.assertRaises(
                        inspection.VaultRecoverySourceInspectionPreparationRequestReplayError
                    ):
                        prepared.decide_once(replay)

    def test_14_concurrent_attempts_have_exactly_one_success(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        barrier = threading.Barrier(8)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                successes.append(
                    prepared.decide_once(
                        inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
                    )
                )
            except inspection.VaultRecoverySourceInspectionPreparationRequestReplayError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 7)

    def test_15_prepared_repr_never_contains_selected_path(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        rendered = repr(prepared)
        self.assertNotIn(BG_PATH, rendered)
        self.assertNotIn("00112233445566778899aabbccddeeff", rendered)
        self.assertIn("retains_source_path_metadata=True", rendered)

    def test_16_prepared_object_refuses_copy_deepcopy_and_pickle(self):
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        )
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(
                inspection.VaultRecoverySourceInspectionPreparationRequestReplayError
            ):
                operation()

    def test_17_outcome_repr_never_contains_selected_path(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        rendered = repr(outcome)
        self.assertNotIn(BG_PATH, rendered)
        self.assertNotIn("00112233445566778899aabbccddeeff", rendered)
        self.assertNotIn("selected_path=", rendered)

    def test_18_outcome_refuses_copy_deepcopy_and_pickle(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        for operation in (
            lambda: copy.copy(outcome),
            lambda: copy.deepcopy(outcome),
            lambda: pickle.dumps(outcome),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_19_request_preserves_exact_path_without_normalization_or_hashing(self):
        source = inspection_request_outcome("en-GB")
        prepared = inspection.prepare_recovery_source_inspection_preparation_request(source)
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertIs(outcome.selected_path, source.selected_path)
        self.assertEqual(outcome.selected_path, EN_PATH)
        self.assertFalse(hasattr(outcome, "selected_path_sha256"))

    def test_20_request_has_every_access_and_operation_flag_false(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        for name in (
            "global_source_outcome_consumption_enforced",
            "memory_zeroization_proven",
            "source_opened",
            "source_content_read",
            "source_identity_validated",
            "source_access_authorized",
            "filesystem_capability_issued",
            "source_preparation_performed",
            "recovery_secret_received",
            "review_session_prepared",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "automatic_transition",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(outcome, name), False)

    def test_21_preserve_has_exact_no_path_route_invariants(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIs(
            outcome.selection_decision,
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        )
        self.assertIs(
            outcome.preparation_decision,
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP,
        )
        self.assertIsNone(outcome.selected_path)

    def test_22_forged_outcome_route_and_path_pairs_are_rejected(self):
        requested = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        stopped = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.PRESERVE_AND_STOP
        )
        for forged in (
            forged_copy(requested, selected_path=None),
            forged_copy(requested, preserved_and_stopped=True),
            forged_copy(stopped, selected_path=BG_PATH),
            forged_copy(stopped, future_secure_source_inspection_preparation_requested=True),
        ):
            with self.assertRaises(
                inspection.VaultRecoverySourceInspectionPreparationRequestFormatError
            ):
                inspection._validate_source_inspection_preparation_request_outcome(forged)

    def test_23_forged_outcome_boolean_types_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        for name in (
            "future_secure_source_inspection_preparation_requested",
            "preserved_and_stopped",
            "source_path_metadata_retained",
            "contains_sensitive_path_metadata",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestFormatError
                ):
                    inspection._validate_source_inspection_preparation_request_outcome(
                        forged_copy(exact, **{name: 1})
                    )

    def test_24_forged_outcome_authority_claims_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        for name in (
            "source_opened",
            "source_content_read",
            "source_identity_validated",
            "source_access_authorized",
            "filesystem_capability_issued",
            "source_preparation_performed",
            "recovery_secret_received",
            "review_session_prepared",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "automatic_transition",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestFormatError
                ):
                    inspection._validate_source_inspection_preparation_request_outcome(
                        forged_copy(exact, **{name: True})
                    )

    def test_25_forged_outcome_schema_and_sequence_claims_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        changes = (
            {"entry_request_sequence": 2},
            {"transition_sequence": 2},
            {"selection_sequence": 2},
            {"inspection_request_sequence": 2},
            {"preparation_request_sequence": 2},
            {"exact_inspection_request_outcome_validated": False},
            {"exact_preparation_decision_validated": False},
            {"one_shot": False},
            {"process_local": False},
            {"global_source_outcome_consumption_enforced": True},
            {"memory_zeroization_proven": True},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestFormatError
                ):
                    inspection._validate_source_inspection_preparation_request_outcome(
                        forged_copy(exact, **change)
                    )

    def test_26_direct_prepared_constructor_revalidates_every_input(self):
        exact = inspection_request_outcome()
        values = (
            ("bg-BG", exact.entry_decision, exact.transition_decision, exact.selection_decision, exact.inspection_decision, BG_PATH),
            (exact.locale, request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP, exact.transition_decision, exact.selection_decision, exact.inspection_decision, BG_PATH),
            (exact.locale, exact.entry_decision, transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP, exact.selection_decision, exact.inspection_decision, BG_PATH),
            (exact.locale, exact.entry_decision, exact.transition_decision, selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP, exact.inspection_decision, BG_PATH),
            (exact.locale, exact.entry_decision, exact.transition_decision, exact.selection_decision, inspection_request.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP, BG_PATH),
            (exact.locale, exact.entry_decision, exact.transition_decision, exact.selection_decision, exact.inspection_decision, "/tmp/../record.mokr"),
        )
        for args in values:
            with self.subTest(args=args[:-1]):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionPreparationRequestSourceError
                ):
                    inspection.PreparedVaultRecoverySourceInspectionPreparationRequest(*args)

    def test_27_import_closure_is_exact_and_has_no_privileged_layer(self):
        path = ROOT / "mokosh_vault_recovery_source_inspection_preparation_request.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        self.assertEqual(
            modules,
            {
                "__future__",
                "dataclasses",
                "enum",
                "threading",
                "typing",
                "mokosh_vault_recovery_entry_request",
                "mokosh_vault_recovery_entry_transition",
                "mokosh_vault_recovery_locale",
                "mokosh_vault_recovery_source_selection",
                "mokosh_vault_recovery_source_inspection_request",
            },
        )
        forbidden = {
            "mokosh_gui",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_workflow",
            "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish",
            "crypto_core",
            "subprocess",
            "socket",
            "logging",
        }
        self.assertTrue(modules.isdisjoint(forbidden))

    def test_28_ast_has_no_filesystem_network_process_or_dynamic_capability(self):
        path = ROOT / "mokosh_vault_recovery_source_inspection_preparation_request.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden_names = {
            "open",
            "exec",
            "eval",
            "compile",
            "__import__",
            "getattr",
            "setattr",
        }
        forbidden_attributes = {
            "open",
            "read",
            "read_bytes",
            "read_text",
            "stat",
            "lstat",
            "resolve",
            "realpath",
            "unlink",
            "remove",
            "replace",
            "rename",
            "Popen",
            "run",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_names)
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, forbidden_attributes)

    def test_29_critical_existing_files_remain_byte_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_vault_recovery_source_selection.py": "856143153b21cc6c3ff81e908cbf875c0433492a79a023ee2ab3e4b793024600",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                    digest,
                )

    def test_30_schema_is_bounded_and_carries_no_extensible_capability(self):
        self.assertEqual(
            tuple(item.name for item in fields(
                inspection.VaultRecoverySourceInspectionPreparationRequestOutcome
            )),
            (
                "locale",
                "entry_decision",
                "transition_decision",
                "selection_decision",
                "inspection_decision",
                "preparation_decision",
                "state",
                "selected_path",
                "future_secure_source_inspection_preparation_requested",
                "preserved_and_stopped",
                "source_path_metadata_retained",
                "contains_sensitive_path_metadata",
                "entry_request_sequence",
                "transition_sequence",
                "selection_sequence",
                "inspection_request_sequence",
                "preparation_request_sequence",
                "exact_inspection_request_outcome_validated",
                "exact_preparation_decision_validated",
                "one_shot",
                "process_local",
                "global_source_outcome_consumption_enforced",
                "memory_zeroization_proven",
                "source_opened",
                "source_content_read",
                "source_identity_validated",
                "source_access_authorized",
                "filesystem_capability_issued",
                "source_preparation_performed",
                "recovery_secret_received",
                "review_session_prepared",
                "operation_authorized",
                "operation_performed",
                "recovery_source_filesystem_access_performed",
                "recovery_source_filesystem_mutation_performed",
                "network_used",
                "automatic_transition",
                "format",
                "version",
            ),
        )
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertFalse(hasattr(outcome, "__dict__"))
        for name in ("callback", "executor", "storage", "secret", "handle"):
            self.assertFalse(hasattr(outcome, name))

    def test_31_request_is_explicitly_not_access_authority_or_capability(self):
        outcome = inspection.prepare_recovery_source_inspection_preparation_request(
            inspection_request_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
        )
        self.assertTrue(outcome.future_secure_source_inspection_preparation_requested)
        self.assertIs(outcome.source_access_authorized, False)
        self.assertIs(outcome.filesystem_capability_issued, False)
        self.assertIs(outcome.source_preparation_performed, False)

    def test_32_repeated_preparation_has_no_global_source_consumption_claim(self):
        source = inspection_request_outcome()
        first = inspection.prepare_recovery_source_inspection_preparation_request(source)
        second = inspection.prepare_recovery_source_inspection_preparation_request(source)
        self.assertIsNot(first, second)
        for prepared in (first, second):
            outcome = prepared.decide_once(
                inspection.RecoverySourceInspectionPreparationRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
            )
            self.assertIs(outcome.global_source_outcome_consumption_enforced, False)
            self.assertIs(outcome.memory_zeroization_proven, False)

    def test_33_fresh_gui_import_excludes_stage_2_31_and_geometry_is_unchanged(self):
        module_name = "mokosh_vault_recovery_source_inspection_preparation_request"
        script = (
            "import sys, types; "
            "argon2 = types.ModuleType('argon2'); "
            "Type = type('Type', (), {'ID': 'ID'}); argon2.Type = Type; "
            "low_level = types.ModuleType('argon2.low_level'); "
            "low_level.hash_secret = lambda *args, **kwargs: b''; "
            "sys.modules['argon2'] = argon2; "
            "sys.modules['argon2.low_level'] = low_level; "
            "import mokosh_gui; "
            f"print({module_name!r} in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.stdout.strip(), "False")
        self.assertEqual(
            hashlib.sha256((ROOT / "mokosh_gui.py").read_bytes()).hexdigest(),
            "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
        )


if __name__ == "__main__":
    unittest.main()
