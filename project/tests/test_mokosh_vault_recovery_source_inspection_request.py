import ast
import copy
from dataclasses import fields
import hashlib
import inspect
from pathlib import Path
import pickle
import threading
import unittest

import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_source_inspection_request as inspection
import mokosh_vault_recovery_source_selection as selection


ROOT = Path(__file__).resolve().parents[1]
BG_PATH = "/home/mitra/recovery/mokosh-vault-recovery-00112233445566778899aabbccddeeff.mokr"
EN_PATH = "/srv/private/възстановяване/mokosh-vault-recovery-ffeeddccbbaa99887766554433221100.mokr"


def selection_outcome(locale="bg-BG", *, selected=True):
    entry = request.prepare_recovery_entry_request(locale).decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    moved = transition.prepare_recovery_entry_transition(entry).decide_once(
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )
    prepared = selection.prepare_recovery_source_selection(moved)
    if not selected:
        return prepared.decide_once(
            selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP
        )
    return prepared.decide_once(
        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        BG_PATH if locale == "bg-BG" else EN_PATH,
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


class VaultRecoverySourceInspectionRequestTests(unittest.TestCase):
    def test_01_bulgarian_positive_request_retains_only_bounded_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertEqual(outcome.selected_path, BG_PATH)
        self.assertTrue(outcome.future_secure_source_inspection_requested)
        self.assertTrue(outcome.source_path_metadata_retained)
        self.assertTrue(outcome.contains_sensitive_path_metadata)

    def test_02_english_positive_request_preserves_exact_unicode_path(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome("en-GB")
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertEqual(outcome.selected_path, EN_PATH)
        self.assertIs(
            outcome.state,
            inspection.RecoverySourceInspectionRequestState.COMPLETED,
        )

    def test_03_bulgarian_preserve_discards_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIsNone(outcome.selected_path)
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertFalse(outcome.future_secure_source_inspection_requested)
        self.assertFalse(outcome.source_path_metadata_retained)
        self.assertFalse(outcome.contains_sensitive_path_metadata)

    def test_04_english_preserve_discards_path_metadata(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome("en-GB")
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertIsNone(outcome.selected_path)
        self.assertTrue(outcome.preserved_and_stopped)

    def test_05_selection_source_requires_exact_outcome_type(self):
        exact = selection_outcome()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, (), "source", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionRequestSourceError
                ):
                    inspection.prepare_recovery_source_inspection_request(invalid)

    def test_06_preserved_selection_cannot_prepare_inspection_request(self):
        with self.assertRaises(
            inspection.VaultRecoverySourceInspectionRequestSourceError
        ):
            inspection.prepare_recovery_source_inspection_request(
                selection_outcome(selected=False)
            )

    def test_07_forged_selection_claims_are_fully_revalidated(self):
        exact = selection_outcome()
        changes = (
            {"source_selected": False},
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
                    inspection.VaultRecoverySourceInspectionRequestSourceError
                ):
                    inspection.prepare_recovery_source_inspection_request(
                        forged_copy(exact, **change)
                    )

    def test_08_prepared_object_retains_path_but_not_original_outcome(self):
        source = selection_outcome()
        prepared = inspection.prepare_recovery_source_inspection_request(source)
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
            inspection.RECOVERY_SOURCE_INSPECTION_REQUEST_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_REQUEST",
        )
        self.assertEqual(inspection.RECOVERY_SOURCE_INSPECTION_REQUEST_VERSION, 1)
        self.assertEqual(inspection.RECOVERY_SOURCE_INSPECTION_REQUEST_SEQUENCE, 1)
        self.assertEqual(
            tuple(inspection.RecoverySourceInspectionRequestDecision),
            (
                inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP,
                inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION,
            ),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    inspection.prepare_recovery_source_inspection_request
                ).parameters
            ),
            ("selection_outcome",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    inspection.PreparedVaultRecoverySourceInspectionRequest.decide_once
                ).parameters
            ),
            ("self", "decision"),
        )

    def test_10_invalid_decision_type_does_not_consume_fresh_object(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        for invalid in (None, "request_future_secure_source_inspection", 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionRequestDecisionError
                ):
                    prepared.decide_once(invalid)
                self.assertIs(
                    prepared.current_state,
                    inspection.RecoverySourceInspectionRequestState.AWAITING_INSPECTION_DECISION,
                )
                self.assertTrue(prepared.retains_source_path_metadata)

    def test_11_positive_request_consumes_prepared_path_once(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        self.assertIs(prepared.outcome, outcome)
        self.assertFalse(prepared.retains_source_path_metadata)
        self.assertIs(
            prepared.current_state,
            inspection.RecoverySourceInspectionRequestState.COMPLETED,
        )

    def test_12_preserve_consumes_and_discards_prepared_path_once(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIs(prepared.outcome, outcome)
        self.assertFalse(prepared.retains_source_path_metadata)
        self.assertIsNone(outcome.selected_path)

    def test_13_replay_is_rejected_after_either_terminal_decision(self):
        for first in tuple(inspection.RecoverySourceInspectionRequestDecision):
            with self.subTest(first=first):
                prepared = inspection.prepare_recovery_source_inspection_request(
                    selection_outcome()
                )
                prepared.decide_once(first)
                for replay in tuple(
                    inspection.RecoverySourceInspectionRequestDecision
                ):
                    with self.assertRaises(
                        inspection.VaultRecoverySourceInspectionRequestReplayError
                    ):
                        prepared.decide_once(replay)

    def test_14_concurrent_attempts_have_exactly_one_success(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        barrier = threading.Barrier(8)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                successes.append(
                    prepared.decide_once(
                        inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
                    )
                )
            except inspection.VaultRecoverySourceInspectionRequestReplayError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 7)

    def test_15_prepared_repr_never_contains_selected_path(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        rendered = repr(prepared)
        self.assertNotIn(BG_PATH, rendered)
        self.assertNotIn("00112233445566778899aabbccddeeff", rendered)
        self.assertIn("retains_source_path_metadata=True", rendered)

    def test_16_prepared_object_refuses_copy_deepcopy_and_pickle(self):
        prepared = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        )
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(
                inspection.VaultRecoverySourceInspectionRequestReplayError
            ):
                operation()

    def test_17_outcome_repr_never_contains_selected_path(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        rendered = repr(outcome)
        self.assertNotIn(BG_PATH, rendered)
        self.assertNotIn("00112233445566778899aabbccddeeff", rendered)
        self.assertNotIn("selected_path=", rendered)

    def test_18_outcome_refuses_copy_deepcopy_and_pickle(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        for operation in (
            lambda: copy.copy(outcome),
            lambda: copy.deepcopy(outcome),
            lambda: pickle.dumps(outcome),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_19_request_preserves_exact_path_without_normalization_or_hashing(self):
        source = selection_outcome("en-GB")
        prepared = inspection.prepare_recovery_source_inspection_request(source)
        outcome = prepared.decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        self.assertIs(outcome.selected_path, source.selected_path)
        self.assertEqual(outcome.selected_path, EN_PATH)
        self.assertFalse(hasattr(outcome, "selected_path_sha256"))

    def test_20_request_has_every_access_and_operation_flag_false(self):
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        for name in (
            "source_opened",
            "source_content_read",
            "source_identity_validated",
            "source_access_authorized",
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
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
        self.assertIs(
            outcome.selection_decision,
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        )
        self.assertIs(
            outcome.inspection_decision,
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP,
        )
        self.assertIsNone(outcome.selected_path)

    def test_22_forged_outcome_route_and_path_pairs_are_rejected(self):
        requested = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        stopped = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
        )
        for forged in (
            forged_copy(requested, selected_path=None),
            forged_copy(requested, preserved_and_stopped=True),
            forged_copy(stopped, selected_path=BG_PATH),
            forged_copy(stopped, future_secure_source_inspection_requested=True),
        ):
            with self.assertRaises(
                inspection.VaultRecoverySourceInspectionRequestFormatError
            ):
                inspection._validate_source_inspection_request_outcome(forged)

    def test_23_forged_outcome_boolean_types_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        for name in (
            "future_secure_source_inspection_requested",
            "preserved_and_stopped",
            "source_path_metadata_retained",
            "contains_sensitive_path_metadata",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionRequestFormatError
                ):
                    inspection._validate_source_inspection_request_outcome(
                        forged_copy(exact, **{name: 1})
                    )

    def test_24_forged_outcome_authority_claims_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        for name in (
            "source_opened",
            "source_content_read",
            "source_identity_validated",
            "source_access_authorized",
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
                    inspection.VaultRecoverySourceInspectionRequestFormatError
                ):
                    inspection._validate_source_inspection_request_outcome(
                        forged_copy(exact, **{name: True})
                    )

    def test_25_forged_outcome_schema_and_sequence_claims_are_rejected(self):
        exact = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        changes = (
            {"entry_request_sequence": 2},
            {"transition_sequence": 2},
            {"selection_sequence": 2},
            {"inspection_request_sequence": 2},
            {"exact_source_selection_outcome_validated": False},
            {"exact_inspection_decision_validated": False},
            {"one_shot": False},
            {"process_local": False},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionRequestFormatError
                ):
                    inspection._validate_source_inspection_request_outcome(
                        forged_copy(exact, **change)
                    )

    def test_26_direct_prepared_constructor_revalidates_every_input(self):
        exact = selection_outcome()
        values = (
            ("bg-BG", exact.entry_decision, exact.transition_decision, exact.selection_decision, BG_PATH),
            (exact.locale, request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP, exact.transition_decision, exact.selection_decision, BG_PATH),
            (exact.locale, exact.entry_decision, transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP, exact.selection_decision, BG_PATH),
            (exact.locale, exact.entry_decision, exact.transition_decision, selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP, BG_PATH),
            (exact.locale, exact.entry_decision, exact.transition_decision, exact.selection_decision, "/tmp/../record.mokr"),
        )
        for args in values:
            with self.subTest(args=args[:-1]):
                with self.assertRaises(
                    inspection.VaultRecoverySourceInspectionRequestSourceError
                ):
                    inspection.PreparedVaultRecoverySourceInspectionRequest(*args)

    def test_27_import_closure_is_exact_and_has_no_privileged_layer(self):
        path = ROOT / "mokosh_vault_recovery_source_inspection_request.py"
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
        path = ROOT / "mokosh_vault_recovery_source_inspection_request.py"
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
                inspection.VaultRecoverySourceInspectionRequestOutcome
            )),
            (
                "locale",
                "entry_decision",
                "transition_decision",
                "selection_decision",
                "inspection_decision",
                "state",
                "selected_path",
                "future_secure_source_inspection_requested",
                "preserved_and_stopped",
                "source_path_metadata_retained",
                "contains_sensitive_path_metadata",
                "entry_request_sequence",
                "transition_sequence",
                "selection_sequence",
                "inspection_request_sequence",
                "exact_source_selection_outcome_validated",
                "exact_inspection_decision_validated",
                "one_shot",
                "process_local",
                "source_opened",
                "source_content_read",
                "source_identity_validated",
                "source_access_authorized",
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
        outcome = inspection.prepare_recovery_source_inspection_request(
            selection_outcome()
        ).decide_once(
            inspection.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
        )
        self.assertFalse(hasattr(outcome, "__dict__"))
        for name in ("callback", "executor", "storage", "secret", "handle"):
            self.assertFalse(hasattr(outcome, name))


if __name__ == "__main__":
    unittest.main()
