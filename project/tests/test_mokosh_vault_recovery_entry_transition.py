import ast
import copy
import dataclasses
import hashlib
import inspect
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def entry_outcome(locale="bg-BG", requested=True):
    prepared = request.prepare_recovery_entry_request(locale)
    decision = (
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        if requested
        else request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP
    )
    return prepared.decide_once(decision)


def forged_dataclass(value, **changes):
    forged = object.__new__(type(value))
    for field in dataclasses.fields(value):
        object.__setattr__(forged, field.name, getattr(value, field.name))
    for name, replacement in changes.items():
        object.__setattr__(forged, name, replacement)
    return forged


class RecoveryEntryTransitionSuccessTests(unittest.TestCase):
    def test_requested_bulgarian_can_request_future_source_selection(self):
        source = entry_outcome("bg-BG", requested=True)
        prepared = transition.prepare_recovery_entry_transition(source)
        self.assertIsNot(prepared.outcome, source)
        self.assertIs(
            prepared.current_state,
            transition.RecoveryEntryTransitionState.AWAITING_TRANSITION_DECISION,
        )
        outcome = prepared.decide_once(
            transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        )
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertTrue(outcome.future_source_selection_requested)
        self.assertFalse(outcome.preserved_and_stopped)
        self.assertFalse(outcome.source_selection_performed)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertFalse(outcome.automatic_transition)

    def test_requested_english_can_preserve_and_stop(self):
        prepared = transition.prepare_recovery_entry_transition(
            entry_outcome("en-GB", requested=True)
        )
        outcome = prepared.decide_once(
            transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertFalse(outcome.future_source_selection_requested)
        self.assertTrue(outcome.preserved_and_stopped)

    def test_preserved_entry_can_only_be_preserved_again(self):
        prepared = transition.prepare_recovery_entry_transition(
            entry_outcome("bg-BG", requested=False)
        )
        outcome = prepared.decide_once(
            transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
        )
        self.assertIs(
            outcome.entry_decision,
            request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP,
        )
        self.assertTrue(outcome.preserved_and_stopped)

    def test_prepared_object_retains_only_locale_and_entry_decision(self):
        source = entry_outcome("en-GB", requested=True)
        prepared = transition.prepare_recovery_entry_transition(source)
        names = set(transition.PreparedVaultRecoveryEntryTransition.__slots__)
        self.assertEqual(
            names,
            {"_locale", "_entry_decision", "_state", "_outcome", "_lock"},
        )
        self.assertFalse(any(getattr(prepared, name, None) is source for name in names))


class RecoveryEntryTransitionRefusalTests(unittest.TestCase):
    def test_non_exact_entry_outcome_types_are_rejected(self):
        for value in (None, {}, "request", True, object()):
            with self.subTest(value=value):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionSourceError
                ):
                    transition.prepare_recovery_entry_transition(value)
        incomplete_exact = object.__new__(request.VaultRecoveryEntryRequestOutcome)
        with self.assertRaises(transition.VaultRecoveryEntryTransitionSourceError):
            transition.prepare_recovery_entry_transition(incomplete_exact)

    def test_forged_entry_authority_flags_are_rejected(self):
        source = entry_outcome()
        for field in (
            "source_access_authorized",
            "source_selection_performed",
            "source_preparation_performed",
            "review_session_prepared",
            "main_gui_binding_prepared",
            "review_displayed",
            "normal_startup_activated",
            "operation_authorized",
            "operation_performed",
            "filesystem_access_performed",
            "network_used",
            "automatic_transition",
        ):
            with self.subTest(field=field):
                forged = forged_dataclass(source, **{field: True})
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionSourceError
                ):
                    transition.prepare_recovery_entry_transition(forged)

    def test_forged_entry_format_version_sequence_and_booleans_are_rejected(self):
        source = entry_outcome()
        changes = (
            {"format": "OTHER"},
            {"version": 2},
            {"request_sequence": 2},
            {"review_requested": False},
            {"preserved_and_stopped": True},
            {"exact_locale_validated": False},
            {"exact_decision_validated": False},
            {"one_shot": False},
            {"non_secret": False},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionSourceError
                ):
                    transition.prepare_recovery_entry_transition(
                        forged_dataclass(source, **change)
                    )

    def test_invalid_transition_decision_does_not_consume(self):
        prepared = transition.prepare_recovery_entry_transition(entry_outcome())
        for value in (None, "preserve_and_stop", True, 1, request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP):
            with self.subTest(value=value):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionDecisionError
                ):
                    prepared.decide_once(value)
                self.assertIs(
                    prepared.current_state,
                    transition.RecoveryEntryTransitionState.AWAITING_TRANSITION_DECISION,
                )

    def test_preserved_entry_cannot_proceed_and_is_not_consumed(self):
        prepared = transition.prepare_recovery_entry_transition(
            entry_outcome(requested=False)
        )
        with self.assertRaises(transition.VaultRecoveryEntryTransitionDecisionError):
            prepared.decide_once(
                transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
            )
        self.assertIs(
            prepared.current_state,
            transition.RecoveryEntryTransitionState.AWAITING_TRANSITION_DECISION,
        )
        self.assertIsNone(prepared.outcome)


class RecoveryEntryTransitionLifecycleTests(unittest.TestCase):
    def test_replay_is_rejected_after_success(self):
        prepared = transition.prepare_recovery_entry_transition(entry_outcome())
        prepared.decide_once(
            transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
        )
        with self.assertRaises(transition.VaultRecoveryEntryTransitionReplayError):
            prepared.decide_once(
                transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
            )

    def test_concurrent_valid_attempts_have_exactly_one_success(self):
        prepared = transition.prepare_recovery_entry_transition(entry_outcome())
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait(timeout=2)
            try:
                prepared.decide_once(
                    transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
                )
                return "success"
            except transition.VaultRecoveryEntryTransitionReplayError:
                return "replay"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(timeout=3) for future in (pool.submit(attempt), pool.submit(attempt))]
        self.assertCountEqual(results, ["success", "replay"])

    def test_copy_deepcopy_and_pickle_are_rejected(self):
        prepared = transition.prepare_recovery_entry_transition(entry_outcome())
        for action in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(action=action):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionReplayError
                ):
                    action()


class RecoveryEntryTransitionOutcomeTests(unittest.TestCase):
    def test_outcome_schema_excludes_sources_secrets_paths_and_capabilities(self):
        names = {field.name for field in dataclasses.fields(transition.VaultRecoveryEntryTransitionOutcome)}
        self.assertTrue(
            names.isdisjoint(
                {
                    "password",
                    "new_password",
                    "recovery_root",
                    "recovery_key",
                    "recovery_record",
                    "keyring",
                    "vault_id",
                    "recovery_id",
                    "path",
                    "filename",
                    "storage",
                    "workflow",
                    "session",
                    "binding",
                    "callback",
                    "executor",
                    "operation_capability",
                }
            )
        )

    def test_forged_transition_authority_flags_are_rejected(self):
        valid = transition.prepare_recovery_entry_transition(entry_outcome()).decide_once(
            transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        )
        for field in (
            "source_access_authorized",
            "source_selection_performed",
            "source_preparation_performed",
            "review_session_prepared",
            "main_gui_binding_prepared",
            "review_displayed",
            "operation_authorized",
            "operation_performed",
            "filesystem_access_performed",
            "network_used",
            "automatic_transition",
        ):
            with self.subTest(field=field):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionFormatError
                ):
                    dataclasses.replace(valid, **{field: True})

    def test_forged_transition_route_and_boolean_combinations_are_rejected(self):
        valid = transition.prepare_recovery_entry_transition(entry_outcome()).decide_once(
            transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
        )
        changes = (
            {"future_source_selection_requested": True},
            {"preserved_and_stopped": False},
            {"format": "OTHER"},
            {"version": 2},
            {"transition_sequence": 2},
            {"one_shot": False},
            {"non_secret": False},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    transition.VaultRecoveryEntryTransitionFormatError
                ):
                    dataclasses.replace(valid, **change)

    def test_preserved_entry_cannot_forge_proceed_outcome(self):
        valid = transition.prepare_recovery_entry_transition(
            entry_outcome(requested=False)
        ).decide_once(transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP)
        with self.assertRaises(transition.VaultRecoveryEntryTransitionFormatError):
            dataclasses.replace(
                valid,
                transition_decision=(
                    transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
                ),
                future_source_selection_requested=True,
                preserved_and_stopped=False,
            )


class RecoveryEntryTransitionStaticBoundaryTests(unittest.TestCase):
    def test_public_api_signatures_are_exact(self):
        self.assertEqual(
            tuple(inspect.signature(transition.prepare_recovery_entry_transition).parameters),
            ("entry_outcome",),
        )
        self.assertEqual(
            tuple(inspect.signature(transition.PreparedVaultRecoveryEntryTransition.decide_once).parameters),
            ("self", "decision"),
        )

    def test_module_has_no_source_filesystem_gui_network_process_or_logging_import(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_entry_transition.py").read_text(
                encoding="utf-8"
            )
        )
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        forbidden = {
            "os",
            "pathlib",
            "shutil",
            "tempfile",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "logging",
            "tkinter",
            "importlib",
            "mokosh_vault_storage",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_workflow",
            "mokosh_vault_recovery_review_controller",
            "mokosh_vault_recovery_main_gui_bridge",
            "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish",
        }
        self.assertTrue(imports.isdisjoint(forbidden))

    def test_module_has_no_source_operation_or_dynamic_calls(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_entry_transition.py").read_text(
                encoding="utf-8"
            )
        )
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        forbidden = {
            "open",
            "eval",
            "exec",
            "compile",
            "__import__",
            "unlink",
            "remove",
            "replace",
            "rename",
            "encrypt_file",
            "decrypt_file",
            "reconcile_recovery_publish",
            "prepare_recovery_workflow",
            "prepare_recovery_review_session",
            "prepare_main_gui_recovery_review_binding",
            "show_prepared_recovery_review",
            "prepare_recovery_candidate",
            "publish_recovery_candidate",
        }
        self.assertTrue(calls.isdisjoint(forbidden))

    def test_contract_contains_exact_no_source_no_authority_boundary(self):
        source = (PROJECT_ROOT / "docs/VAULT_RECOVERY_ENTRY_TRANSITION_CONTRACT_BG.md").read_text(
            encoding="utf-8"
        )
        for text in (
            "няма source selection/preparation",
            "не избира, не отваря и не подготвя source",
            "operation authority",
            "automatic transition",
            "SAFETY_MODE=True",
        ):
            with self.subTest(text=text):
                self.assertIn(text, source)

    def test_safety_mode_and_critical_runtime_files_remain_byte_exact(self):
        gui_tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        safety = next(
            node.value
            for node in gui_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "SAFETY_MODE"
        )
        self.assertIs(safety.value, True)
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
