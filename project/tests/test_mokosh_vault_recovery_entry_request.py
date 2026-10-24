import ast
import copy
import dataclasses
import inspect
import pathlib
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

import mokosh_vault_recovery_entry_request as request


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


def prepare(locale_id="bg-BG"):
    return request.prepare_recovery_entry_request(locale_id)


class RecoveryEntryRequestOutcomeTests(unittest.TestCase):
    def test_review_request_is_bounded_and_has_no_authority(self):
        prepared = prepare()
        outcome = prepared.decide_once(
            request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        )
        self.assertTrue(outcome.review_requested)
        self.assertFalse(outcome.preserved_and_stopped)
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.source_selection_performed)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertFalse(outcome.review_session_prepared)
        self.assertFalse(outcome.main_gui_binding_prepared)
        self.assertFalse(outcome.review_displayed)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)

    def test_preserve_and_stop_is_terminal_without_transition(self):
        outcome = prepare("en-GB").decide_once(
            request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP
        )
        self.assertFalse(outcome.review_requested)
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertFalse(outcome.automatic_transition)

    def test_both_locales_and_decisions_are_exact(self):
        for locale_id in ("bg-BG", "en-GB"):
            for decision in request.RecoveryEntryRequestDecision:
                with self.subTest(locale=locale_id, decision=decision.value):
                    prepared = prepare(locale_id)
                    outcome = prepared.decide_once(decision)
                    self.assertEqual(outcome.locale.value, locale_id)
                    self.assertIs(outcome.decision, decision)
                    self.assertIs(
                        prepared.current_state,
                        request.RecoveryEntryRequestState.COMPLETED,
                    )
                    self.assertIs(prepared.outcome, outcome)

    def test_invalid_locale_is_rejected_before_preparation(self):
        for value in (None, True, "bg", "en", "BG-bg", "bg-BG ", object()):
            with self.subTest(value=repr(value)):
                with self.assertRaises(request.VaultRecoveryEntryRequestSourceError):
                    prepare(value)

    def test_decision_requires_exact_enum_and_invalid_attempt_does_not_consume(self):
        prepared = prepare()
        for value in (
            "request_recovery_review",
            "preserve_and_stop",
            True,
            None,
            object(),
        ):
            with self.subTest(value=repr(value)):
                with self.assertRaises(request.VaultRecoveryEntryRequestSourceError):
                    prepared.decide_once(value)
                self.assertIs(
                    prepared.current_state,
                    request.RecoveryEntryRequestState.AWAITING_DECISION,
                )

    def test_success_cannot_be_replayed(self):
        prepared = prepare()
        prepared.decide_once(request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP)
        with self.assertRaises(request.VaultRecoveryEntryRequestReplayError):
            prepared.decide_once(
                request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
            )

    def test_consumed_request_rejects_even_malformed_replay_as_replay(self):
        prepared = prepare()
        prepared.decide_once(request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP)
        for value in (None, "request_recovery_review", True, object()):
            with self.subTest(value=repr(value)):
                with self.assertRaises(request.VaultRecoveryEntryRequestReplayError):
                    prepared.decide_once(value)

    def test_concurrent_attempts_allow_exactly_one_outcome(self):
        prepared = prepare()
        start = threading.Barrier(3)

        def decide(decision):
            start.wait(timeout=2)
            try:
                return prepared.decide_once(decision)
            except request.VaultRecoveryEntryRequestReplayError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(
                    decide,
                    request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW,
                ),
                pool.submit(
                    decide,
                    request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP,
                ),
            )
            start.wait(timeout=2)
            results = [future.result(timeout=2) for future in futures]
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_prepared_request_cannot_be_copied_or_serialized(self):
        prepared = prepare()
        for action in (
            copy.copy,
            copy.deepcopy,
            lambda value: pickle.dumps(value),
        ):
            with self.subTest(action=action):
                with self.assertRaises(request.VaultRecoveryEntryRequestReplayError):
                    action(prepared)

    def test_outcome_schema_excludes_sources_secrets_and_capabilities(self):
        names = {item.name for item in dataclasses.fields(request.VaultRecoveryEntryRequestOutcome)}
        self.assertTrue(
            names.isdisjoint(
                {
                    "password",
                    "recovery_root",
                    "recovery_record",
                    "keyring",
                    "vault_id",
                    "recovery_id",
                    "vault_path",
                    "recovery_path",
                    "filename",
                    "callback",
                    "executor",
                    "binding",
                    "session",
                    "workflow_state",
                    "presentation",
                    "adapter",
                }
            )
        )

    def test_every_false_safety_flag_rejects_forged_true(self):
        outcome = prepare().decide_once(
            request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        )
        names = (
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
        )
        for name in names:
            with self.subTest(name=name):
                with self.assertRaises(request.VaultRecoveryEntryRequestFormatError):
                    dataclasses.replace(outcome, **{name: True})

    def test_outcome_requires_consistent_decision_booleans(self):
        outcome = prepare().decide_once(
            request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        )
        for changes in (
            {"review_requested": False},
            {"preserved_and_stopped": True},
            {"request_sequence": True},
            {"version": True},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(request.VaultRecoveryEntryRequestFormatError):
                    dataclasses.replace(outcome, **changes)

    def test_repr_contains_only_locale_and_lifecycle(self):
        rendered = repr(prepare())
        self.assertIn("bg-BG", rendered)
        for token in ("password", "root", "keyring", "path", "binding"):
            self.assertNotIn(token, rendered.lower())


class RecoveryEntryRequestStaticBoundaryTests(unittest.TestCase):
    def test_public_prepare_api_accepts_only_locale(self):
        self.assertEqual(
            tuple(inspect.signature(request.prepare_recovery_entry_request).parameters),
            ("locale_id",),
        )
        self.assertEqual(
            tuple(inspect.signature(request.PreparedVaultRecoveryEntryRequest.decide_once).parameters),
            ("self", "decision"),
        )

    def test_module_has_no_source_filesystem_gui_network_process_or_logging_import(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_entry_request.py").read_text(
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
            "mokosh_vault_recovery",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_workflow",
            "mokosh_vault_recovery_review_controller",
            "mokosh_vault_recovery_main_gui_bridge",
        }
        self.assertTrue(imports.isdisjoint(forbidden))

    def test_module_has_no_source_operation_or_dynamic_calls(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_entry_request.py").read_text(
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
            "prepare_recovery_review_session",
            "prepare_main_gui_recovery_review_binding",
            "show_prepared_recovery_review",
            "publish_recovery_candidate",
        }
        self.assertTrue(calls.isdisjoint(forbidden))

    def test_main_gui_and_launcher_remain_byte_exact_unmodified(self):
        import hashlib

        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
