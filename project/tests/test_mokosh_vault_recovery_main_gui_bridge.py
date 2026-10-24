import ast
import copy
import dataclasses
import inspect
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import mokosh_vault_recovery_main_gui_bridge as bridge
import mokosh_vault_recovery_review_controller as controller
import mokosh_vault_recovery_review_window as review
import mokosh_vault_recovery_workflow as workflow
from mokosh_vault_recovery_reconciliation import (
    RecoveryPublishClassification,
    RecoveryReconciliationAction,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


ROUTES = (
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        (workflow.RecoveryWorkflowGate.STAGE_2_6_NEW_CANDIDATE_DECISION,),
        False,
        True,
        None,
    ),
    (
        RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        workflow.RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        (
            workflow.RecoveryWorkflowGate.NORMAL_VAULT_UNLOCK,
            workflow.RecoveryWorkflowGate.STAGE_2_5_NEW_RECOVERY_SETUP_DECISION,
        ),
        False,
        True,
        b"T" * 32,
    ),
    (
        RecoveryPublishClassification.CONFLICT,
        RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        (workflow.RecoveryWorkflowGate.MANUAL_REVIEW_ONLY,),
        True,
        False,
        None,
    ),
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
        workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        workflow.RecoveryWorkflowState.PRESERVED_STOP,
        (),
        True,
        False,
        None,
    ),
)


def make_state(route=ROUTES[0]):
    (
        classification,
        action,
        decision,
        state,
        gates,
        terminal,
        reverification,
        target_sha256,
    ) = route
    evidence = workflow.VaultRecoveryWorkflowEvidence(
        reconciliation_result_sha256=b"E" * 32,
        classification=classification,
        recommended_action=action,
        recovery_id=b"R" * 16,
        vault_id=b"V" * 16,
        source_revision=1,
        target_revision=2,
        source_vault_sha256=b"S" * 32,
        record_sha256=b"D" * 32,
        keyring_sha256=b"K" * 32,
        target_vault_sha256=target_sha256,
        storage_complete=True,
        stable_observation=True,
    )
    return workflow.VaultRecoveryWorkflowState(
        evidence=evidence,
        decision=decision,
        state=state,
        required_gates=gates,
        terminal_stop=terminal,
        downstream_reverification_required=reverification,
    )


def headless_outcome(
    parent,
    presentation,
    adapter,
    locale_id,
    *,
    acknowledge=False,
):
    del parent
    prepared = review.prepare_recovery_review_window(
        presentation,
        adapter,
        locale_id,
    )
    if not acknowledge:
        return prepared.cancel_once(
            review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
        )
    prepared.mark_messages_visible_once(
        tuple(item.ordinal for item in prepared.localized_view.message_items)
    )
    for item in prepared.localized_view.confirmation_controls:
        prepared.record_confirmation_selection(
            item.ordinal,
            item.confirmation_key,
            True,
        )
    return prepared.acknowledge_visible_once()


def make_binding(route=ROUTES[0], locale_id="bg-BG"):
    session = controller.prepare_recovery_review_session(
        make_state(route),
        locale_id,
    )
    return bridge.prepare_main_gui_recovery_review_binding(session, locale_id)


class RecoveryMainGUIBridgePreparationTests(unittest.TestCase):
    def test_every_route_and_locale_binds_fresh_stage216_session(self):
        for route in ROUTES:
            for locale_id in ("bg-BG", "en-GB"):
                with self.subTest(route=route, locale_id=locale_id):
                    prepared = make_binding(route, locale_id)
                    self.assertIs(
                        prepared.current_state,
                        bridge.RecoveryMainGUIBridgeState.READY,
                    )
                    self.assertEqual(prepared.locale.value, locale_id)
                    self.assertIsNone(prepared.outcome)

    def test_source_and_locale_types_are_exact(self):
        session = controller.prepare_recovery_review_session(
            make_state(),
            "bg-BG",
        )
        for invalid in (None, {}, True, make_state()):
            with self.subTest(session=invalid):
                with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeSourceError):
                    bridge.prepare_main_gui_recovery_review_binding(
                        invalid,
                        "bg-BG",
                    )
        for invalid in (None, True, 1, "bg", "en", "bg-BG ", ""):
            with self.subTest(locale=invalid):
                with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeSourceError):
                    bridge.prepare_main_gui_recovery_review_binding(
                        session,
                        invalid,
                    )

    def test_session_locale_mismatch_is_rejected_before_display(self):
        session = controller.prepare_recovery_review_session(
            make_state(),
            "bg-BG",
        )
        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
        ) as show:
            with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeSourceError):
                bridge.prepare_main_gui_recovery_review_binding(
                    session,
                    "en-GB",
                )
        show.assert_not_called()

    def test_nonfresh_session_is_rejected(self):
        session = controller.prepare_recovery_review_session(
            make_state(),
            "bg-BG",
        )
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            session.show_once(object())
        with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeSourceError):
            bridge.prepare_main_gui_recovery_review_binding(session, "bg-BG")

    def test_binding_cannot_be_copied_or_serialized(self):
        prepared = make_binding()
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeOutcomeError):
                    operation()


class RecoveryMainGUIBridgeOutcomeTests(unittest.TestCase):
    def test_cancelled_outcome_is_returned_exactly_and_sources_are_cleared(self):
        prepared = make_binding()
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            outcome = prepared.show_once(object())
        self.assertIs(
            outcome.decision,
            review.RecoveryReviewWindowDecision.CANCELLED,
        )
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertIsNone(prepared._session)
        self.assertIs(
            prepared.current_state,
            bridge.RecoveryMainGUIBridgeState.COMPLETED,
        )

    def test_acknowledged_outcome_remains_no_authority(self):
        prepared = make_binding(locale_id="en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=lambda *args: headless_outcome(*args, acknowledge=True),
        ):
            outcome = prepared.show_once(object())
        self.assertIs(
            outcome.decision,
            review.RecoveryReviewWindowDecision.ACKNOWLEDGED,
        )
        self.assertIsNotNone(outcome.acknowledgement_receipt)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)

    def test_non_outcome_is_rejected_and_consumes_binding(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
            return_value=None,
        ):
            with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeOutcomeError):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            bridge.RecoveryMainGUIBridgeState.FAILED,
        )
        self.assertIsNone(prepared._session)

    def test_wrong_locale_outcome_is_rejected(self):
        valid = make_binding(locale_id="en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            en_outcome = valid.show_once(object())
        forged = dataclasses.replace(
            en_outcome,
            locale=review.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        )
        prepared = make_binding(locale_id="bg-BG")
        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
            return_value=forged,
        ):
            with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeOutcomeError):
                prepared.show_once(object())

    def test_success_cannot_be_replayed(self):
        prepared = make_binding()
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            prepared.show_once(object())
        with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeOutcomeError):
            prepared.show_once(object())

    def test_controller_failure_is_wrapped_and_consumed(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
            side_effect=controller.VaultRecoveryReviewControllerDisplayError(
                "bounded"
            ),
        ):
            with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeDisplayError):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            bridge.RecoveryMainGUIBridgeState.FAILED,
        )
        self.assertIsNone(prepared._session)

    def test_keyboard_interrupt_consumes_binding_and_propagates(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            bridge.RecoveryMainGUIBridgeState.FAILED,
        )
        self.assertIsNone(prepared._session)

    def test_concurrent_attempts_allow_exactly_one_display(self):
        prepared = make_binding()
        entered = threading.Event()
        release = threading.Event()

        def display_once(session, parent):
            del parent
            entered.set()
            release.wait(timeout=2)
            return headless_outcome(
                object(),
                session._presentation,
                session._adapter,
                session.locale.value,
            )

        with mock.patch.object(
            controller.PreparedVaultRecoveryReviewSession,
            "show_once",
            autospec=True,
            side_effect=display_once,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(prepared.show_once, object())
                self.assertTrue(entered.wait(timeout=2))
                second = pool.submit(prepared.show_once, object())
                with self.assertRaises(bridge.VaultRecoveryMainGUIBridgeOutcomeError):
                    second.result(timeout=2)
                release.set()
                outcome = first.result(timeout=2)
        self.assertIs(
            outcome.decision,
            review.RecoveryReviewWindowDecision.CANCELLED,
        )

    def test_outcome_schema_contains_no_source_or_capability(self):
        prepared = make_binding()
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            outcome = prepared.show_once(object())
        names = {item.name for item in dataclasses.fields(outcome)}
        forbidden = {
            "password",
            "recovery_root",
            "recovery_id",
            "vault_id",
            "keyring",
            "path",
            "filename",
            "callback",
            "executor",
            "operation_capability",
            "workflow_state",
            "presentation",
            "adapter",
            "session",
        }
        self.assertTrue(names.isdisjoint(forbidden))


class RecoveryMainGUIBridgeStaticBoundaryTests(unittest.TestCase):
    def test_main_gui_import_and_inactive_seam_forward_only_exact_binding(self):
        import mokosh_gui

        with self.assertRaises(TypeError):
            mokosh_gui.show_prepared_recovery_review(object(), None)
        prepared = make_binding()
        sentinel = object()
        with mock.patch.object(
            bridge.PreparedMainGUIRecoveryReviewBinding,
            "show_once",
            return_value=sentinel,
        ) as show:
            returned = mokosh_gui.show_prepared_recovery_review(
                object(),
                prepared,
            )
        self.assertIs(returned, sentinel)
        show.assert_called_once()

    def test_public_prepare_api_accepts_only_session_and_locale(self):
        parameters = tuple(
            inspect.signature(
                bridge.prepare_main_gui_recovery_review_binding
            ).parameters
        )
        self.assertEqual(parameters, ("prepared_session", "locale_id"))

    def test_bridge_has_no_input_mutation_network_process_or_logging_import(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_main_gui_bridge.py").read_text(
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
            "importlib",
            "mokosh_vault_recovery",
            "mokosh_vault_storage",
            "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish",
        }
        self.assertTrue(imports.isdisjoint(forbidden))

    def test_bridge_has_no_dynamic_or_operation_calls(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_main_gui_bridge.py").read_text(
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
            "publish_recovery_candidate",
        }
        self.assertTrue(calls.isdisjoint(forbidden))

    def test_main_gui_seam_is_exact_and_inactive_during_normal_main(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        )
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        seam = functions["show_prepared_recovery_review"]
        self.assertEqual(
            tuple(arg.arg for arg in seam.args.args),
            ("parent", "prepared_binding"),
        )
        main_calls = {
            node.func.id
            for node in ast.walk(functions["main"])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("show_prepared_recovery_review", main_calls)

    def test_main_gui_remains_fail_closed_and_imports_no_recovery_source(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        )
        assignments = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        self.assertIs(assignments["SAFETY_MODE"].value, True)
        imported_modules = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
        }
        self.assertNotIn("mokosh_vault_recovery_main_gui_bridge", imported_modules)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_recovery_review_bridge_contract"
        )
        helper_imports = {
            node.module
            for node in ast.walk(helper)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertEqual(
            helper_imports,
            {"mokosh_vault_recovery_main_gui_bridge"},
        )
        self.assertNotIn("mokosh_vault_recovery", imported_modules)
        self.assertNotIn("mokosh_vault_recovery_workflow", imported_modules)
        self.assertNotIn("mokosh_vault_recovery_reconciliation", imported_modules)

    def test_controller_exposes_only_bounded_locale_property(self):
        session = controller.prepare_recovery_review_session(
            make_state(),
            "bg-BG",
        )
        self.assertIs(
            session.locale,
            review.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        )
        self.assertNotIn("recovery_id", repr(session))
        self.assertNotIn("vault_id", repr(session))


if __name__ == "__main__":
    unittest.main()
