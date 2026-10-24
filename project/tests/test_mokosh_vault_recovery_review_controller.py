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


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in dataclasses.fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


def headless_outcome(
    parent,
    presentation,
    adapter,
    locale_id,
    *,
    acknowledge=False,
    cancel_reason=review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON,
):
    del parent
    prepared = review.prepare_recovery_review_window(
        presentation,
        adapter,
        locale_id,
    )
    if not acknowledge:
        return prepared.cancel_once(cancel_reason)
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


class RecoveryReviewControllerPreparationTests(unittest.TestCase):
    def test_every_route_and_locale_prepares_without_gui_or_source_retention(self):
        for route in ROUTES:
            for locale_id in ("bg-BG", "en-GB"):
                with self.subTest(route=route, locale_id=locale_id):
                    source = make_state(route)
                    prepared = controller.prepare_recovery_review_session(
                        source,
                        locale_id,
                    )
                    self.assertIs(
                        prepared.current_state,
                        controller.RecoveryReviewControllerState.PREPARED,
                    )
                    self.assertIsNone(prepared.outcome)
                    self.assertNotIn("workflow", prepared.__slots__)
                    self.assertNotIn("recovery_id", repr(prepared))
                    self.assertNotIn("vault_id", repr(prepared))

    def test_only_exact_source_type_and_locale_are_accepted(self):
        source = make_state()
        for invalid in (None, {}, source.evidence, True):
            with self.subTest(source=invalid):
                with self.assertRaises(
                    controller.VaultRecoveryReviewControllerSourceError
                ):
                    controller.prepare_recovery_review_session(invalid, "bg-BG")
        for invalid in (None, True, 1, ["bg-BG"], "bg", "en", "bg-BG ", ""):
            with self.subTest(locale=invalid):
                with self.assertRaises(
                    controller.VaultRecoveryReviewControllerSourceError
                ):
                    controller.prepare_recovery_review_session(source, invalid)

    def test_forged_authority_state_is_rejected_before_display(self):
        forged = forge_dataclass(make_state(), mutation_authorized=True)
        with mock.patch.object(controller, "_show_recovery_review_window") as show:
            with self.assertRaises(controller.VaultRecoveryReviewControllerSourceError):
                controller.prepare_recovery_review_session(forged, "bg-BG")
        show.assert_not_called()

    def test_direct_constructor_rejects_mismatched_adapter(self):
        first = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        second = controller.prepare_recovery_review_session(
            make_state(ROUTES[1]),
            "bg-BG",
        )
        with self.assertRaises(controller.VaultRecoveryReviewControllerSourceError):
            controller.PreparedVaultRecoveryReviewSession(
                first._presentation,
                second._adapter,
                "bg-BG",
            )

    def test_prepared_session_cannot_be_copied_or_serialized(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(
                    controller.VaultRecoveryReviewControllerOutcomeError
                ):
                    operation()


class RecoveryReviewControllerOutcomeTests(unittest.TestCase):
    def test_acknowledgement_composes_exact_stage_210_to_214_chain(self):
        for route in ROUTES:
            for locale_id in ("bg-BG", "en-GB"):
                with self.subTest(route=route, locale_id=locale_id):
                    prepared = controller.prepare_recovery_review_session(
                        make_state(route),
                        locale_id,
                    )
                    with mock.patch.object(
                        controller,
                        "_show_recovery_review_window",
                        side_effect=lambda *args: headless_outcome(
                            *args,
                            acknowledge=True,
                        ),
                    ):
                        outcome = prepared.show_once(object())
                    self.assertIs(
                        outcome.decision,
                        review.RecoveryReviewWindowDecision.ACKNOWLEDGED,
                    )
                    self.assertIsNone(outcome.cancel_reason)
                    self.assertIsNotNone(outcome.acknowledgement_receipt)
                    self.assertFalse(outcome.operation_performed)
                    self.assertFalse(outcome.operation_authorized)
                    self.assertIs(
                        prepared.current_state,
                        controller.RecoveryReviewControllerState.COMPLETED,
                    )
                    self.assertIsNone(prepared._presentation)
                    self.assertIsNone(prepared._adapter)

    def test_all_three_exact_cancellation_reasons_remain_bounded(self):
        for reason in review.RecoveryReviewWindowCancelReason:
            with self.subTest(reason=reason):
                prepared = controller.prepare_recovery_review_session(
                    make_state(),
                    "bg-BG",
                )
                with mock.patch.object(
                    controller,
                    "_show_recovery_review_window",
                    side_effect=lambda *args: headless_outcome(
                        *args,
                        cancel_reason=reason,
                    ),
                ):
                    outcome = prepared.show_once(object())
                self.assertIs(
                    outcome.decision,
                    review.RecoveryReviewWindowDecision.CANCELLED,
                )
                self.assertIs(outcome.cancel_reason, reason)
                self.assertIsNone(outcome.acknowledgement_receipt)

    def test_returned_outcome_has_no_source_identifiers_or_capability_fields(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=lambda *args: headless_outcome(*args),
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
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_wrong_locale_or_presentation_digest_outcome_is_rejected(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")

        def wrong_locale(*args):
            return headless_outcome(args[0], args[1], args[2], "en-GB")

        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=wrong_locale,
        ):
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            controller.RecoveryReviewControllerState.FAILED,
        )

        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")

        def wrong_digest(*args):
            valid = headless_outcome(*args)
            return forge_dataclass(valid, presentation_sha256=b"X" * 32)

        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=wrong_digest,
        ):
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())

    def test_forged_authority_outcome_is_revalidated_and_rejected(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")

        def forged_outcome(*args):
            valid = headless_outcome(*args)
            return forge_dataclass(valid, operation_authorized=True)

        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=forged_outcome,
        ):
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIsNone(prepared.outcome)
        self.assertIsNone(prepared._presentation)
        self.assertIsNone(prepared._adapter)

    def test_non_outcome_return_is_rejected(self):
        for invalid in (None, {}, "acknowledged"):
            with self.subTest(invalid=invalid):
                prepared = controller.prepare_recovery_review_session(
                    make_state(),
                    "bg-BG",
                )
                with mock.patch.object(
                    controller,
                    "_show_recovery_review_window",
                    return_value=invalid,
                ):
                    with self.assertRaises(
                        controller.VaultRecoveryReviewControllerOutcomeError
                    ):
                        prepared.show_once(object())

        class OutcomeSubclass(review.VaultRecoveryReviewWindowOutcome):
            pass

        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")

        def subclass_outcome(*args):
            valid = headless_outcome(*args)
            subclass = object.__new__(OutcomeSubclass)
            for item in dataclasses.fields(valid):
                object.__setattr__(subclass, item.name, getattr(valid, item.name))
            return subclass

        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=subclass_outcome,
        ):
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())


class RecoveryReviewControllerLifecycleTests(unittest.TestCase):
    def test_successful_session_cannot_be_replayed(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=lambda *args: headless_outcome(*args),
        ):
            first = prepared.show_once(object())
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIs(prepared.outcome, first)

    def test_display_failure_is_wrapped_consumed_and_not_retried(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=review.VaultRecoveryReviewWindowDisplayError("synthetic"),
        ) as show:
            with self.assertRaises(controller.VaultRecoveryReviewControllerDisplayError):
                prepared.show_once(object())
            with self.assertRaises(controller.VaultRecoveryReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertEqual(show.call_count, 1)
        self.assertIs(
            prepared.current_state,
            controller.RecoveryReviewControllerState.FAILED,
        )

    def test_keyboard_interrupt_consumes_session_and_propagates(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            controller.RecoveryReviewControllerState.FAILED,
        )

    def test_concurrent_attempts_allow_exactly_one_display(self):
        prepared = controller.prepare_recovery_review_session(make_state(), "bg-BG")
        entered = threading.Event()
        release = threading.Event()

        def blocking_display(*args):
            entered.set()
            self.assertTrue(release.wait(2))
            return headless_outcome(*args)

        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=blocking_display,
        ) as show:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(prepared.show_once, object())
                self.assertTrue(entered.wait(2))
                second = pool.submit(prepared.show_once, object())
                with self.assertRaises(
                    controller.VaultRecoveryReviewControllerOutcomeError
                ):
                    second.result(timeout=2)
                release.set()
                result = first.result(timeout=2)
        self.assertIs(
            result.decision,
            review.RecoveryReviewWindowDecision.CANCELLED,
        )
        self.assertEqual(show.call_count, 1)


class RecoveryReviewControllerStaticBoundaryTests(unittest.TestCase):
    def test_only_one_public_module_function_is_exposed(self):
        functions = [
            name
            for name, value in vars(controller).items()
            if inspect.isfunction(value)
            and value.__module__ == controller.__name__
            and not name.startswith("_")
        ]
        self.assertEqual(functions, ["prepare_recovery_review_session"])

    def test_public_apis_accept_no_secret_path_callback_or_executor(self):
        self.assertEqual(
            tuple(inspect.signature(controller.prepare_recovery_review_session).parameters),
            ("workflow_state", "locale_id"),
        )
        self.assertEqual(
            tuple(inspect.signature(controller.PreparedVaultRecoveryReviewSession.show_once).parameters),
            ("self", "parent"),
        )

    def test_module_imports_only_bounded_review_layers(self):
        source = (PROJECT_ROOT / "mokosh_vault_recovery_review_controller.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        forbidden = {
            "os",
            "pathlib",
            "shutil",
            "subprocess",
            "socket",
            "urllib",
            "logging",
            "mokosh_gui",
            "mokosh_vault_recovery",
            "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish",
            "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_storage",
        }
        self.assertTrue(imports.isdisjoint(forbidden), imports & forbidden)

    def test_module_has_no_filesystem_network_dynamic_or_operation_calls(self):
        source = (PROJECT_ROOT / "mokosh_vault_recovery_review_controller.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        forbidden_calls = {
            "open",
            "eval",
            "exec",
            "compile",
            "remove",
            "unlink",
            "replace",
            "rename",
            "rmtree",
            "Popen",
            "run",
            "publish_recovery_candidate",
            "prepare_recovery_candidate",
            "reconcile_recovery_publish",
        }
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        calls.update(
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        )
        self.assertTrue(calls.isdisjoint(forbidden_calls), calls & forbidden_calls)

    def test_main_gui_remains_unchanged_and_fail_closed(self):
        source = (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignments = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        safety_mode = assignments["SAFETY_MODE"]
        self.assertIsInstance(safety_mode, ast.Constant)
        self.assertIs(safety_mode.value, True)
        self.assertNotIn("mokosh_vault_recovery_review_controller", source)


if __name__ == "__main__":
    unittest.main()
