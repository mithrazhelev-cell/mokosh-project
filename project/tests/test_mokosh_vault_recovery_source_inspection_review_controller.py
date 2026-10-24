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
from unittest import mock

import mokosh_vault_recovery_locale as locale
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_review_controller as controller
import mokosh_vault_recovery_source_inspection_review_window as review


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RECOVERY_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
VAULT_ID = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
SOURCE_HASH = hashlib.sha256(b"source-vault").digest()
RECORD_HASH = hashlib.sha256(b"recovery-record").digest()


def positive_execution(locale_id="bg-BG"):
    return execution.VaultRecoverySourceInspectionExecutionOutcome(
        locale=(
            locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
            if locale_id == "bg-BG"
            else locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM
        ),
        execution_decision=execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION,
        state=execution.RecoverySourceInspectionExecutionState.COMPLETED,
        recovery_id=RECOVERY_ID,
        vault_id=VAULT_ID,
        source_revision=7,
        source_vault_sha256=SOURCE_HASH,
        record_sha256=RECORD_HASH,
        encoded_size=777,
        secure_source_inspection_performed=True,
        preserved_and_stopped=False,
        header_structurally_validated=True,
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


def headless_outcome(parent, presentation, adapter, *, acknowledge=False, cancel_reason=review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON):
    del parent
    prepared = review.prepare_recovery_source_inspection_review_window(
        presentation,
        adapter,
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


class SourceInspectionReviewControllerPreparationTests(unittest.TestCase):
    def test_01_supported_locales_prepare_without_source_retention(self):
        for locale_id in ("bg-BG", "en-GB"):
            with self.subTest(locale_id=locale_id):
                source = positive_execution(locale_id)
                prepared = controller.prepare_recovery_source_inspection_review_session(source)
                self.assertIs(
                    prepared.current_state,
                    controller.RecoverySourceInspectionReviewControllerState.PREPARED,
                )
                self.assertIsNone(prepared.outcome)
                self.assertNotIn("execution", prepared.__slots__)
                self.assertNotIn("recovery_id", prepared.__slots__)
                self.assertNotIn("vault_id", prepared.__slots__)
                self.assertNotIn(RECOVERY_ID.hex(), repr(prepared))
                self.assertNotIn(VAULT_ID.hex(), repr(prepared))

    def test_02_only_exact_positive_stage232_source_is_accepted(self):
        source = positive_execution()
        for invalid in (None, {}, True, source.locale):
            with self.subTest(invalid=invalid):
                with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerSourceError):
                    controller.prepare_recovery_source_inspection_review_session(invalid)
        forged = forge_dataclass(source, operation_authorized=True)
        with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerSourceError):
            controller.prepare_recovery_source_inspection_review_session(forged)

    def test_03_preserve_and_stop_stage232_outcome_is_rejected(self):
        stopped = execution.VaultRecoverySourceInspectionExecutionOutcome(
            locale=locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
            execution_decision=execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP,
            state=execution.RecoverySourceInspectionExecutionState.COMPLETED,
            recovery_id=None,
            vault_id=None,
            source_revision=None,
            source_vault_sha256=None,
            record_sha256=None,
            encoded_size=None,
            secure_source_inspection_performed=False,
            preserved_and_stopped=True,
            header_structurally_validated=False,
        )
        with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerSourceError):
            controller.prepare_recovery_source_inspection_review_session(stopped)

    def test_04_direct_constructor_rejects_mismatched_adapter(self):
        first = controller.prepare_recovery_source_inspection_review_session(positive_execution("bg-BG"))
        second = controller.prepare_recovery_source_inspection_review_session(positive_execution("en-GB"))
        with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerSourceError):
            controller.PreparedVaultRecoverySourceInspectionReviewSession(
                first._presentation,
                second._adapter,
            )

    def test_05_prepared_session_cannot_be_copied_or_serialized(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                    operation()


class SourceInspectionReviewControllerOutcomeTests(unittest.TestCase):
    def test_06_acknowledgement_composes_exact_stage233_to238_chain(self):
        for locale_id in ("bg-BG", "en-GB"):
            with self.subTest(locale_id=locale_id):
                prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution(locale_id))
                with mock.patch.object(
                    controller,
                    "_show_recovery_source_inspection_review_window",
                    side_effect=lambda *args: headless_outcome(*args, acknowledge=True),
                ):
                    outcome = prepared.show_once(object())
                self.assertIs(outcome.decision, review.RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED)
                self.assertIsNone(outcome.cancel_reason)
                self.assertIsNotNone(outcome.acknowledgement_receipt)
                self.assertIs(outcome.locale, prepared.locale)

    def test_07_all_three_cancellation_reasons_remain_bounded(self):
        for reason in review.RecoverySourceInspectionReviewWindowCancelReason:
            with self.subTest(reason=reason):
                prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
                with mock.patch.object(
                    controller,
                    "_show_recovery_source_inspection_review_window",
                    side_effect=lambda *args, reason=reason: headless_outcome(*args, cancel_reason=reason),
                ):
                    outcome = prepared.show_once(object())
                self.assertIs(outcome.decision, review.RecoverySourceInspectionReviewWindowDecision.CANCELLED)
                self.assertIs(outcome.cancel_reason, reason)
                self.assertIsNone(outcome.acknowledgement_receipt)

    def test_08_returned_outcome_has_no_source_identifier_or_capability_fields(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=lambda *args: headless_outcome(*args),
        ):
            outcome = prepared.show_once(object())
        names = {item.name for item in dataclasses.fields(outcome)}
        forbidden = {
            "password", "recovery_root", "recovery_id", "vault_id", "keyring",
            "path", "filename", "callback", "executor", "operation_capability",
            "execution_outcome", "presentation", "adapter",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_09_wrong_locale_or_presentation_digest_is_rejected(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution("bg-BG"))
        def wrong_locale(*args):
            valid = headless_outcome(*args)
            return forge_dataclass(valid, locale=locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM)
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=wrong_locale):
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIs(prepared.current_state, controller.RecoverySourceInspectionReviewControllerState.FAILED)

        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        def wrong_digest(*args):
            valid = headless_outcome(*args)
            return forge_dataclass(valid, presentation_sha256=b"X" * 32)
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=wrong_digest):
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                prepared.show_once(object())

    def test_10_forged_authority_outcome_is_revalidated_and_rejected(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        def forged_outcome(*args):
            valid = headless_outcome(*args)
            return forge_dataclass(valid, operation_authorized=True)
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=forged_outcome):
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIsNone(prepared.outcome)
        self.assertIsNone(prepared._presentation)
        self.assertIsNone(prepared._adapter)

    def test_11_non_outcome_return_is_rejected(self):
        for invalid in (None, {}, "acknowledged"):
            with self.subTest(invalid=invalid):
                prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
                with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", return_value=invalid):
                    with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                        prepared.show_once(object())


class SourceInspectionReviewControllerLifecycleTests(unittest.TestCase):
    def test_12_successful_session_cannot_be_replayed(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=lambda *args: headless_outcome(*args)):
            first = prepared.show_once(object())
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertIs(prepared.outcome, first)
        self.assertIs(prepared.current_state, controller.RecoverySourceInspectionReviewControllerState.COMPLETED)

    def test_13_display_failure_is_wrapped_consumed_and_not_retried(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=review.VaultRecoverySourceInspectionReviewWindowDisplayError("synthetic"),
        ) as show:
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerDisplayError):
                prepared.show_once(object())
            with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                prepared.show_once(object())
        self.assertEqual(show.call_count, 1)
        self.assertIs(prepared.current_state, controller.RecoverySourceInspectionReviewControllerState.FAILED)

    def test_14_keyboard_interrupt_consumes_session_and_propagates(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                prepared.show_once(object())
        self.assertIs(prepared.current_state, controller.RecoverySourceInspectionReviewControllerState.FAILED)

    def test_15_concurrent_attempts_allow_exactly_one_display(self):
        prepared = controller.prepare_recovery_source_inspection_review_session(positive_execution())
        entered = threading.Event()
        release = threading.Event()
        def blocking_display(*args):
            entered.set()
            self.assertTrue(release.wait(2))
            return headless_outcome(*args)
        with mock.patch.object(controller, "_show_recovery_source_inspection_review_window", side_effect=blocking_display) as show:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(prepared.show_once, object())
                self.assertTrue(entered.wait(2))
                second = pool.submit(prepared.show_once, object())
                with self.assertRaises(controller.VaultRecoverySourceInspectionReviewControllerOutcomeError):
                    second.result(timeout=2)
                release.set()
                result = first.result(timeout=2)
        self.assertIs(result.decision, review.RecoverySourceInspectionReviewWindowDecision.CANCELLED)
        self.assertEqual(show.call_count, 1)


class SourceInspectionReviewControllerStaticBoundaryTests(unittest.TestCase):
    def test_16_only_one_public_module_function_is_exposed(self):
        functions = [
            name
            for name, value in vars(controller).items()
            if inspect.isfunction(value)
            and value.__module__ == controller.__name__
            and not name.startswith("_")
        ]
        self.assertEqual(functions, ["prepare_recovery_source_inspection_review_session"])

    def test_17_public_apis_accept_no_locale_secret_path_callback_or_executor(self):
        self.assertEqual(
            tuple(inspect.signature(controller.prepare_recovery_source_inspection_review_session).parameters),
            ("execution_outcome",),
        )
        self.assertEqual(
            tuple(inspect.signature(controller.PreparedVaultRecoverySourceInspectionReviewSession.show_once).parameters),
            ("self", "parent"),
        )

    def test_18_module_imports_only_bounded_review_layers(self):
        source = (PROJECT_ROOT / "mokosh_vault_recovery_source_inspection_review_controller.py").read_text(encoding="utf-8")
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
            "os", "pathlib", "shutil", "subprocess", "socket", "urllib", "logging",
            "mokosh_gui", "mokosh_vault_recovery", "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish", "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_storage", "mokosh_vault_storage",
            "mokosh_vault_recovery_source_inspection_request",
            "mokosh_vault_recovery_source_inspection_preparation_request",
        }
        self.assertTrue(imports.isdisjoint(forbidden), imports & forbidden)

    def test_19_module_has_no_filesystem_network_dynamic_or_operation_calls(self):
        source = (PROJECT_ROOT / "mokosh_vault_recovery_source_inspection_review_controller.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_calls = {
            "open", "eval", "exec", "compile", "remove", "unlink", "rename", "rmtree",
            "Popen", "run", "publish_recovery_candidate", "prepare_recovery_candidate",
            "reconcile_recovery_publish", "prepare_recovery_source_inspection_execution",
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

    def test_20_main_gui_remains_unchanged_fail_closed_and_controller_not_wired(self):
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
        self.assertNotIn("mokosh_vault_recovery_source_inspection_review_controller", source)


if __name__ == "__main__":
    unittest.main()
