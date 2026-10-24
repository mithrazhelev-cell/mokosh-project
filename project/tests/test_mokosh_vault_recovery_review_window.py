import ast
import copy
import dataclasses
import inspect
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import mokosh_vault_recovery_localization as localization
import mokosh_vault_recovery_presentation as presentation
import mokosh_vault_recovery_review_window as review
import mokosh_vault_recovery_ui_adapter as adapter
import mokosh_vault_recovery_workflow as workflow
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification


ROUTES = (
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        False,
        True,
    ),
    (
        RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        workflow.RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        False,
        True,
    ),
    (
        RecoveryPublishClassification.CONFLICT,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        True,
        False,
    ),
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        workflow.RecoveryWorkflowState.PRESERVED_STOP,
        True,
        False,
    ),
)


def make_presentation(route=ROUTES[0], digest=b"W" * 32):
    classification, decision, state, terminal, reverification = route
    messages, gates, confirmations = presentation._presentation_components(
        classification,
        decision,
        state,
        terminal,
        reverification,
    )
    return presentation.VaultRecoveryWorkflowPresentation(
        workflow_state_sha256=digest,
        classification=classification,
        decision=decision,
        state=state,
        message_keys=messages,
        gate_message_keys=gates,
        confirmation_requirements=confirmations,
        terminal_stop=terminal,
        downstream_reverification_required=reverification,
    )


def prepare(route=ROUTES[0], locale_id="bg-BG"):
    source = make_presentation(route)
    prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
    prepared_window = review.prepare_recovery_review_window(
        source,
        prepared_adapter,
        locale_id,
    )
    return source, prepared_adapter, prepared_window


def mark_visible(value):
    value.mark_messages_visible_once(
        tuple(item.ordinal for item in value.localized_view.message_items)
    )


def select_all(value):
    for item in value.localized_view.confirmation_controls:
        value.record_confirmation_selection(
            item.ordinal,
            item.confirmation_key,
            True,
        )


def acknowledge(route=ROUTES[0], locale_id="bg-BG"):
    source, prepared_adapter, prepared_window = prepare(route, locale_id)
    mark_visible(prepared_window)
    select_all(prepared_window)
    return (
        source,
        prepared_adapter,
        prepared_window,
        prepared_window.acknowledge_visible_once(),
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


class RecoveryReviewWindowPreparationTests(unittest.TestCase):
    def test_every_route_and_locale_prepares_exact_localized_view(self):
        for route in ROUTES:
            for locale_id in ("bg-BG", "en-GB"):
                with self.subTest(route=route, locale_id=locale_id):
                    source, prepared_adapter, prepared_window = prepare(
                        route,
                        locale_id,
                    )
                    self.assertEqual(
                        prepared_window.localized_view.locale.value,
                        locale_id,
                    )
                    self.assertEqual(
                        tuple(
                            item.message_key
                            for item in prepared_window.localized_view.message_items
                        ),
                        source.message_keys,
                    )
                    self.assertEqual(
                        tuple(
                            item.confirmation_key
                            for item in prepared_window.localized_view.confirmation_controls
                        ),
                        source.confirmation_requirements,
                    )
                    self.assertIs(prepared_adapter.receipt, None)

    def test_only_exact_locale_ids_are_accepted(self):
        source = make_presentation()
        for locale_id in ("bg", "en", "en-US", "bg-BG ", "BG-bg", ""):
            with self.subTest(locale_id=locale_id):
                prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
                with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
                    review.prepare_recovery_review_window(
                        source,
                        prepared_adapter,
                        locale_id,
                    )

    def test_non_plain_locale_ids_are_rejected(self):
        source = make_presentation()
        for locale_id in (None, True, 1, ["bg-BG"], localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA):
            with self.subTest(locale_id=locale_id):
                prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
                with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
                    review.prepare_recovery_review_window(
                        source,
                        prepared_adapter,
                        locale_id,
                    )

    def test_window_chrome_is_fixed_and_locale_specific(self):
        _, _, bulgarian = prepare(locale_id="bg-BG")
        _, _, english = prepare(locale_id="en-GB")
        self.assertEqual(
            bulgarian.window_text.locale,
            localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        )
        self.assertEqual(
            english.window_text.locale,
            localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        )
        self.assertNotEqual(bulgarian.window_text.title, english.window_text.title)
        self.assertNotIn("{", bulgarian.window_text.introduction)
        self.assertNotIn("{", english.window_text.introduction)

    def test_initial_state_has_no_visibility_selection_or_receipt(self):
        _, prepared_adapter, prepared_window = prepare()
        self.assertEqual(
            prepared_window.current_state,
            review.RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW,
        )
        self.assertFalse(prepared_window.messages_visible)
        self.assertFalse(prepared_window.confirm_enabled)
        self.assertTrue(
            all(item is False for item in prepared_window.confirmation_selections)
        )
        self.assertIsNone(prepared_window.outcome)
        self.assertFalse(prepared_adapter.acknowledged)

    def test_wrong_presentation_type_is_rejected(self):
        source = make_presentation()
        prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
        for invalid in (None, {}, source.message_keys):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
                    review.prepare_recovery_review_window(
                        invalid,
                        prepared_adapter,
                        "bg-BG",
                    )

    def test_wrong_adapter_type_is_rejected(self):
        source = make_presentation()
        for invalid in (None, {}, adapter.prepare_recovery_ui_adapter(source).view):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
                    review.prepare_recovery_review_window(source, invalid, "bg-BG")

    def test_already_acknowledged_adapter_is_rejected(self):
        source = make_presentation()
        prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
        events = tuple(
            adapter.RecoveryUIConfirmationEvent(
                ordinal=index,
                confirmation_key=key,
                visible=True,
                user_selected=True,
                user_initiated=True,
            )
            for index, key in enumerate(source.confirmation_requirements, start=1)
        )
        prepared_adapter.acknowledge_visible_once(source, events)
        with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
            review.prepare_recovery_review_window(source, prepared_adapter, "bg-BG")

    def test_adapter_from_other_presentation_is_rejected(self):
        source = make_presentation(ROUTES[0])
        other = make_presentation(ROUTES[1])
        prepared_adapter = adapter.prepare_recovery_ui_adapter(other)
        with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
            review.prepare_recovery_review_window(source, prepared_adapter, "bg-BG")

    def test_tampered_adapter_view_is_rejected(self):
        source = make_presentation()
        prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
        object.__setattr__(prepared_adapter.view, "presentation_sha256", b"Z" * 32)
        with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
            review.prepare_recovery_review_window(source, prepared_adapter, "bg-BG")


class RecoveryReviewWindowInteractionTests(unittest.TestCase):
    def test_exact_visible_message_order_is_required(self):
        _, _, prepared_window = prepare()
        expected = tuple(
            item.ordinal for item in prepared_window.localized_view.message_items
        )
        for changed in (None, list(expected), (), tuple(reversed(expected)), expected[:-1]):
            with self.subTest(changed=changed):
                _, _, fresh = prepare()
                with self.assertRaises(
                    review.VaultRecoveryReviewWindowInteractionError
                ):
                    fresh.mark_messages_visible_once(changed)

    def test_messages_can_be_marked_visible_only_once(self):
        _, _, prepared_window = prepare()
        mark_visible(prepared_window)
        self.assertTrue(prepared_window.messages_visible)
        with self.assertRaises(review.VaultRecoveryReviewWindowInteractionError):
            mark_visible(prepared_window)

    def test_selection_before_visible_messages_is_rejected(self):
        _, _, prepared_window = prepare()
        control = prepared_window.localized_view.confirmation_controls[0]
        with self.assertRaises(review.VaultRecoveryReviewWindowInteractionError):
            prepared_window.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )

    def test_each_confirmation_is_selected_individually(self):
        _, _, prepared_window = prepare(ROUTES[1])
        mark_visible(prepared_window)
        for index, control in enumerate(
            prepared_window.localized_view.confirmation_controls
        ):
            prepared_window.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )
            selected = prepared_window.confirmation_selections
            self.assertTrue(selected[index])
            self.assertEqual(sum(selected), index + 1)

    def test_confirm_disabled_until_every_selection_is_true(self):
        _, _, prepared_window = prepare(ROUTES[1])
        mark_visible(prepared_window)
        controls = prepared_window.localized_view.confirmation_controls
        for control in controls[:-1]:
            prepared_window.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )
            self.assertFalse(prepared_window.confirm_enabled)
        final = controls[-1]
        prepared_window.record_confirmation_selection(
            final.ordinal,
            final.confirmation_key,
            True,
        )
        self.assertTrue(prepared_window.confirm_enabled)

    def test_unchecking_disables_final_confirmation_again(self):
        _, _, prepared_window = prepare()
        mark_visible(prepared_window)
        select_all(prepared_window)
        self.assertTrue(prepared_window.confirm_enabled)
        control = prepared_window.localized_view.confirmation_controls[0]
        prepared_window.record_confirmation_selection(
            control.ordinal,
            control.confirmation_key,
            False,
        )
        self.assertFalse(prepared_window.confirm_enabled)

    def test_wrong_confirmation_ordinal_is_rejected(self):
        _, _, prepared_window = prepare()
        mark_visible(prepared_window)
        control = prepared_window.localized_view.confirmation_controls[0]
        for ordinal in (0, -1, len(prepared_window.confirmation_selections) + 1, True):
            with self.subTest(ordinal=ordinal):
                with self.assertRaises(
                    review.VaultRecoveryReviewWindowInteractionError
                ):
                    prepared_window.record_confirmation_selection(
                        ordinal,
                        control.confirmation_key,
                        True,
                    )

    def test_wrong_confirmation_key_is_rejected(self):
        _, _, prepared_window = prepare()
        mark_visible(prepared_window)
        control = prepared_window.localized_view.confirmation_controls[0]
        wrong = presentation.RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP
        self.assertIsNot(control.confirmation_key, wrong)
        with self.assertRaises(review.VaultRecoveryReviewWindowInteractionError):
            prepared_window.record_confirmation_selection(1, wrong, True)

    def test_non_boolean_selection_is_rejected(self):
        _, _, prepared_window = prepare()
        mark_visible(prepared_window)
        control = prepared_window.localized_view.confirmation_controls[0]
        for invalid in (None, 0, 1, "true"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    review.VaultRecoveryReviewWindowInteractionError
                ):
                    prepared_window.record_confirmation_selection(
                        control.ordinal,
                        control.confirmation_key,
                        invalid,
                    )

    def test_acknowledgement_before_visibility_is_rejected(self):
        _, prepared_adapter, prepared_window = prepare()
        with self.assertRaises(review.VaultRecoveryReviewWindowInteractionError):
            prepared_window.acknowledge_visible_once()
        self.assertFalse(prepared_adapter.acknowledged)

    def test_partial_acknowledgement_is_rejected_without_consuming_adapter(self):
        _, prepared_adapter, prepared_window = prepare(ROUTES[1])
        mark_visible(prepared_window)
        controls = prepared_window.localized_view.confirmation_controls
        for control in controls[:-1]:
            prepared_window.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )
        with self.assertRaises(review.VaultRecoveryReviewWindowInteractionError):
            prepared_window.acknowledge_visible_once()
        self.assertFalse(prepared_adapter.acknowledged)
        self.assertEqual(
            prepared_window.current_state,
            review.RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW,
        )


class RecoveryReviewWindowOutcomeTests(unittest.TestCase):
    def test_success_returns_only_bounded_no_authority_receipt(self):
        source, prepared_adapter, prepared_window, outcome = acknowledge(ROUTES[1])
        self.assertEqual(outcome.decision, review.RecoveryReviewWindowDecision.ACKNOWLEDGED)
        self.assertIsNone(outcome.cancel_reason)
        self.assertIs(outcome.acknowledgement_receipt, prepared_adapter.receipt)
        self.assertEqual(
            outcome.acknowledgement_receipt.acknowledged_confirmations,
            source.confirmation_requirements,
        )
        self.assertFalse(outcome.operation_performed)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.gate_invoked)
        self.assertFalse(outcome.secrets_retained)
        self.assertIs(prepared_window.outcome, outcome)

    def test_success_works_for_every_route_and_locale(self):
        for route in ROUTES:
            for locale_id in ("bg-BG", "en-GB"):
                with self.subTest(route=route, locale_id=locale_id):
                    _, _, prepared_window, outcome = acknowledge(route, locale_id)
                    self.assertEqual(
                        prepared_window.current_state,
                        review.RecoveryReviewWindowState.ACKNOWLEDGED,
                    )
                    self.assertEqual(outcome.locale.value, locale_id)

    def test_cancel_routes_do_not_consume_adapter(self):
        for reason in review.RecoveryReviewWindowCancelReason:
            with self.subTest(reason=reason):
                _, prepared_adapter, prepared_window = prepare()
                outcome = prepared_window.cancel_once(reason)
                self.assertEqual(
                    outcome.decision,
                    review.RecoveryReviewWindowDecision.CANCELLED,
                )
                self.assertIs(outcome.cancel_reason, reason)
                self.assertIsNone(outcome.acknowledgement_receipt)
                self.assertFalse(prepared_adapter.acknowledged)
                self.assertIsNone(prepared_adapter.receipt)
                self.assertEqual(
                    prepared_window.current_state,
                    review.RecoveryReviewWindowState.CANCELLED,
                )

    def test_cancel_after_partial_selection_has_no_acknowledgement(self):
        _, prepared_adapter, prepared_window = prepare(ROUTES[1])
        mark_visible(prepared_window)
        first = prepared_window.localized_view.confirmation_controls[0]
        prepared_window.record_confirmation_selection(
            first.ordinal,
            first.confirmation_key,
            True,
        )
        outcome = prepared_window.cancel_once(
            review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
        )
        self.assertIsNone(outcome.acknowledgement_receipt)
        self.assertFalse(prepared_adapter.acknowledged)

    def test_invalid_cancel_reason_is_rejected_without_closing(self):
        _, _, prepared_window = prepare()
        for invalid in (None, "escape_key", 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    review.VaultRecoveryReviewWindowInteractionError
                ):
                    prepared_window.cancel_once(invalid)
                self.assertEqual(
                    prepared_window.current_state,
                    review.RecoveryReviewWindowState.AWAITING_VISIBLE_REVIEW,
                )

    def test_acknowledge_and_cancel_are_one_shot(self):
        _, _, prepared_window, _ = acknowledge()
        with self.assertRaises(review.VaultRecoveryReviewWindowStateError):
            prepared_window.acknowledge_visible_once()
        with self.assertRaises(review.VaultRecoveryReviewWindowStateError):
            prepared_window.cancel_once(
                review.RecoveryReviewWindowCancelReason.WINDOW_CLOSE
            )

    def test_cancelled_window_rejects_further_interaction(self):
        _, _, prepared_window = prepare()
        prepared_window.cancel_once(
            review.RecoveryReviewWindowCancelReason.ESCAPE_KEY
        )
        with self.assertRaises(review.VaultRecoveryReviewWindowStateError):
            mark_visible(prepared_window)

    def test_outcome_has_no_source_view_events_or_secret_fields(self):
        _, _, _, outcome = acknowledge()
        names = {item.name for item in dataclasses.fields(outcome)}
        forbidden = {
            "presentation",
            "localized_view",
            "events",
            "password",
            "recovery_root",
            "keyring",
            "path",
            "filename",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_forged_authoritative_outcomes_are_rejected(self):
        _, _, _, outcome = acknowledge()
        for changes in (
            {"operation_performed": True},
            {"operation_authorized": True},
            {"gate_invoked": True},
            {"auto_accept_used": True},
            {"group_select_used": True},
            {"secrets_retained": True},
        ):
            with self.subTest(changes=changes):
                forged = forge_dataclass(outcome, **changes)
                with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
                    review._validate_outcome(forged)

    def test_forged_cancel_with_receipt_is_rejected(self):
        _, _, _, acknowledged = acknowledge()
        _, _, cancelled_window = prepare()
        cancelled = cancelled_window.cancel_once(
            review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
        )
        forged = forge_dataclass(
            cancelled,
            acknowledgement_receipt=acknowledged.acknowledgement_receipt,
        )
        with self.assertRaises(review.VaultRecoveryReviewWindowSourceError):
            review._validate_outcome(forged)


class RecoveryReviewWindowLifecycleTests(unittest.TestCase):
    def test_prepared_window_cannot_be_copied_or_pickled(self):
        _, _, prepared_window = prepare()
        for operation in (
            lambda: copy.copy(prepared_window),
            lambda: copy.deepcopy(prepared_window),
            lambda: pickle.dumps(prepared_window),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(review.VaultRecoveryReviewWindowStateError):
                    operation()

    def test_repr_contains_no_digest_or_localized_text(self):
        _, _, prepared_window = prepare()
        rendered = repr(prepared_window)
        self.assertIn("bg-BG", rendered)
        self.assertNotIn("Прегледайте", rendered)
        self.assertNotIn(prepared_window.localized_view.presentation_sha256.hex(), rendered)

    def test_source_view_is_unchanged_by_cancel(self):
        _, prepared_adapter, prepared_window = prepare()
        before = prepared_adapter.view
        prepared_window.cancel_once(
            review.RecoveryReviewWindowCancelReason.WINDOW_CLOSE
        )
        self.assertIs(prepared_adapter.view, before)
        self.assertFalse(prepared_adapter.acknowledged)

    def test_concurrent_terminal_attempts_have_exactly_one_success(self):
        _, _, prepared_window = prepare(ROUTES[1])
        mark_visible(prepared_window)
        select_all(prepared_window)
        count = 8
        barrier = threading.Barrier(count)

        def attempt(index):
            barrier.wait()
            try:
                if index % 2:
                    return prepared_window.acknowledge_visible_once()
                return prepared_window.cancel_once(
                    review.RecoveryReviewWindowCancelReason.WINDOW_CLOSE
                )
            except review.VaultRecoveryReviewWindowStateError:
                return None

        with ThreadPoolExecutor(max_workers=count) as executor:
            results = list(executor.map(attempt, range(count)))
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertIn(
            prepared_window.current_state,
            (
                review.RecoveryReviewWindowState.ACKNOWLEDGED,
                review.RecoveryReviewWindowState.CANCELLED,
            ),
        )

    def test_fresh_window_required_after_cancel(self):
        source, first_adapter, first = prepare()
        first.cancel_once(review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON)
        second_adapter = adapter.prepare_recovery_ui_adapter(source)
        second = review.prepare_recovery_review_window(
            source,
            second_adapter,
            "bg-BG",
        )
        self.assertIsNot(first, second)
        self.assertIsNot(first_adapter, second_adapter)
        self.assertFalse(second.messages_visible)
        self.assertTrue(all(item is False for item in second.confirmation_selections))


class RecoveryReviewWindowTkContractTests(unittest.TestCase):
    def test_public_show_requires_existing_tk_parent(self):
        source = make_presentation()
        prepared_adapter = adapter.prepare_recovery_ui_adapter(source)
        for invalid in (None, object(), "root"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoveryReviewWindowDisplayError):
                    review.show_recovery_review_window(
                        invalid,
                        source,
                        prepared_adapter,
                        "bg-BG",
                    )

    def test_module_import_does_not_create_tk_root(self):
        source = Path(review.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("Tk", calls)
        self.assertNotIn("mainloop", calls)
        self.assertIn("Toplevel", calls)

    def test_real_widget_types_are_present(self):
        source = Path(review.__file__).read_text(encoding="utf-8")
        for token in (
            "tk.Toplevel",
            "tk.Canvas",
            "ttk.Scrollbar",
            "ttk.Checkbutton",
            "ttk.Button",
            "ttk.Label",
            "ttk.Separator",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)

    def test_messages_are_constructed_before_confirmation_controls(self):
        source = inspect.getsource(review._TkRecoveryReviewWindow.__init__)
        self.assertLess(
            source.index("localized_view.message_items"),
            source.index("localized_view.confirmation_controls"),
        )

    def test_cancel_escape_close_and_return_are_explicitly_bound(self):
        source = inspect.getsource(review._TkRecoveryReviewWindow)
        self.assertIn('"WM_DELETE_WINDOW"', source)
        self.assertIn('"<Escape>"', source)
        self.assertIn('"<Return>"', source)
        self.assertIn("CANCEL_BUTTON", source)
        self.assertIn("ESCAPE_KEY", source)
        self.assertIn("WINDOW_CLOSE", source)

    def test_checks_and_final_button_start_disabled_and_false(self):
        source = inspect.getsource(review._TkRecoveryReviewWindow.__init__)
        self.assertIn("tk.BooleanVar(master=window, value=False)", source)
        self.assertGreaterEqual(source.count('state="disabled"'), 2)
        self.assertNotIn("select_all", source)

    def test_scroll_focus_wrap_and_local_grab_are_present(self):
        source = inspect.getsource(review._TkRecoveryReviewWindow)
        for token in (
            "wraplength=720",
            "wraplength=680",
            "yscrollcommand",
            "yview_scroll",
            "focus_set",
            "grab_set",
            "grab_release",
            "takefocus=True",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)

    def test_public_api_has_no_callback_executor_or_operation_arguments(self):
        for function in (
            review.prepare_recovery_review_window,
            review.show_recovery_review_window,
        ):
            with self.subTest(function=function.__name__):
                names = set(inspect.signature(function).parameters)
                self.assertTrue(
                    names.isdisjoint(
                        {
                            "callback",
                            "executor",
                            "operation",
                            "path",
                            "password",
                            "recovery_root",
                            "keyring",
                        }
                    )
                )

    def test_module_has_no_filesystem_network_logging_or_dynamic_execution(self):
        source = Path(review.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {
                    "os",
                    "pathlib",
                    "subprocess",
                    "socket",
                    "urllib",
                    "requests",
                    "logging",
                    "time",
                    "random",
                    "secrets",
                }
            )
        )
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile", "__import__"}))


if __name__ == "__main__":
    unittest.main()
