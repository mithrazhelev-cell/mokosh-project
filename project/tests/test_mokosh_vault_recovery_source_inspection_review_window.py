import ast
import copy
from dataclasses import fields, replace
import hashlib
import inspect
from pathlib import Path
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import mokosh_vault_recovery_locale as locale
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_localization as localization
import mokosh_vault_recovery_source_inspection_presentation as presentation
import mokosh_vault_recovery_source_inspection_review_window as review
import mokosh_vault_recovery_source_inspection_ui_adapter as adapter


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "mokosh_vault_recovery_source_inspection_review_window.py"
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


def make_presentation(locale_id="bg-BG"):
    return presentation.prepare_recovery_source_inspection_presentation(
        positive_execution(locale_id)
    )


def prepare(locale_id="bg-BG"):
    source = make_presentation(locale_id)
    prepared_adapter = adapter.prepare_recovery_source_inspection_ui_adapter(source)
    prepared_window = review.prepare_recovery_source_inspection_review_window(
        source,
        prepared_adapter,
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


class FakeGeometryWidget:
    def __init__(self, rect, *, mapped=True):
        self.left, self.top, self.right, self.bottom = rect
        self.mapped = mapped

    def winfo_ismapped(self):
        return self.mapped

    def winfo_width(self):
        return self.right - self.left

    def winfo_height(self):
        return self.bottom - self.top

    def winfo_rootx(self):
        return self.left

    def winfo_rooty(self):
        return self.top


def acknowledge(locale_id="bg-BG"):
    source, prepared_adapter, prepared_window = prepare(locale_id)
    mark_visible(prepared_window)
    select_all(prepared_window)
    outcome = prepared_window.acknowledge_visible_once()
    return source, prepared_adapter, prepared_window, outcome


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class SourceInspectionReviewWindowTests(unittest.TestCase):
    def test_01_bulgarian_preparation_is_exact(self):
        source, prepared_adapter, prepared_window = prepare("bg-BG")
        self.assertIs(prepared_window.localized_view.locale, source.locale)
        self.assertIs(prepared_window.window_text.locale, source.locale)
        self.assertIsNone(prepared_adapter.receipt)

    def test_02_english_preparation_is_exact(self):
        source, prepared_adapter, prepared_window = prepare("en-GB")
        self.assertIs(prepared_window.localized_view.locale, source.locale)
        self.assertIn("inspection", prepared_window.window_text.title)
        self.assertFalse(prepared_adapter.acknowledged)

    def test_03_locale_is_derived_without_caller_argument(self):
        parameters = inspect.signature(
            review.prepare_recovery_source_inspection_review_window
        ).parameters
        self.assertEqual(tuple(parameters), ("presentation", "adapter"))

    def test_04_exact_seven_messages_are_ordered(self):
        source, _, value = prepare()
        self.assertEqual(len(value.localized_view.message_items), 7)
        self.assertEqual(
            tuple(item.message_key for item in value.localized_view.message_items),
            source.message_keys,
        )

    def test_05_exact_three_confirmations_are_ordered(self):
        source, _, value = prepare()
        self.assertEqual(len(value.localized_view.confirmation_controls), 3)
        self.assertEqual(
            tuple(
                item.confirmation_key
                for item in value.localized_view.confirmation_controls
            ),
            source.confirmation_requirements,
        )

    def test_06_initial_controls_are_all_false(self):
        _, _, value = prepare()
        self.assertEqual(value.confirmation_selections, (False, False, False))
        self.assertFalse(value.confirm_enabled)
        self.assertFalse(value.messages_visible)

    def test_07_wrong_presentation_type_is_rejected(self):
        source = make_presentation()
        prepared_adapter = adapter.prepare_recovery_source_inspection_ui_adapter(source)
        for invalid in (None, {}, prepared_adapter.view):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowSourceError):
                    review.prepare_recovery_source_inspection_review_window(
                        invalid, prepared_adapter
                    )

    def test_08_wrong_adapter_type_is_rejected(self):
        source = make_presentation()
        for invalid in (None, {}, source):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowSourceError):
                    review.prepare_recovery_source_inspection_review_window(
                        source, invalid
                    )

    def test_09_adapter_for_other_presentation_is_rejected(self):
        source = make_presentation("bg-BG")
        other = make_presentation("en-GB")
        prepared_adapter = adapter.prepare_recovery_source_inspection_ui_adapter(other)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowSourceError):
            review.prepare_recovery_source_inspection_review_window(
                source, prepared_adapter
            )

    def test_10_consumed_adapter_is_rejected(self):
        source, prepared_adapter, _, _ = acknowledge()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowSourceError):
            review.prepare_recovery_source_inspection_review_window(
                source, prepared_adapter
            )

    def test_11_visible_ordinals_must_be_exact_tuple(self):
        _, _, value = prepare()
        for invalid in ([1, 2, 3, 4, 5, 6, 7], (1, 2), tuple(range(7, 0, -1))):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
                    value.mark_messages_visible_once(invalid)

    def test_12_messages_can_be_marked_visible_only_once(self):
        _, _, value = prepare()
        mark_visible(value)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            mark_visible(value)

    def test_13_selection_before_visibility_is_rejected(self):
        _, _, value = prepare()
        control = value.localized_view.confirmation_controls[0]
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            value.record_confirmation_selection(
                control.ordinal, control.confirmation_key, True
            )

    def test_14_wrong_confirmation_ordinal_is_rejected(self):
        _, _, value = prepare()
        mark_visible(value)
        control = value.localized_view.confirmation_controls[0]
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            value.record_confirmation_selection(2, control.confirmation_key, True)

    def test_15_wrong_confirmation_key_is_rejected(self):
        _, _, value = prepare()
        mark_visible(value)
        first, second = value.localized_view.confirmation_controls[:2]
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            value.record_confirmation_selection(
                first.ordinal, second.confirmation_key, True
            )

    def test_16_non_boolean_selection_is_rejected(self):
        _, _, value = prepare()
        mark_visible(value)
        control = value.localized_view.confirmation_controls[0]
        for invalid in (1, None, "true"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
                    value.record_confirmation_selection(
                        control.ordinal, control.confirmation_key, invalid
                    )

    def test_17_each_control_can_be_selected_individually(self):
        _, _, value = prepare()
        mark_visible(value)
        for index, control in enumerate(value.localized_view.confirmation_controls):
            value.record_confirmation_selection(
                control.ordinal, control.confirmation_key, True
            )
            self.assertTrue(value.confirmation_selections[index])

    def test_18_confirm_enables_only_after_all_three(self):
        _, _, value = prepare()
        mark_visible(value)
        for index, control in enumerate(value.localized_view.confirmation_controls):
            value.record_confirmation_selection(
                control.ordinal, control.confirmation_key, True
            )
            self.assertEqual(value.confirm_enabled, index == 2)

    def test_19_uncheck_disables_confirmation(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        control = value.localized_view.confirmation_controls[1]
        value.record_confirmation_selection(
            control.ordinal, control.confirmation_key, False
        )
        self.assertFalse(value.confirm_enabled)

    def test_20_acknowledge_without_all_is_rejected_nonterminal(self):
        _, _, value = prepare()
        mark_visible(value)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            value.acknowledge_visible_once()
        self.assertIs(
            value.current_state,
            review.RecoverySourceInspectionReviewWindowState.AWAITING_VISIBLE_REVIEW,
        )

    def test_21_cancel_button_is_bounded(self):
        _, prepared_adapter, value = prepare()
        outcome = value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        self.assertIs(outcome.decision, review.RecoverySourceInspectionReviewWindowDecision.CANCELLED)
        self.assertFalse(prepared_adapter.terminal)

    def test_22_escape_cancel_is_bounded(self):
        _, _, value = prepare()
        outcome = value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
        )
        self.assertIs(outcome.cancel_reason, review.RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY)

    def test_23_window_close_cancel_is_bounded(self):
        _, _, value = prepare()
        outcome = value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
        )
        self.assertIs(outcome.cancel_reason, review.RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE)

    def test_24_cancel_before_visibility_reports_false(self):
        _, _, value = prepare()
        outcome = value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        self.assertFalse(outcome.messages_visible_reported)

    def test_25_cancel_after_visibility_reports_true(self):
        _, _, value = prepare()
        mark_visible(value)
        outcome = value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        self.assertTrue(outcome.messages_visible_reported)

    def test_26_invalid_cancel_reason_is_rejected_nonterminal(self):
        _, _, value = prepare()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowInteractionError):
            value.cancel_once("escape_key")
        self.assertIsNone(value.outcome)

    def test_27_cancel_is_terminal_against_cancel(self):
        _, _, value = prepare()
        value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            value.cancel_once(
                review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
            )

    def test_28_cancel_is_terminal_against_visibility(self):
        _, _, value = prepare()
        value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            mark_visible(value)

    def test_29_cancel_is_terminal_against_selection(self):
        _, _, value = prepare()
        control = value.localized_view.confirmation_controls[0]
        value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            value.record_confirmation_selection(
                control.ordinal, control.confirmation_key, True
            )

    def test_30_cancel_leaves_adapter_directly_reusable(self):
        source, prepared_adapter, value = prepare()
        value.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
        second = review.prepare_recovery_source_inspection_review_window(
            source, prepared_adapter
        )
        self.assertIs(second.current_state, review.RecoverySourceInspectionReviewWindowState.AWAITING_VISIBLE_REVIEW)

    def test_31_acknowledgement_consumes_adapter_once(self):
        _, prepared_adapter, value, outcome = acknowledge()
        self.assertTrue(prepared_adapter.acknowledged)
        self.assertIs(prepared_adapter.receipt, outcome.acknowledgement_receipt)
        self.assertIs(value.outcome, outcome)

    def test_32_acknowledged_state_and_count_are_exact(self):
        _, _, value, outcome = acknowledge()
        self.assertIs(value.current_state, review.RecoverySourceInspectionReviewWindowState.ACKNOWLEDGED)
        self.assertEqual(outcome.confirmation_count, 3)

    def test_33_acknowledgement_is_terminal_against_replay(self):
        _, _, value, _ = acknowledge()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            value.acknowledge_visible_once()

    def test_34_runtime_exception_after_boundary_fails_closed(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        with mock.patch.object(
            adapter.PreparedVaultRecoverySourceInspectionUIAdapter,
            "acknowledge_visible_once",
            side_effect=RuntimeError("fault"),
        ):
            with self.assertRaises(RuntimeError):
                value.acknowledge_visible_once()
        self.assertIs(value.current_state, review.RecoverySourceInspectionReviewWindowState.FAILED_CLOSED)

    def test_35_baseexception_after_boundary_fails_closed(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        with mock.patch.object(
            adapter.PreparedVaultRecoverySourceInspectionUIAdapter,
            "acknowledge_visible_once",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                value.acknowledge_visible_once()
        self.assertIs(value.current_state, review.RecoverySourceInspectionReviewWindowState.FAILED_CLOSED)

    def test_36_post_delegate_validation_fault_fails_closed(self):
        _, prepared_adapter, value = prepare()
        mark_visible(value)
        select_all(value)
        with mock.patch.object(
            review,
            "_validate_adapter_receipt",
            side_effect=RuntimeError("post delegate"),
        ):
            with self.assertRaises(RuntimeError):
                value.acknowledge_visible_once()
        self.assertTrue(prepared_adapter.acknowledged)
        self.assertIs(value.current_state, review.RecoverySourceInspectionReviewWindowState.FAILED_CLOSED)

    def test_37_failed_closed_has_no_outcome(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        with mock.patch.object(
            adapter.PreparedVaultRecoverySourceInspectionUIAdapter,
            "acknowledge_visible_once",
            side_effect=SystemExit(9),
        ):
            with self.assertRaises(SystemExit):
                value.acknowledge_visible_once()
        self.assertIsNone(value.outcome)

    def test_38_concurrent_acknowledgement_has_one_success(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        barrier = threading.Barrier(3)

        def call():
            barrier.wait()
            try:
                return value.acknowledge_visible_once()
            except review.VaultRecoverySourceInspectionReviewWindowStateError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(call) for _ in range(2)]
            barrier.wait()
            results = [future.result() for future in futures]
        self.assertEqual(sum(item is not None for item in results), 1)

    def test_39_concurrent_cancel_has_one_success(self):
        _, _, value = prepare()
        barrier = threading.Barrier(3)

        def call():
            barrier.wait()
            try:
                return value.cancel_once(
                    review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
                )
            except review.VaultRecoverySourceInspectionReviewWindowStateError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(call) for _ in range(2)]
            barrier.wait()
            results = [future.result() for future in futures]
        self.assertEqual(sum(item is not None for item in results), 1)

    def test_40_concurrent_acknowledge_cancel_has_one_terminal(self):
        _, _, value = prepare()
        mark_visible(value)
        select_all(value)
        barrier = threading.Barrier(3)

        def acknowledge_call():
            barrier.wait()
            try:
                return value.acknowledge_visible_once()
            except review.VaultRecoverySourceInspectionReviewWindowStateError:
                return None

        def cancel_call():
            barrier.wait()
            try:
                return value.cancel_once(
                    review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
                )
            except review.VaultRecoverySourceInspectionReviewWindowStateError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(acknowledge_call), pool.submit(cancel_call)]
            barrier.wait()
            results = [future.result() for future in futures]
        self.assertEqual(sum(item is not None for item in results), 1)

    def test_41_outcome_repr_hides_digest_and_receipt(self):
        _, _, _, outcome = acknowledge()
        rendered = repr(outcome)
        self.assertNotIn(outcome.presentation_sha256.hex(), rendered)
        self.assertNotIn("acknowledged_confirmations", rendered)

    def test_42_prepared_repr_hides_text_and_digest(self):
        _, _, value = prepare()
        rendered = repr(value)
        self.assertNotIn(value.localized_view.presentation_sha256.hex(), rendered)
        self.assertNotIn(value.localized_view.message_items[0].text, rendered)

    def test_43_outcome_cannot_be_copied(self):
        _, _, _, outcome = acknowledge()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            copy.copy(outcome)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            copy.deepcopy(outcome)

    def test_44_outcome_cannot_be_pickled(self):
        _, _, _, outcome = acknowledge()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            pickle.dumps(outcome)

    def test_45_prepared_controller_cannot_be_copied_or_pickled(self):
        _, _, value = prepare()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            copy.copy(value)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            copy.deepcopy(value)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            pickle.dumps(value)

    def test_46_window_text_cannot_be_copied_or_pickled(self):
        _, _, value = prepare()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            copy.copy(value.window_text)
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowStateError):
            pickle.dumps(value.window_text)

    def test_47_outcome_fields_exclude_sensitive_capabilities(self):
        names = {item.name for item in fields(review.VaultRecoverySourceInspectionReviewWindowOutcome)}
        forbidden = {"path", "source", "source_bytes", "secret", "callback", "executor", "authority"}
        self.assertTrue(forbidden.isdisjoint(names))

    def test_48_outcome_no_authority_flags_are_false(self):
        _, _, _, outcome = acknowledge()
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertFalse(outcome.human_understanding_proven)
        self.assertFalse(outcome.accessibility_conformance_proven)

    def test_49_forged_authority_outcome_is_rejected(self):
        _, _, _, outcome = acknowledge()
        with self.assertRaises(review.VaultRecoverySourceInspectionReviewWindowFormatError):
            review._validate_outcome(
                forged_copy(outcome, operation_authorized=True)
            )

    def test_50_public_export_surface_is_explicit(self):
        self.assertEqual(len(review.__all__), len(set(review.__all__)))
        self.assertIn("show_recovery_source_inspection_review_window", review.__all__)
        self.assertNotIn("_validate_review_sources", review.__all__)
        self.assertNotIn("_TkRecoverySourceInspectionReviewWindow", review.__all__)

    def test_51_public_signatures_have_no_locale_or_capability_input(self):
        self.assertEqual(
            tuple(inspect.signature(review.show_recovery_source_inspection_review_window).parameters),
            ("parent", "presentation", "adapter"),
        )
        self.assertNotIn("locale", inspect.getsource(review.prepare_recovery_source_inspection_review_window).split("def ", 1)[1].split(")", 1)[0])

    def test_52_module_never_constructs_tk_root_or_mainloop(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        attributes = {
            node.func.attr
            for node in calls
            if isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("Tk", attributes)
        self.assertNotIn("mainloop", attributes)

    def test_53_module_has_no_window_wide_return_binding(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('bind("<Return>"', source)
        self.assertNotIn("bind('<Return>'", source)
        self.assertIn('bind("<Escape>"', source)

    def test_54_module_has_one_toplevel_and_no_main_gui_import(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("tk.Toplevel("), 1)
        self.assertNotIn("mokosh_gui", source)
        self.assertNotIn("mokosh_main", source)

    def test_55_module_has_no_filesystem_network_crypto_or_logging_import(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(
            {"os", "pathlib", "socket", "requests", "logging", "cryptography"}.isdisjoint(imported)
        )

    def test_56_source_declares_single_terminal_marker_design(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("_TERMINAL_FAILURE = object()", source)
        slots = review.PreparedVaultRecoverySourceInspectionReviewWindow.__slots__
        self.assertIn("_terminal", slots)
        self.assertNotIn("_state", slots)
        self.assertNotIn("_outcome", slots)

    def test_57_window_is_explicitly_resizable_in_both_directions(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("window.resizable(True, True)", source)
        self.assertIn("window.minsize(560, 440)", source)

    def test_58_dynamic_wrap_has_exact_readability_bounds(self):
        self.assertEqual(review._TkRecoverySourceInspectionReviewWindow._WRAP_MIN, 240)
        self.assertEqual(review._TkRecoverySourceInspectionReviewWindow._WRAP_MAX, 960)
        self.assertEqual(review._TkRecoverySourceInspectionReviewWindow._WRAP_PADDING, 32)

    def test_59_old_fixed_wide_wrap_lengths_are_absent(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("wraplength=720", source)
        self.assertNotIn("wraplength=760", source)
        self.assertIn("width - self._WRAP_PADDING", source)

    def test_60_wheel_bindings_are_window_local_not_global(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('window.bind("<MouseWheel>"', source)
        self.assertNotIn("bind_all", source)
        self.assertNotIn("unbind_all", source)

    def test_61_linux_wheel_buttons_are_window_local(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('window.bind("<Button-4>"', source)
        self.assertIn('window.bind("<Button-5>"', source)

    def test_62_canvas_has_bounded_keyboard_scrolling(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        for sequence in ("<Prior>", "<Next>", "<Home>", "<End>"):
            self.assertIn(f'canvas.bind("{sequence}"', source)
        self.assertIn('canvas.yview_scroll(pages, "pages")', source)

    def test_63_initial_focus_starts_at_top_reading_region(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("self._canvas.yview_moveto(0.0)", source)
        self.assertIn("self._canvas.focus_set()", source)
        self.assertNotIn("self._checks[0].focus_set()", source)

    def test_64_confirmation_focus_requests_visible_reveal(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"<FocusIn>"', source)
        self.assertIn("self._schedule_focus_reveal(widget)", source)
        self.assertIn("self.window.after_idle(self._reveal_widget, widget)", source)

    def test_65_focus_reveal_uses_viewport_and_requested_content_height(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("self._content.winfo_reqheight()", source)
        self.assertIn("self._canvas.winfo_height()", source)
        self.assertIn("self._canvas.canvasy(0)", source)

    def test_66_confirmation_text_is_wrappable_for_locale_expansion(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("check = tk.Checkbutton(", source)
        self.assertIn("self._wrapping_widgets.append(check)", source)
        self.assertIn("widget.configure(wraplength=wraplength)", source)

    def test_67_modal_ownership_and_grab_are_preserved(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("window.transient(parent)", source)
        self.assertIn("self.window.grab_set()", source)
        self.assertIn("self.window.grab_release()", source)

    def test_68_responsive_work_does_not_add_event_injection_or_return_confirm(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("event_generate", source)
        self.assertNotIn('bind("<Return>"', source)
        self.assertNotIn("bind_all", source)

    def test_69_outer_grid_has_one_expanding_content_column(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("outer.columnconfigure(0, weight=1)", source)

    def test_70_only_middle_review_row_absorbs_vertical_resize(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("outer.rowconfigure(1, weight=1)", source)
        self.assertNotIn("outer.rowconfigure(0, weight=1)", source)
        self.assertNotIn("outer.rowconfigure(2, weight=1)", source)

    def test_71_short_header_occupies_reserved_top_grid_row(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'header.grid(row=0, column=0, sticky="ew"',
            source,
        )
        self.assertIn("text=prepared.window_text.title", source)
        self.assertIn("introduction = ttk.Label(\n            content,", source)

    def test_72_review_canvas_occupies_only_expanding_middle_row(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'review_frame.grid(row=1, column=0, sticky="nsew")',
            source,
        )

    def test_73_action_footer_occupies_reserved_bottom_grid_row(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'buttons.grid(row=2, column=0, sticky="ew"',
            source,
        )

    def test_74_expanding_review_frame_no_longer_uses_pack(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("review_frame.pack(", source)

    def test_75_action_footer_no_longer_competes_in_pack_order(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("buttons.pack(", source)

    def test_76_top_content_footer_grid_order_is_exact(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        top = source.index("header.grid(row=0")
        middle = source.index("review_frame.grid(row=1")
        footer = source.index("buttons.grid(row=2")
        self.assertLess(top, middle)
        self.assertLess(middle, footer)

    def test_77_runtime_geometry_accepts_exact_visible_regions(self):
        container = FakeGeometryWidget((0, 0, 600, 500))
        regions = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 590, 420)),
            FakeGeometryWidget((10, 420, 590, 490)),
        )
        controls = (
            FakeGeometryWidget((400, 440, 480, 475)),
            FakeGeometryWidget((490, 440, 580, 475)),
        )
        self.assertTrue(
            review._review_layout_regions_visible(container, regions, controls)
        )

    def test_78_runtime_geometry_rejects_unmapped_or_zero_widgets(self):
        container = FakeGeometryWidget((0, 0, 600, 500))
        valid = FakeGeometryWidget((10, 60, 590, 420))
        footer = FakeGeometryWidget((10, 420, 590, 490))
        control = FakeGeometryWidget((490, 440, 580, 475))
        for invalid in (
            FakeGeometryWidget((10, 10, 590, 60), mapped=False),
            FakeGeometryWidget((10, 10, 10, 60)),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(
                    review._review_layout_regions_visible(
                        container,
                        (invalid, valid, footer),
                        (control,),
                    )
                )

    def test_79_runtime_geometry_rejects_outside_or_overlapping_regions(self):
        container = FakeGeometryWidget((0, 0, 600, 500))
        footer = FakeGeometryWidget((10, 420, 590, 490))
        control = FakeGeometryWidget((490, 440, 580, 475))
        outside = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 610, 420)),
            footer,
        )
        overlap = (
            FakeGeometryWidget((10, 10, 590, 80)),
            FakeGeometryWidget((10, 60, 590, 420)),
            footer,
        )
        self.assertFalse(
            review._review_layout_regions_visible(container, outside, (control,))
        )
        self.assertFalse(
            review._review_layout_regions_visible(container, overlap, (control,))
        )

    def test_80_runtime_geometry_requires_usable_middle_height(self):
        container = FakeGeometryWidget((0, 0, 600, 500))
        regions = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 590, 139)),
            FakeGeometryWidget((10, 139, 590, 490)),
        )
        control = FakeGeometryWidget((490, 440, 580, 475))
        self.assertEqual(review._MIN_REVIEW_MIDDLE_HEIGHT, 80)
        self.assertFalse(
            review._review_layout_regions_visible(container, regions, (control,))
        )

    def test_81_activation_schedules_geometry_finish_before_visible_claim(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow.activate
        )
        self.assertIn("self.window.after(75, self._finish_activation)", source)
        self.assertNotIn("mark_messages_visible_once", source)

    def test_82_geometry_gate_precedes_visible_claim_and_control_enable(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._finish_activation
        )
        gate = source.index("_review_layout_regions_visible")
        visible = source.index("mark_messages_visible_once")
        enabled = source.index('check.configure(state="normal")')
        self.assertLess(gate, visible)
        self.assertLess(visible, enabled)

    def test_83_geometry_gate_tracks_exact_header_footer_actions(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        for assignment in (
            "self._header = header",
            "self._footer = buttons",
            "self._cancel_button",
            "self._confirm_button",
        ):
            self.assertIn(assignment, source)

    def test_84_geometry_helper_does_not_log_client_measurements(self):
        source = inspect.getsource(review._review_layout_regions_visible)
        self.assertNotIn("print(", source)
        self.assertNotIn("logging", source)
        self.assertNotIn("screen", source.lower())


    def test_85_runtime_resize_guard_is_debounced_and_toplevel_scoped(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._schedule_runtime_layout_validation
        )
        self.assertEqual(
            review._TkRecoverySourceInspectionReviewWindow._RESIZE_SETTLE_MS,
            125,
        )
        self.assertIn('getattr(event, "widget", None) is not self.window', source)
        self.assertIn("self.window.after_cancel(pending)", source)
        self.assertIn("self.window.after(", source)
        self.assertIn("self._validate_runtime_layout", source)

    def test_86_runtime_resize_guard_is_bound_without_replacing_other_bindings(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('window.bind(\n            "<Configure>"', source)
        self.assertIn("self._schedule_runtime_layout_validation", source)
        self.assertIn('add="+"', source)

    def test_87_runtime_validation_rechecks_exact_layout_before_state_sync(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._validate_runtime_layout
        )
        gate = source.index("_review_layout_regions_visible")
        state_sync = source.index("self._confirm_button.configure")
        self.assertLess(gate, state_sync)
        self.assertIn("self._header, self._canvas, self._footer", source)
        self.assertIn("self._cancel_button, self._confirm_button", source)

    def test_88_runtime_validation_resynchronizes_confirm_from_controller_only(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._validate_runtime_layout
        )
        self.assertIn("self._prepared.confirm_enabled", source)
        self.assertNotIn("record_confirmation_selection", source)
        self.assertNotIn("acknowledge_visible_once", source)
        self.assertNotIn("event_generate", source)

    def test_89_runtime_validation_reveals_only_an_already_focused_confirmation(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._validate_runtime_layout
        )
        self.assertIn("focused = self.window.focus_get()", source)
        self.assertIn("if focused in self._checks", source)
        self.assertIn("self._reveal_widget(focused)", source)
        self.assertNotIn("focus_set()", source)

    def test_90_runtime_layout_failure_is_fail_closed(self):
        source = inspect.getsource(
            review._TkRecoverySourceInspectionReviewWindow._validate_runtime_layout
        )
        self.assertIn("VaultRecoverySourceInspectionReviewWindowDisplayError", source)
        self.assertIn("self._error = exc", source)
        self.assertIn("self._destroy()", source)

    def test_91_destroy_cancels_pending_resize_validation_before_window_destroy(self):
        source = inspect.getsource(review._TkRecoverySourceInspectionReviewWindow._destroy)
        pending = source.index("pending = self._resize_validation_after_id")
        cancel = source.index("self.window.after_cancel(pending)")
        destroy = source.index("self.window.destroy()")
        self.assertLess(pending, cancel)
        self.assertLess(cancel, destroy)

    def test_92_runtime_guard_does_not_add_network_filesystem_or_authority_paths(self):
        source = "\n".join(
            (
                inspect.getsource(
                    review._TkRecoverySourceInspectionReviewWindow._schedule_runtime_layout_validation
                ),
                inspect.getsource(
                    review._TkRecoverySourceInspectionReviewWindow._validate_runtime_layout
                ),
            )
        )
        for forbidden in (
            "socket",
            "requests",
            "urllib",
            "open(",
            "Path(",
            "os.",
            "subprocess",
            "authorize",
            "executor",
            "source_material",
            "secret",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


    def test_93_runtime_scheduler_cancels_previous_and_schedules_exact_validator(self):
        value = object.__new__(review._TkRecoverySourceInspectionReviewWindow)
        value._closed = False
        value._activated = True
        value._resize_validation_after_id = "old-after"
        value.window = mock.Mock()
        value.window.after.return_value = "new-after"
        value._validate_runtime_layout = mock.Mock()
        event = mock.Mock(widget=value.window)

        value._schedule_runtime_layout_validation(event)

        value.window.after_cancel.assert_called_once_with("old-after")
        value.window.after.assert_called_once_with(
            value._RESIZE_SETTLE_MS,
            value._validate_runtime_layout,
        )
        self.assertEqual(value._resize_validation_after_id, "new-after")

    def test_94_runtime_scheduler_ignores_pre_activation_and_child_configure(self):
        value = object.__new__(review._TkRecoverySourceInspectionReviewWindow)
        value._closed = False
        value._activated = False
        value._resize_validation_after_id = None
        value.window = mock.Mock()
        value._validate_runtime_layout = mock.Mock()
        value._schedule_runtime_layout_validation(mock.Mock(widget=value.window))
        value.window.after.assert_not_called()

        value._activated = True
        value._schedule_runtime_layout_validation(mock.Mock(widget=mock.Mock()))
        value.window.after.assert_not_called()

    def test_95_runtime_validator_resyncs_enabled_state_and_reveals_existing_focus(self):
        value = object.__new__(review._TkRecoverySourceInspectionReviewWindow)
        value._resize_validation_after_id = "completed-after"
        value._closed = False
        value._activated = True
        value.window = mock.Mock()
        value._header = mock.Mock()
        value._canvas = mock.Mock()
        value._footer = mock.Mock()
        value._cancel_button = mock.Mock()
        value._confirm_button = mock.Mock()
        value._prepared = mock.Mock(confirm_enabled=True)
        focused = mock.Mock()
        value._checks = [focused, mock.Mock()]
        value.window.focus_get.return_value = focused
        value._reveal_widget = mock.Mock()
        value._destroy = mock.Mock()

        with mock.patch.object(review, "_review_layout_regions_visible", return_value=True) as gate:
            value._validate_runtime_layout()

        self.assertIsNone(value._resize_validation_after_id)
        value.window.update_idletasks.assert_called_once_with()
        gate.assert_called_once_with(
            value.window,
            (value._header, value._canvas, value._footer),
            (value._cancel_button, value._confirm_button),
        )
        value._confirm_button.configure.assert_called_once_with(state="normal")
        value._reveal_widget.assert_called_once_with(focused)
        value._destroy.assert_not_called()

    def test_96_runtime_validator_resyncs_disabled_state_without_focus_stealing(self):
        value = object.__new__(review._TkRecoverySourceInspectionReviewWindow)
        value._resize_validation_after_id = None
        value._closed = False
        value._activated = True
        value.window = mock.Mock()
        value._header = mock.Mock()
        value._canvas = mock.Mock()
        value._footer = mock.Mock()
        value._cancel_button = mock.Mock()
        value._confirm_button = mock.Mock()
        value._prepared = mock.Mock(confirm_enabled=False)
        value._checks = [mock.Mock(), mock.Mock()]
        value.window.focus_get.return_value = value._canvas
        value._reveal_widget = mock.Mock()
        value._destroy = mock.Mock()

        with mock.patch.object(review, "_review_layout_regions_visible", return_value=True):
            value._validate_runtime_layout()

        value._confirm_button.configure.assert_called_once_with(state="disabled")
        value._reveal_widget.assert_not_called()
        value._destroy.assert_not_called()

    def test_97_runtime_validator_fails_closed_on_layout_loss(self):
        value = object.__new__(review._TkRecoverySourceInspectionReviewWindow)
        value._resize_validation_after_id = None
        value._closed = False
        value._activated = True
        value.window = mock.Mock()
        value._header = mock.Mock()
        value._canvas = mock.Mock()
        value._footer = mock.Mock()
        value._cancel_button = mock.Mock()
        value._confirm_button = mock.Mock()
        value._prepared = mock.Mock(confirm_enabled=True)
        value._checks = []
        value._error = None
        value._destroy = mock.Mock()

        with mock.patch.object(review, "_review_layout_regions_visible", return_value=False):
            value._validate_runtime_layout()

        self.assertIsInstance(
            value._error,
            review.VaultRecoverySourceInspectionReviewWindowDisplayError,
        )
        value._confirm_button.configure.assert_not_called()
        value._destroy.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
