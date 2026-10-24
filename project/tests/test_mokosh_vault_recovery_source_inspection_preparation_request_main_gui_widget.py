import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


try:
    import argon2  # noqa: F401
except ModuleNotFoundError:
    fake_argon2 = types.ModuleType("argon2")

    class _FakeArgon2Type:
        ID = "ID"

    fake_argon2.Type = _FakeArgon2Type
    fake_low_level = types.ModuleType("argon2.low_level")
    fake_low_level.hash_secret = lambda *args, **kwargs: b""
    sys.modules["argon2"] = fake_argon2
    sys.modules["argon2.low_level"] = fake_low_level

import mokosh_gui
import mokosh_vault_recovery_entry_request as entry_request
import mokosh_vault_recovery_entry_transition as entry_transition
import mokosh_vault_recovery_source_inspection_preparation_request as preparation
import mokosh_vault_recovery_source_inspection_preparation_request_main_gui_visual_harness as visual
import mokosh_vault_recovery_source_inspection_request as inspection_request
import mokosh_vault_recovery_source_selection as source_selection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SELECTED_PATH = "/tmp/mokosh-stage2-43-synthetic-private-name.mokr"


class FakeWidget:
    def __init__(self, parent=None, **kwargs):
        self.parent = parent
        self.options = dict(kwargs)
        self.pack_calls = []
        self.value = kwargs.get("value")

    def config(self, **kwargs):
        self.options.update(kwargs)

    configure = config

    def pack(self, **kwargs):
        self.pack_calls.append(kwargs)

    def invoke(self):
        command = self.options.get("command")
        return command() if command is not None else None

    def get(self):
        return self.value

    def cget(self, name):
        return self.options.get(name, "")

    def title(self, value):
        self.options["title"] = value


class RaisingWidget(FakeWidget):
    def __init__(self, raised, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raised = raised

    def config(self, **kwargs):
        del kwargs
        raise self.raised


def positive_transition(locale="en-GB"):
    entry = entry_request.prepare_recovery_entry_request(locale).decide_once(
        entry_request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    return entry_transition.prepare_recovery_entry_transition(entry).decide_once(
        entry_transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )


def positive_selection(locale="en-GB"):
    return source_selection.prepare_recovery_source_selection(
        positive_transition(locale)
    ).decide_once(
        source_selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        SELECTED_PATH,
    )


def positive_inspection_request(locale="en-GB"):
    return inspection_request.prepare_recovery_source_inspection_request(
        positive_selection(locale)
    ).decide_once(
        inspection_request.RecoverySourceInspectionRequestDecision.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
    )


def preserved_inspection_request(locale="en-GB"):
    return inspection_request.prepare_recovery_source_inspection_request(
        positive_selection(locale)
    ).decide_once(
        inspection_request.RecoverySourceInspectionRequestDecision.PRESERVE_AND_STOP
    )


def forged_inspection_request(**changes):
    exact = positive_inspection_request()
    forged = object.__new__(
        inspection_request.VaultRecoverySourceInspectionRequestOutcome
    )
    for field in dataclasses.fields(exact):
        object.__setattr__(
            forged,
            field.name,
            changes.get(field.name, getattr(exact, field.name)),
        )
    return forged


def wire_preparation(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        event = mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
            object()
        )
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            return (
                mokosh_gui._wire_recovery_source_inspection_preparation_request_widget(
                    object(), object(), event
                )
            )
    finally:
        mokosh_gui.current_lang = previous


def wire_five_step_flow(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        preparation_event = (
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
                object()
            )
        )
        inspection_event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(
            object(), preparation_event
        )
        selection_event = mokosh_gui._RecoverySourceSelectionGUIEvent(
            object(), inspection_event
        )
        transition_event = mokosh_gui._RecoveryEntryTransitionGUIEvent(
            object(), selection_event
        )
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            entry_widgets = mokosh_gui._wire_recovery_entry_request_widget(
                object(), object(), transition_event
            )
            transition_widgets = mokosh_gui._wire_recovery_entry_transition_widget(
                object(), object(), transition_event
            )
            selection_widgets = mokosh_gui._wire_recovery_source_selection_widget(
                object(), object(), selection_event
            )
            inspection_widgets = (
                mokosh_gui._wire_recovery_source_inspection_request_widget(
                    object(), object(), inspection_event
                )
            )
            preparation_widgets = (
                mokosh_gui._wire_recovery_source_inspection_preparation_request_widget(
                    object(), object(), preparation_event
                )
            )
        return (
            entry_widgets,
            transition_widgets,
            selection_widgets,
            inspection_widgets,
            preparation_widgets,
        )
    finally:
        mokosh_gui.current_lang = previous


def pass_observations():
    passed = (
        visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.PASS
    )
    return visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservations(
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
    )


class RecoverySourceInspectionPreparationRequestMainGUIWidgetTests(
    unittest.TestCase
):
    def test_01_fifth_action_starts_locked_without_retained_outcome(self):
        banner, button, event = wire_preparation()
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.LOCKED,
        )
        self.assertFalse(event.retains_source_inspection_request_outcome)
        self.assertIsNone(event.bound_locale_id)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertIn("does not open", banner.options["text"])

    def test_02_both_locales_disclose_retention_and_unproven_zeroisation(self):
        for locale, tokens in (
            ("en", ("process", "zeroisation")),
            ("bg", ("паметта", "зануляване")),
        ):
            with self.subTest(locale=locale):
                banner, button, _ = wire_preparation(locale)
                rendered = banner.options["text"].lower()
                for token in tokens:
                    self.assertIn(token, rendered)
                self.assertIn("...", button.options["text"])
                self.assertNotIn(SELECTED_PATH, rendered)

    def test_03_widget_requires_exact_event_and_single_attachment(self):
        with self.assertRaises(TypeError):
            mokosh_gui._wire_recovery_source_inspection_preparation_request_widget(
                object(), object(), object()
            )
        _, _, event = wire_preparation()
        with self.assertRaises(TypeError):
            event.attach_widgets(FakeWidget(), FakeWidget())

    def test_04_fourth_event_constructor_requires_exact_downstream_type(self):
        with self.assertRaises(TypeError):
            mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object(), object())
        exact = mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
            object()
        )
        event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object(), exact)
        self.assertIs(event._preparation_request_event, exact)

    def test_05_exact_bulgarian_request_arms_and_binds_locale(self):
        banner, button, event = wire_preparation()
        self.assertTrue(event.arm_once(positive_inspection_request("bg-BG")))
        self.assertEqual(event.bound_locale_id, "bg-BG")
        self.assertTrue(event.retains_source_inspection_request_outcome)
        self.assertEqual(button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertIn("ПОДГОТОВКА", banner.options["text"])

    def test_06_exact_english_request_arms_and_binds_locale(self):
        banner, button, event = wire_preparation("bg")
        self.assertTrue(event.arm_once(positive_inspection_request("en-GB")))
        self.assertEqual(event.bound_locale_id, "en-GB")
        self.assertIn("FUTURE", banner.options["text"])
        self.assertIn("Request", button.options["text"])

    def test_07_arm_rejects_wrong_type_and_becomes_terminal_failed(self):
        for invalid in (None, {}, (), "request", object()):
            with self.subTest(invalid=type(invalid).__name__):
                _, _, event = wire_preparation()
                with self.assertRaises(TypeError):
                    event.arm_once(invalid)
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.FAILED,
                )

    def test_08_preserved_inspection_request_cannot_arm_fifth_action(self):
        _, button, event = wire_preparation()
        with self.assertRaises(TypeError):
            event.arm_once(preserved_inspection_request())
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertFalse(event.retains_source_inspection_request_outcome)

    def test_09_forged_request_claims_are_rejected_before_retention(self):
        changes = (
            {"future_secure_source_inspection_requested": False},
            {"selected_path": "/tmp/../private.mokr"},
            {"source_opened": True},
            {"source_identity_validated": True},
            {"source_access_authorized": True},
            {"source_preparation_performed": True},
            {"recovery_secret_received": True},
            {"operation_authorized": True},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                _, _, event = wire_preparation()
                with self.assertRaises(TypeError):
                    event.arm_once(forged_inspection_request(**change))
                self.assertFalse(event.retains_source_inspection_request_outcome)

    def test_10_widget_configuration_failure_does_not_retain_outcome(self):
        event = mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
            object()
        )
        event.attach_widgets(RaisingWidget(RuntimeError("detail")), FakeWidget())
        self.assertFalse(event.arm_once(positive_inspection_request()))
        self.assertFalse(event.retains_source_inspection_request_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.FAILED,
        )

    def test_11_baseexception_during_arm_marks_failed_and_propagates(self):
        event = mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
            object()
        )
        event.attach_widgets(RaisingWidget(KeyboardInterrupt()), FakeWidget())
        with self.assertRaises(KeyboardInterrupt):
            event.arm_once(positive_inspection_request())
        self.assertFalse(event.retains_source_inspection_request_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.FAILED,
        )

    def test_12_locked_or_failed_event_cannot_open_confirmation(self):
        _, _, event = wire_preparation()
        with mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm:
            self.assertIsNone(event())
            with self.assertRaises(TypeError):
                event.arm_once(None)
            self.assertIsNone(event())
        confirm.assert_not_called()

    def test_13_yes_maps_to_exact_stage2_31_request(self):
        _, button, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = button.invoke()
        self.assertTrue(
            outcome.future_secure_source_inspection_preparation_requested
        )
        self.assertEqual(outcome.selected_path, SELECTED_PATH)
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertNotIn(SELECTED_PATH, str(info.call_args))

    def test_14_no_maps_to_exact_stage2_31_preserve(self):
        _, button, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = button.invoke()
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertIsNone(outcome.selected_path)
        self.assertFalse(outcome.source_path_metadata_retained)
        self.assertNotIn(SELECTED_PATH, str(info.call_args))

    def test_15_confirmation_and_results_are_fixed_and_path_free(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=True
            ) as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            event()
        rendered = str((confirm.call_args, info.call_args))
        self.assertNotIn(SELECTED_PATH, rendered)
        self.assertNotIn("synthetic-private-name", rendered)
        self.assertIn("not be opened", rendered)
        self.assertIn("zeroised", rendered)

    def test_16_retained_outcome_is_cleared_before_loader_and_dialog(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())

        def inspect_loader():
            self.assertFalse(event.retains_source_inspection_request_outcome)
            self.assertIsNone(event.bound_locale_id)
            return (
                preparation.RecoverySourceInspectionPreparationRequestDecision,
                preparation.VaultRecoverySourceInspectionPreparationRequestError,
                preparation.prepare_recovery_source_inspection_preparation_request,
            )

        def inspect_dialog(*args, **kwargs):
            del args, kwargs
            self.assertFalse(event.retains_source_inspection_request_outcome)
            return True

        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_preparation_request_contract",
                side_effect=inspect_loader,
            ),
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=inspect_dialog
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            event()

    def test_17_contract_loader_error_is_generic_and_terminal(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_preparation_request_contract",
                side_effect=RuntimeError("private loader detail"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        confirm.assert_not_called()
        self.assertNotIn("private loader detail", str(error.call_args))
        self.assertFalse(event.retains_source_inspection_request_outcome)

    def test_18_stage2_31_prepare_error_is_generic_and_before_dialog(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_preparation_request_contract",
                return_value=(
                    preparation.RecoverySourceInspectionPreparationRequestDecision,
                    preparation.VaultRecoverySourceInspectionPreparationRequestError,
                    mock.Mock(side_effect=RuntimeError("private prepare detail")),
                ),
            ),
            mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        confirm.assert_not_called()
        self.assertNotIn("private prepare detail", str(error.call_args))

    def test_19_confirmation_exception_is_generic_without_path_or_detail(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(
                mokosh_gui.messagebox,
                "askyesno",
                side_effect=RuntimeError("private dialog detail"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        rendered = str(error.call_args)
        self.assertNotIn("private dialog detail", rendered)
        self.assertNotIn(SELECTED_PATH, rendered)

    def test_20_baseexception_after_consumption_marks_failed_and_propagates(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with mock.patch.object(
            mokosh_gui,
            "_recovery_source_inspection_preparation_request_contract",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                event()
        self.assertFalse(event.retains_source_inspection_request_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.FAILED,
        )

    def test_21_success_is_terminal_without_retained_path_or_outcome(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = event()
            self.assertIsNone(event())
        self.assertTrue(
            outcome.future_secure_source_inspection_preparation_requested
        )
        self.assertFalse(event.retains_source_inspection_request_outcome)
        self.assertFalse(hasattr(event, "_selected_path"))
        self.assertFalse(hasattr(event, "_outcome"))

    def test_22_concurrent_clicks_allow_exactly_one_decision(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        worker_count = 16
        barrier = threading.Barrier(worker_count)

        def invoke():
            barrier.wait()
            return event()

        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=True
            ) as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            ThreadPoolExecutor(max_workers=worker_count) as pool,
        ):
            results = list(pool.map(lambda _: invoke(), range(worker_count)))
        self.assertEqual(len([value for value in results if value is not None]), 1)
        self.assertEqual(confirm.call_count, 1)

    def test_23_positive_fourth_action_arms_only_the_fifth_action(self):
        _, _, _, inspection_widgets, preparation_widgets = wire_five_step_flow()
        _, inspection_button, inspection_event = inspection_widgets
        _, preparation_button, preparation_event = preparation_widgets
        inspection_event.arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=True
            ) as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = inspection_button.invoke()
        self.assertEqual(confirm.call_count, 1)
        self.assertTrue(outcome.future_secure_source_inspection_requested)
        self.assertEqual(preparation_button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertTrue(preparation_event.retains_source_inspection_request_outcome)

    def test_24_fourth_preserve_keeps_fifth_action_locked(self):
        _, _, _, inspection_widgets, preparation_widgets = wire_five_step_flow()
        inspection_widgets[2].arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=False
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            inspection_widgets[1].invoke()
        self.assertEqual(
            preparation_widgets[1].options["state"], mokosh_gui.tk.DISABLED
        )
        self.assertFalse(
            preparation_widgets[2].retains_source_inspection_request_outcome
        )

    def test_25_downstream_arm_failure_is_generic_and_discards_reference(self):
        preparation_event = (
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEvent(
                object()
            )
        )
        inspection_event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(
            object(), preparation_event
        )
        inspection_event.attach_widgets(FakeWidget(), FakeWidget())
        inspection_event.arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=True
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            outcome = inspection_event()
        self.assertTrue(outcome.future_secure_source_inspection_requested)
        self.assertNotIn(SELECTED_PATH, str(error.call_args))
        self.assertFalse(
            preparation_event.retains_source_inspection_request_outcome
        )

    def test_26_five_step_flow_uses_five_separate_positive_actions(self):
        widgets = wire_five_step_flow()
        entry, transition, selection, inspection, preparation_widgets = widgets
        with (
            mock.patch.object(
                mokosh_gui.messagebox,
                "askyesno",
                side_effect=(True, True, True, True),
            ) as confirms,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(
                mokosh_gui.filedialog,
                "askopenfilename",
                return_value=SELECTED_PATH,
            ) as picker,
        ):
            entry[1].invoke()
            self.assertEqual(transition[1].options["state"], mokosh_gui.tk.NORMAL)
            transition[1].invoke()
            self.assertEqual(selection[1].options["state"], mokosh_gui.tk.NORMAL)
            selection[1].invoke()
            self.assertEqual(inspection[1].options["state"], mokosh_gui.tk.NORMAL)
            inspection[1].invoke()
            self.assertEqual(
                preparation_widgets[1].options["state"], mokosh_gui.tk.NORMAL
            )
            outcome = preparation_widgets[1].invoke()
        self.assertEqual(confirms.call_count, 4)
        self.assertEqual(picker.call_count, 1)
        self.assertTrue(
            outcome.future_secure_source_inspection_preparation_requested
        )

    def test_27_first_preserve_keeps_all_four_later_actions_locked(self):
        widgets = wire_five_step_flow()
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            widgets[0][1].invoke()
        for _, button, _ in widgets[1:]:
            self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_28_second_preserve_keeps_three_later_actions_locked(self):
        widgets = wire_five_step_flow()
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=(True, False)
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            widgets[0][1].invoke()
            widgets[1][1].invoke()
        for _, button, _ in widgets[2:]:
            self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_29_picker_cancel_keeps_fourth_and_fifth_actions_locked(self):
        widgets = wire_five_step_flow()
        widgets[2][2].arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=""
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            widgets[2][1].invoke()
        for _, button, _ in widgets[3:]:
            self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_30_fourth_preserve_does_not_automatically_invoke_fifth(self):
        widgets = wire_five_step_flow()
        widgets[3][2].arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", return_value=False
            ) as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            widgets[3][1].invoke()
        self.assertEqual(confirm.call_count, 1)
        self.assertIs(
            widgets[4][2].current_state,
            mokosh_gui._RecoverySourceInspectionPreparationRequestGUIEventState.LOCKED,
        )

    def test_31_bound_locale_cannot_be_changed_after_fourth_action(self):
        banner, button, event = wire_preparation("en")
        event.arm_once(positive_inspection_request("en-GB"))
        widgets = {
            "lang_label": FakeWidget(),
            "vault_title": FakeWidget(),
            "btn_choose_vault": FakeWidget(),
            "pwd_title": FakeWidget(),
            "nick_title": FakeWidget(),
            "btn_encrypt_main": FakeWidget(),
            "btn_decrypt_main": FakeWidget(),
            "btn_clean_main": FakeWidget(),
            "btn_bottom_contacts": FakeWidget(),
            "btn_bottom_contact_crypto": FakeWidget(),
            "btn_bottom_master": FakeWidget(),
            "safety_banner": FakeWidget(),
            "recovery_source_inspection_preparation_request_banner": banner,
            "btn_recovery_source_inspection_preparation_request": button,
            "recovery_source_inspection_preparation_request_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeWidget(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertIn("FUTURE", banner.options["text"])
        self.assertEqual(event.bound_locale_id, "en-GB")

    def test_32_unarmed_language_change_updates_fifth_action_text(self):
        banner, button, event = wire_preparation("en")
        widgets = {
            "lang_label": FakeWidget(),
            "vault_title": FakeWidget(),
            "btn_choose_vault": FakeWidget(),
            "pwd_title": FakeWidget(),
            "nick_title": FakeWidget(),
            "btn_encrypt_main": FakeWidget(),
            "btn_decrypt_main": FakeWidget(),
            "btn_clean_main": FakeWidget(),
            "btn_bottom_contacts": FakeWidget(),
            "btn_bottom_contact_crypto": FakeWidget(),
            "btn_bottom_master": FakeWidget(),
            "safety_banner": FakeWidget(),
            "recovery_source_inspection_preparation_request_banner": banner,
            "btn_recovery_source_inspection_preparation_request": button,
            "recovery_source_inspection_preparation_request_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeWidget(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertIn("ПОДГОТОВКА", banner.options["text"])
        self.assertIsNone(event.bound_locale_id)

    def test_33_positive_outcome_preserves_honest_memory_claims(self):
        _, _, event = wire_preparation()
        event.arm_once(positive_inspection_request())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = event()
        self.assertTrue(outcome.process_local)
        self.assertTrue(outcome.contains_sensitive_path_metadata)
        self.assertFalse(outcome.memory_zeroization_proven)
        self.assertFalse(outcome.global_source_outcome_consumption_enforced)

    def test_34_fourth_event_remains_usable_without_optional_downstream(self):
        event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object())
        event.attach_widgets(FakeWidget(), FakeWidget())
        self.assertTrue(event.arm_once(positive_selection()))
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = event()
        self.assertTrue(outcome.future_secure_source_inspection_requested)


class RecoverySourceInspectionPreparationRequestMainGUIVisualTests(
    unittest.TestCase
):
    def test_35_both_locales_and_routes_build_canonical_bounded_reports(self):
        observed = []
        for case_number in range(1, 5):
            case = visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
                case_number
            )
            report = visual.build_recovery_source_inspection_preparation_request_main_gui_visual_report(
                case, pass_observations()
            )
            payload = json.loads(
                visual.recovery_source_inspection_preparation_request_main_gui_visual_report_json(
                    report
                )
            )
            observed.append(
                (
                    payload["locale"],
                    payload["scale_percent"],
                    payload["profile"],
                    payload["route"],
                )
            )
            requesting = (
                case.route
                is visual.RecoverySourceInspectionPreparationRequestMainGUIVisualRoute.REQUEST
            )
            self.assertEqual(
                payload["future_secure_source_inspection_preparation_requested"],
                requesting,
            )
            self.assertEqual(
                payload["preparation_request_preserved_and_stopped"],
                not requesting,
            )
            self.assertTrue(payload["process_local_path_retention_disclosed"])
            self.assertFalse(payload["memory_zeroisation_proven"])
            self.assertTrue(payload["parallel_step_guide_visible"])
            self.assertTrue(payload["per_action_guidance_provided"])
            self.assertTrue(payload["graphical_observation_wizard_used"])
            self.assertTrue(payload["observations_defaulted_to_not_checked"])
            self.assertTrue(payload["synthetic_mokr_fixture_used"])
            self.assertTrue(payload["visual_fixture_filesystem_mutation_disclosed"])
            self.assertTrue(payload["visual_fixture_removed_before_report"])
            self.assertEqual(payload["version"], 3)
        self.assertEqual(
            tuple(observed),
            visual.RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_MATRIX,
        )

    def test_36_invalid_locale_route_and_observation_types_are_rejected(self):
        for value in (0, 5, True, "1", None):
            with self.subTest(value=value):
                with self.assertRaises(
                    visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
                ):
                    visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
                        value
                    )
        case = visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
            1
        )
        with self.assertRaises(
            visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
        ):
            dataclasses.replace(case, locale="en-GB")
        with self.assertRaises(
            visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
        ):
            visual.build_recovery_source_inspection_preparation_request_main_gui_visual_report(
                object(), pass_observations()
            )

    def test_37_forged_authority_and_honesty_claims_are_rejected(self):
        case = visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
            1
        )
        report = visual.build_recovery_source_inspection_preparation_request_main_gui_visual_report(
            case, pass_observations()
        )
        false_fields = (
            "true_recovery_input_used",
            "memory_zeroisation_proven",
            "application_source_open_read_performed",
            "source_identity_validated",
            "source_access_authorized",
            "filesystem_capability_issued",
            "source_preparation_performed",
            "recovery_secret_received",
            "review_session_prepared",
            "stage_2_32_authorization_activated",
            "stage_2_41_review_activated",
            "operation_authorized",
            "operation_performed",
            "application_recovery_source_filesystem_mutation_performed",
            "whole_process_no_filesystem_access_claimed",
            "network_used",
            "automatic_transition_performed",
            "accessibility_conformity_claimed",
            "legal_or_platform_certification_claimed",
        )
        for name in false_fields:
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: True})
        true_fields = (
            "parallel_step_guide_visible",
            "per_action_guidance_provided",
            "graphical_observation_wizard_used",
            "observations_defaulted_to_not_checked",
            "synthetic_mokr_fixture_used",
            "visual_fixture_filesystem_mutation_disclosed",
            "visual_fixture_removed_before_report",
        )
        for name in true_fields:
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: False})
        failed = dataclasses.replace(
            pass_observations(),
            parallel_step_guide_visible_and_usable=(
                visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.FAIL
            ),
        )
        failed_report = (
            visual.build_recovery_source_inspection_preparation_request_main_gui_visual_report(
                case, failed
            )
        )
        self.assertFalse(failed_report.parallel_step_guide_visible)
        self.assertFalse(failed_report.per_action_guidance_provided)

    def test_38_visual_schema_excludes_paths_secrets_and_capabilities(self):
        names = {
            field.name
            for field in dataclasses.fields(
                visual.RecoverySourceInspectionPreparationRequestMainGUIVisualReport
            )
        }
        self.assertTrue(
            names.isdisjoint(
                {
                    "password",
                    "recovery_root",
                    "recovery_record",
                    "keyring",
                    "vault_path",
                    "selected_path",
                    "path",
                    "filename",
                    "callback",
                    "executor",
                    "notes",
                    "filesystem_access_performed",
                    "filesystem_mutation_performed",
                }
            )
        )

    def test_39_visual_json_is_canonical_path_free_and_exactly_bounded(self):
        case = visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
            1
        )
        report = visual.build_recovery_source_inspection_preparation_request_main_gui_visual_report(
            case, pass_observations()
        )
        encoded = visual.recovery_source_inspection_preparation_request_main_gui_visual_report_json(
            report
        )
        self.assertEqual(
            encoded,
            json.dumps(
                json.loads(encoded),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        self.assertNotIn(SELECTED_PATH, encoded)
        self.assertNotIn("private-name", encoded)

    def test_40_invalid_observation_value_is_rejected(self):
        passed = (
            visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservation.PASS
        )
        with self.assertRaises(
            visual.RecoverySourceInspectionPreparationRequestMainGUIVisualHarnessError
        ):
            visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservations(
                "pass",
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
            )


class RecoverySourceInspectionPreparationRequestMainGUIStaticTests(
    unittest.TestCase
):
    def test_41_stage2_31_contract_is_conditional_not_top_level(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        top_imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        module = "mokosh_vault_recovery_source_inspection_preparation_request"
        self.assertNotIn(module, top_imports)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            == "_recovery_source_inspection_preparation_request_contract"
        )
        imports = [node for node in ast.walk(helper) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, module)

    def test_42_fresh_import_does_not_load_stage2_27_29_or_31(self):
        source = """
import sys
import types
argon2 = types.ModuleType('argon2')
class Type:
    ID = 'ID'
argon2.Type = Type
low_level = types.ModuleType('argon2.low_level')
low_level.hash_secret = lambda *args, **kwargs: b''
sys.modules['argon2'] = argon2
sys.modules['argon2.low_level'] = low_level
import mokosh_gui
for name in (
    'mokosh_vault_recovery_source_selection',
    'mokosh_vault_recovery_source_inspection_request',
    'mokosh_vault_recovery_source_inspection_preparation_request',
):
    print(name in sys.modules)
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            result.stdout.strip().splitlines(),
            ["False", "False", "False"],
        )

    def test_43_fifth_event_has_no_source_or_operation_calls(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        event_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name
            == "_RecoverySourceInspectionPreparationRequestGUIEvent"
        )
        calls = {
            node.func.id
            for node in ast.walk(event_class)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            calls.isdisjoint(
                {
                    "open",
                    "stat",
                    "lstat",
                    "resolve",
                    "realpath",
                    "eval",
                    "exec",
                    "compile",
                    "__import__",
                    "unlock_vault",
                    "reconcile_recovery_publish",
                    "rehearse_recovery_file",
                    "prepare_recovery_review_session",
                    "publish_recovery_candidate",
                    "show_prepared_recovery_source_inspection_review",
                }
            )
        )

    def test_44_visual_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        path = (
            PROJECT_ROOT
            / "mokosh_vault_recovery_source_inspection_preparation_request_main_gui_visual_harness.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {
                    "os",
                    "pathlib",
                    "subprocess",
                    "socket",
                    "urllib",
                    "requests",
                    "logging",
                    "tkinter",
                    "importlib",
                }
            )
        )

    def test_45_visual_launcher_uses_normal_main_and_exact_routes(self):
        launcher_path = (
            PROJECT_ROOT
            / "run_main_gui_recovery_source_inspection_preparation_request_visual_harness.py"
        )
        source = launcher_path.read_text(encoding="utf-8")
        self.assertIn("mokosh_gui.main()", source)
        self.assertIn(
            "RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_MAIN_GUI_MATRIX",
            source,
        )
        self.assertIn('root.tk.call("tk", "scaling"', source)
        self.assertNotIn("event_generate", source)
        self.assertIn("Never choose a real recovery record", source)
        self.assertIn("class _StepGuide", source)
        self.assertIn("class _ObservationWizard", source)
        self.assertIn('attributes("-topmost", True)', source)
        self.assertIn("open_guide_after_main_is_built", source)
        self.assertIn("_present_above_all", source)
        self.assertIn("_next_guide_progress", source)
        self.assertIn("_complete_guide_text", source)
        self.assertIn("passive guide observer failed", source)
        self.assertIn("except _PreparationRequestMainGUIVisualLaunchError as exc", source)
        self.assertIn("after_cancel", source)
        self.assertIn("body_scrollbar", source)
        self.assertIn("self._body_canvas", source)
        self.assertNotIn("after(500", source)
        self.assertNotIn("def _keep_visible", source)
        self.assertIn("graphical_observations", source)
        self.assertIn("O_EXCL", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn(".mokr", source)
        self.assertIn("Directory", source)
        self.assertIn("observations_defaulted_to_not_checked", (
            PROJECT_ROOT
            / "mokosh_vault_recovery_source_inspection_preparation_request_main_gui_visual_harness.py"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("input(", source)
        self.assertNotIn("_read_observation", source)
        specification = importlib.util.spec_from_file_location(
            "stage243_guided_visual_launcher_test",
            launcher_path,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        launcher = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(launcher)
        self.assertEqual(
            tuple(item[0] for item in launcher._OBSERVATION_FIELDS_AND_TEXT),
            tuple(
                field.name
                for field in dataclasses.fields(
                    visual.RecoverySourceInspectionPreparationRequestMainGUIVisualObservations
                )
            ),
        )
        with tempfile.TemporaryDirectory(prefix="stage243-fixture-test.") as directory:
            downloads = Path(directory)
            fixture = launcher._SyntheticMokrFixture(downloads)
            path = fixture.create()
            info = path.lstat()
            self.assertEqual(path.name, launcher._FIXTURE_NAME)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_gid, os.getgid())
            self.assertEqual(info.st_size, 0)
            with self.assertRaises(launcher._PreparationRequestMainGUIVisualLaunchError):
                launcher._SyntheticMokrFixture(downloads).create()
            fixture.remove()
            self.assertFalse(path.exists())
            request_steps = launcher._guide_steps(
                visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(1),
                downloads / launcher._FIXTURE_NAME,
            )
            preserve_steps = launcher._guide_steps(
                visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(2),
                downloads / launcher._FIXTURE_NAME,
            )
            self.assertEqual(len(request_steps), 6)
            self.assertEqual(len(preserve_steps), 6)
            self.assertIn("Да / Yes", request_steps[4])
            self.assertIn("Не / No", preserve_steps[4])
            self.assertIn(launcher._FIXTURE_NAME, request_steps[2])
            for steps in (request_steps, preserve_steps):
                keyboard_step = steps[4]
                for token in ("Tab", "Shift+Tab", "натиснете Space"):
                    self.assertIn(token, keyboard_step)
                self.assertLess(
                    keyboard_step.index("Shift+Tab"),
                    keyboard_step.index("натиснете Space"),
                )
                self.assertIn(
                    "за да задействате петото действие чрез клавиатурата",
                    keyboard_step,
                )
        for case_number in range(1, 5):
            case = visual.prepare_recovery_source_inspection_preparation_request_main_gui_visual_case(
                case_number
            )
            steps = launcher._guide_steps(case, Path("/tmp") / launcher._FIXTURE_NAME)
            for current_index in range(6):
                rendered = launcher._complete_guide_text(steps, current_index)
                self.assertIn("ПОСТОЯНЕН ПЪЛЕН ПЛАН", rendered)
                self.assertIn(f"→ ФАЗА {current_index + 1}/6", rendered)
                for step in steps:
                    self.assertIn(step, rendered)
        valid_states = {"normal", "active", "disabled"}
        for state in valid_states:
            index, fifth_seen = launcher._next_guide_progress(
                0,
                (state, "disabled", "disabled", "disabled", "disabled"),
                False,
            )
            self.assertEqual((index, fifth_seen), (0, False))
        index, fifth_seen = 0, False
        for expected, states in (
            (1, ("disabled", "active", "disabled", "disabled", "disabled")),
            (2, ("disabled", "disabled", "normal", "disabled", "disabled")),
            (3, ("disabled", "disabled", "disabled", "active", "disabled")),
            (4, ("disabled", "disabled", "disabled", "disabled", "active")),
            (5, ("disabled", "disabled", "disabled", "disabled", "disabled")),
        ):
            index, fifth_seen = launcher._next_guide_progress(index, states, fifth_seen)
            self.assertEqual(index, expected)
        self.assertTrue(fifth_seen)
        self.assertEqual(
            launcher._next_guide_progress(
                0,
                ("disabled", "disabled", "active", "disabled", "disabled"),
                False,
            ),
            (2, False),
        )
        self.assertEqual(
            launcher._next_guide_progress(
                1,
                ("disabled", "disabled", "disabled", "disabled", "normal"),
                False,
            ),
            (4, True),
        )
        for invalid_states in (
            ("pressed", "disabled", "disabled", "disabled", "disabled"),
            ("disabled",) * 4,
            ["disabled"] * 5,
        ):
            with self.assertRaises(launcher._PreparationRequestMainGUIVisualLaunchError):
                launcher._next_guide_progress(0, invalid_states, False)
        after_idle_calls = []
        fake_guide = types.SimpleNamespace(
            _buttons=tuple(
                types.SimpleNamespace(cget=lambda _name, state=state: state)
                for state in ("pressed", "disabled", "disabled", "disabled", "disabled")
            ),
            _index=0,
            _fifth_seen_enabled=False,
            _observer_id="scheduled",
            _root=types.SimpleNamespace(
                after_idle=lambda callback: after_idle_calls.append(callback),
                destroy=lambda: None,
            ),
            error=None,
        )
        launcher._StepGuide._observe_actions(fake_guide)
        self.assertIsInstance(
            fake_guide.error,
            launcher._PreparationRequestMainGUIVisualLaunchError,
        )
        self.assertIsNone(fake_guide._observer_id)
        self.assertEqual(len(after_idle_calls), 1)
        self.assertEqual(len(launcher._OBSERVATION_FIELDS_AND_TEXT), 12)
        self.assertEqual(
            launcher._OBSERVATION_FIELDS_AND_TEXT[0][0],
            "parallel_step_guide_visible_and_usable",
        )
        for token in (
            "VaultStorage",
            "unlock_vault",
            "publish_recovery",
            "recovery_root",
            "keyring_path",
            "contacts_core",
            "requests",
            "socket",
        ):
            self.assertNotIn(token, source)

    def test_46_safety_mode_and_critical_non_gui_files_remain_exact(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        assignments = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        self.assertIs(assignments["SAFETY_MODE"].value, True)
        expected = {
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "seed_manager.py": "3b5b7c3d1b47338185a2fb8b28b9a7f621ce48698e31df6cdef429aadafe818e",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_source_inspection_main_gui_bridge.py": "a031849c1a6da82b35df803de344c081068196c8ec8816685c78b1fdadd6de1a",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_47_main_gui_has_fifth_widget_and_existing_geometry_boundary(self):
        source = (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn(
            'root.geometry("820x560" if conditional_recovery_review else "820x720")',
            source,
        )
        for token in (
            "recovery_source_inspection_preparation_request_banner",
            "btn_recovery_source_inspection_preparation_request",
            "recovery_source_inspection_preparation_request_event",
            "_wire_recovery_source_inspection_preparation_request_widget",
        ):
            self.assertIn(token, source)
        self.assertNotIn("rehearse_recovery_file(", source)
        self.assertNotIn("_read_recovery_path(", source)

    def test_48_no_stage2_32_or_review_activation_was_added(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        event_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name
            == "_RecoverySourceInspectionPreparationRequestGUIEvent"
        )
        names = {node.id for node in ast.walk(event_class) if isinstance(node, ast.Name)}
        self.assertTrue(
            names.isdisjoint(
                {
                    "prepare_recovery_source_inspection_execution",
                    "prepare_main_gui_recovery_source_inspection_review",
                    "show_prepared_recovery_source_inspection_review",
                }
            )
        )
        self.assertEqual(
            hashlib.sha256(
                (
                    PROJECT_ROOT
                    / "mokosh_vault_recovery_source_inspection_review_controller.py"
                ).read_bytes()
            ).hexdigest(),
            "330a6a79451a4fc8e4d982c7468b55faa3064afc08efe1c9eafa869db2b7fda2",
        )


if __name__ == "__main__":
    unittest.main()
