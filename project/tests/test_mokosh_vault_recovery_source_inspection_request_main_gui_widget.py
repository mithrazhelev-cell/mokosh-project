import ast
import dataclasses
import hashlib
import json
import subprocess
import sys
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
import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_source_inspection_request as inspection
import mokosh_vault_recovery_source_inspection_request_main_gui_visual_harness as visual
import mokosh_vault_recovery_source_selection as selection


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SELECTED_PATH = "/tmp/mokosh-stage2-30-synthetic-private-name.mokr"


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
    entry = request.prepare_recovery_entry_request(locale).decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    return transition.prepare_recovery_entry_transition(entry).decide_once(
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )


def positive_selection(locale="en-GB"):
    return selection.prepare_recovery_source_selection(
        positive_transition(locale)
    ).decide_once(
        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        SELECTED_PATH,
    )


def preserved_selection(locale="en-GB"):
    return selection.prepare_recovery_source_selection(
        positive_transition(locale)
    ).decide_once(selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP)


def forged_selection(**changes):
    exact = positive_selection()
    forged = object.__new__(selection.VaultRecoverySourceSelectionOutcome)
    for field in dataclasses.fields(exact):
        object.__setattr__(
            forged,
            field.name,
            changes.get(field.name, getattr(exact, field.name)),
        )
    return forged


def wire_request(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object())
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            return mokosh_gui._wire_recovery_source_inspection_request_widget(
                object(), object(), event
            )
    finally:
        mokosh_gui.current_lang = previous


def wire_four_step_flow(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        inspection_event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(
            object()
        )
        source_event = mokosh_gui._RecoverySourceSelectionGUIEvent(
            object(), inspection_event
        )
        transition_event = mokosh_gui._RecoveryEntryTransitionGUIEvent(
            object(), source_event
        )
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            request_widgets = mokosh_gui._wire_recovery_entry_request_widget(
                object(), object(), transition_event
            )
            transition_widgets = mokosh_gui._wire_recovery_entry_transition_widget(
                object(), object(), transition_event
            )
            source_widgets = mokosh_gui._wire_recovery_source_selection_widget(
                object(), object(), source_event
            )
            inspection_widgets = (
                mokosh_gui._wire_recovery_source_inspection_request_widget(
                    object(), object(), inspection_event
                )
            )
        return (
            request_widgets,
            transition_widgets,
            source_widgets,
            inspection_widgets,
        )
    finally:
        mokosh_gui.current_lang = previous


def pass_observations():
    passed = visual.RecoverySourceInspectionRequestMainGUIVisualObservation.PASS
    return visual.RecoverySourceInspectionRequestMainGUIVisualObservations(
        passed, passed, passed, passed, passed, passed, passed, passed, passed
    )


class RecoverySourceInspectionRequestMainGUIWidgetTests(unittest.TestCase):
    def test_01_fourth_action_starts_locked_without_retained_path_outcome(self):
        banner, button, event = wire_request()
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionRequestGUIEventState.LOCKED,
        )
        self.assertFalse(event.retains_source_selection_outcome)
        self.assertIsNone(event.bound_locale_id)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertIn("does not open", banner.options["text"])

    def test_02_both_locales_have_fixed_request_not_access_disclosure(self):
        for locale, token in (("en", "does not open"), ("bg", "не отваря")):
            with self.subTest(locale=locale):
                banner, button, _ = wire_request(locale)
                self.assertIn(token, banner.options["text"])
                self.assertIn("...", button.options["text"])
                self.assertNotIn(SELECTED_PATH, banner.options["text"])

    def test_03_widget_requires_exact_event_and_single_attachment(self):
        with self.assertRaises(TypeError):
            mokosh_gui._wire_recovery_source_inspection_request_widget(
                object(), object(), object()
            )
        _, _, event = wire_request()
        with self.assertRaises(TypeError):
            event.attach_widgets(FakeWidget(), FakeWidget())

    def test_04_source_event_constructor_requires_exact_downstream_type(self):
        with self.assertRaises(TypeError):
            mokosh_gui._RecoverySourceSelectionGUIEvent(object(), object())
        exact = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object())
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(object(), exact)
        self.assertIs(event._inspection_request_event, exact)

    def test_05_exact_bulgarian_selection_arms_and_binds_locale(self):
        banner, button, event = wire_request()
        self.assertTrue(event.arm_once(positive_selection("bg-BG")))
        self.assertEqual(event.bound_locale_id, "bg-BG")
        self.assertTrue(event.retains_source_selection_outcome)
        self.assertEqual(button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertIn("БЪДЕЩА", banner.options["text"])

    def test_06_exact_english_selection_arms_and_binds_locale(self):
        banner, button, event = wire_request("bg")
        self.assertTrue(event.arm_once(positive_selection("en-GB")))
        self.assertEqual(event.bound_locale_id, "en-GB")
        self.assertIn("FUTURE", banner.options["text"])
        self.assertIn("Request", button.options["text"])

    def test_07_arm_rejects_wrong_type_and_becomes_terminal_failed(self):
        for invalid in (None, {}, (), "selection", object()):
            with self.subTest(invalid=type(invalid).__name__):
                _, _, event = wire_request()
                with self.assertRaises(TypeError):
                    event.arm_once(invalid)
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoverySourceInspectionRequestGUIEventState.FAILED,
                )

    def test_08_preserved_selection_cannot_arm_fourth_action(self):
        _, button, event = wire_request()
        with self.assertRaises(TypeError):
            event.arm_once(preserved_selection())
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertFalse(event.retains_source_selection_outcome)

    def test_09_forged_selection_claims_are_rejected_before_retention(self):
        changes = (
            {"source_selected": False},
            {"selected_path": "/tmp/../private.mokr"},
            {"source_opened": True},
            {"source_access_authorized": True},
            {"source_preparation_performed": True},
            {"recovery_secret_received": True},
            {"operation_authorized": True},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                _, _, event = wire_request()
                with self.assertRaises(TypeError):
                    event.arm_once(forged_selection(**change))
                self.assertFalse(event.retains_source_selection_outcome)

    def test_10_widget_configuration_failure_does_not_retain_outcome(self):
        event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object())
        event.attach_widgets(RaisingWidget(RuntimeError("detail")), FakeWidget())
        self.assertFalse(event.arm_once(positive_selection()))
        self.assertFalse(event.retains_source_selection_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionRequestGUIEventState.FAILED,
        )

    def test_11_baseexception_during_arm_marks_failed_and_propagates(self):
        event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(object())
        event.attach_widgets(RaisingWidget(KeyboardInterrupt()), FakeWidget())
        with self.assertRaises(KeyboardInterrupt):
            event.arm_once(positive_selection())
        self.assertFalse(event.retains_source_selection_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionRequestGUIEventState.FAILED,
        )

    def test_12_locked_or_failed_event_cannot_open_confirmation(self):
        _, _, event = wire_request()
        with mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm:
            self.assertIsNone(event())
            with self.assertRaises(TypeError):
                event.arm_once(None)
            self.assertIsNone(event())
        confirm.assert_not_called()

    def test_13_yes_maps_to_exact_stage2_29_request(self):
        _, button, event = wire_request()
        event.arm_once(positive_selection())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = button.invoke()
        self.assertTrue(outcome.future_secure_source_inspection_requested)
        self.assertEqual(outcome.selected_path, SELECTED_PATH)
        self.assertFalse(outcome.source_access_authorized)
        self.assertNotIn(SELECTED_PATH, str(info.call_args))

    def test_14_no_maps_to_exact_stage2_29_preserve(self):
        _, button, event = wire_request()
        event.arm_once(positive_selection())
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
        _, _, event = wire_request()
        event.arm_once(positive_selection())
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

    def test_16_retained_outcome_is_cleared_before_loader_and_dialog(self):
        _, _, event = wire_request()
        event.arm_once(positive_selection())

        def inspect_loader():
            self.assertFalse(event.retains_source_selection_outcome)
            self.assertIsNone(event.bound_locale_id)
            return (
                inspection.RecoverySourceInspectionRequestDecision,
                inspection.VaultRecoverySourceInspectionRequestError,
                inspection.prepare_recovery_source_inspection_request,
            )

        def inspect_dialog(*args, **kwargs):
            del args, kwargs
            self.assertFalse(event.retains_source_selection_outcome)
            return True

        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_request_contract",
                side_effect=inspect_loader,
            ),
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=inspect_dialog
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            event()

    def test_17_contract_loader_error_is_generic_and_terminal(self):
        _, _, event = wire_request()
        event.arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_request_contract",
                side_effect=RuntimeError("private loader detail"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        confirm.assert_not_called()
        self.assertNotIn("private loader detail", str(error.call_args))
        self.assertFalse(event.retains_source_selection_outcome)

    def test_18_stage2_29_prepare_error_is_generic_and_before_dialog(self):
        _, _, event = wire_request()
        event.arm_once(positive_selection())
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_inspection_request_contract",
                return_value=(
                    inspection.RecoverySourceInspectionRequestDecision,
                    inspection.VaultRecoverySourceInspectionRequestError,
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
        _, _, event = wire_request()
        event.arm_once(positive_selection())
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
        _, _, event = wire_request()
        event.arm_once(positive_selection())
        with mock.patch.object(
            mokosh_gui,
            "_recovery_source_inspection_request_contract",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                event()
        self.assertFalse(event.retains_source_selection_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionRequestGUIEventState.FAILED,
        )

    def test_21_success_is_terminal_without_retained_path_or_outcome(self):
        _, _, event = wire_request()
        event.arm_once(positive_selection())
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = event()
            self.assertIsNone(event())
        self.assertTrue(outcome.future_secure_source_inspection_requested)
        self.assertFalse(event.retains_source_selection_outcome)
        self.assertFalse(hasattr(event, "_selected_path"))
        self.assertFalse(hasattr(event, "_outcome"))

    def test_22_concurrent_clicks_allow_exactly_one_decision(self):
        _, _, event = wire_request()
        event.arm_once(positive_selection())
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

    def test_23_positive_third_action_arms_only_the_fourth_action(self):
        _, _, source_widgets, inspection_widgets = wire_four_step_flow()
        _, source_button, source_event = source_widgets
        _, inspection_button, inspection_event = inspection_widgets
        source_event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=SELECTED_PATH
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(mokosh_gui.messagebox, "askyesno") as confirm,
        ):
            source_button.invoke()
        confirm.assert_not_called()
        self.assertEqual(inspection_button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertTrue(inspection_event.retains_source_selection_outcome)

    def test_24_picker_cancel_keeps_fourth_action_locked(self):
        _, _, source_widgets, inspection_widgets = wire_four_step_flow()
        source_widgets[2].arm_once(positive_transition())
        with (
            mock.patch.object(mokosh_gui.filedialog, "askopenfilename", return_value=""),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            source_widgets[1].invoke()
        self.assertEqual(inspection_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
        self.assertFalse(inspection_widgets[2].retains_source_selection_outcome)

    def test_25_downstream_arm_failure_is_generic_and_does_not_retain_path(self):
        inspection_event = mokosh_gui._RecoverySourceInspectionRequestGUIEvent(
            object()
        )
        source_event = mokosh_gui._RecoverySourceSelectionGUIEvent(
            object(), inspection_event
        )
        source_event.attach_widgets(FakeWidget(), FakeWidget())
        source_event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=SELECTED_PATH
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            outcome = source_event()
        self.assertTrue(outcome.source_selected)
        self.assertNotIn(SELECTED_PATH, str(error.call_args))
        self.assertFalse(inspection_event.retains_source_selection_outcome)

    def test_26_four_step_flow_uses_four_separate_positive_actions(self):
        request_widgets, transition_widgets, source_widgets, inspection_widgets = (
            wire_four_step_flow()
        )
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=(True, True, True)
            ) as confirms,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=SELECTED_PATH
            ) as picker,
        ):
            request_widgets[1].invoke()
            self.assertEqual(transition_widgets[1].options["state"], mokosh_gui.tk.NORMAL)
            self.assertEqual(source_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
            transition_widgets[1].invoke()
            self.assertEqual(source_widgets[1].options["state"], mokosh_gui.tk.NORMAL)
            self.assertEqual(inspection_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
            source_widgets[1].invoke()
            self.assertEqual(inspection_widgets[1].options["state"], mokosh_gui.tk.NORMAL)
            outcome = inspection_widgets[1].invoke()
        self.assertEqual(confirms.call_count, 3)
        self.assertEqual(picker.call_count, 1)
        self.assertTrue(outcome.future_secure_source_inspection_requested)

    def test_27_first_preserve_keeps_all_three_later_actions_locked(self):
        request_widgets, transition_widgets, source_widgets, inspection_widgets = (
            wire_four_step_flow()
        )
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            request_widgets[1].invoke()
        for button in (
            transition_widgets[1],
            source_widgets[1],
            inspection_widgets[1],
        ):
            self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_28_second_preserve_keeps_both_later_actions_locked(self):
        request_widgets, transition_widgets, source_widgets, inspection_widgets = (
            wire_four_step_flow()
        )
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=(True, False)
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            request_widgets[1].invoke()
            transition_widgets[1].invoke()
        self.assertEqual(source_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
        self.assertEqual(inspection_widgets[1].options["state"], mokosh_gui.tk.DISABLED)

    def test_29_bound_locale_cannot_be_changed_after_selection(self):
        banner, button, event = wire_request("en")
        event.arm_once(positive_selection("en-GB"))
        widgets = {
            "lang_label": FakeWidget(), "vault_title": FakeWidget(),
            "btn_choose_vault": FakeWidget(), "pwd_title": FakeWidget(),
            "nick_title": FakeWidget(), "btn_encrypt_main": FakeWidget(),
            "btn_decrypt_main": FakeWidget(), "btn_clean_main": FakeWidget(),
            "btn_bottom_contacts": FakeWidget(),
            "btn_bottom_contact_crypto": FakeWidget(),
            "btn_bottom_master": FakeWidget(), "safety_banner": FakeWidget(),
            "recovery_source_inspection_request_banner": banner,
            "btn_recovery_source_inspection_request": button,
            "recovery_source_inspection_request_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeWidget(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertIn("FUTURE", banner.options["text"])
        self.assertEqual(event.bound_locale_id, "en-GB")

    def test_30_unarmed_language_change_updates_fourth_action_text(self):
        banner, button, event = wire_request("en")
        widgets = {
            "lang_label": FakeWidget(), "vault_title": FakeWidget(),
            "btn_choose_vault": FakeWidget(), "pwd_title": FakeWidget(),
            "nick_title": FakeWidget(), "btn_encrypt_main": FakeWidget(),
            "btn_decrypt_main": FakeWidget(), "btn_clean_main": FakeWidget(),
            "btn_bottom_contacts": FakeWidget(),
            "btn_bottom_contact_crypto": FakeWidget(),
            "btn_bottom_master": FakeWidget(), "safety_banner": FakeWidget(),
            "recovery_source_inspection_request_banner": banner,
            "btn_recovery_source_inspection_request": button,
            "recovery_source_inspection_request_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeWidget(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertIn("БЪДЕЩА", banner.options["text"])
        self.assertIsNone(event.bound_locale_id)


class RecoverySourceInspectionRequestMainGUIVisualTests(unittest.TestCase):
    def test_31_both_locales_and_routes_build_canonical_bounded_reports(self):
        for locale in visual.RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_LOCALES:
            for route in visual.RecoverySourceInspectionRequestMainGUIVisualRoute:
                with self.subTest(locale=locale, route=route.value):
                    report = visual.build_recovery_source_inspection_request_main_gui_visual_report(
                        locale, route, pass_observations()
                    )
                    payload = json.loads(
                        visual.recovery_source_inspection_request_main_gui_visual_report_json(
                            report
                        )
                    )
                    requesting = (
                        route
                        is visual.RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST
                    )
                    self.assertEqual(
                        payload["future_secure_source_inspection_requested"],
                        requesting,
                    )
                    self.assertEqual(
                        payload["inspection_request_preserved_and_stopped"],
                        not requesting,
                    )
                    self.assertTrue(payload["source_selection_performed"])
                    self.assertFalse(payload["application_source_open_read_performed"])

    def test_32_invalid_locale_route_and_observation_types_are_rejected(self):
        route = visual.RecoverySourceInspectionRequestMainGUIVisualRoute.PRESERVE
        for locale in ("bg", "en", "BG-bg", "bg-BG ", None, True):
            with self.subTest(locale=locale):
                with self.assertRaises(
                    visual.RecoverySourceInspectionRequestMainGUIVisualHarnessError
                ):
                    visual.build_recovery_source_inspection_request_main_gui_visual_report(
                        locale, route, pass_observations()
                    )
        with self.assertRaises(
            visual.RecoverySourceInspectionRequestMainGUIVisualHarnessError
        ):
            visual.build_recovery_source_inspection_request_main_gui_visual_report(
                "en-GB", "request", pass_observations()
            )
        passed = visual.RecoverySourceInspectionRequestMainGUIVisualObservation.PASS
        with self.assertRaises(
            visual.RecoverySourceInspectionRequestMainGUIVisualHarnessError
        ):
            visual.RecoverySourceInspectionRequestMainGUIVisualObservations(
                "pass", passed, passed, passed, passed, passed, passed, passed, passed
            )

    def test_33_forged_authority_and_honesty_claims_are_rejected(self):
        report = visual.build_recovery_source_inspection_request_main_gui_visual_report(
            "en-GB",
            visual.RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST,
            pass_observations(),
        )
        false_fields = (
            "true_recovery_input_used",
            "application_source_open_read_performed",
            "source_identity_validated",
            "source_access_authorized",
            "source_preparation_performed",
            "recovery_secret_received",
            "review_session_prepared",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_mutation_performed",
            "whole_process_no_filesystem_access_claimed",
            "network_used",
            "automatic_transition_performed",
            "platform_certification_claimed",
        )
        for name in false_fields:
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoverySourceInspectionRequestMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: True})
        for name in (
            "native_source_picker_invoked",
            "native_picker_filesystem_metadata_access_possible",
            "source_selection_performed",
            "source_path_metadata_received",
            "inspection_request_action_invoked",
            "runtime_directory_preparation_performed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoverySourceInspectionRequestMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: False})

    def test_34_visual_schema_excludes_paths_secrets_and_capabilities(self):
        names = {
            field.name
            for field in dataclasses.fields(
                visual.RecoverySourceInspectionRequestMainGUIVisualReport
            )
        }
        self.assertTrue(
            names.isdisjoint(
                {
                    "password", "recovery_root", "recovery_record", "keyring",
                    "vault_path", "selected_path", "path", "filename",
                    "callback", "executor", "notes", "filesystem_access_performed",
                    "filesystem_mutation_performed",
                }
            )
        )

    def test_35_visual_json_is_canonical_path_free_and_exactly_bounded(self):
        report = visual.build_recovery_source_inspection_request_main_gui_visual_report(
            "bg-BG",
            visual.RecoverySourceInspectionRequestMainGUIVisualRoute.REQUEST,
            pass_observations(),
        )
        encoded = visual.recovery_source_inspection_request_main_gui_visual_report_json(
            report
        )
        self.assertEqual(encoded, json.dumps(json.loads(encoded), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        self.assertNotIn(SELECTED_PATH, encoded)
        self.assertNotIn("private-name", encoded)


class RecoverySourceInspectionRequestMainGUIStaticTests(unittest.TestCase):
    def test_36_stage2_29_contract_is_conditional_not_top_level(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        top_imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn("mokosh_vault_recovery_source_inspection_request", top_imports)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_recovery_source_inspection_request_contract"
        )
        imports = [node for node in ast.walk(helper) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(
            imports[0].module,
            "mokosh_vault_recovery_source_inspection_request",
        )

    def test_37_fresh_normal_import_does_not_load_stage2_27_or_stage2_29(self):
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
print('mokosh_vault_recovery_source_selection' in sys.modules)
print('mokosh_vault_recovery_source_inspection_request' in sys.modules)
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.stdout.strip().splitlines(), ["False", "False"])

    def test_38_inspection_event_has_no_source_open_or_operation_calls(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        event_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "_RecoverySourceInspectionRequestGUIEvent"
        )
        calls = {
            node.func.id
            for node in ast.walk(event_class)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            calls.isdisjoint(
                {
                    "open", "stat", "lstat", "resolve", "realpath", "eval",
                    "exec", "compile", "__import__", "unlock_vault",
                    "reconcile_recovery_publish", "rehearse_recovery_file",
                    "prepare_recovery_review_session", "publish_recovery_candidate",
                }
            )
        )

    def test_39_visual_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        path = PROJECT_ROOT / "mokosh_vault_recovery_source_inspection_request_main_gui_visual_harness.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {"os", "pathlib", "subprocess", "socket", "urllib", "requests", "logging", "tkinter", "importlib"}
            )
        )

    def test_40_visual_launcher_uses_normal_main_and_exact_routes(self):
        source = (
            PROJECT_ROOT
            / "run_main_gui_recovery_source_inspection_request_visual_harness.py"
        ).read_text(encoding="utf-8")
        self.assertIn("mokosh_gui.main()", source)
        self.assertIn('choices=("request", "preserve")', source)
        self.assertIn("never choose a real recovery record", source)
        for token in (
            "VaultStorage", "unlock_vault", "publish_recovery", "recovery_root",
            "keyring_path", "contacts_core", "requests", "socket",
        ):
            self.assertNotIn(token, source)

    def test_41_safety_mode_and_critical_non_gui_files_remain_exact(self):
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
            "mokosh_vault_recovery_source_selection.py": "856143153b21cc6c3ff81e908cbf875c0433492a79a023ee2ab3e4b793024600",
            "mokosh_vault_recovery_source_inspection_request.py": "e494709a2cd501a3957b947e7bd913168d0a1ee4e58a5db2a8b6e963dd18d403",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_42_main_gui_has_fourth_widget_and_exact_review_geometry_boundary(self):
        source = (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn(
            'root.geometry("820x560" if conditional_recovery_review else "820x720")',
            source,
        )
        for token in (
            "recovery_source_inspection_request_banner",
            "btn_recovery_source_inspection_request",
            "recovery_source_inspection_request_event",
            "_wire_recovery_source_inspection_request_widget",
        ):
            self.assertIn(token, source)
        self.assertNotIn("rehearse_recovery_file(", source)
        self.assertNotIn("_read_recovery_path(", source)


if __name__ == "__main__":
    unittest.main()
