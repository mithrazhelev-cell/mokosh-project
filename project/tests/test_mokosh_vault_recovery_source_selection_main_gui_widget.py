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
import mokosh_vault_recovery_source_selection as selection
import mokosh_vault_recovery_source_selection_main_gui_visual_harness as visual


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SELECTED_PATH = "/tmp/mokosh-stage2-28-synthetic.mokr"


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


class RaisingWidget(FakeWidget):
    def __init__(self, raised, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raised = raised

    def config(self, **kwargs):
        del kwargs
        raise self.raised


def positive_request(locale="en-GB"):
    return request.prepare_recovery_entry_request(locale).decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )


def positive_transition(locale="en-GB"):
    return transition.prepare_recovery_entry_transition(
        positive_request(locale)
    ).decide_once(
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
    )


def preserved_transition(locale="en-GB"):
    return transition.prepare_recovery_entry_transition(
        positive_request(locale)
    ).decide_once(
        transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
    )


def forged_transition(**changes):
    exact = positive_transition()
    forged = object.__new__(transition.VaultRecoveryEntryTransitionOutcome)
    for field in dataclasses.fields(exact):
        object.__setattr__(
            forged,
            field.name,
            changes.get(field.name, getattr(exact, field.name)),
        )
    return forged


def wire_source(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(object())
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            return mokosh_gui._wire_recovery_source_selection_widget(
                object(), object(), event
            )
    finally:
        mokosh_gui.current_lang = previous


def wire_three_step_flow(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        source_event = mokosh_gui._RecoverySourceSelectionGUIEvent(object())
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
        return request_widgets, transition_widgets, source_widgets
    finally:
        mokosh_gui.current_lang = previous


def pass_observations():
    passed = visual.RecoverySourceSelectionMainGUIVisualObservation.PASS
    return visual.RecoverySourceSelectionMainGUIVisualObservations(
        passed, passed, passed, passed, passed, passed, passed, passed
    )


class RecoverySourceSelectionMainGUIWidgetTests(unittest.TestCase):
    def test_01_source_action_starts_locked_without_retained_authority(self):
        banner, button, event = wire_source()
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.LOCKED,
        )
        self.assertFalse(event.retains_transition_outcome)
        self.assertIsNone(event.bound_locale_id)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertIn("native picker", banner.options["text"])

    def test_02_both_locales_have_fixed_picker_metadata_disclosure(self):
        for locale, token in (("en", "filesystem metadata"), ("bg", "filesystem metadata")):
            with self.subTest(locale=locale):
                banner, button, _ = wire_source(locale)
                self.assertIn(token, banner.options["text"])
                self.assertNotIn(SELECTED_PATH, banner.options["text"])
                self.assertTrue(button.options["text"])

    def test_03_widget_rejects_wrong_event_and_duplicate_attachment(self):
        with self.assertRaises(TypeError):
            mokosh_gui._wire_recovery_source_selection_widget(
                object(), object(), object()
            )
        _, button, event = wire_source()
        with self.assertRaises(TypeError):
            event.attach_widgets(FakeWidget(), button)

    def test_04_exact_positive_transition_arms_and_binds_each_locale(self):
        for locale in ("bg-BG", "en-GB"):
            with self.subTest(locale=locale):
                banner, button, event = wire_source()
                self.assertTrue(event.arm_once(positive_transition(locale)))
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoverySourceSelectionGUIEventState.READY,
                )
                self.assertTrue(event.retains_transition_outcome)
                self.assertEqual(event.bound_locale_id, locale)
                self.assertEqual(button.options["state"], mokosh_gui.tk.NORMAL)
                expected = mokosh_gui._RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[locale]
                self.assertEqual(button.options["text"], expected["button"])
                self.assertEqual(banner.options["text"], expected["banner"])

    def test_05_preserve_wrong_type_and_forged_transition_cannot_arm(self):
        invalid = (
            None,
            object(),
            preserved_transition(),
            forged_transition(operation_authorized=True),
            forged_transition(format="WRONG"),
        )
        for value in invalid:
            with self.subTest(value=type(value).__name__):
                _, button, event = wire_source()
                with self.assertRaises(TypeError):
                    event.arm_once(value)
                self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
                self.assertFalse(event.retains_transition_outcome)

    def test_06_arm_without_widgets_fails_closed(self):
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(object())
        self.assertFalse(event.arm_once(positive_transition()))
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.FAILED,
        )
        self.assertFalse(event.retains_transition_outcome)

    def test_07_widget_configuration_error_does_not_retain_authority(self):
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(object())
        event.attach_widgets(FakeWidget(), RaisingWidget(RuntimeError("secret")))
        self.assertFalse(event.arm_once(positive_transition()))
        self.assertFalse(event.retains_transition_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.FAILED,
        )

    def test_08_widget_baseexception_marks_failed_and_propagates(self):
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(object())
        event.attach_widgets(FakeWidget(), RaisingWidget(KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            event.arm_once(positive_transition())
        self.assertFalse(event.retains_transition_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.FAILED,
        )

    def test_09_arm_is_one_shot(self):
        _, _, event = wire_source()
        self.assertTrue(event.arm_once(positive_transition()))
        self.assertFalse(event.arm_once(positive_transition()))

    def test_10_no_click_before_arm_performs_no_prepare_or_picker(self):
        _, _, event = wire_source()
        with (
            mock.patch.object(
                mokosh_gui, "_recovery_source_selection_contract"
            ) as contract_mock,
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename"
            ) as picker_mock,
        ):
            self.assertIsNone(event())
        contract_mock.assert_not_called()
        picker_mock.assert_not_called()

    def test_11_select_records_only_bounded_path_metadata(self):
        _, button, event = wire_source()
        self.assertTrue(event.arm_once(positive_transition("bg-BG")))
        with (
            mock.patch.object(
                mokosh_gui.filedialog,
                "askopenfilename",
                return_value=SELECTED_PATH,
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = event()
        self.assertTrue(outcome.source_selected)
        self.assertEqual(outcome.selected_path, SELECTED_PATH)
        self.assertFalse(outcome.source_opened)
        self.assertFalse(outcome.source_identity_validated)
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertFalse(outcome.recovery_source_filesystem_access_performed)
        self.assertFalse(outcome.recovery_source_filesystem_mutation_performed)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertNotIn(SELECTED_PATH, repr(outcome))
        self.assertNotIn(SELECTED_PATH, str(info.call_args))

    def test_12_cancel_maps_exactly_to_preserve_and_stop(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=""
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = event()
        self.assertIs(
            outcome.selection_decision,
            selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP,
        )
        self.assertIsNone(outcome.selected_path)
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertIn("Stopped safely", info.call_args.args[1])

    def test_13_authority_is_cleared_and_button_disabled_before_prepare_and_picker(self):
        _, button, event = wire_source()
        event.arm_once(positive_transition())
        observations = []

        def prepare(outcome):
            observations.append(
                (
                    "prepare",
                    event.retains_transition_outcome,
                    button.options["state"],
                )
            )
            return selection.prepare_recovery_source_selection(outcome)

        def picker(**kwargs):
            del kwargs
            observations.append(
                (
                    "picker",
                    event.retains_transition_outcome,
                    button.options["state"],
                )
            )
            return ""

        contract = (
            selection.RecoverySourceSelectionDecision,
            selection.VaultRecoverySourceSelectionError,
            prepare,
        )
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_selection_contract",
                return_value=contract,
            ),
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", side_effect=picker
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            event()
        self.assertEqual(
            observations,
            [
                ("prepare", False, mokosh_gui.tk.DISABLED),
                ("picker", False, mokosh_gui.tk.DISABLED),
            ],
        )

    def test_14_picker_receives_parent_title_and_bounded_filetypes(self):
        parent = object()
        event = mokosh_gui._RecoverySourceSelectionGUIEvent(parent)
        banner, button = FakeWidget(), FakeWidget(state=mokosh_gui.tk.DISABLED)
        event.attach_widgets(banner, button)
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=""
            ) as picker,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            event()
        kwargs = picker.call_args.kwargs
        self.assertIs(kwargs["parent"], parent)
        self.assertEqual(kwargs["filetypes"][0][1], "*.mokr")
        self.assertEqual(len(kwargs["filetypes"]), 2)

    def test_15_bound_locale_does_not_follow_later_global_language_change(self):
        banner, button, event = wire_source("en")
        event.arm_once(positive_transition("bg-BG"))
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
            "recovery_source_selection_banner": banner,
            "btn_recovery_source_selection": button,
            "recovery_source_selection_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="en"), FakeRoot(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertEqual(event.bound_locale_id, "bg-BG")
        self.assertEqual(
            button.options["text"],
            mokosh_gui._RECOVERY_SOURCE_SELECTION_WIDGET_TEXT["bg-BG"]["button"],
        )

    def test_16_unbound_widget_follows_valid_global_language_change(self):
        banner, button, event = wire_source("en")
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
            "recovery_source_selection_banner": banner,
            "btn_recovery_source_selection": button,
            "recovery_source_selection_event": event,
        }
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeRoot(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertIn("Избери", button.options["text"])
        self.assertIsNone(event.bound_locale_id)

    def test_17_invalid_path_fails_generically_without_path_or_exception_text(self):
        bad_path = "relative/private-secret.mokr"
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename", return_value=bad_path
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.FAILED,
        )
        rendered = str(error.call_args)
        self.assertNotIn(bad_path, rendered)
        self.assertNotIn("absolute POSIX", rendered)

    def test_18_picker_exception_fails_generically_without_exception_text(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog,
                "askopenfilename",
                side_effect=RuntimeError("private picker detail"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        self.assertNotIn("private picker detail", str(error.call_args))
        self.assertFalse(event.retains_transition_outcome)

    def test_19_contract_loader_exception_fails_before_picker(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui,
                "_recovery_source_selection_contract",
                side_effect=RuntimeError("loader detail"),
            ),
            mock.patch.object(
                mokosh_gui.filedialog, "askopenfilename"
            ) as picker,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        picker.assert_not_called()
        self.assertNotIn("loader detail", str(error.call_args))

    def test_20_baseexception_after_consumption_marks_failed_and_propagates(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with mock.patch.object(
            mokosh_gui,
            "_recovery_source_selection_contract",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                event()
        self.assertFalse(event.retains_transition_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceSelectionGUIEventState.FAILED,
        )

    def test_21_success_is_terminal_and_event_retains_no_path_or_outcome(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        with (
            mock.patch.object(
                mokosh_gui.filedialog,
                "askopenfilename",
                return_value=SELECTED_PATH,
            ) as picker,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = event()
            self.assertIsNone(event())
        self.assertTrue(outcome.source_selected)
        self.assertEqual(picker.call_count, 1)
        self.assertFalse(event.retains_transition_outcome)
        self.assertFalse(hasattr(event, "_selected_path"))
        self.assertFalse(hasattr(event, "_outcome"))

    def test_22_concurrent_clicks_allow_exactly_one_picker_and_outcome(self):
        _, _, event = wire_source()
        event.arm_once(positive_transition())
        worker_count = 16
        barrier = threading.Barrier(worker_count)

        def invoke():
            barrier.wait()
            return event()

        with (
            mock.patch.object(
                mokosh_gui.filedialog,
                "askopenfilename",
                return_value=SELECTED_PATH,
            ) as picker,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            ThreadPoolExecutor(max_workers=worker_count) as pool,
        ):
            results = list(pool.map(lambda _: invoke(), range(worker_count)))
        successes = [result for result in results if result is not None]
        self.assertEqual(len(successes), 1)
        self.assertEqual(picker.call_count, 1)

    def test_23_three_step_positive_flow_arms_only_the_next_action(self):
        request_widgets, transition_widgets, source_widgets = wire_three_step_flow()
        _, request_button, _ = request_widgets
        _, transition_button, _ = transition_widgets
        _, source_button, source_event = source_widgets
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(mokosh_gui.filedialog, "askopenfilename") as picker,
        ):
            request_button.invoke()
            self.assertEqual(transition_button.options["state"], mokosh_gui.tk.NORMAL)
            self.assertEqual(source_button.options["state"], mokosh_gui.tk.DISABLED)
            transition_button.invoke()
        picker.assert_not_called()
        self.assertEqual(source_button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertTrue(source_event.retains_transition_outcome)

    def test_24_first_preserve_keeps_both_later_actions_locked(self):
        request_widgets, transition_widgets, source_widgets = wire_three_step_flow()
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            request_widgets[1].invoke()
        self.assertEqual(transition_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
        self.assertEqual(source_widgets[1].options["state"], mokosh_gui.tk.DISABLED)

    def test_25_second_preserve_keeps_source_action_locked(self):
        request_widgets, transition_widgets, source_widgets = wire_three_step_flow()
        with (
            mock.patch.object(
                mokosh_gui.messagebox, "askyesno", side_effect=(True, False)
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            request_widgets[1].invoke()
            transition_widgets[1].invoke()
        self.assertEqual(source_widgets[1].options["state"], mokosh_gui.tk.DISABLED)
        self.assertFalse(source_widgets[2].retains_transition_outcome)


class FakeRoot:
    def __init__(self):
        self.geometry_value = None
        self.title_value = None
        self.mainloop_calls = 0

    def title(self, value):
        self.title_value = value

    def geometry(self, value):
        self.geometry_value = value

    def mainloop(self):
        self.mainloop_calls += 1


class RecoverySourceSelectionMainGUIVisualTests(unittest.TestCase):
    def test_26_both_locales_and_routes_build_canonical_bounded_reports(self):
        for locale in visual.RECOVERY_SOURCE_SELECTION_MAIN_GUI_LOCALES:
            for route in visual.RecoverySourceSelectionMainGUIVisualRoute:
                with self.subTest(locale=locale, route=route.value):
                    report = visual.build_recovery_source_selection_main_gui_visual_report(
                        locale, route, pass_observations()
                    )
                    encoded = visual.recovery_source_selection_main_gui_visual_report_json(
                        report
                    )
                    payload = json.loads(encoded)
                    selecting = route is visual.RecoverySourceSelectionMainGUIVisualRoute.SELECT
                    self.assertEqual(payload["source_selection_performed"], selecting)
                    self.assertEqual(payload["source_path_metadata_received"], selecting)
                    self.assertEqual(payload["preserved_and_stopped"], not selecting)
                    self.assertTrue(payload["native_source_picker_invoked"])
                    self.assertTrue(
                        payload["native_picker_filesystem_metadata_access_possible"]
                    )
                    self.assertFalse(payload["application_source_open_read_performed"])
                    self.assertFalse(payload["whole_process_no_filesystem_access_claimed"])
                    self.assertNotIn(SELECTED_PATH, encoded)

    def test_27_invalid_locale_route_and_observation_types_are_rejected(self):
        for locale in ("bg", "en", "BG-bg", "bg-BG ", None, True):
            with self.subTest(locale=locale):
                with self.assertRaises(
                    visual.RecoverySourceSelectionMainGUIVisualHarnessError
                ):
                    visual.build_recovery_source_selection_main_gui_visual_report(
                        locale,
                        visual.RecoverySourceSelectionMainGUIVisualRoute.CANCEL,
                        pass_observations(),
                    )
        with self.assertRaises(visual.RecoverySourceSelectionMainGUIVisualHarnessError):
            visual.build_recovery_source_selection_main_gui_visual_report(
                "en-GB", "cancel", pass_observations()
            )
        passed = visual.RecoverySourceSelectionMainGUIVisualObservation.PASS
        with self.assertRaises(visual.RecoverySourceSelectionMainGUIVisualHarnessError):
            visual.RecoverySourceSelectionMainGUIVisualObservations(
                "pass", passed, passed, passed, passed, passed, passed, passed
            )

    def test_28_forged_authority_and_claim_fields_are_rejected(self):
        report = visual.build_recovery_source_selection_main_gui_visual_report(
            "en-GB",
            visual.RecoverySourceSelectionMainGUIVisualRoute.CANCEL,
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
                    visual.RecoverySourceSelectionMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: True})
        for name in (
            "native_source_picker_invoked",
            "native_picker_filesystem_metadata_access_possible",
            "runtime_directory_preparation_performed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoverySourceSelectionMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: False})

    def test_29_route_coupled_claims_reject_inconsistent_values(self):
        report = visual.build_recovery_source_selection_main_gui_visual_report(
            "en-GB",
            visual.RecoverySourceSelectionMainGUIVisualRoute.SELECT,
            pass_observations(),
        )
        for changes in (
            {"source_selection_performed": False},
            {"source_path_metadata_received": False},
            {"preserved_and_stopped": True},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(
                    visual.RecoverySourceSelectionMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **changes)

    def test_30_report_schema_excludes_paths_secrets_and_capabilities(self):
        names = {
            field.name
            for field in dataclasses.fields(
                visual.RecoverySourceSelectionMainGUIVisualReport
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


class RecoverySourceSelectionMainGUIStaticTests(unittest.TestCase):
    def test_31_source_selection_contract_is_conditional_not_top_level(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        top_imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn("mokosh_vault_recovery_source_selection", top_imports)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_recovery_source_selection_contract"
        )
        imports = [node for node in ast.walk(helper) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, "mokosh_vault_recovery_source_selection")

    def test_32_fresh_normal_import_does_not_load_source_selection(self):
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
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.stdout.strip(), "False")

    def test_33_source_event_has_no_source_open_operation_or_dynamic_calls(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        event_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "_RecoverySourceSelectionGUIEvent"
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
                    "prepare_recovery_review_session",
                    "prepare_main_gui_recovery_review_binding",
                    "show_prepared_recovery_review",
                    "publish_recovery_candidate",
                }
            )
        )

    def test_34_visual_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        path = (
            PROJECT_ROOT
            / "mokosh_vault_recovery_source_selection_main_gui_visual_harness.py"
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

    def test_35_visual_launcher_uses_normal_main_without_secret_or_operation_tokens(self):
        source = (
            PROJECT_ROOT
            / "run_main_gui_recovery_source_selection_visual_harness.py"
        ).read_text(encoding="utf-8")
        self.assertIn("mokosh_gui.main()", source)
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
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_36_safety_mode_and_critical_core_files_remain_exact(self):
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
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
            "mokosh_vault_recovery_entry_transition.py": "8558efa6b8b27c28969e55bc179e3da97796b14f3a06c1b6d8cee08cf91ed697",
            "mokosh_vault_recovery_source_selection.py": "856143153b21cc6c3ff81e908cbf875c0433492a79a023ee2ab3e4b793024600",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
