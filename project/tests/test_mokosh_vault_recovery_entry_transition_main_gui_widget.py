import ast
import dataclasses
import hashlib
import json
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
import mokosh_vault_recovery_entry_transition_main_gui_visual_harness as visual


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeWidget:
    def __init__(self, parent=None, **kwargs):
        self.parent = parent
        self.options = dict(kwargs)
        self.pack_calls = []
        self.value = kwargs.get("value")
        self.bindings = {}

    def config(self, **kwargs):
        self.options.update(kwargs)

    configure = config

    def pack(self, **kwargs):
        self.pack_calls.append(kwargs)

    def bind(self, sequence, callback, add=None):
        self.bindings[sequence] = (callback, add)

    def create_window(self, *_args, **_kwargs):
        return 1

    def bbox(self, _item):
        return (0, 0, 820, 1200)

    def itemconfigure(self, *_args, **_kwargs):
        return None

    def yview(self, *_args):
        return None

    def yview_scroll(self, *_args):
        return None

    def yview_moveto(self, *_args):
        return None

    def set(self, *_args):
        return None

    def after_idle(self, callback, *args):
        return callback(*args)

    def invoke(self):
        command = self.options.get("command")
        return command() if command is not None else None

    def get(self):
        return self.value

    def cget(self, name):
        return self.options.get(name, "")


class FakeRoot:
    def __init__(self):
        self.geometry_value = None
        self.title_value = None
        self.mainloop_calls = 0
        self.bindings = {}

    def title(self, value):
        self.title_value = value

    def geometry(self, value):
        self.geometry_value = value

    def mainloop(self):
        self.mainloop_calls += 1

    def bind(self, sequence, callback, add=None):
        self.bindings[sequence] = (callback, add)

    def after_idle(self, callback, *args):
        return callback(*args)


def positive_request(locale="en-GB"):
    prepared = request.prepare_recovery_entry_request(locale)
    return prepared.decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )


def preserved_request(locale="en-GB"):
    prepared = request.prepare_recovery_entry_request(locale)
    return prepared.decide_once(
        request.RecoveryEntryRequestDecision.PRESERVE_AND_STOP
    )


def wire_transition(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            return mokosh_gui._wire_recovery_entry_transition_widget(
                object(),
                object(),
                event,
            )
    finally:
        mokosh_gui.current_lang = previous


def wire_flow(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        transition_event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            request_widgets = mokosh_gui._wire_recovery_entry_request_widget(
                object(),
                object(),
                transition_event,
            )
            transition_widgets = (
                mokosh_gui._wire_recovery_entry_transition_widget(
                    object(),
                    object(),
                    transition_event,
                )
            )
        return request_widgets, transition_widgets
    finally:
        mokosh_gui.current_lang = previous


def pass_observations():
    passed = visual.RecoveryEntryTransitionMainGUIVisualObservation.PASS
    return visual.RecoveryEntryTransitionMainGUIVisualObservations(
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
        passed,
    )


class RecoveryEntryTransitionMainGUIEventTests(unittest.TestCase):
    def test_exact_localized_locked_banner_and_button_are_wired(self):
        for locale, button_text, banner_text in (
            ("bg", "Продължи заявката за възстановяване...", "бъдещ избор"),
            ("en", "Continue recovery request...", "future source-selection"),
        ):
            with self.subTest(locale=locale):
                banner, button, event = wire_transition(locale)
                self.assertEqual(button.options["text"], button_text)
                self.assertIn(banner_text, banner.options["text"])
                self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
                self.assertIs(button.options["command"], event)
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoveryEntryTransitionGUIEventState.LOCKED,
                )

    def test_positive_request_arms_only_the_separate_button(self):
        _, button, event = wire_transition()
        outcome = positive_request()
        with mock.patch.object(
            mokosh_gui,
            "prepare_recovery_entry_transition",
        ) as prepare:
            self.assertTrue(event.arm_once(outcome))
        prepare.assert_not_called()
        self.assertEqual(button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertTrue(event.retains_entry_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.READY,
        )

    def test_preserved_request_cannot_arm_and_does_not_consume_lock(self):
        _, button, event = wire_transition()
        with self.assertRaises(TypeError):
            event.arm_once(preserved_request())
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertFalse(event.retains_entry_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.LOCKED,
        )
        self.assertTrue(event.arm_once(positive_request()))

    def test_non_exact_outcome_is_rejected_without_consumption(self):
        _, _, event = wire_transition()
        for value in (None, True, {}, object()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    event.arm_once(value)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.LOCKED,
        )

    def test_yes_records_only_future_intent_without_authority(self):
        _, button, event = wire_transition("bg")
        self.assertTrue(event.arm_once(positive_request("bg-BG")))
        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "bg"
        try:
            with (
                mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
                mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
            ):
                outcome = button.invoke()
        finally:
            mokosh_gui.current_lang = previous
        self.assertTrue(outcome.future_source_selection_requested)
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.source_selection_performed)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertFalse(outcome.review_session_prepared)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertFalse(outcome.filesystem_access_performed)
        self.assertFalse(outcome.automatic_transition)
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertIn("Намерението", info.call_args.args[1])
        self.assertFalse(event.retains_entry_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.COMPLETED,
        )

    def test_no_preserves_and_stops_without_source_selection(self):
        _, button, event = wire_transition("en")
        self.assertTrue(event.arm_once(positive_request()))
        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "en"
        try:
            with (
                mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
                mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
            ):
                outcome = button.invoke()
        finally:
            mokosh_gui.current_lang = previous
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertFalse(outcome.future_source_selection_requested)
        self.assertFalse(outcome.automatic_transition)
        self.assertIn("Stopped safely", info.call_args.args[1])

    def test_second_button_disables_before_transition_preparation(self):
        _, button, event = wire_transition()
        self.assertTrue(event.arm_once(positive_request()))
        observed = []

        def prepare(outcome):
            observed.append((button.options.get("state"), outcome.review_requested))
            return transition.prepare_recovery_entry_transition(outcome)

        with (
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
                side_effect=prepare,
            ),
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            first = button.invoke()
            replay = button.invoke()
        self.assertTrue(first.future_source_selection_requested)
        self.assertIsNone(replay)
        self.assertEqual(observed, [(mokosh_gui.tk.DISABLED, True)])

    def test_forged_entry_outcome_is_revalidated_and_fails_generically(self):
        _, button, event = wire_transition()
        forged = positive_request()
        object.__setattr__(forged, "source_access_authorized", True)
        self.assertTrue(event.arm_once(forged))
        with mock.patch.object(mokosh_gui.messagebox, "showerror") as error:
            self.assertIsNone(button.invoke())
        self.assertNotIn("invalid", error.call_args.args[1].lower())
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.FAILED,
        )

    def test_transition_failure_is_generic_consumed_and_has_no_retry(self):
        _, button, event = wire_transition()
        self.assertTrue(event.arm_once(positive_request()))
        with (
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
                side_effect=transition.VaultRecoveryEntryTransitionSourceError(
                    "private detail"
                ),
            ) as prepare,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
            self.assertIsNone(button.invoke())
        self.assertEqual(prepare.call_count, 1)
        self.assertNotIn("private detail", error.call_args.args[1])
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.FAILED,
        )

    def test_button_disable_failure_prevents_transition_preparation(self):
        event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        button = mock.Mock()
        event.attach_button(button)
        self.assertTrue(event.arm_once(positive_request()))
        button.config.side_effect = RuntimeError("destroyed widget")
        with (
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
            ) as prepare,
            mock.patch.object(mokosh_gui.messagebox, "showerror"),
        ):
            self.assertIsNone(event())
        prepare.assert_not_called()
        self.assertFalse(event.retains_entry_outcome)

    def test_arm_button_failure_is_terminal_without_retaining_outcome(self):
        event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        button = mock.Mock()
        button.config.side_effect = RuntimeError("destroyed widget")
        event.attach_button(button)
        self.assertFalse(event.arm_once(positive_request()))
        self.assertFalse(event.retains_entry_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.FAILED,
        )

    def test_keyboard_interrupt_propagates_after_consumption(self):
        _, button, event = wire_transition()
        self.assertTrue(event.arm_once(positive_request()))
        with mock.patch.object(
            mokosh_gui.messagebox,
            "askyesno",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                button.invoke()
        self.assertFalse(event.retains_entry_outcome)
        self.assertIsNone(button.invoke())

    def test_concurrent_attempts_prepare_exactly_one_transition(self):
        _, _, event = wire_transition()
        button = event._button
        self.assertTrue(event.arm_once(positive_request()))
        started = threading.Event()
        release = threading.Event()

        def confirm(*args, **kwargs):
            del args, kwargs
            started.set()
            release.wait(timeout=2)
            return True

        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", side_effect=confirm),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
                wraps=transition.prepare_recovery_entry_transition,
            ) as prepare,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(event)
                self.assertTrue(started.wait(timeout=2))
                second = pool.submit(event)
                self.assertIsNone(second.result(timeout=2))
                release.set()
                self.assertTrue(
                    first.result(timeout=2).future_source_selection_requested
                )
        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_confirmation_and_result_remain_bound_to_entry_locale(self):
        _, button, event = wire_transition("en")
        self.assertTrue(event.arm_once(positive_request("en-GB")))
        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "bg"
        try:
            with (
                mock.patch.object(
                    mokosh_gui.messagebox,
                    "askyesno",
                    return_value=True,
                ) as confirm,
                mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
            ):
                outcome = button.invoke()
        finally:
            mokosh_gui.current_lang = previous
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertIn("future source-selection", confirm.call_args.args[1])
        self.assertIn("future source-selection intent", info.call_args.args[1])

    def test_button_cannot_be_attached_twice(self):
        event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        event.attach_button(FakeWidget())
        with self.assertRaises(TypeError):
            event.attach_button(FakeWidget())

    def test_missing_button_fails_closed(self):
        event = mokosh_gui._RecoveryEntryTransitionGUIEvent(object())
        self.assertFalse(event.arm_once(positive_request()))
        self.assertFalse(event.retains_entry_outcome)
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.FAILED,
        )


class RecoveryEntryTransitionMainGUIFlowTests(unittest.TestCase):
    def test_request_yes_only_arms_transition_without_preparing_it(self):
        (_, request_button, _), (_, transition_button, transition_event) = wire_flow()
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
            ) as prepare,
        ):
            request_outcome = request_button.invoke()
        self.assertTrue(request_outcome.review_requested)
        prepare.assert_not_called()
        self.assertEqual(transition_button.options["state"], mokosh_gui.tk.NORMAL)
        self.assertIs(
            transition_event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.READY,
        )

    def test_request_no_keeps_transition_locked(self):
        (_, request_button, _), (_, transition_button, transition_event) = wire_flow()
        with (
            mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=False),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            request_outcome = request_button.invoke()
        self.assertTrue(request_outcome.preserved_and_stopped)
        self.assertEqual(transition_button.options["state"], mokosh_gui.tk.DISABLED)
        self.assertIs(
            transition_event.current_state,
            mokosh_gui._RecoveryEntryTransitionGUIEventState.LOCKED,
        )

    def test_transition_event_requires_exact_internal_type(self):
        with self.assertRaises(TypeError):
            mokosh_gui._RecoveryEntryGUIEvent(object(), object())
        with self.assertRaises(TypeError):
            mokosh_gui._wire_recovery_entry_transition_widget(
                object(),
                object(),
                object(),
            )


class RecoveryEntryTransitionMainGUIConstructionTests(unittest.TestCase):
    def _run_fake_main(self, binding=None):
        root = FakeRoot()
        created = []

        def factory(parent=None, **kwargs):
            widget = FakeWidget(parent, **kwargs)
            created.append(widget)
            return widget

        with (
            mock.patch.object(mokosh_gui, "ensure_private_data_dir"),
            mock.patch.object(mokosh_gui.tk, "Tk", return_value=root),
            mock.patch.object(mokosh_gui.tk, "Label", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Frame", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Canvas", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Scrollbar", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Button", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Radiobutton", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Entry", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "StringVar", side_effect=factory),
        ):
            mokosh_gui.main(binding)
        return root, created

    def test_normal_main_shows_locked_transition_without_automatic_prepare(self):
        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "en"
        try:
            with mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_transition",
            ) as prepare:
                root, created = self._run_fake_main()
        finally:
            mokosh_gui.current_lang = previous
        transition_button = next(
            item
            for item in created
            if item.options.get("text") == "Continue recovery request..."
        )
        self.assertEqual(root.geometry_value, "820x720")
        self.assertEqual(root.mainloop_calls, 1)
        self.assertEqual(transition_button.options["state"], mokosh_gui.tk.DISABLED)
        prepare.assert_not_called()

    def test_conditional_prepared_review_excludes_both_entry_actions(self):
        import mokosh_vault_recovery_main_gui_visual_harness as review_harness

        case = review_harness.prepare_synthetic_main_gui_recovery_review_case(
            "absent",
            "bg-BG",
        )
        previous = mokosh_gui.current_lang
        try:
            _, created = self._run_fake_main(case.binding)
        finally:
            mokosh_gui.current_lang = previous
        texts = {item.options.get("text") for item in created}
        self.assertIn("Отвори подготвения преглед", texts)
        self.assertNotIn("Заяви преглед за възстановяване...", texts)
        self.assertNotIn("Продължи заявката за възстановяване...", texts)

    def test_language_change_updates_transition_banner_and_button(self):
        names = (
            "lang_label",
            "vault_title",
            "btn_choose_vault",
            "pwd_title",
            "nick_title",
            "btn_encrypt_main",
            "btn_decrypt_main",
            "btn_clean_main",
            "btn_bottom_contacts",
            "btn_bottom_contact_crypto",
            "btn_bottom_master",
            "safety_banner",
            "recovery_entry_banner",
            "btn_recovery_entry",
            "recovery_transition_banner",
            "btn_recovery_transition",
        )
        widgets = {name: FakeWidget() for name in names}
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(FakeWidget(value="bg"), FakeRoot(), widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertEqual(
            widgets["btn_recovery_transition"].options["text"],
            "Продължи заявката за възстановяване...",
        )
        self.assertIn(
            "не може да избере",
            widgets["recovery_transition_banner"].options["text"],
        )


class RecoveryEntryTransitionMainGUIVisualReportTests(unittest.TestCase):
    def test_both_locales_build_canonical_bounded_reports(self):
        for locale in visual.RECOVERY_ENTRY_TRANSITION_MAIN_GUI_LOCALES:
            with self.subTest(locale=locale):
                report = visual.build_recovery_entry_transition_main_gui_visual_report(
                    locale,
                    pass_observations(),
                )
                encoded = visual.recovery_entry_transition_main_gui_visual_report_json(
                    report
                )
                self.assertEqual(
                    encoded,
                    visual.recovery_entry_transition_main_gui_visual_report_json(
                        report
                    ),
                )
                payload = json.loads(encoded)
                self.assertEqual(payload["locale"], locale)
                self.assertTrue(payload["human_observation_only"])
                self.assertFalse(payload["source_selection_performed"])
                self.assertFalse(payload["operation_performed"])
                self.assertFalse(payload["automatic_transition_performed"])
                self.assertTrue(payload["runtime_directory_preparation_performed"])
                self.assertFalse(payload["recovery_source_filesystem_access_performed"])
                self.assertFalse(payload["recovery_source_filesystem_mutation_performed"])
                self.assertNotIn("filesystem_access_performed", payload)
                self.assertNotIn("filesystem_mutation_performed", payload)

    def test_invalid_locale_or_observation_type_is_rejected(self):
        for locale in ("bg", "en", "BG-bg", "bg-BG ", None, True):
            with self.subTest(locale=locale):
                with self.assertRaises(
                    visual.RecoveryEntryTransitionMainGUIVisualHarnessError
                ):
                    visual.build_recovery_entry_transition_main_gui_visual_report(
                        locale,
                        pass_observations(),
                    )
        passed = visual.RecoveryEntryTransitionMainGUIVisualObservation.PASS
        with self.assertRaises(
            visual.RecoveryEntryTransitionMainGUIVisualHarnessError
        ):
            visual.RecoveryEntryTransitionMainGUIVisualObservations(
                "pass",
                passed,
                passed,
                passed,
                passed,
                passed,
                passed,
            )

    def test_false_authority_and_certification_claims_reject_forged_true(self):
        report = visual.build_recovery_entry_transition_main_gui_visual_report(
            "en-GB",
            pass_observations(),
        )
        names = (
            "true_recovery_input_used",
            "source_access_authorized",
            "source_selection_performed",
            "source_preparation_performed",
            "review_session_prepared",
            "review_displayed",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "automatic_transition_performed",
            "platform_certification_claimed",
        )
        for name in names:
            with self.subTest(name=name):
                with self.assertRaises(
                    visual.RecoveryEntryTransitionMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: True})
        with self.assertRaises(
            visual.RecoveryEntryTransitionMainGUIVisualHarnessError
        ):
            dataclasses.replace(
                report,
                runtime_directory_preparation_performed=False,
            )

    def test_report_schema_excludes_secrets_paths_and_capabilities(self):
        names = {
            item.name
            for item in dataclasses.fields(
                visual.RecoveryEntryTransitionMainGUIVisualReport
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


class RecoveryEntryTransitionMainGUIStaticBoundaryTests(unittest.TestCase):
    def test_main_gui_imports_transition_but_no_recovery_source_or_operation(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertIn("mokosh_vault_recovery_entry_transition", imports)
        self.assertTrue(
            imports.isdisjoint(
                {
                    "mokosh_vault_recovery",
                    "mokosh_vault_recovery_storage",
                    "mokosh_vault_recovery_reconciliation",
                    "mokosh_vault_recovery_workflow",
                    "mokosh_vault_recovery_candidate",
                    "mokosh_vault_recovery_publish",
                    "mokosh_vault_storage",
                }
            )
        )

    def test_transition_event_has_no_source_operation_or_dynamic_calls(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        event_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "_RecoveryEntryTransitionGUIEvent"
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

    def test_visual_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        path = (
            PROJECT_ROOT
            / "mokosh_vault_recovery_entry_transition_main_gui_visual_harness.py"
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

    def test_visual_launcher_uses_normal_main_without_source_tokens(self):
        source = (
            PROJECT_ROOT
            / "run_main_gui_recovery_entry_transition_visual_harness.py"
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

    def test_safety_mode_and_critical_core_files_remain_unchanged(self):
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
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
