import ast
import dataclasses
import hashlib
import json
import pathlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import mokosh_gui
import mokosh_vault_recovery_entry_main_gui_visual_harness as visual
import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_main_gui_visual_harness as review_harness


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeWidget:
    def __init__(self, parent=None, **kwargs):
        self.parent = parent
        self.options = dict(kwargs)
        self.pack_options = None
        self.config_history = []
        self.bindings = {}

    def pack(self, **kwargs):
        self.pack_options = dict(kwargs)

    def config(self, **kwargs):
        self.options.update(kwargs)
        self.config_history.append(dict(kwargs))

    configure = config

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
        return None if command is None else command()

    def get(self):
        return self.options.get("value")


class FakeRoot(FakeWidget):
    def __init__(self):
        super().__init__()
        self.title_value = None
        self.geometry_value = None
        self.mainloop_calls = 0

    def title(self, value):
        self.title_value = value

    def geometry(self, value):
        self.geometry_value = value

    def mainloop(self):
        self.mainloop_calls += 1


def wire(locale="en"):
    previous = mokosh_gui.current_lang
    mokosh_gui.current_lang = locale
    try:
        with (
            mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
            mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
        ):
            return mokosh_gui._wire_recovery_entry_request_widget(
                object(), object()
            )
    finally:
        mokosh_gui.current_lang = previous


def pass_observations():
    passed = visual.RecoveryEntryMainGUIVisualObservation.PASS
    return visual.RecoveryEntryMainGUIVisualObservations(
        passed, passed, passed, passed, passed
    )


class RecoveryEntryMainGUIEventTests(unittest.TestCase):
    def test_exact_localized_banner_and_button_are_wired(self):
        for locale, button_text, banner_text in (
            ("bg", "Заяви преглед за възстановяване...", "само еднократно намерение"),
            ("en", "Request recovery review...", "only a one-time request"),
        ):
            with self.subTest(locale=locale):
                banner, button, event = wire(locale)
                self.assertEqual(button.options["text"], button_text)
                self.assertIn(banner_text, banner.options["text"])
                self.assertIs(button.options["command"], event)
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoveryEntryGUIEventState.READY,
                )

    def test_yes_records_only_bounded_request_without_authority(self):
        _, button, event = wire("bg")
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
        self.assertTrue(outcome.review_requested)
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.source_preparation_performed)
        self.assertFalse(outcome.review_displayed)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.COMPLETED)
        self.assertIn("Заявката е записана", info.call_args.args[1])

    def test_no_preserves_and_stops_without_transition(self):
        _, button, event = wire("en")
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
        self.assertFalse(outcome.automatic_transition)
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.COMPLETED)
        self.assertIn("Stopped safely", info.call_args.args[1])

    def test_button_is_disabled_before_request_preparation(self):
        _, button, event = wire()
        observed = []

        def prepare(locale_id):
            observed.append((button.options.get("state"), locale_id))
            return request.prepare_recovery_entry_request(locale_id)

        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "en"
        try:
            with (
                mock.patch.object(mokosh_gui, "prepare_recovery_entry_request", side_effect=prepare),
                mock.patch.object(mokosh_gui.messagebox, "askyesno", return_value=True),
                mock.patch.object(mokosh_gui.messagebox, "showinfo"),
            ):
                first = button.invoke()
                replay = button.invoke()
        finally:
            mokosh_gui.current_lang = previous
        self.assertTrue(first.review_requested)
        self.assertIsNone(replay)
        self.assertEqual(observed, [(mokosh_gui.tk.DISABLED, "en-GB")])

    def test_request_failure_is_generic_consumed_and_has_no_retry(self):
        _, button, event = wire()
        with (
            mock.patch.object(
                mokosh_gui,
                "prepare_recovery_entry_request",
                side_effect=request.VaultRecoveryEntryRequestSourceError("secret detail"),
            ) as prepare,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
            self.assertIsNone(button.invoke())
        self.assertEqual(prepare.call_count, 1)
        self.assertNotIn("secret detail", error.call_args.args[1])
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.FAILED)

    def test_unexpected_exception_is_generic_and_consumed(self):
        _, button, event = wire()
        with (
            mock.patch.object(
                mokosh_gui.messagebox,
                "askyesno",
                side_effect=RuntimeError("private runtime detail"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
        self.assertNotIn("private runtime detail", error.call_args.args[1])
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.FAILED)

    def test_button_disable_failure_prevents_request_preparation(self):
        event = mokosh_gui._RecoveryEntryGUIEvent(object())
        button = mock.Mock()
        button.config.side_effect = RuntimeError("destroyed widget")
        event.attach_button(button)
        with (
            mock.patch.object(mokosh_gui, "prepare_recovery_entry_request") as prepare,
            mock.patch.object(mokosh_gui.messagebox, "showerror"),
        ):
            self.assertIsNone(event())
        prepare.assert_not_called()
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.FAILED)

    def test_keyboard_interrupt_propagates_after_consumption(self):
        _, button, event = wire()
        with mock.patch.object(
            mokosh_gui.messagebox, "askyesno", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                button.invoke()
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.FAILED)
        self.assertIsNone(button.invoke())

    def test_concurrent_attempts_prepare_exactly_one_request(self):
        _, _, event = wire()
        button = event._button
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
                "prepare_recovery_entry_request",
                wraps=request.prepare_recovery_entry_request,
            ) as prepare,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(event)
                self.assertTrue(started.wait(timeout=2))
                second = pool.submit(event)
                self.assertIsNone(second.result(timeout=2))
                release.set()
                self.assertTrue(first.result(timeout=2).review_requested)
        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(button.options["state"], mokosh_gui.tk.DISABLED)

    def test_button_cannot_be_attached_twice(self):
        event = mokosh_gui._RecoveryEntryGUIEvent(object())
        event.attach_button(FakeWidget())
        with self.assertRaises(TypeError):
            event.attach_button(FakeWidget())

    def test_missing_button_fails_closed_without_preparation(self):
        event = mokosh_gui._RecoveryEntryGUIEvent(object())
        with mock.patch.object(mokosh_gui, "prepare_recovery_entry_request") as prepare:
            self.assertIsNone(event())
        prepare.assert_not_called()
        self.assertIs(event.current_state, mokosh_gui._RecoveryEntryGUIEventState.FAILED)


class RecoveryEntryMainGUIConstructionTests(unittest.TestCase):
    def _run_fake_main(self, binding=None):
        root = FakeRoot()
        created = []

        def factory(parent=None, **kwargs):
            widget = FakeWidget(parent, **kwargs)
            created.append(widget)
            return widget

        patches = (
            mock.patch.object(mokosh_gui.tk, "Tk", return_value=root),
            mock.patch.object(mokosh_gui.tk, "Label", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Frame", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Canvas", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Scrollbar", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Button", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Radiobutton", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "Entry", side_effect=factory),
            mock.patch.object(mokosh_gui.tk, "StringVar", side_effect=factory),
        )
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], patches[7], patches[8],
        ):
            mokosh_gui.main(binding)
        return root, created

    def test_normal_main_shows_entry_without_automatic_request(self):
        previous = mokosh_gui.current_lang
        mokosh_gui.current_lang = "en"
        try:
            with mock.patch.object(mokosh_gui, "prepare_recovery_entry_request") as prepare:
                root, created = self._run_fake_main()
        finally:
            mokosh_gui.current_lang = previous
        button = next(
            item for item in created if item.options.get("text") == "Request recovery review..."
        )
        self.assertEqual(root.geometry_value, "820x720")
        self.assertEqual(root.mainloop_calls, 1)
        self.assertNotEqual(button.options.get("state"), mokosh_gui.tk.DISABLED)
        prepare.assert_not_called()

    def test_conditional_prepared_review_main_excludes_normal_entry(self):
        case = review_harness.prepare_synthetic_main_gui_recovery_review_case(
            "absent", "bg-BG"
        )
        root, created = self._run_fake_main(case.binding)
        texts = {item.options.get("text") for item in created}
        self.assertEqual(root.geometry_value, "820x560")
        self.assertIn("Отвори подготвения преглед", texts)
        self.assertNotIn("Заяви преглед за възстановяване...", texts)

    def test_language_change_updates_entry_banner_and_button(self):
        widgets = {
            name: FakeWidget()
            for name in (
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
            )
        }
        lang = FakeWidget(value="bg")
        root = FakeRoot()
        previous = mokosh_gui.current_lang
        try:
            mokosh_gui.choose_language(lang, root, widgets)
        finally:
            mokosh_gui.current_lang = previous
        self.assertEqual(
            widgets["btn_recovery_entry"].options["text"],
            "Заяви преглед за възстановяване...",
        )
        self.assertIn(
            "Не се отваря трезор",
            widgets["recovery_entry_banner"].options["text"],
        )


class RecoveryEntryMainGUIVisualReportTests(unittest.TestCase):
    def test_both_locales_build_canonical_bounded_reports(self):
        for locale in visual.RECOVERY_ENTRY_MAIN_GUI_LOCALES:
            with self.subTest(locale=locale):
                report = visual.build_recovery_entry_main_gui_visual_report(
                    locale, pass_observations()
                )
                encoded = visual.recovery_entry_main_gui_visual_report_json(report)
                self.assertEqual(encoded, visual.recovery_entry_main_gui_visual_report_json(report))
                payload = json.loads(encoded)
                self.assertEqual(payload["locale"], locale)
                self.assertTrue(payload["human_observation_only"])
                self.assertFalse(payload["source_access_performed"])
                self.assertFalse(payload["operation_performed"])
                self.assertTrue(payload["runtime_directory_preparation_performed"])
                self.assertFalse(payload["recovery_source_filesystem_access_performed"])
                self.assertFalse(payload["recovery_source_filesystem_mutation_performed"])
                self.assertNotIn("filesystem_mutation_performed", payload)

    def test_invalid_locale_or_observation_type_is_rejected(self):
        for locale in ("bg", "en", "BG-bg", "bg-BG ", None, True):
            with self.subTest(locale=locale):
                with self.assertRaises(visual.RecoveryEntryMainGUIVisualHarnessError):
                    visual.build_recovery_entry_main_gui_visual_report(
                        locale, pass_observations()
                    )
        passed = visual.RecoveryEntryMainGUIVisualObservation.PASS
        with self.assertRaises(visual.RecoveryEntryMainGUIVisualHarnessError):
            visual.RecoveryEntryMainGUIVisualObservations(
                "pass", passed, passed, passed, passed
            )

    def test_false_authority_and_certification_claims_reject_forged_true(self):
        report = visual.build_recovery_entry_main_gui_visual_report(
            "en-GB", pass_observations()
        )
        for name in (
            "true_recovery_input_used",
            "source_access_authorized",
            "source_access_performed",
            "recovery_review_displayed",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "platform_certification_claimed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(visual.RecoveryEntryMainGUIVisualHarnessError):
                    dataclasses.replace(report, **{name: True})
        with self.assertRaises(visual.RecoveryEntryMainGUIVisualHarnessError):
            dataclasses.replace(
                report,
                runtime_directory_preparation_performed=False,
            )

    def test_report_schema_excludes_secrets_paths_and_capabilities(self):
        names = {item.name for item in dataclasses.fields(visual.RecoveryEntryMainGUIVisualReport)}
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


class RecoveryEntryMainGUIStaticBoundaryTests(unittest.TestCase):
    def test_main_gui_imports_only_entry_request_not_recovery_sources(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertIn("mokosh_vault_recovery_entry_request", imports)
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

    def test_entry_event_has_no_source_operation_or_dynamic_calls(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        entry_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "_RecoveryEntryGUIEvent"
        )
        calls = {
            node.func.id
            for node in ast.walk(entry_class)
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
                    "prepare_recovery_review_session",
                    "prepare_main_gui_recovery_review_binding",
                    "show_prepared_recovery_review",
                    "publish_recovery_candidate",
                }
            )
        )

    def test_visual_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_entry_main_gui_visual_harness.py").read_text(
                encoding="utf-8"
            )
        )
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
        source = (PROJECT_ROOT / "run_main_gui_recovery_entry_visual_harness.py").read_text(
            encoding="utf-8"
        )
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

    def test_safety_mode_and_critical_runtime_files_remain_unchanged(self):
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
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
