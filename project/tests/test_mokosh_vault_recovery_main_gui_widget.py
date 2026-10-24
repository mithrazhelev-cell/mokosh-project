import ast
import dataclasses
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import mokosh_gui
import mokosh_vault_recovery_review_controller as controller
import mokosh_vault_recovery_review_window as review
from mokosh_vault_recovery_main_gui_bridge import (
    RecoveryMainGUIBridgeState,
    VaultRecoveryMainGUIBridgeDisplayError,
)
import mokosh_vault_recovery_main_gui_visual_harness as harness


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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


def prepare_case(route="absent", locale="bg-BG"):
    return harness.prepare_synthetic_main_gui_recovery_review_case(route, locale)


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


def wire(case):
    with (
        mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
        mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
    ):
        return mokosh_gui._wire_prepared_recovery_review_widget(
            object(),
            object(),
            case.binding,
        )


def pass_observations():
    value = harness.MainGUIVisualHarnessObservation.PASS
    return harness.MainGUIRecoveryReviewObservations(value, value, value, value)


class RecoveryMainGUIWidgetEventTests(unittest.TestCase):
    def test_exact_localized_banner_and_button_are_wired_for_both_locales(self):
        for locale_id, expected, expected_banner in (
            (
                "bg-BG",
                "Отвори подготвения преглед",
                "няма да бъде извършена операция",
            ),
            (
                "en-GB",
                "Open prepared recovery review",
                "no operation will be performed",
            ),
        ):
            with self.subTest(locale=locale_id):
                case = prepare_case(locale=locale_id)
                banner, button, event = wire(case)
                self.assertIn(expected_banner, banner.options["text"].lower())
                self.assertEqual(button.options["text"], expected)
                self.assertIs(button.options["command"], event)
                self.assertIs(
                    event.current_state,
                    mokosh_gui._RecoveryReviewGUIEventState.READY,
                )
                self.assertTrue(event.retains_binding)

    def test_invalid_or_nonfresh_binding_is_rejected_before_widget_creation(self):
        for invalid in (None, {}, True, object()):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TypeError):
                    mokosh_gui._PreparedRecoveryReviewGUIEvent(object(), invalid)
        case = prepare_case()
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            case.binding.show_once(object())
        with self.assertRaises(TypeError):
            mokosh_gui._PreparedRecoveryReviewGUIEvent(object(), case.binding)

    def test_cancelled_event_disables_before_display_and_completes_once(self):
        case = prepare_case()
        _, button, event = wire(case)
        observed_states = []

        def display(parent, binding):
            observed_states.append(button.options["state"])
            return binding.show_once(parent)

        with (
            mock.patch.object(
                controller,
                "_show_recovery_review_window",
                side_effect=headless_outcome,
            ),
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_review",
                side_effect=display,
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = button.invoke()
            replay = button.invoke()
        self.assertIs(outcome.decision, review.RecoveryReviewWindowDecision.CANCELLED)
        self.assertIsNone(replay)
        self.assertEqual(observed_states, [mokosh_gui.tk.DISABLED])
        self.assertEqual(show.call_count, 1)
        info.assert_called_once()
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.COMPLETED)
        self.assertFalse(event.retains_binding)
        self.assertIs(case.binding.current_state, RecoveryMainGUIBridgeState.COMPLETED)

    def test_acknowledged_event_returns_only_bounded_outcome(self):
        case = prepare_case("exact", "en-GB")
        _, button, event = wire(case)

        def acknowledge(*args, **kwargs):
            return headless_outcome(*args, **kwargs, acknowledge=True)

        with (
            mock.patch.object(
                controller,
                "_show_recovery_review_window",
                side_effect=acknowledge,
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = button.invoke()
        self.assertIs(outcome.decision, review.RecoveryReviewWindowDecision.ACKNOWLEDGED)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.COMPLETED)

    def test_bridge_failure_is_generic_consumed_and_has_no_retry(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_review",
                side_effect=VaultRecoveryMainGUIBridgeDisplayError("secret detail"),
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
            self.assertIsNone(button.invoke())
        self.assertEqual(show.call_count, 1)
        self.assertEqual(error.call_count, 1)
        self.assertNotIn("secret detail", error.call_args.args[1])
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.FAILED)
        self.assertFalse(event.retains_binding)

    def test_unexpected_exception_fails_closed_with_generic_message(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_review",
                side_effect=RuntimeError("sensitive runtime text"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
        self.assertNotIn("sensitive runtime text", error.call_args.args[1])
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.FAILED)

    def test_button_disable_failure_consumes_event_before_bridge_call(self):
        case = prepare_case()
        event = mokosh_gui._PreparedRecoveryReviewGUIEvent(object(), case.binding)
        button = mock.Mock()
        button.config.side_effect = RuntimeError("destroyed widget detail")
        event.attach_button(button)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_review",
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
            self.assertIsNone(event())
        show.assert_not_called()
        self.assertEqual(error.call_count, 1)
        self.assertNotIn("destroyed widget detail", error.call_args.args[1])
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.FAILED)
        self.assertFalse(event.retains_binding)

    def test_keyboard_interrupt_propagates_after_event_consumption(self):
        case = prepare_case()
        _, button, event = wire(case)
        with mock.patch.object(
            mokosh_gui,
            "show_prepared_recovery_review",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                button.invoke()
        self.assertIs(event.current_state, mokosh_gui._RecoveryReviewGUIEventState.FAILED)
        self.assertFalse(event.retains_binding)
        self.assertIsNone(button.invoke())

    def test_concurrent_event_attempts_call_the_bridge_exactly_once(self):
        case = prepare_case()
        _, button, event = wire(case)
        started = threading.Event()
        release = threading.Event()

        def display(parent, binding):
            del parent, binding
            started.set()
            release.wait(timeout=2)
            return object()

        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_review",
                side_effect=display,
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(event)
                self.assertTrue(started.wait(timeout=2))
                second = pool.submit(event)
                self.assertIsNone(second.result(timeout=2))
                release.set()
                self.assertIsNotNone(first.result(timeout=2))
        self.assertEqual(show.call_count, 1)

    def test_button_cannot_be_attached_twice(self):
        case = prepare_case()
        event = mokosh_gui._PreparedRecoveryReviewGUIEvent(object(), case.binding)
        event.attach_button(FakeWidget())
        with self.assertRaises(TypeError):
            event.attach_button(FakeWidget())

    def test_normal_main_builds_no_prepared_review_widget_or_automatic_review(self):
        root = FakeRoot()
        created = []

        def factory(parent=None, **kwargs):
            widget = FakeWidget(parent, **kwargs)
            created.append(widget)
            return widget

        previous_lang = mokosh_gui.current_lang
        mokosh_gui.current_lang = "en"
        try:
            with (
                mock.patch.object(mokosh_gui.tk, "Tk", return_value=root),
                mock.patch.object(mokosh_gui.tk, "Label", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Frame", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Canvas", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Scrollbar", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Button", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Radiobutton", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Entry", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "StringVar", side_effect=factory),
                mock.patch.object(
                    mokosh_gui,
                    "show_prepared_recovery_review",
                ) as show,
            ):
                mokosh_gui.main()
        finally:
            mokosh_gui.current_lang = previous_lang
        self.assertEqual(root.geometry_value, "820x720")
        self.assertEqual(root.mainloop_calls, 1)
        self.assertFalse(
            any(
                widget.options.get("text")
                in {
                    "Open prepared recovery review",
                    "Отвори подготвения преглед",
                }
                for widget in created
            )
        )
        self.assertTrue(
            any(
                widget.options.get("text") == "Request recovery review..."
                for widget in created
            )
        )
        show.assert_not_called()

    def test_conditional_main_is_visible_but_does_not_auto_display(self):
        case = prepare_case(locale="bg-BG")
        root = FakeRoot()
        created = []

        def factory(parent=None, **kwargs):
            widget = FakeWidget(parent, **kwargs)
            created.append(widget)
            return widget

        previous_lang = mokosh_gui.current_lang
        try:
            with (
                mock.patch.object(mokosh_gui.tk, "Tk", return_value=root),
                mock.patch.object(mokosh_gui.tk, "Label", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Frame", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Canvas", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Scrollbar", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Button", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Radiobutton", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "Entry", side_effect=factory),
                mock.patch.object(mokosh_gui.tk, "StringVar", side_effect=factory),
                mock.patch.object(
                    mokosh_gui,
                    "show_prepared_recovery_review",
                ) as show,
            ):
                mokosh_gui.main(case.binding)
        finally:
            mokosh_gui.current_lang = previous_lang
        review_button = next(
            widget
            for widget in created
            if widget.options.get("text") == "Отвори подготвения преглед"
        )
        decrypt_button = next(
            widget
            for widget in created
            if widget.options.get("text") == "Декриптиране..."
        )
        self.assertEqual(root.geometry_value, "820x560")
        self.assertEqual(root.mainloop_calls, 1)
        self.assertNotEqual(review_button.options.get("state"), mokosh_gui.tk.DISABLED)
        self.assertEqual(decrypt_button.options.get("state"), mokosh_gui.tk.DISABLED)
        self.assertIs(case.binding.current_state, RecoveryMainGUIBridgeState.READY)
        show.assert_not_called()


class RecoveryMainGUIVisualHarnessTests(unittest.TestCase):
    def test_every_route_and_locale_prepares_exact_fresh_binding(self):
        for route_id in harness.MAIN_GUI_VISUAL_HARNESS_ROUTES:
            for locale_id in harness.MAIN_GUI_VISUAL_HARNESS_LOCALES:
                with self.subTest(route=route_id, locale=locale_id):
                    case = prepare_case(route_id, locale_id)
                    self.assertEqual(case.route.value, route_id)
                    self.assertEqual(case.locale.value, locale_id)
                    self.assertIs(case.binding.current_state, RecoveryMainGUIBridgeState.READY)
                    self.assertTrue(case.synthetic_non_secret)
                    self.assertFalse(case.true_vault_input_used)
                    self.assertFalse(case.operation_capability_included)

    def test_invalid_route_and_locale_are_rejected_exactly(self):
        for route_id, locale_id in (
            ("ABSENT", "bg-BG"),
            ("absent ", "bg-BG"),
            ("absent", "bg"),
            ("absent", "en"),
            (None, "bg-BG"),
            ("absent", True),
        ):
            with self.subTest(route=route_id, locale=locale_id):
                with self.assertRaises(harness.VaultRecoveryMainGUIVisualHarnessError):
                    harness.prepare_synthetic_main_gui_recovery_review_case(
                        route_id,
                        locale_id,
                    )

    def test_completed_case_builds_canonical_bounded_report(self):
        case = prepare_case("conflict", "en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            outcome = case.binding.show_once(object())
        report = harness.build_main_gui_recovery_review_report(
            case,
            outcome,
            pass_observations(),
        )
        first = harness.main_gui_recovery_review_report_json(report)
        self.assertEqual(first, harness.main_gui_recovery_review_report_json(report))
        payload = json.loads(first)
        self.assertEqual(payload["route"], "conflict")
        self.assertEqual(payload["locale"], "en-GB")
        self.assertTrue(payload["conditional_main_gui_activated"])
        self.assertFalse(payload["normal_startup_activated"])
        self.assertFalse(payload["operation_authorized"])
        self.assertFalse(payload["operation_performed"])
        self.assertTrue(payload["runtime_directory_preparation_performed"])
        self.assertFalse(payload["recovery_source_filesystem_access_performed"])
        self.assertFalse(payload["recovery_source_filesystem_mutation_performed"])
        self.assertNotIn("filesystem_mutation_performed", payload)
        self.assertEqual(len(payload["presentation_sha256"]), 64)

    def test_fresh_failed_or_mismatched_case_cannot_build_success_report(self):
        fresh = prepare_case()
        other = prepare_case("exact", "en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            other_outcome = other.binding.show_once(object())
        for case, outcome in ((fresh, other_outcome), (other, object())):
            with self.subTest(case=case.route.value):
                with self.assertRaises(harness.VaultRecoveryMainGUIVisualHarnessError):
                    harness.build_main_gui_recovery_review_report(
                        case,
                        outcome,
                        pass_observations(),
                    )

    def test_observations_accept_only_exact_enums(self):
        valid = harness.MainGUIVisualHarnessObservation.PASS
        for invalid in ("pass", True, 1, None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(harness.VaultRecoveryMainGUIVisualHarnessError):
                    harness.MainGUIRecoveryReviewObservations(
                        invalid,
                        valid,
                        valid,
                        valid,
                    )

    def test_false_authority_or_certification_claim_is_rejected(self):
        case = prepare_case()
        with mock.patch.object(
            controller,
            "_show_recovery_review_window",
            side_effect=headless_outcome,
        ):
            outcome = case.binding.show_once(object())
        report = harness.build_main_gui_recovery_review_report(
            case,
            outcome,
            pass_observations(),
        )
        for name in (
            "normal_startup_activated",
            "true_vault_input_used",
            "operation_performed",
            "operation_authorized",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "platform_certification_claimed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(harness.VaultRecoveryMainGUIVisualHarnessError):
                    dataclasses.replace(report, **{name: True})
        with self.assertRaises(harness.VaultRecoveryMainGUIVisualHarnessError):
            dataclasses.replace(
                report,
                runtime_directory_preparation_performed=False,
            )

    def test_report_schema_excludes_sensitive_or_capability_fields(self):
        names = {item.name for item in dataclasses.fields(harness.MainGUIRecoveryReviewReport)}
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
                    "operation_capability",
                    "notes",
                    "filesystem_access_performed",
                    "filesystem_mutation_performed",
                }
            )
        )


class RecoveryMainGUIWidgetStaticBoundaryTests(unittest.TestCase):
    def test_normal_startup_calls_main_without_binding(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        module_main_calls = [
            node
            for node in tree.body
            if isinstance(node, ast.If)
            for node in ast.walk(node)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "main"
        ]
        self.assertEqual(len(module_main_calls), 1)
        self.assertEqual(module_main_calls[0].args, [])
        self.assertEqual(module_main_calls[0].keywords, [])

    def test_main_preserves_old_binding_and_adds_one_keyword_only_binding(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        main_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        self.assertEqual(
            tuple(arg.arg for arg in main_node.args.args),
            ("prepared_recovery_review_binding",),
        )
        self.assertEqual(len(main_node.args.defaults), 1)
        self.assertIsNone(main_node.args.defaults[0].value)
        self.assertEqual(
            tuple(arg.arg for arg in main_node.args.kwonlyargs),
            ("prepared_recovery_source_inspection_review_binding",),
        )
        self.assertEqual(len(main_node.args.kw_defaults), 1)
        self.assertIsNone(main_node.args.kw_defaults[0].value)

    def test_main_gui_has_no_recovery_source_or_operation_import(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn("mokosh_vault_recovery_main_gui_bridge", imports)
        self.assertIn("mokosh_vault_recovery_entry_request", imports)
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
        self.assertTrue(
            imports.isdisjoint(
                {
                    "mokosh_vault_recovery",
                    "mokosh_vault_recovery_workflow",
                    "mokosh_vault_recovery_reconciliation",
                    "mokosh_vault_recovery_candidate",
                    "mokosh_vault_recovery_publish",
                    "mokosh_vault_storage",
                }
            )
        )

    def test_harness_core_has_no_filesystem_network_process_gui_or_logging_import(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_main_gui_visual_harness.py").read_text(
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

    def test_visual_launcher_uses_only_synthetic_case_and_conditional_main(self):
        source = (PROJECT_ROOT / "run_main_gui_recovery_review_visual_harness.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("prepare_synthetic_main_gui_recovery_review_case", source)
        self.assertIn("mokosh_gui.main(case.binding)", source)
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
        }
        import hashlib

        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
