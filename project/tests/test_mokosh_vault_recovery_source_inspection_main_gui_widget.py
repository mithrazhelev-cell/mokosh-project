import ast
import dataclasses
import hashlib
import inspect
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import mokosh_gui
import mokosh_vault_recovery_main_gui_visual_harness as old_harness
import mokosh_vault_recovery_source_inspection_main_gui_bridge as bridge
import mokosh_vault_recovery_source_inspection_main_gui_visual_harness as harness
import mokosh_vault_recovery_source_inspection_review_controller as controller
import mokosh_vault_recovery_source_inspection_review_window as review


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


def prepare_case(case_number=2):
    return harness.prepare_synthetic_main_gui_source_inspection_review_case(
        case_number
    )


def headless_outcome(
    parent,
    presentation,
    adapter,
    *,
    action="cancel_button",
):
    del parent
    prepared = review.prepare_recovery_source_inspection_review_window(
        presentation,
        adapter,
    )
    if action == "acknowledge":
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
    reasons = {
        "escape_key": review.RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY,
        "cancel_button": review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON,
        "window_close": review.RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE,
    }
    return prepared.cancel_once(reasons[action])


def complete_case(case):
    action = case.required_terminal_action.value
    with mock.patch.object(
        controller,
        "_show_recovery_source_inspection_review_window",
        side_effect=lambda *args: headless_outcome(*args, action=action),
    ):
        return case.binding.show_once(object())


def pass_observations():
    value = harness.MainGUISourceInspectionVisualHarnessObservation.PASS
    return harness.MainGUISourceInspectionReviewObservations(
        value, value, value, value, value, value
    )


def wire(case):
    with (
        mock.patch.object(mokosh_gui.tk, "Label", FakeWidget),
        mock.patch.object(mokosh_gui.tk, "Button", FakeWidget),
    ):
        return mokosh_gui._wire_prepared_recovery_source_inspection_review_widget(
            object(),
            object(),
            case.binding,
        )


def fake_main(*args, **kwargs):
    root = FakeRoot()
    created = []

    def factory(parent=None, **options):
        widget = FakeWidget(parent, **options)
        created.append(widget)
        return widget

    previous_lang = mokosh_gui.current_lang
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(mokosh_gui.tk, "Tk", return_value=root))
        for name in (
            "Label",
            "Frame",
            "Canvas",
            "Scrollbar",
            "Button",
            "Radiobutton",
            "Entry",
            "StringVar",
        ):
            stack.enter_context(mock.patch.object(mokosh_gui.tk, name, side_effect=factory))
        ensure = stack.enter_context(
            mock.patch.object(mokosh_gui, "ensure_private_data_dir")
        )
        try:
            mokosh_gui.main(*args, **kwargs)
        finally:
            mokosh_gui.current_lang = previous_lang
    return root, created, ensure


class SourceInspectionMainGUIWidgetEventTests(unittest.TestCase):
    def test_01_localized_banner_and_button_are_exact(self):
        for case_number, expected_button, expected_banner in (
            (1, "Отвори подготвения source-inspection преглед", "не разрешава"),
            (2, "Open prepared source-inspection review", "neither authorises"),
        ):
            with self.subTest(case_number=case_number):
                banner, button, event = wire(prepare_case(case_number))
                self.assertIn(expected_banner, banner.options["text"])
                self.assertEqual(button.options["text"], expected_button)
                self.assertIs(button.options["command"], event)

    def test_02_invalid_or_nonfresh_binding_is_rejected(self):
        for invalid in (None, {}, True, object()):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TypeError):
                    mokosh_gui._PreparedRecoverySourceInspectionReviewGUIEvent(
                        object(), invalid
                    )
        case = prepare_case()
        complete_case(case)
        with self.assertRaises(TypeError):
            mokosh_gui._PreparedRecoverySourceInspectionReviewGUIEvent(
                object(), case.binding
            )

    def test_03_button_can_be_attached_only_once(self):
        case = prepare_case()
        event = mokosh_gui._PreparedRecoverySourceInspectionReviewGUIEvent(
            object(), case.binding
        )
        event.attach_button(FakeWidget())
        with self.assertRaises(TypeError):
            event.attach_button(FakeWidget())

    def test_04_cancel_disables_before_display_and_completes_once(self):
        case = prepare_case()
        _, button, event = wire(case)
        observed = []

        def display(parent, binding):
            observed.append(button.options["state"])
            return binding.show_once(parent)

        with (
            mock.patch.object(
                controller,
                "_show_recovery_source_inspection_review_window",
                side_effect=headless_outcome,
            ),
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                side_effect=display,
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showinfo") as info,
        ):
            outcome = button.invoke()
            replay = button.invoke()
        self.assertIsNone(replay)
        self.assertEqual(observed, [mokosh_gui.tk.DISABLED])
        self.assertEqual(show.call_count, 1)
        self.assertEqual(info.call_count, 1)
        self.assertIs(
            outcome.decision,
            review.RecoverySourceInspectionReviewWindowDecision.CANCELLED,
        )
        self.assertIs(
            event.current_state,
            mokosh_gui._RecoverySourceInspectionReviewGUIEventState.COMPLETED,
        )
        self.assertFalse(event.retains_binding)

    def test_05_acknowledge_returns_only_bounded_no_authority_outcome(self):
        case = prepare_case(4)
        _, button, event = wire(case)
        with (
            mock.patch.object(
                controller,
                "_show_recovery_source_inspection_review_window",
                side_effect=lambda *args: headless_outcome(
                    *args, action="acknowledge"
                ),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            outcome = button.invoke()
        self.assertIs(
            outcome.decision,
            review.RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED,
        )
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)
        self.assertEqual(event.current_state.value, "completed")

    def test_06_bridge_failure_is_generic_consumed_and_not_retried(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                side_effect=bridge.VaultRecoverySourceInspectionMainGUIBridgeDisplayError(
                    "sensitive detail"
                ),
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
            self.assertIsNone(button.invoke())
        self.assertEqual(show.call_count, 1)
        self.assertEqual(error.call_count, 1)
        self.assertNotIn("sensitive detail", error.call_args.args[1])
        self.assertEqual(event.current_state.value, "failed")
        self.assertFalse(event.retains_binding)

    def test_07_unexpected_exception_fails_closed_with_generic_message(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                side_effect=RuntimeError("runtime secret"),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
        self.assertNotIn("runtime secret", error.call_args.args[1])
        self.assertEqual(event.current_state.value, "failed")

    def test_08_button_disable_failure_prevents_bridge_call(self):
        case = prepare_case()
        event = mokosh_gui._PreparedRecoverySourceInspectionReviewGUIEvent(
            object(), case.binding
        )
        button = mock.Mock()
        button.config.side_effect = RuntimeError("destroyed widget detail")
        event.attach_button(button)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(event())
        show.assert_not_called()
        self.assertNotIn("destroyed widget detail", error.call_args.args[1])
        self.assertFalse(event.retains_binding)

    def test_09_keyboard_interrupt_marks_failed_and_propagates(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            with self.assertRaises(KeyboardInterrupt):
                button.invoke()
        error.assert_not_called()
        self.assertEqual(event.current_state.value, "failed")
        self.assertFalse(event.retains_binding)

    def test_10_concurrent_invocation_allows_one_display(self):
        case = prepare_case()
        _, button, event = wire(case)
        entered = threading.Event()
        release = threading.Event()

        def display(parent, binding):
            entered.set()
            self.assertTrue(release.wait(timeout=2))
            return binding.show_once(parent)

        with (
            mock.patch.object(
                controller,
                "_show_recovery_source_inspection_review_window",
                side_effect=headless_outcome,
            ),
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                side_effect=display,
            ) as show,
            mock.patch.object(mokosh_gui.messagebox, "showinfo"),
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(button.invoke)
                self.assertTrue(entered.wait(timeout=2))
                second = pool.submit(button.invoke)
                self.assertIsNone(second.result(timeout=2))
                release.set()
                self.assertIsNotNone(first.result(timeout=2))
        self.assertEqual(show.call_count, 1)

    def test_11_foreign_seam_result_is_rejected(self):
        case = prepare_case()
        _, button, event = wire(case)
        with (
            mock.patch.object(
                mokosh_gui,
                "show_prepared_recovery_source_inspection_review",
                return_value=object(),
            ),
            mock.patch.object(mokosh_gui.messagebox, "showerror") as error,
        ):
            self.assertIsNone(button.invoke())
        self.assertEqual(error.call_count, 1)
        self.assertEqual(event.current_state.value, "failed")

    def test_12_event_retains_no_source_secret_or_authority_slot(self):
        slots = set(mokosh_gui._PreparedRecoverySourceInspectionReviewGUIEvent.__slots__)
        self.assertTrue(
            slots.isdisjoint(
                {
                    "source",
                    "path",
                    "password",
                    "secret",
                    "callback",
                    "executor",
                    "operation_capability",
                    "outcome",
                }
            )
        )


class SourceInspectionMainGUIModeTests(unittest.TestCase):
    def test_13_main_signature_preserves_old_positional_and_adds_keyword_only(self):
        signature = inspect.signature(mokosh_gui.main)
        self.assertEqual(
            list(signature.parameters),
            [
                "prepared_recovery_review_binding",
                "prepared_recovery_source_inspection_review_binding",
            ],
        )
        self.assertIs(
            signature.parameters[
                "prepared_recovery_source_inspection_review_binding"
            ].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertIsNone(
            signature.parameters["prepared_recovery_review_binding"].default
        )

    def test_14_mutually_exclusive_bindings_fail_before_runtime_or_tk(self):
        old = old_harness.prepare_synthetic_main_gui_recovery_review_case(
            "absent", "bg-BG"
        ).binding
        new = prepare_case().binding
        with (
            mock.patch.object(mokosh_gui, "ensure_private_data_dir") as ensure,
            mock.patch.object(mokosh_gui.tk, "Tk") as tk_root,
        ):
            with self.assertRaises(TypeError):
                mokosh_gui.main(
                    old,
                    prepared_recovery_source_inspection_review_binding=new,
                )
        ensure.assert_not_called()
        tk_root.assert_not_called()

    def test_15_invalid_new_binding_fails_before_runtime_or_tk(self):
        with (
            mock.patch.object(mokosh_gui, "ensure_private_data_dir") as ensure,
            mock.patch.object(mokosh_gui.tk, "Tk") as tk_root,
        ):
            with self.assertRaises(TypeError):
                mokosh_gui.main(
                    prepared_recovery_source_inspection_review_binding=object()
                )
        ensure.assert_not_called()
        tk_root.assert_not_called()

    def test_16_normal_main_builds_no_conditional_source_review(self):
        with mock.patch.object(
            mokosh_gui,
            "show_prepared_recovery_source_inspection_review",
        ) as show:
            root, created, ensure = fake_main()
        self.assertEqual(root.geometry_value, "820x720")
        self.assertEqual(root.mainloop_calls, 1)
        ensure.assert_called_once_with()
        self.assertFalse(
            any(
                "source-inspection review" in str(item.options.get("text", ""))
                for item in created
            )
        )
        show.assert_not_called()

    def test_17_old_conditional_mode_remains_positional_and_isolated(self):
        old = old_harness.prepare_synthetic_main_gui_recovery_review_case(
            "absent", "bg-BG"
        )
        with mock.patch.object(
            mokosh_gui,
            "show_prepared_recovery_source_inspection_review",
        ) as show:
            root, created, _ = fake_main(old.binding)
        self.assertEqual(root.geometry_value, "820x560")
        self.assertTrue(
            any(
                item.options.get("text") == "Отвори подготвения преглед"
                for item in created
            )
        )
        show.assert_not_called()

    def test_18_new_conditional_mode_inherits_locale_and_geometry(self):
        case = prepare_case(2)
        root, created, _ = fake_main(
            prepared_recovery_source_inspection_review_binding=case.binding
        )
        self.assertEqual(root.geometry_value, "820x560")
        self.assertTrue(
            any(
                item.parent is None and item.options.get("value") == "en"
                for item in created
            )
        )
        self.assertTrue(
            any(
                item.options.get("text")
                == "Open prepared source-inspection review"
                for item in created
            )
        )

    def test_19_new_conditional_mode_omits_normal_recovery_chain(self):
        case = prepare_case(1)
        _, created, _ = fake_main(
            prepared_recovery_source_inspection_review_binding=case.binding
        )
        text = {item.options.get("text") for item in created}
        self.assertNotIn("Заяви преглед за възстановяване...", text)
        self.assertNotIn("Избери локален recovery record...", text)
        self.assertNotIn("Продължи заявката за възстановяване...", text)

    def test_20_new_conditional_mode_wires_once_without_auto_display(self):
        case = prepare_case()
        with mock.patch.object(
            mokosh_gui,
            "show_prepared_recovery_source_inspection_review",
        ) as show:
            _, created, _ = fake_main(
                prepared_recovery_source_inspection_review_binding=case.binding
            )
        buttons = [
            item
            for item in created
            if item.options.get("text")
            == "Open prepared source-inspection review"
        ]
        self.assertEqual(len(buttons), 1)
        self.assertIs(
            case.binding.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.READY,
        )
        show.assert_not_called()

    def test_21_all_unrelated_action_controls_are_disabled(self):
        case = prepare_case()
        _, created, _ = fake_main(
            prepared_recovery_source_inspection_review_binding=case.binding
        )
        review_button = next(
            item
            for item in created
            if item.options.get("text")
            == "Open prepared source-inspection review"
        )
        self.assertNotEqual(review_button.options.get("state"), mokosh_gui.tk.DISABLED)
        for label in (
            "EN",
            "BG",
            "Choose vault folder...",
            "Decrypt...",
            "LOGIN",
            "Encrypt...",
            "Clean originals...",
            "Contacts & Sharing",
            "Contact Encryption",
            "Sandbox",
        ):
            with self.subTest(label=label):
                control = next(
                    item for item in created if item.options.get("text") == label
                )
                self.assertEqual(control.options.get("state"), mokosh_gui.tk.DISABLED)
        eye_controls = [
            item for item in created if item.options.get("text") == "👁"
        ]
        secret_entries = [
            item for item in created if item.options.get("show") == "*"
        ]
        self.assertEqual(len(eye_controls), 2)
        self.assertEqual(len(secret_entries), 2)
        self.assertTrue(
            all(
                item.options.get("state") == mokosh_gui.tk.DISABLED
                for item in (*eye_controls, *secret_entries)
            )
        )

    def test_22_runtime_preparation_occurs_once_after_binding_validation(self):
        case = prepare_case()
        order = []
        root = FakeRoot()

        def ensure():
            order.append("runtime")

        def make_root():
            order.append("tk")
            return root

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(mokosh_gui, "ensure_private_data_dir", side_effect=ensure))
            stack.enter_context(mock.patch.object(mokosh_gui.tk, "Tk", side_effect=make_root))
            for name in ("Label", "Frame", "Button", "Radiobutton", "Entry", "StringVar"):
                stack.enter_context(mock.patch.object(mokosh_gui.tk, name, side_effect=FakeWidget))
            mokosh_gui.main(
                prepared_recovery_source_inspection_review_binding=case.binding
            )
        self.assertEqual(order, ["runtime", "tk"])

    def test_23_source_bridge_remains_lazy_at_module_import(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        top_imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn(
            "mokosh_vault_recovery_source_inspection_main_gui_bridge",
            top_imports,
        )
        loader = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_recovery_source_inspection_review_bridge_contract"
        )
        self.assertEqual(
            {
                node.module
                for node in ast.walk(loader)
                if isinstance(node, ast.ImportFrom)
            },
            {"mokosh_vault_recovery_source_inspection_main_gui_bridge"},
        )

    def test_24_module_entrypoint_still_calls_main_without_arguments(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        calls = [
            node
            for item in tree.body
            if isinstance(item, ast.If)
            for node in ast.walk(item)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "main"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, [])
        self.assertEqual(calls[0].keywords, [])


class SourceInspectionMainGUIHarnessTests(unittest.TestCase):
    def test_25_fixed_matrix_prepares_exact_fresh_bindings(self):
        self.assertEqual(
            harness.MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX,
            (
                ("bg-BG", 100, "escape_key"),
                ("en-GB", 125, "cancel_button"),
                ("bg-BG", 150, "window_close"),
                ("en-GB", 200, "acknowledge"),
            ),
        )
        for number in range(1, 5):
            case = prepare_case(number)
            self.assertIs(
                case.binding.current_state,
                bridge.RecoverySourceInspectionMainGUIBridgeState.READY,
            )
            self.assertTrue(case.synthetic_non_secret)
            self.assertFalse(case.true_vault_input_used)
            self.assertFalse(case.operation_capability_included)

    def test_26_invalid_case_numbers_are_rejected_exactly(self):
        for invalid in (0, 5, -1, True, None, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
                ):
                    harness.prepare_synthetic_main_gui_source_inspection_review_case(
                        invalid
                    )

    def test_27_completed_case_builds_canonical_bounded_report(self):
        case = prepare_case(4)
        outcome = complete_case(case)
        report = harness.build_main_gui_source_inspection_review_report(
            case, outcome, pass_observations()
        )
        first = harness.main_gui_source_inspection_review_report_json(report)
        self.assertEqual(first, harness.main_gui_source_inspection_review_report_json(report))
        payload = json.loads(first)
        self.assertEqual(payload["case_number"], 4)
        self.assertEqual(payload["locale"], "en-GB")
        self.assertEqual(payload["scale_percent"], 200)
        self.assertEqual(payload["terminal_action"], "acknowledge")
        self.assertTrue(payload["runtime_directory_preparation_performed"])
        self.assertFalse(payload["recovery_source_filesystem_access_performed"])
        self.assertFalse(payload["operation_authorized"])

    def test_28_fresh_foreign_or_wrong_action_cannot_build_report(self):
        fresh = prepare_case(1)
        completed = prepare_case(2)
        outcome = complete_case(completed)
        with self.assertRaises(
            harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
        ):
            harness.build_main_gui_source_inspection_review_report(
                fresh, outcome, pass_observations()
            )
        other = prepare_case(3)
        foreign = complete_case(other)
        with self.assertRaises(
            harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
        ):
            harness.build_main_gui_source_inspection_review_report(
                completed, foreign, pass_observations()
            )

    def test_29_observations_require_six_exact_enums(self):
        value = harness.MainGUISourceInspectionVisualHarnessObservation.PASS
        for index in range(6):
            items = [value] * 6
            items[index] = "pass"
            with self.subTest(index=index):
                with self.assertRaises(
                    harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
                ):
                    harness.MainGUISourceInspectionReviewObservations(*items)

    def test_30_false_authority_activation_and_runtime_claims_are_rejected(self):
        case = prepare_case(2)
        outcome = complete_case(case)
        report = harness.build_main_gui_source_inspection_review_report(
            case, outcome, pass_observations()
        )
        for name in (
            "normal_startup_activated",
            "true_vault_input_used",
            "operation_performed",
            "operation_authorized",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "automatic_gui_event_injection_used",
            "accessibility_conformance_claimed",
            "legal_conformity_claimed",
            "platform_certification_claimed",
            "human_understanding_proven",
            "secrets_retained",
            "source_material_retained",
            "source_path_metadata_retained",
            "callbacks_or_executors_retained",
        ):
            with self.subTest(name=name):
                with self.assertRaises(
                    harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
                ):
                    dataclasses.replace(report, **{name: True})
        with self.assertRaises(
            harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
        ):
            dataclasses.replace(report, runtime_directory_preparation_performed=False)
        with self.assertRaises(
            harness.VaultRecoverySourceInspectionMainGUIVisualHarnessError
        ):
            dataclasses.replace(
                report,
                decision=review.RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED,
            )

    def test_31_report_schema_excludes_sensitive_capability_and_whole_process_claims(self):
        names = {
            item.name
            for item in dataclasses.fields(
                harness.MainGUISourceInspectionReviewReport
            )
        }
        self.assertTrue(
            names.isdisjoint(
                {
                    "password",
                    "recovery_root",
                    "recovery_record",
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

    def test_32_json_is_bounded_and_contains_no_arbitrary_notes(self):
        case = prepare_case(1)
        outcome = complete_case(case)
        report = harness.build_main_gui_source_inspection_review_report(
            case, outcome, pass_observations()
        )
        encoded = harness.main_gui_source_inspection_review_report_json(report)
        self.assertLessEqual(
            len(encoded.encode("utf-8")),
            harness.MAIN_GUI_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN,
        )
        self.assertNotIn("notes", json.loads(encoded))


class SourceInspectionMainGUIStaticBoundaryTests(unittest.TestCase):
    def test_33_harness_core_has_no_gui_filesystem_network_process_or_logging_import(self):
        path = PROJECT_ROOT / "mokosh_vault_recovery_source_inspection_main_gui_visual_harness.py"
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

    def test_34_launcher_uses_only_synthetic_keyword_conditional_main(self):
        source = (
            PROJECT_ROOT
            / "run_main_gui_recovery_source_inspection_review_visual_harness.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "prepare_synthetic_main_gui_source_inspection_review_case",
            source,
        )
        self.assertIn(
            "prepared_recovery_source_inspection_review_binding=case.binding",
            source,
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

    def test_35_safety_mode_and_critical_non_gui_files_remain_exact(self):
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
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_source_inspection_review_controller.py": "330a6a79451a4fc8e4d982c7468b55faa3064afc08efe1c9eafa869db2b7fda2",
            "mokosh_vault_recovery_source_inspection_main_gui_bridge.py": "a031849c1a6da82b35df803de344c081068196c8ec8816685c78b1fdadd6de1a",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_36_exact_target_count_and_no_top_level_source_bridge_import(self):
        source = (PROJECT_ROOT / "tests/test_mokosh_vault_recovery_source_inspection_main_gui_widget.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        tests = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        ]
        self.assertEqual(len(tests), 36)
        gui_tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        self.assertNotIn(
            "mokosh_vault_recovery_source_inspection_main_gui_bridge",
            {
                node.module
                for node in gui_tree.body
                if isinstance(node, ast.ImportFrom) and node.module
            },
        )


if __name__ == "__main__":
    unittest.main()
