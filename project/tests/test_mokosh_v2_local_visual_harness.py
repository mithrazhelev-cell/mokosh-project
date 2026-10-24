import ast
import json
import stat
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import Mock, patch

import mokosh_v2_local_visual_harness as visual
import run_mokosh_v2_local_visual_harness as runner
from mokosh_profile_localization import ProfileLocale
from mokosh_v2_local_gui import LocalV2Mode


ROOT = Path(__file__).resolve().parents[1]


def passed():
    return visual.LocalV2GUIVisualObservations(
        **{
            field.name: visual.VisualObservation.PASS
            for field in fields(visual.LocalV2GUIVisualObservations)
        }
    )


class LocalV2GUIVisualHarnessTests(unittest.TestCase):
    def test_matrix_covers_locales_scales_and_both_modes(self):
        matrix = visual.LOCAL_V2_GUI_VISUAL_MATRIX
        self.assertEqual(len(matrix), 16)
        self.assertEqual(
            {(case.locale, case.scale_percent, case.mode) for case in matrix},
            {
                (locale, scale, mode)
                for locale in ("en", "bg")
                for scale in (100, 125, 150, 200)
                for mode in ("encrypt", "decrypt")
            },
        )
        self.assertEqual(
            [case.case_number for case in matrix],
            list(range(1, 17)),
        )

    def test_case_selection_is_exact_and_bounded(self):
        for number in range(1, 17):
            self.assertIs(
                visual.prepare_local_v2_gui_visual_case(number),
                visual.LOCAL_V2_GUI_VISUAL_MATRIX[number - 1],
            )
        for invalid in (0, 17, -1, True, None, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(visual.LocalV2GUIVisualHarnessError):
                    visual.prepare_local_v2_gui_visual_case(invalid)

    def test_report_is_canonical_bounded_and_contains_no_sensitive_fields(self):
        report = visual.build_local_v2_gui_visual_report(
            visual.prepare_local_v2_gui_visual_case(1),
            passed(),
        )
        first = visual.local_v2_gui_visual_report_json(report)
        second = visual.local_v2_gui_visual_report_json(report)
        self.assertEqual(first, second)
        self.assertLessEqual(
            len(first.encode("utf-8")),
            visual.LOCAL_V2_GUI_VISUAL_MAX_JSON_BYTES,
        )
        payload = json.loads(first)
        self.assertEqual(payload["version"], 1)
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["filesystem_mutation_performed"])
        self.assertFalse(payload["cryptographic_operation_performed"])
        for forbidden in (
            "path",
            "password",
            "secret_value",
            "hostname",
            "username",
        ):
            self.assertNotIn(forbidden, payload)

    def test_every_observation_is_required_to_pass(self):
        self.assertTrue(visual.local_v2_gui_visual_observations_pass(passed()))
        names = {field.name for field in fields(visual.LocalV2GUIVisualObservations)}
        self.assertIn("published_warning_says_do_not_retry", names)
        self.assertIn("historical_mok1_route_is_separate", names)
        self.assertIn("ambiguous_residue_is_preserved_and_blocking", names)
        for field in fields(visual.LocalV2GUIVisualObservations):
            changed = replace(
                passed(),
                **{field.name: visual.VisualObservation.NOT_CHECKED},
            )
            with self.subTest(field=field.name):
                self.assertFalse(
                    visual.local_v2_gui_visual_observations_pass(changed)
                )

    def test_invalid_report_inputs_fail_closed(self):
        with self.assertRaises(visual.LocalV2GUIVisualHarnessError):
            visual.build_local_v2_gui_visual_report(object(), passed())
        with self.assertRaises(visual.LocalV2GUIVisualHarnessError):
            visual.build_local_v2_gui_visual_report(
                visual.prepare_local_v2_gui_visual_case(1), object()
            )
        with self.assertRaises(visual.LocalV2GUIVisualHarnessError):
            visual.local_v2_gui_visual_report_json(object())

    def test_contract_core_is_stdlib_only_and_non_operational(self):
        source = (ROOT / "mokosh_v2_local_visual_harness.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {
                    "tkinter",
                    "os",
                    "pathlib",
                    "subprocess",
                    "socket",
                    "threading",
                }
            )
        )

    def test_runner_is_executable_synthetic_and_has_no_operation_route(self):
        path = ROOT / "run_mokosh_v2_local_visual_harness.py"
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        source = path.read_text(encoding="utf-8")
        for token in (
            "--case",
            "Synthetic non-secret local-V2 preview",
            "No profile, file, key, worker thread, or cryptographic operation",
            "SYNTHETIC STATES",
            '"cleanable"',
            '"blocked"',
            '"published"',
            '"not_v2"',
            "show_synthetic_chooser_feedback",
            "_activate_state",
            "_bind_state_keyboard_activation",
            '"<Return>"',
            '"<KP_Enter>"',
            "local_v2_cleanup_confirm",
            "return 130",
            "return 1",
            "return 0",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        for forbidden in (
            "SecureProfileSession",
            "LocalV2Service",
            "threading.Thread",
            "create_profile(",
            "load_profile(",
            "open(",
            "write_bytes",
            "unlink(",
            "filedialog",
            "command=lambda: None",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

        tree = ast.parse(source)
        chooser_routes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Lambda)
            and isinstance(node.body, ast.Call)
            and isinstance(node.body.func, ast.Attribute)
            and node.body.func.attr == "show_synthetic_chooser_feedback"
        ]
        self.assertEqual(len(chooser_routes), 1)
        self.assertEqual(len(chooser_routes[0].body.args), 1)
        self.assertIsInstance(chooser_routes[0].body.args[0], ast.Name)
        self.assertEqual(chooser_routes[0].body.args[0].id, "value")

    def test_state_button_activation_moves_focus_before_display_change(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        events = []
        button = Mock()
        button.focus_set.side_effect = lambda: events.append("focus")
        preview.state_buttons = {"not_v2": button}
        preview.show_state = Mock(
            side_effect=lambda state: events.append(("state", state))
        )

        preview._activate_state("not_v2")

        self.assertEqual(events, ["focus", ("state", "not_v2")])
        preview.show_state.assert_called_once_with("not_v2")

    def test_return_and_keypad_enter_invoke_state_button_once(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        bindings = {}

        class Button:
            def __init__(self):
                self.invocations = 0

            def bind(self, sequence, callback, **options):
                bindings[sequence] = (callback, options)

            def invoke(self):
                self.invocations += 1

        button = Button()
        preview._bind_state_keyboard_activation(button)

        self.assertEqual(set(bindings), {"<Return>", "<KP_Enter>"})
        for sequence, (callback, options) in bindings.items():
            with self.subTest(sequence=sequence):
                before = button.invocations
                self.assertEqual(callback(object()), "break")
                self.assertEqual(button.invocations, before + 1)
                self.assertEqual(options, {"add": "+"})

    def test_preview_state_machine_is_ui_only_and_fail_closed(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        preview.root = Mock()
        preview.root.focus_get.return_value = None
        preview.locale = ProfileLocale.ENGLISH
        preview.mode = LocalV2Mode.ENCRYPT
        preview.status = Mock()
        preview.synthetic_state = Mock()
        preview.state_buttons = {
            name: Mock()
            for name in (
                "ready",
                "working",
                "cleanable",
                "blocked",
                "published",
                "not_v2",
            )
        }
        preview.widgets = {
            name: Mock()
            for name in (
                "status",
                "choose_source",
                "choose_output",
                "run",
                "cancel",
                "cleanup",
            )
        }
        preview.show_state("published")
        displayed = preview.status.set.call_args.args[0]
        self.assertIn("Do not retry", displayed)
        preview.widgets["cleanup"].configure.assert_called_with(
            state=runner.tk.DISABLED
        )
        preview.widgets["run"].configure.assert_called_with(
            state=runner.tk.DISABLED
        )
        preview.synthetic_state.set.assert_called_with(
            "DISPLAYED / ПОКАЗАНО: PUBLISHED"
        )
        preview.state_buttons["published"].configure.assert_called_with(
            relief=runner.tk.SUNKEN
        )
        preview.state_buttons["ready"].configure.assert_called_with(
            relief=runner.tk.RAISED
        )

        preview.show_state("cleanable")
        preview.widgets["cleanup"].configure.assert_called_with(
            state=runner.tk.NORMAL
        )
        preview.widgets["run"].configure.assert_called_with(
            state=runner.tk.DISABLED
        )

        preview.show_state("blocked")
        preview.widgets["run"].configure.assert_called_with(
            state=runner.tk.DISABLED
        )

        preview.show_state("not_v2")
        preview.widgets["run"].configure.assert_called_with(
            state=runner.tk.NORMAL
        )
        preview.synthetic_state.set.assert_called_with(
            "DISPLAYED / ПОКАЗАНО: NOT V2"
        )
        with self.assertRaises(KeyError):
            preview.show_state("unknown")

    def test_working_and_cancelled_move_focus_before_disabling_actions(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        preview.locale = ProfileLocale.ENGLISH
        preview.mode = LocalV2Mode.ENCRYPT
        preview.status = Mock()
        preview.synthetic_state = Mock()
        preview.state_buttons = {
            name: Mock()
            for name in (
                "ready",
                "working",
                "cleanable",
                "blocked",
                "published",
                "not_v2",
            )
        }
        events = []
        focused = [None]

        def control(name):
            widget = Mock()
            widget.configure.side_effect = lambda **values: events.append(
                ("state", name, values["state"])
            ) if "state" in values else None
            widget.focus_set.side_effect = lambda: (
                events.append(("focus", name)),
                focused.__setitem__(0, widget),
            )
            return widget

        preview.widgets = {
            "status": Mock(),
            **{
                name: control(name)
                for name in (
                    "choose_source",
                    "choose_output",
                    "run",
                    "cancel",
                    "cleanup",
                )
            },
        }
        preview.root = Mock()
        preview.root.focus_get.side_effect = lambda: focused[0]

        focused[0] = preview.widgets["run"]
        preview.show_state("working")
        self.assertIs(focused[0], preview.widgets["cancel"])
        self.assertLess(
            events.index(("focus", "cancel")),
            events.index(("state", "run", runner.tk.DISABLED)),
        )

        events.clear()
        preview.show_state("cancelled")
        self.assertIs(focused[0], preview.widgets["run"])
        self.assertLess(
            events.index(("focus", "run")),
            events.index(("state", "cancel", runner.tk.DISABLED)),
        )

    def test_each_synthetic_chooser_has_distinct_explicit_no_io_feedback(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        preview.locale = ProfileLocale.ENGLISH
        preview.status = Mock()
        preview.widgets = {"status": Mock()}

        preview.show_synthetic_chooser_feedback("source")
        source_feedback = preview.status.set.call_args.args[0]
        preview.show_synthetic_chooser_feedback("output")
        output_feedback = preview.status.set.call_args.args[0]

        self.assertNotEqual(source_feedback, output_feedback)
        self.assertIn("no file is read", source_feedback.lower())
        self.assertIn("no file is created", output_feedback.lower())

        preview.locale = ProfileLocale.BULGARIAN
        preview.show_synthetic_chooser_feedback("source")
        source_feedback_bg = preview.status.set.call_args.args[0]
        preview.show_synthetic_chooser_feedback("output")
        output_feedback_bg = preview.status.set.call_args.args[0]

        self.assertNotEqual(source_feedback_bg, output_feedback_bg)
        self.assertIn("не се чете файл", source_feedback_bg)
        self.assertIn("не се създава файл", output_feedback_bg)

    def test_synthetic_cleanup_confirmation_defaults_to_preservation(self):
        preview = runner._SyntheticLocalV2Preview.__new__(
            runner._SyntheticLocalV2Preview
        )
        preview.root = object()
        preview.locale = ProfileLocale.ENGLISH
        preview.status = Mock()
        preview.widgets = {"cleanup": Mock()}
        with patch.object(runner, "ask_action_decision", return_value=False) as ask:
            preview.confirm_synthetic_cleanup()
        self.assertIn("exact released quarantine", ask.call_args.kwargs["text"])
        self.assertEqual(ask.call_args.kwargs["cancel_label"], "PRESERVE")
        preview.status.set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
