import ast
import json
import stat
import unittest
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace

import mokosh_profile_main_gui_visual_harness as visual
import run_mokosh_profile_main_gui_visual_harness as runner
from mokosh_profile_session import ProfileLockReason, ProfileSessionState
from mokosh_profile_storage import ProfileState


ROOT = Path(__file__).resolve().parents[1]


def passed():
    return visual.ProfileMainGUIVisualObservations(
        **{
            field.name: visual.VisualObservation.PASS
            for field in fields(visual.ProfileMainGUIVisualObservations)
        }
    )


def entry_passed():
    return visual.ProfileEntryTransitionVisualObservations(
        **{
            field.name: visual.VisualObservation.PASS
            for field in fields(visual.ProfileEntryTransitionVisualObservations)
        }
    )


class ProfileMainGUIVisualHarnessTests(unittest.TestCase):
    def test_matrix_covers_both_locales_and_all_four_scales(self):
        matrix = visual.PROFILE_MAIN_GUI_VISUAL_MATRIX
        self.assertEqual(len(matrix), 8)
        self.assertEqual(
            {(item.locale, item.scale_percent) for item in matrix},
            {(locale, scale) for locale in ("en", "bg") for scale in (100, 125, 150, 200)},
        )
        self.assertEqual({item.session_state for item in matrix}, {"locked", "unlocked"})
        self.assertEqual([item.case_number for item in matrix], list(range(1, 9)))

    def test_case_selection_is_exact_and_bounded(self):
        for number in range(1, 9):
            self.assertIs(
                visual.prepare_profile_main_gui_visual_case(number),
                visual.PROFILE_MAIN_GUI_VISUAL_MATRIX[number - 1],
            )
        for invalid in (0, 9, -1, True, None, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(visual.ProfileMainGUIVisualHarnessError):
                    visual.prepare_profile_main_gui_visual_case(invalid)

    def test_canonical_report_is_bounded_and_contains_no_sensitive_fields(self):
        report = visual.build_profile_main_gui_visual_report(
            visual.prepare_profile_main_gui_visual_case(1), passed()
        )
        first = visual.profile_main_gui_visual_report_json(report)
        second = visual.profile_main_gui_visual_report_json(report)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first.encode()), visual.PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES)
        payload = json.loads(first)
        self.assertEqual(payload["version"], 4)
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["filesystem_mutation_performed"])
        self.assertFalse(payload["operation_performed"])
        for forbidden in ("path", "password", "secret_value", "hostname", "username"):
            self.assertNotIn(forbidden, payload)

    def test_all_eight_observations_are_required_to_pass(self):
        self.assertTrue(visual.profile_main_gui_visual_observations_pass(passed()))
        for field in fields(visual.ProfileMainGUIVisualObservations):
            failed = replace(
                passed(), **{field.name: visual.VisualObservation.NOT_CHECKED}
            )
            with self.subTest(field=field.name):
                self.assertFalse(visual.profile_main_gui_visual_observations_pass(failed))
        self.assertIn(
            "locked_recovery_only_gate_correct",
            {field.name for field in fields(visual.ProfileMainGUIVisualObservations)},
        )
        self.assertIn(
            "unlocked_v2_legacy_and_recovery_setup_gates_correct",
            {field.name for field in fields(visual.ProfileMainGUIVisualObservations)},
        )
        self.assertIn(
            "v2_actions_and_historical_mok1_are_visually_separate",
            {field.name for field in fields(visual.ProfileMainGUIVisualObservations)},
        )

    def test_invalid_report_inputs_fail_closed(self):
        with self.assertRaises(visual.ProfileMainGUIVisualHarnessError):
            visual.build_profile_main_gui_visual_report(object(), passed())
        with self.assertRaises(visual.ProfileMainGUIVisualHarnessError):
            visual.build_profile_main_gui_visual_report(
                visual.prepare_profile_main_gui_visual_case(1), object()
            )
        with self.assertRaises(visual.ProfileMainGUIVisualHarnessError):
            visual.profile_main_gui_visual_report_json(object())

    def test_harness_core_imports_only_standard_library(self):
        tree = ast.parse(
            (ROOT / "mokosh_profile_main_gui_visual_harness.py").read_text(
                encoding="utf-8"
            )
        )
        imports = {
            alias.name.split(".", 1)[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(imports.isdisjoint({"tkinter", "os", "pathlib", "subprocess", "socket"}))

    def test_runner_is_executable_synthetic_and_one_case_at_a_time(self):
        path = ROOT / "run_mokosh_profile_main_gui_visual_harness.py"
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        source = path.read_text(encoding="utf-8")
        for token in (
            "--case",
            "Synthetic non-secret case",
            "No profile or operation data is read or written",
            "ProfileMainWindow",
            "locked/unlocked action gates",
            "enabled local V2 actions",
            "visibly separate historical MOK1 recovery action",
            'self.profile_root = "/synthetic/not-used"',
            "--entry-transition",
            "_SyntheticEntryTransitionController",
            "auto_first_run_prompt=args.entry_transition",
            "ENTRY_TRANSITION_CONSTRUCTED=PASS",
            "ENTRY_TRANSITION_MAIN_MAPPED=PASS",
            "ENTRY_TRANSITION_FIRST_RUN_MAPPED=PASS",
            "_entry_transition_map_observer",
            "return 130",
            "return 1",
            "return 0",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertNotIn("create_profile(", source)
        self.assertNotIn("load_profile(", source)
        self.assertLess(
            source.index("application = ProfileMainWindow("),
            source.index("print(ENTRY_TRANSITION_CONSTRUCTED_MARKER"),
        )

    def test_entry_transition_map_observer_reports_each_window_once(self):
        root = object()
        dialog_window = object()
        application = SimpleNamespace(
            first_run_window=SimpleNamespace(window=dialog_window)
        )
        emitted = []
        observe = runner._entry_transition_map_observer(
            root,
            {"application": application},
            emitted.append,
        )

        observe(SimpleNamespace(widget=root))
        observe(SimpleNamespace(widget=root))
        observe(SimpleNamespace(widget=dialog_window))
        observe(SimpleNamespace(widget=dialog_window))
        observe(SimpleNamespace(widget=object()))

        self.assertEqual(
            emitted,
            [
                runner.ENTRY_TRANSITION_MAIN_MAPPED_MARKER,
                runner.ENTRY_TRANSITION_FIRST_RUN_MAPPED_MARKER,
            ],
        )

    def test_entry_transition_report_is_bounded_non_secret_and_complete(self):
        report = visual.build_profile_entry_transition_visual_report(
            entry_passed(), locale="bg", scale_percent=100
        )
        first = visual.profile_entry_transition_visual_report_json(report)
        second = visual.profile_entry_transition_visual_report_json(report)
        self.assertEqual(first, second)
        self.assertLessEqual(
            len(first.encode()), visual.PROFILE_MAIN_GUI_VISUAL_MAX_JSON_BYTES
        )
        payload = json.loads(first)
        self.assertEqual(payload["version"], 3)
        self.assertEqual(payload["workflow"], "first_run_login_lock")
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["filesystem_mutation_performed"])
        self.assertFalse(payload["operation_performed"])
        self.assertEqual(
            set(payload["observations"]),
            {
                field.name
                for field in fields(
                    visual.ProfileEntryTransitionVisualObservations
                )
            },
        )
        for forbidden in ("path", "password", "secret_value", "hostname", "username"):
            self.assertNotIn(forbidden, payload)
        self.assertEqual(
            len(fields(visual.ProfileEntryTransitionVisualObservations)),
            14,
        )

    def test_entry_transition_requires_every_observation_and_bounded_case(self):
        self.assertTrue(
            visual.profile_entry_transition_visual_observations_pass(
                entry_passed()
            )
        )
        for field in fields(visual.ProfileEntryTransitionVisualObservations):
            changed = replace(
                entry_passed(),
                **{field.name: visual.VisualObservation.NOT_CHECKED},
            )
            with self.subTest(field=field.name):
                self.assertFalse(
                    visual.profile_entry_transition_visual_observations_pass(
                        changed
                    )
                )
        for locale, scale in (("ru", 100), ("bg", 99), ("bg", True)):
            with self.subTest(locale=locale, scale=scale):
                with self.assertRaises(visual.ProfileMainGUIVisualHarnessError):
                    visual.build_profile_entry_transition_visual_report(
                        entry_passed(), locale=locale, scale_percent=scale
                    )

    def test_synthetic_entry_transition_covers_create_login_and_lock_in_memory(self):
        controller = runner._SyntheticEntryTransitionController()
        self.assertIs(controller.inspection.state, ProfileState.ABSENT)
        self.assertIsNone(controller.session)

        nickname = "VisualTest"
        password = "Temporary-Test-246!"
        controller.create(nickname, password, password)
        self.assertIs(controller.inspection.state, ProfileState.READY)
        self.assertIs(controller.state, ProfileSessionState.LOCKED)

        failed = controller.login(nickname, "Wrong-Test-Password!")
        self.assertFalse(failed.unlocked)
        self.assertIs(controller.state, ProfileSessionState.LOCKED)

        succeeded = controller.login(nickname, password)
        self.assertTrue(succeeded.unlocked)
        self.assertTrue(succeeded.clear_password)
        self.assertTrue(succeeded.clear_nickname)
        self.assertIs(controller.state, ProfileSessionState.UNLOCKED)

        controller.lock(ProfileLockReason.USER)
        self.assertIs(controller.state, ProfileSessionState.LOCKED)
        controller.close()
        self.assertEqual(controller._nickname, "")
        self.assertEqual(controller._password, "")


if __name__ == "__main__":
    unittest.main()
