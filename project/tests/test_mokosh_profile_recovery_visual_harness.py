import ast
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace

import mokosh_profile_recovery_visual_harness as visual
import run_mokosh_profile_recovery_visual_harness as runner
from mokosh_profile_recovery import ProfileRecoveryDecision, ProfileRecoverySeparationError
from mokosh_profile_session import ProfileLockReason, ProfileSessionState


ROOT = Path(__file__).resolve().parents[1]


def passed():
    return visual.ProfileRecoveryGUIVisualObservations(
        **{
            field.name: visual.RecoveryVisualObservation.PASS
            for field in fields(visual.ProfileRecoveryGUIVisualObservations)
        }
    )


def transition_passed():
    return visual.ProfileRecoveryTransitionVisualObservations(
        **{
            field.name: visual.RecoveryVisualObservation.PASS
            for field in fields(
                visual.ProfileRecoveryTransitionVisualObservations
            )
        }
    )


class ProfileRecoveryGUIVisualHarnessTests(unittest.TestCase):
    def test_matrix_covers_both_workflows_locales_and_four_scales(self):
        matrix = visual.PROFILE_RECOVERY_GUI_VISUAL_MATRIX
        self.assertEqual(len(matrix), 16)
        self.assertEqual(
            {(item.locale, item.scale_percent, item.workflow) for item in matrix},
            {
                (locale, scale, workflow)
                for locale in ("en", "bg")
                for scale in (100, 125, 150, 200)
                for workflow in ("setup", "password_recovery")
            },
        )
        self.assertEqual([item.case_number for item in matrix], list(range(1, 17)))

    def test_case_selection_is_exact_and_bounded(self):
        for number in range(1, 17):
            self.assertIs(
                visual.prepare_profile_recovery_gui_visual_case(number),
                visual.PROFILE_RECOVERY_GUI_VISUAL_MATRIX[number - 1],
            )
        for invalid in (0, 17, -1, True, None, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    visual.ProfileRecoveryGUIVisualHarnessError
                ):
                    visual.prepare_profile_recovery_gui_visual_case(invalid)

    def test_report_is_bounded_deterministic_and_non_secret(self):
        report = visual.build_profile_recovery_gui_visual_report(
            visual.prepare_profile_recovery_gui_visual_case(1), passed()
        )
        first = visual.profile_recovery_gui_visual_report_json(report)
        second = visual.profile_recovery_gui_visual_report_json(report)
        self.assertEqual(first, second)
        self.assertLessEqual(
            len(first.encode()), visual.PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES
        )
        payload = json.loads(first)
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["filesystem_mutation_performed"])
        self.assertFalse(payload["recovery_operation_performed"])
        for forbidden in (
            "path",
            "password",
            "phrase_value",
            "secret_value",
            "hostname",
            "username",
        ):
            self.assertNotIn(forbidden, payload)

    def test_every_observation_is_required_to_pass(self):
        self.assertTrue(visual.profile_recovery_gui_visual_observations_pass(passed()))
        for field in fields(visual.ProfileRecoveryGUIVisualObservations):
            changed = replace(
                passed(),
                **{field.name: visual.RecoveryVisualObservation.NOT_CHECKED},
            )
            with self.subTest(field=field.name):
                self.assertFalse(
                    visual.profile_recovery_gui_visual_observations_pass(changed)
                )

    def test_invalid_reports_fail_closed(self):
        case = visual.prepare_profile_recovery_gui_visual_case(1)
        with self.assertRaises(visual.ProfileRecoveryGUIVisualHarnessError):
            visual.build_profile_recovery_gui_visual_report(object(), passed())
        with self.assertRaises(visual.ProfileRecoveryGUIVisualHarnessError):
            visual.build_profile_recovery_gui_visual_report(case, object())
        with self.assertRaises(visual.ProfileRecoveryGUIVisualHarnessError):
            visual.profile_recovery_gui_visual_report_json(object())

    def test_contract_core_imports_only_standard_library(self):
        tree = ast.parse(
            (ROOT / "mokosh_profile_recovery_visual_harness.py").read_text(
                encoding="utf-8"
            )
        )
        imports = {
            alias.name.split(".", 1)[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {"tkinter", "os", "pathlib", "subprocess", "socket"}
            )
        )

    def test_runner_is_executable_one_case_and_synthetic_only(self):
        path = ROOT / "run_mokosh_profile_recovery_visual_harness.py"
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        source = path.read_text(encoding="utf-8")
        for token in (
            "--case",
            "--transition",
            "--setup-layout-audit",
            "Synthetic non-secret recovery case",
            "No profile, recovery file",
            "RecoverySetupWindow",
            "PasswordRecoveryWindow",
            "SYNTHETIC_PROFILE_ROOT",
            "SYNTHETIC_WORDS",
            "root.withdraw()",
            "RECOVERY_TRANSITION_CONSTRUCTED=PASS",
            "RECOVERY_TRANSITION_MAIN_MAPPED=PASS",
            "RECOVERY_TRANSITION_SETUP_MAPPED=PASS",
            "RECOVERY_TRANSITION_PASSWORD_MAPPED=PASS",
            "RECOVERY_SETUP_LAYOUT_AUDIT=PASS",
            "RECOVERY_SETUP_LAYOUT_PREVIEW=OPEN",
            "RECOVERY_SETUP_LAYOUT_PREVIEW=CLOSED_NO_PROJECT_MUTATION",
            '("choose_folder", "decrypt", "maintenance")',
            "return 130",
            "return 1",
            "return 0",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        for forbidden in (
            "create_profile(",
            "load_profile(",
            "begin_profile_recovery_setup(",
            "open(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_runner_blocks_project_bytecode_without_environment_help(self):
        with tempfile.TemporaryDirectory(prefix="mokosh_preview_no_bytecode_") as raw:
            copied = Path(raw) / "candidate"
            shutil.copytree(
                ROOT,
                copied,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    "*.pyc",
                    "*.pyo",
                ),
            )
            environment = os.environ.copy()
            for key in (
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONHOME",
                "PYTHONPATH",
                "PYTHONPYCACHEPREFIX",
                "PYTHONSAFEPATH",
            ):
                environment.pop(key, None)
            environment["PYTHONNOUSERSITE"] = "1"
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(
                        copied / "run_mokosh_profile_recovery_visual_harness.py"
                    ),
                    "--help",
                ],
                cwd=copied,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            residue = sorted(
                path.relative_to(copied).as_posix()
                for path in copied.rglob("*")
                if path.name == "__pycache__"
                or path.name.endswith((".pyc", ".pyo"))
            )
            self.assertEqual(residue, [])

    def test_setup_layout_contract_rejects_exact_r6_failure_shape(self):
        def measurement(*, stacked=False):
            return {
                "container_width": 560,
                "container_height": 90,
                "entry_box": (5, 5, 220, 32),
                "entry_requested": 206,
                "toggle_box": (231, 0, 107, 42),
                "toggle_requested": 107,
                "prepare_box": (343, 0, 212, 42),
                "prepare_requested": 212,
                "stacked": stacked,
                "entry_eye_row": True,
                "entry_prepare_row": not stacked,
                "in_bounds": True,
                "mapped": True,
                "wraps": tuple(
                    {
                        "name": name,
                        "width": 540,
                        "requested": 560,
                        "wraplength": 500,
                        "padx": 10,
                        "clearance": 40,
                        "mapped": True,
                    }
                    for name in (
                        "main_recovery_status",
                        "setup_phrase_warning",
                        "setup_phrase_help",
                    )
                ),
            }

        green_inline = measurement(stacked=False)
        runner._require_setup_layout_measurement(
            green_inline,
            expected_stacked=False,
        )
        green_stacked = measurement(stacked=True)
        green_stacked.update(
            {
                "prepare_box": (343, 48, 212, 42),
                "entry_prepare_row": False,
            }
        )
        runner._require_setup_layout_measurement(
            green_stacked,
            expected_stacked=True,
        )

        exact_r6_clipped = measurement(stacked=False)
        exact_r6_clipped.update(
            {
                "prepare_box": (343, 0, 170, 42),
                "prepare_requested": 212,
            }
        )
        with self.assertRaisesRegex(RuntimeError, "clipped or stretched"):
            runner._require_setup_layout_measurement(
                exact_r6_clipped,
                expected_stacked=False,
            )

        exact_r6_wall = measurement(stacked=True)
        exact_r6_wall.update(
            {
                "prepare_box": (343, 48, 212, 42),
                "entry_prepare_row": False,
            }
        )
        exact_r6_wall["wraps"][1]["wraplength"] = 525
        exact_r6_wall["wraps"][1]["clearance"] = 15
        with self.assertRaisesRegex(RuntimeError, "reaches its wall"):
            runner._require_setup_layout_measurement(
                exact_r6_wall,
                expected_stacked=True,
            )

    def test_transition_report_is_bounded_and_requires_all_observations(self):
        report = visual.build_profile_recovery_transition_visual_report(
            transition_passed(), locale="bg", scale_percent=100
        )
        encoded = visual.profile_recovery_transition_visual_report_json(report)
        payload = json.loads(encoded)
        self.assertEqual(payload["version"], 2)
        self.assertEqual(
            payload["workflow"],
            "unlock_enroll_lock_recover_new_login_lock",
        )
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["filesystem_mutation_performed"])
        self.assertFalse(payload["recovery_operation_performed"])
        self.assertLessEqual(
            len(encoded.encode()), visual.PROFILE_RECOVERY_GUI_VISUAL_MAX_JSON_BYTES
        )
        for field in fields(visual.ProfileRecoveryTransitionVisualObservations):
            changed = replace(
                transition_passed(),
                **{field.name: visual.RecoveryVisualObservation.FAIL},
            )
            self.assertFalse(
                visual.profile_recovery_transition_visual_observations_pass(changed)
            )

    def test_transition_report_rejects_unknown_locale_and_scale(self):
        for locale, scale in (("ru", 100), ("bg", 99), ("bg", True)):
            with self.subTest(locale=locale, scale=scale):
                with self.assertRaises(
                    visual.ProfileRecoveryGUIVisualHarnessError
                ):
                    visual.build_profile_recovery_transition_visual_report(
                        transition_passed(),
                        locale=locale,
                        scale_percent=scale,
                    )

    def test_synthetic_transition_covers_setup_recovery_and_new_login(self):
        controller = runner._SyntheticRecoveryController()
        self.assertIs(controller.state, ProfileSessionState.UNLOCKED)
        setup = controller.begin_setup(
            runner.SYNTHETIC_PROFILE_ROOT,
            runner.SYNTHETIC_OLD_PASSWORD,
            ProfileRecoveryDecision.AUTHORIZE,
        )
        setup.export_record("/synthetic/record-parent")
        with self.assertRaises(ProfileRecoverySeparationError):
            setup.export_phrase("/synthetic/same-device-parent")
        setup.export_phrase("/synthetic/separate-phrase-parent")
        setup.complete(ProfileRecoveryDecision.AUTHORIZE)
        self.assertTrue(controller.recovery_configured)
        self.assertTrue(controller.recovery_state.recovery_available)

        controller.lock(ProfileLockReason.USER)
        prepared = controller.prepare_from_sheet(
            runner.SYNTHETIC_PROFILE_ROOT,
            "/synthetic/record.mokr",
            "/synthetic/phrase.txt",
            runner.SYNTHETIC_NEW_PASSWORD,
            runner.SYNTHETIC_NEW_PASSWORD,
            ProfileRecoveryDecision.AUTHORIZE,
        )
        self.assertEqual(prepared.preview.target_revision, 2)
        prepared.publish(ProfileRecoveryDecision.AUTHORIZE)
        self.assertTrue(controller.recovery_state.replacement_required)
        self.assertFalse(controller.recovery_state.recovery_available)
        controller.refresh()
        old = controller.login(
            runner.SYNTHETIC_NICKNAME,
            runner.SYNTHETIC_OLD_PASSWORD,
        )
        self.assertFalse(old.unlocked)
        new = controller.login(
            runner.SYNTHETIC_NICKNAME,
            runner.SYNTHETIC_NEW_PASSWORD,
        )
        self.assertTrue(new.unlocked)
        notice = controller.consume_recovery_login_notice()
        self.assertIsNotNone(notice)
        self.assertTrue(notice.show_reminder)
        controller.lock(ProfileLockReason.USER)
        self.assertIs(controller.state, ProfileSessionState.LOCKED)

    def test_transition_map_observer_reports_each_window_once(self):
        root = object()
        setup_window = object()
        password_window = object()
        application = SimpleNamespace(
            recovery_setup_window=SimpleNamespace(window=setup_window),
            password_recovery_window=SimpleNamespace(window=password_window),
        )
        emitted = []
        observer = runner._transition_map_observer(
            root,
            {"application": application},
            emitted.append,
        )
        for widget in (root, root, setup_window, setup_window, password_window, password_window):
            observer(SimpleNamespace(widget=widget))
        self.assertEqual(
            emitted,
            [
                runner.RECOVERY_TRANSITION_MAIN_MAPPED_MARKER,
                runner.RECOVERY_TRANSITION_SETUP_MAPPED_MARKER,
                runner.RECOVERY_TRANSITION_PASSWORD_MAPPED_MARKER,
            ],
        )


if __name__ == "__main__":
    unittest.main()
