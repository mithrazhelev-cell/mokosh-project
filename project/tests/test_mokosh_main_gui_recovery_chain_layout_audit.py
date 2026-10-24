from __future__ import annotations

import ast
import hashlib
import inspect
import json
import stat
import unittest
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace

import mokosh_main_gui_recovery_chain_layout_audit as audit


ROOT = Path(__file__).resolve().parents[1]


def all_pass() -> audit.MainGUIRecoveryChainLayoutAuditObservations:
    value = audit.MainGUIRecoveryChainLayoutAuditObservation.PASS
    return audit.MainGUIRecoveryChainLayoutAuditObservations(
        value, value, value, value, value, value, value, value
    )


class MainGUIRecoveryChainLayoutAuditTests(unittest.TestCase):
    def test_01_matrix_is_exact_and_bounded(self):
        self.assertEqual(
            audit.MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX,
            (
                ("bg-BG", 100, "initial_keyboard"),
                ("en-GB", 125, "initial_keyboard"),
                ("bg-BG", 150, "resize_restore_keyboard"),
                ("en-GB", 200, "resize_restore_keyboard"),
            ),
        )

    def test_02_every_case_prepares_exactly(self):
        for case_number, expected in enumerate(
            audit.MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX, start=1
        ):
            case = audit.prepare_main_gui_recovery_chain_layout_audit_case(case_number)
            self.assertEqual(
                (case.locale, case.scale_percent, case.profile.value), expected
            )
            self.assertIs(case.synthetic_non_secret, True)

    def test_03_invalid_case_numbers_are_rejected(self):
        for value in (True, False, 0, 5, -1, 1.0, "1", None):
            with self.subTest(value=value):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    audit.prepare_main_gui_recovery_chain_layout_audit_case(value)

    def test_04_direct_case_requires_exact_matrix_tuple(self):
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            audit.MainGUIRecoveryChainLayoutAuditCase(
                1,
                "en-GB",
                100,
                audit.MainGUIRecoveryChainLayoutAuditProfile.INITIAL_KEYBOARD,
            )

    def test_05_direct_case_rejects_forged_synthetic_claim(self):
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            audit.MainGUIRecoveryChainLayoutAuditCase(
                1,
                "bg-BG",
                100,
                audit.MainGUIRecoveryChainLayoutAuditProfile.INITIAL_KEYBOARD,
                False,
            )

    def test_06_observations_require_eight_exact_enums(self):
        values = [audit.MainGUIRecoveryChainLayoutAuditObservation.PASS] * 8
        values[4] = "pass"
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            audit.MainGUIRecoveryChainLayoutAuditObservations(*values)

    def test_07_builder_requires_exact_case_type(self):
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            audit.build_main_gui_recovery_chain_layout_audit_report(object(), all_pass())

    def test_08_builder_requires_exact_observations_type(self):
        case = audit.prepare_main_gui_recovery_chain_layout_audit_case(1)
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            audit.build_main_gui_recovery_chain_layout_audit_report(case, object())

    def test_09_every_case_builds_one_exact_report(self):
        for case_number in range(1, 5):
            case = audit.prepare_main_gui_recovery_chain_layout_audit_case(case_number)
            report = audit.build_main_gui_recovery_chain_layout_audit_report(
                case, all_pass()
            )
            self.assertEqual(report.case_number, case_number)
            self.assertEqual(report.locale, case.locale)
            self.assertIs(report.profile, case.profile)

    def test_10_report_truthfully_records_existing_runtime_preparation(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        self.assertIs(report.normal_startup_observed, True)
        self.assertIs(report.runtime_directory_preparation_performed, True)
        self.assertIs(report.current_four_action_chain_observed, True)

    def test_11_report_rejects_false_normal_startup_claim(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
            replace(report, normal_startup_observed=False)

    def test_12_report_rejects_source_path_or_picker_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        for name in ("native_source_picker_invoked", "source_path_metadata_received"):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_13_report_rejects_recovery_source_access_or_mutation_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        for name in (
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_14_report_rejects_future_layer_activation_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(2), all_pass()
        )
        for name in (
            "stage_2_31_gui_wiring_activated",
            "stage_2_32_secure_read_authorized",
            "stage_2_41_normal_activation_performed",
        ):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_15_report_rejects_operation_or_network_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(2), all_pass()
        )
        for name in ("operation_authorized", "operation_performed", "network_used"):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_16_report_rejects_instrumentation_and_metadata_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(3), all_pass()
        )
        for name in (
            "automatic_gui_event_injection_used",
            "screen_capture_performed",
            "host_or_geometry_metadata_recorded",
        ):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_17_report_rejects_conformity_and_understanding_claims(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(4), all_pass()
        )
        for name in (
            "accessibility_conformance_claimed",
            "legal_conformity_claimed",
            "platform_certification_claimed",
            "human_understanding_proven",
        ):
            with self.subTest(name=name):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **{name: True})

    def test_18_report_rejects_schema_and_version_forgery(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(4), all_pass()
        )
        for changes in ({"format": "FOREIGN"}, {"version": 2}, {"version": True}):
            with self.subTest(changes=changes):
                with self.assertRaises(audit.MainGUIRecoveryChainLayoutAuditError):
                    replace(report, **changes)

    def test_19_json_is_canonical_and_round_trips(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        encoded = audit.main_gui_recovery_chain_layout_audit_report_json(report)
        payload = json.loads(encoded)
        self.assertEqual(
            encoded,
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )

    def test_20_json_is_bounded(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(1), all_pass()
        )
        encoded = audit.main_gui_recovery_chain_layout_audit_report_json(report)
        self.assertLessEqual(
            len(encoded.encode("utf-8")),
            audit.MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MAX_JSON_UTF8_LEN,
        )

    def test_21_json_contains_all_eight_fixed_observations(self):
        report = audit.build_main_gui_recovery_chain_layout_audit_report(
            audit.prepare_main_gui_recovery_chain_layout_audit_case(2), all_pass()
        )
        payload = json.loads(
            audit.main_gui_recovery_chain_layout_audit_report_json(report)
        )
        self.assertEqual(len(payload["observations"]), 8)
        self.assertEqual(set(payload["observations"].values()), {"pass"})

    def test_22_report_schema_has_no_free_text_or_sensitive_fields(self):
        names = {field.name for field in fields(audit.MainGUIRecoveryChainLayoutAuditReport)}
        for forbidden in (
            "notes",
            "path",
            "filename",
            "password",
            "secret",
            "recovery_id",
            "vault_id",
            "geometry",
            "screen",
            "hostname",
            "exception",
        ):
            self.assertNotIn(forbidden, names)

    def test_23_all_pass_helper_requires_every_pass(self):
        self.assertTrue(
            audit.main_gui_recovery_chain_layout_audit_observations_pass(all_pass())
        )

    def test_24_fail_or_not_checked_blocks_human_gate(self):
        for value in (
            audit.MainGUIRecoveryChainLayoutAuditObservation.FAIL,
            audit.MainGUIRecoveryChainLayoutAuditObservation.NOT_CHECKED,
        ):
            observations = replace(
                all_pass(), localized_text_unclipped_and_readable=value
            )
            self.assertFalse(
                audit.main_gui_recovery_chain_layout_audit_observations_pass(
                    observations
                )
            )

    def test_25_core_imports_only_bounded_standard_library_modules(self):
        tree = ast.parse(
            (ROOT / "mokosh_main_gui_recovery_chain_layout_audit.py").read_text(
                encoding="utf-8"
            )
        )
        imports = {
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        } | {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(imports, {"__future__", "dataclasses", "enum", "json", "typing"})

    def test_26_core_has_no_filesystem_gui_network_process_or_dynamic_calls(self):
        source = (ROOT / "mokosh_main_gui_recovery_chain_layout_audit.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("callback", source)
        self.assertIn("executor", source)
        self.assertTrue(
            called_names.isdisjoint(
                {"open", "eval", "exec", "compile", "__import__", "input"}
            )
        )
        self.assertTrue(
            called_attributes.isdisjoint(
                {"open", "read", "write", "stat", "lstat", "resolve", "connect"}
            )
        )

    def test_27_launcher_is_separate_and_executable(self):
        path = ROOT / "run_main_gui_recovery_chain_layout_audit.py"
        self.assertTrue(path.is_file())
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)

    def test_28_launcher_uses_fixed_matrix_and_normal_main_without_arguments(self):
        source = (ROOT / "run_main_gui_recovery_chain_layout_audit.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_MATRIX", source)
        self.assertIn("mokosh_gui.main()", source)
        self.assertNotIn("prepared_recovery", source)

    def test_29_launcher_does_not_inject_actions_or_open_source_picker(self):
        source = (ROOT / "run_main_gui_recovery_chain_layout_audit.py").read_text(
            encoding="utf-8"
        )
        for token in (
            "event_generate",
            ".invoke(",
            "askopenfilename",
            "filedialog",
            "open(",
            "_read_recovery_path",
            "prepare_recovery_source_inspection_execution",
        ):
            self.assertNotIn(token, source)

    def test_30_launcher_has_bounded_failure_and_interrupt_exit_codes(self):
        source = (ROOT / "run_main_gui_recovery_chain_layout_audit.py").read_text(
            encoding="utf-8"
        )
        for token in ("return 1", "return 2", "return 130", "return 0"):
            self.assertIn(token, source)
        self.assertIn("--no-observations", source)
        self.assertIn("Keep the initial window size unchanged", source)
        self.assertIn("Enlarge the window, then restore it", source)

    def test_31_critical_production_and_predecessor_files_remain_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "docs/VAULT_RECOVERY_SOURCE_INSPECTION_REQUEST_MAIN_GUI_WIDGET_CONTRACT_BG.md": "394ec84348fd8f39b6d0c66a8041a0a04fff21c8e8e84a25d5cd66d903eea33b",
            "tests/test_mokosh_vault_recovery_source_inspection_main_gui_widget.py": "eae5e798f3a07913c77b9443ccf96beda0cdc14176788fcdbb402aa8ae6310bd",
            "tests/test_mokosh_vault_recovery_entry_main_gui_widget.py": "14acd8df5b90389aea71e2cc598399cf317ed5015358af9a9d1fc23c48de9f43",
            "tests/test_mokosh_vault_recovery_entry_transition_main_gui_widget.py": "8fddcbee82d35fb655077684fb6283a3d6bf86e9d80fa8e26773cc4721c1315c",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_32_exact_target_count_and_public_signatures(self):
        methods = [
            name
            for name in vars(MainGUIRecoveryChainLayoutAuditTests)
            if name.startswith("test_")
        ]
        self.assertEqual(len(methods), 48)
        self.assertEqual(
            tuple(
                inspect.signature(
                    audit.prepare_main_gui_recovery_chain_layout_audit_case
                ).parameters
            ),
            ("case_number",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    audit.build_main_gui_recovery_chain_layout_audit_report
                ).parameters
            ),
            ("case", "observations"),
        )

    def test_33_linux_wheel_up_is_normalized(self):
        import mokosh_gui

        self.assertEqual(mokosh_gui._normal_main_scroll_units(SimpleNamespace(num=4)), -1)

    def test_34_linux_wheel_down_is_normalized(self):
        import mokosh_gui

        self.assertEqual(mokosh_gui._normal_main_scroll_units(SimpleNamespace(num=5)), 1)

    def test_35_positive_delta_scrolls_up(self):
        import mokosh_gui

        self.assertEqual(
            mokosh_gui._normal_main_scroll_units(SimpleNamespace(num=None, delta=120)),
            -1,
        )

    def test_36_negative_delta_scrolls_down(self):
        import mokosh_gui

        self.assertEqual(
            mokosh_gui._normal_main_scroll_units(SimpleNamespace(num=None, delta=-120)),
            1,
        )

    def test_37_absent_zero_or_foreign_wheel_delta_is_ignored(self):
        import mokosh_gui

        for event in (object(), SimpleNamespace(delta=0), SimpleNamespace(delta="120")):
            with self.subTest(event=event):
                self.assertEqual(mokosh_gui._normal_main_scroll_units(event), 0)

    @staticmethod
    def _reveal_fixture(*, visible_top, control_top, control_height=40):
        class Canvas:
            height = 200
            moves = []

            def winfo_height(self):
                return self.height

            def canvasy(self, _value):
                return visible_top

            def yview_moveto(self, value):
                self.moves.append(value)

        class Content:
            def winfo_reqheight(self):
                return 1000

            def winfo_rooty(self):
                return 100

        class Control:
            def winfo_rooty(self):
                return 100 + control_top

            def winfo_height(self):
                return control_height

        return Canvas(), Content(), Control()

    def test_38_focus_above_viewport_is_revealed(self):
        import mokosh_gui

        canvas, content, control = self._reveal_fixture(
            visible_top=300, control_top=100
        )
        mokosh_gui._reveal_normal_main_control(canvas, content, control)
        self.assertEqual(canvas.moves, [0.1])

    def test_39_focus_below_viewport_is_revealed(self):
        import mokosh_gui

        canvas, content, control = self._reveal_fixture(
            visible_top=100, control_top=470, control_height=30
        )
        mokosh_gui._reveal_normal_main_control(canvas, content, control)
        self.assertEqual(canvas.moves, [0.3])

    def test_40_visible_focus_does_not_move_viewport(self):
        import mokosh_gui

        canvas, content, control = self._reveal_fixture(
            visible_top=100, control_top=150
        )
        mokosh_gui._reveal_normal_main_control(canvas, content, control)
        self.assertEqual(canvas.moves, [])

    def test_41_focus_reveal_clamps_to_top(self):
        import mokosh_gui

        canvas, content, control = self._reveal_fixture(
            visible_top=20, control_top=-50
        )
        mokosh_gui._reveal_normal_main_control(canvas, content, control)
        self.assertEqual(canvas.moves, [0.0])

    def test_42_focus_reveal_clamps_to_last_viewport(self):
        import mokosh_gui

        canvas, content, control = self._reveal_fixture(
            visible_top=100, control_top=980, control_height=40
        )
        mokosh_gui._reveal_normal_main_control(canvas, content, control)
        self.assertEqual(canvas.moves, [0.8])

    def test_43_normal_viewport_has_canvas_and_vertical_scrollbar(self):
        source = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn("canvas = tk.Canvas(body", source)
        self.assertIn("scrollbar = tk.Scrollbar(", source)
        self.assertIn('orient="vertical"', source)
        self.assertIn("yscrollcommand=scrollbar.set", source)

    def test_44_viewport_scrollregion_and_width_follow_content(self):
        source = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn('scrollregion=canvas.bbox("all")', source)
        self.assertIn("canvas.itemconfigure(content_window, width=event.width)", source)

    def test_45_keyboard_page_home_and_end_scroll_without_activation(self):
        source = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        for token in ('"<Prior>"', '"<Next>"', '"<Home>"', '"<End>"'):
            self.assertIn(token, source)
        self.assertNotIn("event_generate", source)

    def test_46_focus_reveal_uses_after_idle_and_additive_binding(self):
        source = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn('"<FocusIn>"', source)
        self.assertIn("root.after_idle(", source)
        self.assertIn('add="+"', source)

    def test_47_adaptive_viewport_is_normal_startup_only(self):
        source = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn("if not conditional_recovery_review:", source)
        self.assertIn("_create_normal_main_scroll_viewport", source)
        self.assertIn(
            'root.geometry("820x560" if conditional_recovery_review else "820x720")',
            source,
        )

    def test_48_corrective_scope_retains_no_new_sensitive_capability(self):
        tree = ast.parse((ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        helpers = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            in {
                "_normal_main_scroll_units",
                "_reveal_normal_main_control",
                "_create_normal_main_scroll_viewport",
                "_bind_normal_main_focus_reveal",
            }
        }
        self.assertEqual(len(helpers), 4)
        forbidden = {
            "open",
            "eval",
            "exec",
            "compile",
            "__import__",
            "askopenfilename",
            "askdirectory",
            "event_generate",
            "invoke",
        }
        calls = {
            node.func.id
            for helper in helpers.values()
            for node in ast.walk(helper)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        } | {
            node.func.attr
            for helper in helpers.values()
            for node in ast.walk(helper)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(calls.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
