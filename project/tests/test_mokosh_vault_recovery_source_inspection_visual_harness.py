import ast
import dataclasses
import inspect
import json
import unittest
from pathlib import Path

import mokosh_vault_recovery_source_inspection_review_window as review
import mokosh_vault_recovery_source_inspection_ui_adapter as adapter
import mokosh_vault_recovery_source_inspection_visual_harness as harness


ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "mokosh_vault_recovery_source_inspection_visual_harness.py"
LAUNCHER_PATH = ROOT / "run_recovery_source_inspection_review_visual_harness.py"


def case(number=1):
    return harness.prepare_synthetic_recovery_source_inspection_visual_case(number)


def pass_observations():
    value = harness.RecoverySourceInspectionVisualHarnessObservation.PASS
    return harness.RecoverySourceInspectionVisualHarnessObservations(
        value, value, value, value, value, value
    )


def observations(value):
    return harness.RecoverySourceInspectionVisualHarnessObservations(
        value, value, value, value, value, value
    )


class FakeGeometryWidget:
    def __init__(self, rect, *, mapped=True):
        self.left, self.top, self.right, self.bottom = rect
        self.mapped = mapped

    def winfo_ismapped(self):
        return self.mapped

    def winfo_width(self):
        return self.right - self.left

    def winfo_height(self):
        return self.bottom - self.top

    def winfo_rootx(self):
        return self.left

    def winfo_rooty(self):
        return self.top


def outcome_for(value, *, reason_override=None):
    prepared = review.prepare_recovery_source_inspection_review_window(
        value.presentation,
        value.adapter,
    )
    action = value.required_terminal_action
    if action is harness.RecoverySourceInspectionVisualHarnessTerminalAction.ACKNOWLEDGE:
        prepared.mark_messages_visible_once(
            tuple(item.ordinal for item in prepared.localized_view.message_items)
        )
        for control in prepared.localized_view.confirmation_controls:
            prepared.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )
        return prepared.acknowledge_visible_once()
    reason = {
        harness.RecoverySourceInspectionVisualHarnessTerminalAction.ESCAPE_KEY: (
            review.RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY
        ),
        harness.RecoverySourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON: (
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        ),
        harness.RecoverySourceInspectionVisualHarnessTerminalAction.WINDOW_CLOSE: (
            review.RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE
        ),
    }[action]
    return prepared.cancel_once(reason_override or reason)


def report(number=1, observation_value=None):
    value = case(number)
    observed = (
        pass_observations()
        if observation_value is None
        else observations(observation_value)
    )
    return harness.build_recovery_source_inspection_visual_harness_report(
        value,
        outcome_for(value),
        observed,
    )


def forge(value, **changes):
    forged = object.__new__(type(value))
    for item in dataclasses.fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class SourceInspectionVisualFixtureTests(unittest.TestCase):
    def test_01_matrix_is_exact(self):
        self.assertEqual(
            harness.RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MATRIX,
            (
                ("bg-BG", 100, "small", "escape_key"),
                ("en-GB", 125, "small", "cancel_button"),
                ("bg-BG", 150, "standard", "window_close"),
                ("en-GB", 200, "standard", "acknowledge"),
                ("bg-BG", 125, "standard", "cancel_button"),
                ("en-GB", 150, "small", "escape_key"),
                ("bg-BG", 200, "small", "acknowledge"),
                ("en-GB", 100, "standard", "window_close"),
            ),
        )

    def test_02_each_locale_occurs_four_times(self):
        locales = [case(number).locale.value for number in range(1, 9)]
        self.assertEqual(locales.count("bg-BG"), 4)
        self.assertEqual(locales.count("en-GB"), 4)

    def test_03_each_scale_occurs_twice(self):
        scales = [case(number).scale_percent for number in range(1, 9)]
        self.assertEqual({value: scales.count(value) for value in set(scales)}, {100: 2, 125: 2, 150: 2, 200: 2})

    def test_04_profiles_have_exact_safe_dimensions(self):
        for number in range(1, 9):
            value = case(number)
            expected = (560, 440) if value.window_profile.value == "small" else (800, 640)
            self.assertEqual((value.width, value.height), expected)

    def test_05_each_terminal_action_occurs_twice(self):
        actions = [case(number).required_terminal_action.value for number in range(1, 9)]
        self.assertEqual(
            {value: actions.count(value) for value in set(actions)},
            {"escape_key": 2, "cancel_button": 2, "window_close": 2, "acknowledge": 2},
        )

    def test_06_every_case_prepares_exact_stage_233_to_235_data(self):
        for number in range(1, 9):
            value = case(number)
            prepared = review.prepare_recovery_source_inspection_review_window(
                value.presentation, value.adapter
            )
            self.assertEqual(len(prepared.localized_view.message_items), 7)
            self.assertEqual(len(prepared.localized_view.confirmation_controls), 3)

    def test_07_every_case_is_synthetic_non_secret_and_no_capability(self):
        for number in range(1, 9):
            value = case(number)
            self.assertTrue(value.synthetic_non_secret)
            self.assertFalse(value.real_source_input_used)
            self.assertFalse(value.operation_capability_included)

    def test_08_same_case_is_deterministic(self):
        first = case(3)
        second = case(3)
        self.assertEqual(
            first.presentation.inspection_evidence_sha256,
            second.presentation.inspection_evidence_sha256,
        )
        self.assertEqual(first.adapter.view.presentation_sha256, second.adapter.view.presentation_sha256)

    def test_09_locales_are_digest_separated(self):
        self.assertNotEqual(
            case(1).presentation.inspection_evidence_sha256,
            case(6).presentation.inspection_evidence_sha256,
        )

    def test_10_out_of_range_case_numbers_are_rejected(self):
        for invalid in (-1, 0, 9, 10):
            with self.subTest(invalid=invalid):
                with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
                    case(invalid)

    def test_11_boolean_case_number_is_rejected(self):
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            case(True)

    def test_12_non_integer_case_numbers_are_rejected(self):
        for invalid in (None, "1", 1.0, [1]):
            with self.subTest(invalid=invalid):
                with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
                    case(invalid)

    def test_13_forged_dimensions_are_rejected(self):
        value = case(1)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness._validate_case(forge(value, width=559))

    def test_14_forged_matrix_action_is_rejected(self):
        value = case(1)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness._validate_case(
                forge(
                    value,
                    required_terminal_action=(
                        harness.RecoverySourceInspectionVisualHarnessTerminalAction.CANCEL_BUTTON
                    ),
                )
            )

    def test_15_presentation_and_adapter_mismatch_is_rejected(self):
        first = case(1)
        other = case(6)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness._validate_case(forge(first, adapter=other.adapter))

    def test_16_fresh_adapter_is_required_for_public_case(self):
        value = case(4)
        outcome_for(value)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness._validate_case(value)


class SourceInspectionVisualObservationTests(unittest.TestCase):
    def test_17_six_exact_pass_observations_are_accepted(self):
        self.assertTrue(harness.visual_observations_pass(pass_observations()))

    def test_18_raw_string_observation_is_rejected(self):
        value = pass_observations()
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness._validate_observations(
                forge(value, keyboard_only_no_trap="pass")
            )

    def test_19_non_enum_observation_values_are_rejected(self):
        for invalid in (True, 1, None, {}):
            value = pass_observations()
            with self.subTest(invalid=invalid):
                with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
                    harness._validate_observations(
                        forge(value, locale_title_and_labels=invalid)
                    )

    def test_20_observation_schema_has_exact_six_fields(self):
        self.assertEqual(
            tuple(item.name for item in dataclasses.fields(harness.RecoverySourceInspectionVisualHarnessObservations)),
            (
                "content_reachability_and_scrolling",
                "text_wrapping_no_clipping_or_overlap",
                "focus_order_visible_unobscured",
                "keyboard_only_no_trap",
                "default_false_and_enable_redisable",
                "locale_title_and_labels",
            ),
        )

    def test_21_one_fail_observation_fails_gate(self):
        value = pass_observations()
        failed = forge(
            value,
            content_reachability_and_scrolling=(
                harness.RecoverySourceInspectionVisualHarnessObservation.FAIL
            ),
        )
        self.assertFalse(harness.visual_observations_pass(failed))

    def test_22_one_not_checked_observation_fails_gate(self):
        value = pass_observations()
        unchecked = forge(
            value,
            focus_order_visible_unobscured=(
                harness.RecoverySourceInspectionVisualHarnessObservation.NOT_CHECKED
            ),
        )
        self.assertFalse(harness.visual_observations_pass(unchecked))

    def test_23_all_fail_observations_are_explicit(self):
        value = harness.RecoverySourceInspectionVisualHarnessObservation.FAIL
        checked = observations(value)
        self.assertTrue(all(item is value for item in dataclasses.astuple(checked)))

    def test_24_all_not_checked_observations_are_explicit(self):
        value = harness.RecoverySourceInspectionVisualHarnessObservation.NOT_CHECKED
        checked = observations(value)
        self.assertTrue(all(item is value for item in dataclasses.astuple(checked)))


class SourceInspectionVisualReportTests(unittest.TestCase):
    def test_25_all_three_cancel_routes_are_reported_exactly(self):
        for number, expected in (
            (1, review.RecoverySourceInspectionReviewWindowCancelReason.ESCAPE_KEY),
            (2, review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON),
            (3, review.RecoverySourceInspectionReviewWindowCancelReason.WINDOW_CLOSE),
        ):
            with self.subTest(number=number):
                value = report(number)
                self.assertIs(value.cancel_reason, expected)
                self.assertIs(value.decision, review.RecoverySourceInspectionReviewWindowDecision.CANCELLED)

    def test_26_acknowledgement_builds_bounded_report(self):
        value = report(4)
        self.assertIs(value.decision, review.RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED)
        self.assertIsNone(value.cancel_reason)
        self.assertFalse(value.operation_authorized)

    def test_27_wrong_terminal_action_outcome_is_rejected(self):
        value = case(1)
        wrong = outcome_for(
            value,
            reason_override=review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON,
        )
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.build_recovery_source_inspection_visual_harness_report(
                value, wrong, pass_observations()
            )
        valid_report = report(1)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.recovery_source_inspection_visual_harness_report_json(
                forge(
                    valid_report,
                    cancel_reason=(
                        review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
                    ),
                )
            )

    def test_28_forged_outcome_digest_is_rejected(self):
        value = case(1)
        result = outcome_for(value)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.build_recovery_source_inspection_visual_harness_report(
                value,
                forge(result, presentation_sha256=b"X" * 32),
                pass_observations(),
            )

    def test_29_outcome_locale_mismatch_is_rejected(self):
        first = case(1)
        other = case(6)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.build_recovery_source_inspection_visual_harness_report(
                first, outcome_for(other), pass_observations()
            )

    def test_30_report_dimensions_match_profile(self):
        self.assertEqual((report(1).width, report(1).height), (560, 440))
        self.assertEqual((report(3).width, report(3).height), (800, 640))

    def test_31_report_records_mapped_real_stage_237_request(self):
        value = report(2)
        self.assertTrue(value.real_stage_2_37_toplevel_requested)
        self.assertTrue(value.window_mapped_before_timeout)
        self.assertTrue(value.inspection_only)

    def test_32_report_denies_all_conformity_and_authority_claims(self):
        value = report(2)
        for name in (
            "platform_certification_claimed",
            "accessibility_conformance_claimed",
            "screen_reader_behavior_verified",
            "accessibility_api_verified",
            "contrast_conformance_verified",
            "human_understanding_proven",
            "informed_consent_proven",
            "operation_performed",
            "operation_authorized",
        ):
            self.assertIs(getattr(value, name), False)

    def test_33_forged_true_claim_is_rejected(self):
        value = report(1)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.recovery_source_inspection_visual_harness_report_json(
                forge(value, accessibility_conformance_claimed=True)
            )

    def test_34_non_boolean_safety_flag_is_rejected(self):
        value = report(1)
        with self.assertRaises(harness.VaultRecoverySourceInspectionVisualHarnessError):
            harness.recovery_source_inspection_visual_harness_report_json(
                forge(value, network_used=0)
            )

    def test_35_report_schema_excludes_arbitrary_and_sensitive_fields(self):
        names = {item.name for item in dataclasses.fields(harness.RecoverySourceInspectionVisualHarnessReport)}
        self.assertTrue(
            names.isdisjoint(
                {"notes", "comment", "password", "vault_path", "path", "filename", "source_bytes", "callback", "executor"}
            )
        )

    def test_36_report_json_is_canonical(self):
        value = report(3)
        first = harness.recovery_source_inspection_visual_harness_report_json(value)
        second = harness.recovery_source_inspection_visual_harness_report_json(value)
        self.assertEqual(first, second)
        self.assertEqual(first, json.dumps(json.loads(first), ensure_ascii=False, sort_keys=True, separators=(",", ":")))

    def test_37_report_json_is_bounded(self):
        encoded = harness.recovery_source_inspection_visual_harness_report_json(report(4)).encode("utf-8")
        self.assertLessEqual(len(encoded), harness.RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_MAX_JSON_UTF8_LEN)

    def test_38_report_json_excludes_sensitive_keys(self):
        payload = json.loads(harness.recovery_source_inspection_visual_harness_report_json(report(1)))
        self.assertTrue(
            set(payload).isdisjoint(
                {"notes", "hostname", "environment", "password", "vault_path", "path", "filename", "source_bytes", "callback", "executor"}
            )
        )

    def test_39_report_json_has_exact_six_observations(self):
        payload = json.loads(harness.recovery_source_inspection_visual_harness_report_json(report(1)))
        self.assertEqual(len(payload["observations"]), 6)
        self.assertEqual(set(payload["observations"].values()), {"pass"})

    def test_40_all_eight_matching_cases_build_reports(self):
        for number in range(1, 9):
            with self.subTest(number=number):
                value = report(number)
                self.assertEqual(value.case_number, number)

    def test_41_not_checked_report_remains_honest(self):
        value = report(
            1,
            harness.RecoverySourceInspectionVisualHarnessObservation.NOT_CHECKED,
        )
        payload = json.loads(harness.recovery_source_inspection_visual_harness_report_json(value))
        self.assertEqual(set(payload["observations"].values()), {"not_checked"})
        self.assertFalse(payload["accessibility_conformance_claimed"])

    def test_42_fail_report_remains_honest(self):
        value = report(
            1,
            harness.RecoverySourceInspectionVisualHarnessObservation.FAIL,
        )
        payload = json.loads(harness.recovery_source_inspection_visual_harness_report_json(value))
        self.assertEqual(set(payload["observations"].values()), {"fail"})


class SourceInspectionVisualStaticBoundaryTests(unittest.TestCase):
    def test_43_core_has_no_filesystem_network_process_gui_or_logging_import(self):
        tree = ast.parse(CORE_PATH.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(imported.isdisjoint({"os", "pathlib", "subprocess", "socket", "urllib", "requests", "logging", "tkinter", "time", "random", "secrets"}))

    def test_44_core_has_no_file_dynamic_execution_or_operation_calls(self):
        tree = ast.parse(CORE_PATH.read_text(encoding="utf-8"))
        names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(names.isdisjoint({"open", "eval", "exec", "compile", "__import__"}))
        self.assertTrue(attributes.isdisjoint({"unlink", "remove", "rename", "replace", "write", "write_text", "connect", "send", "run", "Popen", "system"}))

    def test_45_public_core_parameters_exclude_real_inputs_and_capabilities(self):
        forbidden = {"password", "recovery_root", "keyring", "vault", "path", "filename", "source", "callback", "executor", "operation", "storage"}
        for function in (
            harness.prepare_synthetic_recovery_source_inspection_visual_case,
            harness.build_recovery_source_inspection_visual_harness_report,
            harness.recovery_source_inspection_visual_harness_report_json,
            harness.visual_observations_pass,
        ):
            self.assertTrue(set(inspect.signature(function).parameters).isdisjoint(forbidden))

    def test_46_launcher_has_no_automatic_gui_event_injection(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("event_generate", source)
        self.assertNotIn("invoke()", source)
        self.assertNotIn(".set(True)", source)

    def test_47_launcher_uses_relative_not_absolute_tk_scaling(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertIn('base_scaling = float(root.tk.call("tk", "scaling"))', source)
        self.assertIn("base_scaling * case.scale_percent / 100.0", source)
        self.assertNotIn('root.tk.call("tk", "scaling", case.scale_percent / 100.0)', source)

    def test_48_launcher_has_bounded_map_watchdog_and_stderr_prompts(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertIn("_MAP_MAX_POLLS = 80", source)
        self.assertIn('mapping_state["timed_out"] = True', source)
        self.assertIn("file=sys.stderr", source)

    def test_49_instruction_has_exact_numbered_manual_sequence(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        for number in range(1, 10):
            self.assertIn(f'"{number}. ', source)
        self.assertIn("_instruction_text(case, action)", source)

    def test_50_each_terminal_action_has_distinct_visible_instruction(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        for action in ("escape_key", "cancel_button", "window_close", "acknowledge"):
            self.assertIn(f'"{action}"', source)
        self.assertIn("не натискайте бутона", source)

    def test_51_launcher_has_no_terminal_observation_input(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("sys.stdin", source)
        self.assertNotIn("readline", source)
        self.assertNotIn("input(", source)
        self.assertNotIn("_read_observation", source)

    def test_52_instruction_and_observation_windows_are_resizable(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("root.resizable(True, True)"), 2)
        self.assertNotIn("root.resizable(False, False)", source)

    def test_53_instruction_phase_has_own_scrollable_canvas(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._show_case_instructions)
        self.assertIn("tk.Canvas", source)
        self.assertIn("ttk.Scrollbar", source)
        self.assertIn("scrollregion", source)

    def test_54_instruction_wrap_tracks_visible_width_with_bounds(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertIn("_WRAP_MIN = 240", source)
        self.assertIn("_WRAP_MAX = 960", source)
        self.assertIn("event.width - 48", source)

    def test_55_gui_observation_schema_has_exact_six_rows(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        self.assertEqual(
            tuple(name for name, _ in launcher._OBSERVATION_ROWS),
            tuple(item.name for item in dataclasses.fields(harness.RecoverySourceInspectionVisualHarnessObservations)),
        )

    def test_56_observations_start_without_preselected_result(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._observation_dialog)
        self.assertIn('tk.StringVar(master=root, value="")', source)
        self.assertNotIn('value="pass"', source)

    def test_57_observation_submit_starts_disabled(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._observation_dialog)
        self.assertIn('text="Запиши наблюденията"', source)
        self.assertIn('state="disabled"', source)
        self.assertIn("all(value.get() for value in variables.values())", source)

    def test_58_observation_choices_are_explicit_and_vertical(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._observation_dialog)
        for value in ("pass", "fail", "not_checked"):
            self.assertIn(f'"{value}"', source)
        self.assertIn('radio.pack(anchor="w"', source)
        self.assertNotIn('radio.pack(side="left"', source)

    def test_59_terminal_action_is_validated_before_observation_dialog(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._run_case)
        first_report = source.index("build_recovery_source_inspection_visual_harness_report")
        observations = source.index("_observation_dialog(root, case)")
        self.assertLess(first_report, observations)

    def test_60_wrong_action_has_visible_error_and_no_report_bypass(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._run_case)
        self.assertIn("messagebox.showerror", source)
        self.assertIn("raise\n", source)

    def test_61_matrix_is_fail_fast_after_first_failed_observation_set(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness").main)
        self.assertIn("if not _run_case", source)
        self.assertIn("return 2", source)
        self.assertNotIn("all_passed", source)

    def test_62_observation_focus_reveal_is_viewport_bounded(self):
        source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertIn("_reveal_canvas_widget", source)
        self.assertIn("content.winfo_reqheight()", source)
        self.assertIn("canvas.canvasy(0)", source)

    def test_63_phase_bindings_are_removed_before_widgets_are_destroyed(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._clear_root)
        self.assertIn("root.unbind(sequence)", source)
        self.assertIn("child.destroy()", source)
        self.assertLess(source.index("root.unbind(sequence)"), source.index("child.destroy()"))

    def test_64_stdout_is_reserved_for_canonical_report_json(self):
        source = inspect.getsource(__import__("run_recovery_source_inspection_review_visual_harness")._run_case)
        self.assertIn("recovery_source_inspection_visual_harness_report_json(report)", source)
        self.assertNotIn("file=sys.stderr,\n            flush=True", source)

    def test_65_matrix_overview_declares_fixed_sequential_cases(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_matrix_overview)
        self.assertIn("осем последователни теста", source)
        self.assertIn("1 → 2 → 3 → 4", source)
        self.assertIn("Не избирате Case според резултата", source)

    def test_66_matrix_overview_lists_all_eight_terminal_actions(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_matrix_overview)
        for fragment in (
            "Case 1 — Escape",
            "Case 2 — Cancel",
            "Case 3 — X",
            "Case 4 — Confirm",
            "Case 5 — Cancel",
            "Case 6 — Escape",
            "Case 7 — Confirm",
            "Case 8 — X",
        ):
            self.assertIn(fragment, source)

    def test_67_matrix_overview_requires_explicit_acknowledgement(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_matrix_overview)
        self.assertIn("accepted = tk.BooleanVar(master=root, value=False)", source)
        self.assertIn('state="disabled"', source)
        self.assertIn("if cancelled[\"value\"] or not accepted.get()", source)

    def test_68_action_banner_is_case_specific_and_not_result_driven(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        text = launcher._action_banner_text(2, "cancel_button")
        self.assertIn("CASE 2/8", text)
        self.assertIn("CANCEL", text)
        self.assertIn("не зависи от PASS/FAIL", text)

    def test_69_each_case_start_requires_action_acknowledgement(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_case_instructions)
        self.assertIn("action_understood = tk.BooleanVar(master=root, value=False)", source)
        self.assertIn('state="disabled"', source)
        self.assertIn("if cancelled[\"value\"] or not action_understood.get()", source)

    def test_70_action_acknowledgement_names_case_and_exact_action(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_case_instructions)
        self.assertIn("Разбирам точното действие", source)
        self.assertIn("_ACTION_LABELS[action]", source)

    def test_71_instruction_says_questions_open_automatically(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        value = case(2)
        source = launcher._instruction_text(value, "cancel_button")
        self.assertIn("Въпросите се отварят автоматично", source)
        self.assertIn("Escape не е общ клавиш", source)

    def test_72_observed_action_classifier_covers_all_routes(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        expected = {
            1: "escape_key",
            2: "cancel_button",
            3: "window_close",
            4: "acknowledge",
        }
        for number, action in expected.items():
            with self.subTest(number=number):
                value = case(number)
                self.assertEqual(
                    launcher._observed_terminal_action(outcome_for(value)),
                    action,
                )

    def test_73_mismatch_diagnostic_has_case_expected_and_observed(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._run_case)
        self.assertIn("STAGE2_38_VISUAL_ACTION_MISMATCH", source)
        self.assertIn("CASE={case.case_number}", source)
        self.assertIn("EXPECTED={action}", source)
        self.assertIn("OBSERVED={observed_action}", source)

    def test_74_action_mismatch_is_rejected_before_observation_collection(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._run_case)
        mismatch = source.index("if observed_action != action")
        observations = source.index("_observation_dialog(root, case)")
        self.assertLess(mismatch, observations)

    def test_75_matching_action_contract_failure_is_distinct(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._run_case)
        self.assertIn("STAGE2_38_MATCHING_ACTION_CONTRACT_VALIDATION_FAILED", source)
        self.assertIn("вътрешна contract грешка", source)

    def test_76_overview_runs_once_and_no_automatic_event_is_added(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._run_case)
        self.assertIn("if case.case_number == 1:", source)
        self.assertIn("_show_matrix_overview(root, case)", source)
        launcher_source = LAUNCHER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("event_generate", launcher_source)
        self.assertNotIn("invoke()", launcher_source)

    def test_77_overview_has_no_case_specific_action_content(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_matrix_overview)
        tree = ast.parse(inspect.getsource(launcher._show_matrix_overview))
        loaded_names = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        self.assertNotIn("action", loaded_names)
        self.assertNotIn("case.case_number", source)
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("_action_banner_text", called_names)

    def test_78_case_action_banner_is_created_before_resize_use(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_case_instructions)
        creation = source.index("action_banner = ttk.Label(")
        resize_use = source.index("action_banner.configure(")
        self.assertLess(creation, resize_use)
        self.assertIn(
            "text=_action_banner_text(case.case_number, action)",
            source,
        )

    def test_79_runtime_geometry_accepts_exact_visible_regions(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        container = FakeGeometryWidget((0, 0, 600, 500))
        regions = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 590, 420)),
            FakeGeometryWidget((10, 420, 590, 490)),
        )
        controls = (
            FakeGeometryWidget((400, 440, 480, 475)),
            FakeGeometryWidget((490, 440, 580, 475)),
        )
        self.assertTrue(
            launcher._layout_regions_visible(container, regions, controls)
        )

    def test_80_runtime_geometry_rejects_unmapped_or_zero_widgets(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        container = FakeGeometryWidget((0, 0, 600, 500))
        middle = FakeGeometryWidget((10, 60, 590, 420))
        footer = FakeGeometryWidget((10, 420, 590, 490))
        control = FakeGeometryWidget((490, 440, 580, 475))
        for invalid in (
            FakeGeometryWidget((10, 10, 590, 60), mapped=False),
            FakeGeometryWidget((10, 10, 10, 60)),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(
                    launcher._layout_regions_visible(
                        container,
                        (invalid, middle, footer),
                        (control,),
                    )
                )

    def test_81_runtime_geometry_rejects_outside_or_overlap(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        container = FakeGeometryWidget((0, 0, 600, 500))
        footer = FakeGeometryWidget((10, 420, 590, 490))
        control = FakeGeometryWidget((490, 440, 580, 475))
        outside = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 610, 420)),
            footer,
        )
        overlap = (
            FakeGeometryWidget((10, 10, 590, 80)),
            FakeGeometryWidget((10, 60, 590, 420)),
            footer,
        )
        self.assertFalse(
            launcher._layout_regions_visible(container, outside, (control,))
        )
        self.assertFalse(
            launcher._layout_regions_visible(container, overlap, (control,))
        )

    def test_82_runtime_geometry_requires_usable_middle_height(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        container = FakeGeometryWidget((0, 0, 600, 500))
        regions = (
            FakeGeometryWidget((10, 10, 590, 60)),
            FakeGeometryWidget((10, 60, 590, 139)),
            FakeGeometryWidget((10, 139, 590, 490)),
        )
        control = FakeGeometryWidget((490, 440, 580, 475))
        self.assertEqual(launcher._MIN_MIDDLE_HEIGHT, 80)
        self.assertFalse(
            launcher._layout_regions_visible(container, regions, (control,))
        )

    def test_83_overview_uses_exact_three_region_grid(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_matrix_overview)
        self.assertIn('header.grid(row=0, column=0, sticky="ew"', source)
        self.assertIn('body.grid(row=1, column=0, sticky="nsew")', source)
        self.assertIn('footer.grid(row=2, column=0, sticky="ew"', source)
        self.assertIn("outer.rowconfigure(1, weight=1)", source)

    def test_84_case_instruction_uses_exact_three_region_grid(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._show_case_instructions)
        self.assertIn('action_banner.grid(row=0, column=0, sticky="ew"', source)
        self.assertIn('body.grid(row=1, column=0, sticky="nsew")', source)
        self.assertIn('footer.grid(row=2, column=0, sticky="ew"', source)
        self.assertIn("outer.rowconfigure(1, weight=1)", source)

    def test_85_observations_use_exact_three_region_grid(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._observation_dialog)
        self.assertIn('heading.grid(row=0, column=0, sticky="ew"', source)
        self.assertIn('body.grid(row=1, column=0, sticky="nsew")', source)
        self.assertIn('footer.grid(row=2, column=0, sticky="ew"', source)
        self.assertIn("outer.rowconfigure(1, weight=1)", source)

    def test_86_page_regions_do_not_compete_in_pack_order(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        for function in (
            launcher._show_matrix_overview,
            launcher._show_case_instructions,
            launcher._observation_dialog,
        ):
            source = inspect.getsource(function)
            self.assertNotIn("outer.pack(", source)
            self.assertNotIn("body.pack(", source)
            self.assertNotIn("footer.pack(", source)

    def test_87_geometry_failure_diagnostic_is_bounded(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        source = inspect.getsource(launcher._require_visible_layout)
        for field in ("PHASE=", "CASE=", "SCALE=", "PROFILE="):
            self.assertIn(field, source)
        for forbidden in ("winfo_screen", "rootx", "rooty", "width=", "height="):
            self.assertNotIn(forbidden, source)

    def test_88_each_phase_gates_geometry_before_user_wait(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        for function in (
            launcher._show_matrix_overview,
            launcher._show_case_instructions,
            launcher._observation_dialog,
        ):
            source = inspect.getsource(function)
            gate = source.index("_require_visible_layout(")
            wait = source.index("root.wait_variable(")
            self.assertLess(gate, wait)

    def test_89_each_phase_gates_exact_required_footer_controls(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        overview = inspect.getsource(launcher._show_matrix_overview)
        instruction = inspect.getsource(launcher._show_case_instructions)
        observations_source = inspect.getsource(launcher._observation_dialog)
        self.assertIn("(acknowledgement, start)", overview)
        self.assertIn("(action_acknowledgement, button)", instruction)
        self.assertIn("(abort, submit)", observations_source)

    def test_90_case_four_is_exact_first_200_percent_gated_case(self):
        launcher = __import__("run_recovery_source_inspection_review_visual_harness")
        value = case(4)
        self.assertEqual(value.scale_percent, 200)
        self.assertEqual(value.window_profile.value, "standard")
        source = inspect.getsource(launcher._run_case)
        self.assertIn("_show_case_instructions(root, case, action)", source)
        self.assertIn("_observation_dialog(root, case)", source)


if __name__ == "__main__":
    unittest.main()
