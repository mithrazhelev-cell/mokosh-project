import ast
import dataclasses
import inspect
import json
import unittest
from pathlib import Path

import mokosh_vault_recovery_review_window as review
import mokosh_vault_recovery_ui_adapter as adapter
import mokosh_vault_recovery_visual_harness as harness


def prepared_case(route="absent", locale="bg-BG", scale=100, profile="small"):
    case = harness.prepare_synthetic_recovery_visual_case(
        route,
        locale,
        scale,
        profile,
    )
    prepared = review.prepare_recovery_review_window(
        case.presentation,
        case.adapter,
        locale,
    )
    return case, prepared


def observations(value=harness.RecoveryVisualHarnessObservation.PASS):
    return harness.RecoveryVisualHarnessObservations(value, value, value, value)


def cancelled_report(route="absent", locale="bg-BG"):
    case, prepared = prepared_case(route, locale)
    outcome = prepared.cancel_once(
        review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
    )
    return harness.build_recovery_visual_harness_report(
        case,
        outcome,
        observations(),
    )


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in dataclasses.fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


class RecoveryVisualHarnessFixtureTests(unittest.TestCase):
    def test_every_exact_route_and_locale_prepares_real_stage_214_controller(self):
        expected_counts = {
            "absent": (9, 3),
            "exact": (10, 4),
            "conflict": (9, 3),
            "preserve": (8, 3),
        }
        for route_id in harness.RECOVERY_VISUAL_HARNESS_ROUTES:
            for locale_id in harness.RECOVERY_VISUAL_HARNESS_LOCALES:
                with self.subTest(route=route_id, locale=locale_id):
                    case, prepared = prepared_case(route_id, locale_id)
                    self.assertEqual(
                        (
                            len(prepared.localized_view.message_items),
                            len(prepared.localized_view.confirmation_controls),
                        ),
                        expected_counts[route_id],
                    )
                    self.assertEqual(case.locale.value, locale_id)
                    self.assertTrue(case.synthetic_non_secret)
                    self.assertFalse(case.operation_capability_included)
                    self.assertTrue(
                        all(
                            selected is False
                            for selected in prepared.confirmation_selections
                        )
                    )

    def test_every_scale_and_window_profile_is_exact_and_bounded(self):
        for scale in harness.RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS:
            for profile, dimensions in (("small", (520, 420)), ("standard", (800, 640))):
                with self.subTest(scale=scale, profile=profile):
                    case, _ = prepared_case(scale=scale, profile=profile)
                    self.assertEqual(case.scale_percent, scale)
                    self.assertEqual((case.width, case.height), dimensions)

    def test_invalid_route_locale_scale_and_profile_are_rejected(self):
        invalid = (
            ("ABSENT", "bg-BG", 100, "small"),
            ("absent", "bg", 100, "small"),
            ("absent", "bg-BG", 101, "small"),
            ("absent", "bg-BG", True, "small"),
            ("absent", "bg-BG", 100, "tiny"),
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
                    harness.prepare_synthetic_recovery_visual_case(*values)

    def test_non_plain_identifiers_are_rejected(self):
        for field, values in (
            (0, (None, True, 1, ["absent"])),
            (1, (None, True, 1, ["bg-BG"])),
            (3, (None, True, 1, ["small"])),
        ):
            for value in values:
                args = ["absent", "bg-BG", 100, "small"]
                args[field] = value
                with self.subTest(field=field, value=value):
                    with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
                        harness.prepare_synthetic_recovery_visual_case(*args)

    def test_fixture_digest_is_deterministic_and_route_separated(self):
        digests = []
        for route_id in harness.RECOVERY_VISUAL_HARNESS_ROUTES:
            first, _ = prepared_case(route_id)
            second, _ = prepared_case(route_id)
            self.assertEqual(
                first.presentation.workflow_state_sha256,
                second.presentation.workflow_state_sha256,
            )
            digests.append(first.presentation.workflow_state_sha256)
        self.assertEqual(len(set(digests)), len(digests))

    def test_locale_does_not_change_the_synthetic_route_evidence(self):
        bulgarian, _ = prepared_case(locale="bg-BG")
        english, _ = prepared_case(locale="en-GB")
        self.assertEqual(
            bulgarian.presentation.workflow_state_sha256,
            english.presentation.workflow_state_sha256,
        )

    def test_adapter_from_different_same_route_presentation_is_rejected(self):
        first, _ = prepared_case()
        second, _ = prepared_case()
        altered_presentation = dataclasses.replace(
            second.presentation,
            workflow_state_sha256=b"X" * 32,
        )
        altered_adapter = adapter.prepare_recovery_ui_adapter(altered_presentation)
        with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
            dataclasses.replace(first, adapter=altered_adapter)


class RecoveryVisualHarnessReportTests(unittest.TestCase):
    def test_cancel_button_escape_and_window_close_are_reported_exactly(self):
        for reason in review.RecoveryReviewWindowCancelReason:
            case, prepared = prepared_case()
            outcome = prepared.cancel_once(reason)
            report = harness.build_recovery_visual_harness_report(
                case,
                outcome,
                observations(),
            )
            self.assertIs(report.cancel_reason, reason)
            self.assertIs(
                report.decision,
                review.RecoveryReviewWindowDecision.CANCELLED,
            )

    def test_acknowledged_route_builds_bounded_report(self):
        case, prepared = prepared_case("exact", "en-GB")
        prepared.mark_messages_visible_once(
            tuple(item.ordinal for item in prepared.localized_view.message_items)
        )
        for control in prepared.localized_view.confirmation_controls:
            prepared.record_confirmation_selection(
                control.ordinal,
                control.confirmation_key,
                True,
            )
        report = harness.build_recovery_visual_harness_report(
            case,
            prepared.acknowledge_visible_once(),
            observations(),
        )
        self.assertIs(
            report.decision,
            review.RecoveryReviewWindowDecision.ACKNOWLEDGED,
        )
        self.assertIsNone(report.cancel_reason)
        self.assertFalse(report.operation_performed)
        self.assertFalse(report.operation_authorized)

    def test_not_checked_is_explicit_and_does_not_claim_certification(self):
        case, prepared = prepared_case()
        outcome = prepared.cancel_once(
            review.RecoveryReviewWindowCancelReason.WINDOW_CLOSE
        )
        not_checked = observations(
            harness.RecoveryVisualHarnessObservation.NOT_CHECKED
        )
        report = harness.build_recovery_visual_harness_report(
            case,
            outcome,
            not_checked,
        )
        self.assertTrue(
            all(
                item is harness.RecoveryVisualHarnessObservation.NOT_CHECKED
                for item in dataclasses.astuple(report.observations)
            )
        )
        self.assertFalse(report.platform_certification_claimed)

    def test_report_json_is_canonical_bounded_and_nonsecret(self):
        report = cancelled_report("conflict", "en-GB")
        first = harness.recovery_visual_harness_report_json(report)
        second = harness.recovery_visual_harness_report_json(report)
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(payload["route"], "conflict")
        self.assertEqual(payload["locale"], "en-GB")
        self.assertEqual(len(payload["presentation_sha256"]), 64)
        self.assertTrue(payload["synthetic_non_secret"])
        self.assertFalse(payload["operation_authorized"])
        self.assertTrue(
            set(payload).isdisjoint(
                {
                    "password",
                    "recovery_root",
                    "keyring",
                    "vault_path",
                    "path",
                    "filename",
                    "callback",
                    "executor",
                    "notes",
                }
            )
        )

    def test_case_and_outcome_digest_or_locale_mismatch_is_rejected(self):
        first, first_prepared = prepared_case("absent", "bg-BG")
        second, second_prepared = prepared_case("exact", "en-GB")
        first_outcome = first_prepared.cancel_once(
            review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
        )
        second_outcome = second_prepared.cancel_once(
            review.RecoveryReviewWindowCancelReason.CANCEL_BUTTON
        )
        for case, outcome in ((first, second_outcome), (second, first_outcome)):
            with self.subTest(case=case.route, outcome=outcome.locale):
                with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
                    harness.build_recovery_visual_harness_report(
                        case,
                        outcome,
                        observations(),
                    )

    def test_forged_authority_and_certification_flags_are_rejected(self):
        report = cancelled_report()
        for name in (
            "platform_certification_claimed",
            "main_gui_activated",
            "true_vault_input_used",
            "operation_performed",
            "operation_authorized",
            "filesystem_mutation_performed",
            "network_used",
            "secrets_retained",
        ):
            with self.subTest(name=name):
                with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
                    harness.recovery_visual_harness_report_json(
                        forge_dataclass(report, **{name: True})
                    )

    def test_observations_accept_only_exact_enums(self):
        for invalid in ("pass", True, 1, None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(harness.VaultRecoveryVisualHarnessError):
                    harness.RecoveryVisualHarnessObservations(
                        invalid,
                        harness.RecoveryVisualHarnessObservation.PASS,
                        harness.RecoveryVisualHarnessObservation.PASS,
                        harness.RecoveryVisualHarnessObservation.PASS,
                    )

    def test_report_schema_has_no_arbitrary_text_or_sensitive_fields(self):
        names = {item.name for item in dataclasses.fields(harness.RecoveryVisualHarnessReport)}
        self.assertTrue(
            names.isdisjoint(
                {
                    "notes",
                    "comment",
                    "password",
                    "recovery_root",
                    "keyring",
                    "vault_path",
                    "path",
                    "filename",
                    "callback",
                    "executor",
                    "operation_capability",
                }
            )
        )


class RecoveryVisualHarnessStaticBoundaryTests(unittest.TestCase):
    def test_public_contract_has_no_real_input_or_operation_parameters(self):
        forbidden = {
            "password",
            "recovery_root",
            "keyring",
            "vault",
            "path",
            "filename",
            "callback",
            "executor",
            "operation",
            "candidate",
            "storage",
        }
        for function in (
            harness.prepare_synthetic_recovery_visual_case,
            harness.build_recovery_visual_harness_report,
            harness.recovery_visual_harness_report_json,
        ):
            with self.subTest(function=function.__name__):
                self.assertTrue(
                    set(inspect.signature(function).parameters).isdisjoint(forbidden)
                )

    def test_core_module_has_no_filesystem_network_process_gui_or_logging_import(self):
        source = Path(harness.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {
                    "os",
                    "pathlib",
                    "subprocess",
                    "socket",
                    "urllib",
                    "requests",
                    "logging",
                    "tkinter",
                    "time",
                    "random",
                    "secrets",
                }
            )
        )

    def test_core_module_has_no_file_dynamic_execution_or_operation_calls(self):
        source = Path(harness.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
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
        self.assertTrue(
            attributes.isdisjoint(
                {
                    "unlink",
                    "remove",
                    "rename",
                    "replace",
                    "write",
                    "write_text",
                    "write_bytes",
                    "connect",
                    "send",
                    "publish",
                    "unlock",
                }
            )
        )

    def test_launcher_is_separate_and_uses_only_synthetic_case_entrypoint(self):
        source = Path("run_recovery_review_visual_harness.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("prepare_synthetic_recovery_visual_case", source)
        self.assertIn("show_recovery_review_window", source)
        self.assertIn("tk.Tk()", source)
        self.assertIn("root.deiconify()", source)
        self.assertIn("root.update()", source)
        self.assertNotIn("root.withdraw()", source)
        self.assertNotIn("mokosh_gui", source)
        for token in (
            "VaultStorage",
            "unlock_vault",
            "publish_recovery",
            "recovery_root",
            "password",
            "keyring",
            "contacts_core",
            "requests",
            "socket",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_launcher_choices_cover_exact_matrix_scales_and_sizes(self):
        source = Path("run_recovery_review_visual_harness.py").read_text(
            encoding="utf-8"
        )
        for token in (
            "RECOVERY_VISUAL_HARNESS_ROUTES",
            "RECOVERY_VISUAL_HARNESS_LOCALES",
            "RECOVERY_VISUAL_HARNESS_SCALE_PERCENTS",
            "RECOVERY_VISUAL_HARNESS_WINDOW_PROFILES",
            '"--matrix"',
            '"--validation-matrix"',
            '"--no-observations"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
