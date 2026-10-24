import ast
import hashlib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

HARNESS_FILES = (
    "mokosh_vault_recovery_main_gui_visual_harness.py",
    "mokosh_vault_recovery_entry_main_gui_visual_harness.py",
    "mokosh_vault_recovery_entry_transition_main_gui_visual_harness.py",
)
RUNNER_FILES = (
    "run_main_gui_recovery_review_visual_harness.py",
    "run_main_gui_recovery_entry_visual_harness.py",
    "run_main_gui_recovery_entry_transition_visual_harness.py",
)
REPORT_CLASSES = (
    "MainGUIRecoveryReviewReport",
    "RecoveryEntryMainGUIVisualReport",
    "RecoveryEntryTransitionMainGUIVisualReport",
)


def parsed(filename):
    return ast.parse((PROJECT_ROOT / filename).read_text(encoding="utf-8"))


def report_fields(filename, class_name):
    tree = parsed(filename)
    report = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return {
        node.target.id: node.value
        for node in report.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
    }


class MainGUIVisualFilesystemClaimSchemaTests(unittest.TestCase):
    def test_all_affected_report_versions_are_exactly_two(self):
        expected = {
            "mokosh_vault_recovery_main_gui_visual_harness.py": (
                "MAIN_GUI_VISUAL_HARNESS_VERSION",
                2,
            ),
            "mokosh_vault_recovery_entry_main_gui_visual_harness.py": (
                "RECOVERY_ENTRY_MAIN_GUI_REPORT_VERSION",
                2,
            ),
            "mokosh_vault_recovery_entry_transition_main_gui_visual_harness.py": (
                "RECOVERY_ENTRY_TRANSITION_MAIN_GUI_REPORT_VERSION",
                2,
            ),
        }
        for filename, (name, value) in expected.items():
            with self.subTest(filename=filename):
                assignments = {
                    node.targets[0].id: node.value
                    for node in parsed(filename).body
                    if isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                }
                self.assertEqual(ast.literal_eval(assignments[name]), value)

    def test_all_reports_have_exact_precise_filesystem_fields(self):
        exact = {
            "runtime_directory_preparation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
        }
        for filename, class_name in zip(HARNESS_FILES, REPORT_CLASSES):
            with self.subTest(filename=filename):
                fields = report_fields(filename, class_name)
                self.assertTrue(exact.issubset(fields))

    def test_runtime_preparation_defaults_true(self):
        for filename, class_name in zip(HARNESS_FILES, REPORT_CLASSES):
            with self.subTest(filename=filename):
                fields = report_fields(filename, class_name)
                self.assertIs(
                    ast.literal_eval(
                        fields["runtime_directory_preparation_performed"]
                    ),
                    True,
                )

    def test_recovery_source_filesystem_claims_default_false(self):
        names = (
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
        )
        for filename, class_name in zip(HARNESS_FILES, REPORT_CLASSES):
            fields = report_fields(filename, class_name)
            for name in names:
                with self.subTest(filename=filename, name=name):
                    self.assertIs(ast.literal_eval(fields[name]), False)

    def test_generic_filesystem_fields_are_absent_from_report_schemas(self):
        generic = {
            "filesystem_access_performed",
            "filesystem_mutation_performed",
        }
        for filename, class_name in zip(HARNESS_FILES, REPORT_CLASSES):
            with self.subTest(filename=filename):
                self.assertTrue(
                    generic.isdisjoint(report_fields(filename, class_name))
                )

    def test_validators_enforce_exact_true_and_false_semantics(self):
        for filename in HARNESS_FILES:
            tree = parsed(filename)
            validator = next(
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "_validate_report"
            )
            source = ast.unparse(validator)
            with self.subTest(filename=filename):
                self.assertIn(
                    "runtime_directory_preparation_performed",
                    source,
                )
                self.assertIn(
                    "recovery_source_filesystem_access_performed",
                    source,
                )
                self.assertIn(
                    "recovery_source_filesystem_mutation_performed",
                    source,
                )

    def test_canonical_json_encoders_use_only_precise_filesystem_keys(self):
        exact = {
            "runtime_directory_preparation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
        }
        generic = {
            "filesystem_access_performed",
            "filesystem_mutation_performed",
        }
        for filename in HARNESS_FILES:
            tree = parsed(filename)
            json_functions = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name.endswith("report_json")
            ]
            self.assertEqual(len(json_functions), 1)
            strings = {
                node.value
                for node in ast.walk(json_functions[0])
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
            }
            with self.subTest(filename=filename):
                self.assertTrue(exact.issubset(strings))
                self.assertTrue(generic.isdisjoint(strings))


class MainGUIVisualFilesystemClaimBoundaryTests(unittest.TestCase):
    def test_each_runner_discloses_runtime_preparation_before_main(self):
        disclosure = (
            "Normal GUI startup performs its existing private "
            "runtime-directory preparation."
        )
        for filename in RUNNER_FILES:
            tree = parsed(filename)
            disclosure_nodes = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and node.value == disclosure
            ]
            main_calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "mokosh_gui"
                and node.func.attr == "main"
            ]
            with self.subTest(filename=filename):
                self.assertEqual(len(disclosure_nodes), 1)
                self.assertEqual(len(main_calls), 1)
                self.assertLess(disclosure_nodes[0].lineno, main_calls[0].lineno)

    def test_each_runner_rejects_a_whole_process_no_filesystem_claim(self):
        for filename in RUNNER_FILES:
            strings = {
                node.value
                for node in ast.walk(parsed(filename))
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
            }
            with self.subTest(filename=filename):
                self.assertTrue(
                    any(
                        "no whole-process no-filesystem-access" in value
                        for value in strings
                    )
                )

    def test_report_cores_add_no_direct_privileged_import(self):
        forbidden = {
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
        for filename in HARNESS_FILES:
            imports = {
                alias.name.split(".")[0]
                for node in parsed(filename).body
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
            }
            with self.subTest(filename=filename):
                self.assertTrue(imports.isdisjoint(forbidden))

    def test_critical_runtime_and_core_files_remain_byte_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_contract_records_exact_correction_and_forbidden_scope(self):
        source = (
            PROJECT_ROOT
            / "docs/MAIN_GUI_VISUAL_FILESYSTEM_CLAIM_SEMANTICS_CONTRACT_BG.md"
        ).read_text(encoding="utf-8")
        for token in (
            "runtime_directory_preparation_performed=true",
            "recovery_source_filesystem_access_performed=false",
            "recovery_source_filesystem_mutation_performed=false",
            "Историческите version-1 JSON reports",
            "не избира, не задържа, не отваря и не валидира recovery source",
            "не наблюдава system calls",
            "whole-process filesystem",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
