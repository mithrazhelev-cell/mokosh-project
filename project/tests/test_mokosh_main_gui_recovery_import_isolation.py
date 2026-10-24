import ast
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUI_PATH = PROJECT_ROOT / "mokosh_gui.py"


def run_python(source):
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


FAKE_ARGON2 = """
import sys
import types
argon2 = types.ModuleType('argon2')
class Type:
    ID = 'ID'
argon2.Type = Type
low_level = types.ModuleType('argon2.low_level')
low_level.hash_secret = lambda *args, **kwargs: b''
sys.modules['argon2'] = argon2
sys.modules['argon2.low_level'] = low_level
"""


class NormalMainGUIRecoveryImportIsolationTests(unittest.TestCase):
    def test_normal_import_loads_exact_minimal_mokosh_module_set(self):
        output = run_python(
            FAKE_ARGON2
            + """
import json
before = set(sys.modules)
import mokosh_gui
print(json.dumps(sorted(
    name for name in set(sys.modules) - before if name.startswith('mokosh')
)))
"""
        )
        self.assertEqual(
            json.loads(output),
            [
                "mokosh_gui",
                "mokosh_paths",
                "mokosh_vault_recovery_entry_request",
                "mokosh_vault_recovery_entry_transition",
                "mokosh_vault_recovery_locale",
            ],
        )

    def test_normal_import_does_not_load_stage_2_17_bridge(self):
        output = run_python(
            FAKE_ARGON2
            + """
import mokosh_gui
print('mokosh_vault_recovery_main_gui_bridge' in sys.modules)
"""
        )
        self.assertEqual(output, "False")

    def test_normal_import_succeeds_with_privileged_recovery_modules_blocked(self):
        output = run_python(
            FAKE_ARGON2
            + """
import importlib.abc

blocked = (
    'mokosh_vault_recovery_main_gui_bridge',
    'mokosh_vault_recovery_review_controller',
    'mokosh_vault_recovery_review_window',
    'mokosh_vault_recovery_localization',
    'mokosh_vault_recovery_presentation',
    'mokosh_vault_recovery_ui_adapter',
    'mokosh_vault_recovery_acknowledgement',
    'mokosh_vault_recovery_reconciliation',
    'mokosh_vault_recovery_workflow',
    'mokosh_vault_recovery_storage',
    'mokosh_vault_storage',
)

class Blocked(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if any(fullname == item or fullname.startswith(item + '.') for item in blocked):
            raise ImportError('blocked recovery dependency: ' + fullname)
        return None

sys.meta_path.insert(0, Blocked())
import mokosh_gui
print('PASS')
"""
        )
        self.assertEqual(output, "PASS")

    def test_explicit_conditional_contract_loads_stage_2_17_bridge(self):
        output = run_python(
            FAKE_ARGON2
            + """
import mokosh_gui
before = 'mokosh_vault_recovery_main_gui_bridge' in sys.modules
contract = mokosh_gui._recovery_review_bridge_contract()
after = 'mokosh_vault_recovery_main_gui_bridge' in sys.modules
print(before, after, ','.join(item.__name__ for item in contract))
"""
        )
        self.assertEqual(
            output,
            "False True PreparedMainGUIRecoveryReviewBinding,"
            "RecoveryMainGUIBridgeState,VaultRecoveryMainGUIBridgeError",
        )

    def test_explicit_contract_returns_exact_bridge_types(self):
        output = run_python(
            FAKE_ARGON2
            + """
import mokosh_gui
import mokosh_vault_recovery_main_gui_bridge as bridge
contract = mokosh_gui._recovery_review_bridge_contract()
print(
    contract[0] is bridge.PreparedMainGUIRecoveryReviewBinding,
    contract[1] is bridge.RecoveryMainGUIBridgeState,
    contract[2] is bridge.VaultRecoveryMainGUIBridgeError,
)
"""
        )
        self.assertEqual(output, "True True True")


class NormalMainGUIRecoveryImportStaticTests(unittest.TestCase):
    def setUp(self):
        self.source = GUI_PATH.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.functions = {
            node.name: node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
        }

    def test_bridge_is_absent_from_top_level_runtime_imports(self):
        imports = {
            node.module
            for node in self.tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn("mokosh_vault_recovery_main_gui_bridge", imports)
        self.assertIn("mokosh_vault_recovery_entry_request", imports)

    def test_type_checking_import_is_non_runtime_and_exact(self):
        block = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        )
        imports = [node for node in block.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, "mokosh_vault_recovery_main_gui_bridge")
        self.assertEqual(
            tuple(alias.name for alias in imports[0].names),
            ("PreparedMainGUIRecoveryReviewBinding",),
        )

    def test_conditional_loader_imports_only_exact_stage_2_17_bridge_types(self):
        helper = self.functions["_recovery_review_bridge_contract"]
        imports = [node for node in ast.walk(helper) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, "mokosh_vault_recovery_main_gui_bridge")
        self.assertEqual(
            tuple(alias.name for alias in imports[0].names),
            (
                "PreparedMainGUIRecoveryReviewBinding",
                "RecoveryMainGUIBridgeState",
                "VaultRecoveryMainGUIBridgeError",
            ),
        )

    def test_conditional_loader_has_exact_no_argument_signature(self):
        helper = self.functions["_recovery_review_bridge_contract"]
        self.assertEqual(helper.args.args, [])
        self.assertIsNone(helper.returns)

    def test_no_dynamic_import_execution_or_plugin_loader(self):
        calls = {
            node.func.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            calls.isdisjoint(
                {"__import__", "eval", "exec", "compile", "load_plugin"}
            )
        )
        self.assertNotIn("importlib", self.source)

    def test_default_main_guard_still_calls_main_without_binding(self):
        calls = [
            node
            for node in self.tree.body
            if isinstance(node, ast.If)
            for node in ast.walk(node)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "main"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, [])
        self.assertEqual(calls[0].keywords, [])

    def test_bridge_loader_is_reached_only_inside_explicit_review_paths(self):
        allowed = {
            "show_prepared_recovery_review",
            "main",
        }
        classes = {"_PreparedRecoveryReviewGUIEvent"}
        for name, function in self.functions.items():
            calls = {
                node.func.id
                for node in ast.walk(function)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            if "_recovery_review_bridge_contract" in calls:
                self.assertIn(name, allowed)
        class_users = {
            node.name
            for node in self.tree.body
            if isinstance(node, ast.ClassDef)
            and any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "_recovery_review_bridge_contract"
                for call in ast.walk(node)
            )
        }
        self.assertEqual(class_users, classes)

    def test_main_loads_bridge_only_after_non_none_binding_check(self):
        main = self.functions["main"]
        guarded = next(
            node
            for node in main.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "prepared_recovery_review_binding"
        )
        calls = {
            node.func.id
            for node in ast.walk(guarded)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("_recovery_review_bridge_contract", calls)

    def test_show_seam_keeps_exact_signature_and_exact_type_check(self):
        seam = self.functions["show_prepared_recovery_review"]
        self.assertEqual(
            tuple(arg.arg for arg in seam.args.args),
            ("parent", "prepared_binding"),
        )
        calls = {
            node.func.id
            for node in ast.walk(seam)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("_recovery_review_bridge_contract", calls)
        self.assertIn("type", calls)

    def test_review_and_normal_gui_text_registries_remain_exact(self):
        expected = {
            "_RECOVERY_REVIEW_WIDGET_TEXT": "ab32053a7cde7f680069f8527f024a8b177f880eb0cae71d97f6aeefbb918dd8",
            "STRINGS": "ea374dd896f179aa37e234c282c80d7e91865ae6a97902f145b79c81faf6aeca",
        }
        assignments = {
            target.id: node.value
            for node in self.tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                encoded = ast.dump(assignments[name], include_attributes=False).encode()
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)

    def test_safety_mode_remains_true(self):
        assignment = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "SAFETY_MODE"
        )
        self.assertIs(assignment.value.value, True)

    def test_recovery_import_isolation_adds_no_source_or_operation_import(self):
        imports = {
            node.module
            for node in ast.walk(self.tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
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

    def test_critical_contract_and_runtime_files_remain_byte_exact(self):
        expected = {
            "mokosh_vault_recovery_main_gui_bridge.py": "0bd00a10a21a0e5d595dbacafe1f20bdcfb13ca516d1caba1d32af731eec8047",
            "mokosh_vault_recovery_review_controller.py": "88d1088fc53b92a71a96e019ee3ce6f33b7348ec5d7cf34bdbadfb265b8d33d5",
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
            "mokosh_vault_recovery_entry_transition.py": "8558efa6b8b27c28969e55bc179e3da97796b14f3a06c1b6d8cee08cf91ed697",
            "mokosh_vault_recovery_locale.py": "4d4a2e4db1b2a41335a208d42b2aeb7fdcb2d08784f42c8e1d95f5d1a8dfa827",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_contract_documents_exact_no_source_no_authority_boundary(self):
        source = (
            PROJECT_ROOT
            / "docs/MAIN_GUI_RECOVERY_IMPORT_ISOLATION_CONTRACT_BG.md"
        ).read_text(encoding="utf-8")
        for text in (
            "normal startup не зарежда Stage 2.17 bridge",
            "не избира и не подготвя recovery source",
            "operation authority",
            "SAFETY_MODE=True",
        ):
            with self.subTest(text=text):
                self.assertIn(text, source)


if __name__ == "__main__":
    unittest.main()
