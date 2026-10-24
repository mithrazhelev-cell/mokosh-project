import ast
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Stage0SafetyTests(unittest.TestCase):
    def test_main_gui_is_fail_closed(self):
        tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        assignments = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        value = assignments.get("SAFETY_MODE")
        self.assertIsInstance(value, ast.Constant)
        self.assertIs(value.value, True)

    def test_launcher_no_longer_uses_retired_path(self):
        launcher = (PROJECT_ROOT / "run_mokosh_gui.sh").read_text(encoding="utf-8")
        self.assertNotIn("phi_crypto", launcher)
        self.assertIn("BASH_SOURCE", launcher)
        self.assertIn("umask 077", launcher)

    def test_active_seed_runtime_path_is_centralized(self):
        source = (PROJECT_ROOT / "seed_manager.py").read_text(encoding="utf-8")
        self.assertNotIn("~/phi_crypto", source)
        self.assertIn("mokosh_paths", source)

    def test_legacy_contacts_tombstone_has_no_runtime_path_capability(self):
        source = (PROJECT_ROOT / "contacts_core.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and not (
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
            )
        ]
        self.assertEqual(imports, [])
        self.assertNotIn("~/phi_crypto", source)
        self.assertNotIn("mokosh_paths", source)
        self.assertNotIn("cryptography", source)


if __name__ == "__main__":
    unittest.main()
