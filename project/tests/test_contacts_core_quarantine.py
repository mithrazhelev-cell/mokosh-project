import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTACTS_SOURCE = PROJECT_ROOT / "contacts_core.py"
QUARANTINE_ID = "MOKOSH-STAGE2.45.1-LEGACY-CONTACTS"


class ContactsCoreQuarantineTests(unittest.TestCase):
    def test_tombstone_has_no_runtime_import_or_function_surface(self):
        source = CONTACTS_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        runtime_imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and not (
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
            )
        ]
        functions = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assertEqual(runtime_imports, [])
        self.assertEqual(functions, [])
        self.assertNotIn("cryptography", source)
        self.assertNotIn("mokosh_paths", source)
        self.assertNotIn("import os", source)
        self.assertNotIn("import json", source)
        self.assertNotIn("base64", source)

    def test_tombstone_ends_in_unconditional_typed_raise(self):
        tree = ast.parse(CONTACTS_SOURCE.read_text(encoding="utf-8"))
        self.assertIsInstance(tree.body[-1], ast.Raise)
        exception_classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "LegacyContactSubsystemQuarantinedError"
        ]
        self.assertEqual(len(exception_classes), 1)
        self.assertEqual(ast.unparse(exception_classes[0].bases[0]), "RuntimeError")

    def test_isolated_import_refuses_before_any_data_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            isolated_data = temporary / "must_not_be_created"
            before = tuple(temporary.iterdir())
            environment = os.environ.copy()
            environment["MOKOSH_DATA_DIR"] = str(isolated_data)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; "
                        f"sys.path.insert(0, {str(PROJECT_ROOT)!r}); "
                        "import contacts_core"
                    ),
                ],
                cwd=temporary,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertIn(
                "LegacyContactSubsystemQuarantinedError",
                completed.stderr,
            )
            self.assertIn(QUARANTINE_ID, completed.stderr)
            self.assertNotIn(str(temporary), completed.stderr)
            self.assertFalse(isolated_data.exists())
            self.assertEqual(tuple(temporary.iterdir()), before)

    def test_retired_callable_names_are_absent(self):
        tree = ast.parse(CONTACTS_SOURCE.read_text(encoding="utf-8"))
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        retired = {
            "get_contacts_path",
            "ensure_contacts_file_exists",
            "load_contacts",
            "save_contacts",
            "list_contacts",
            "add_or_update_contact",
            "delete_contact",
            "import_contact_file",
            "export_contact_to_file",
            "generate_my_identity",
            "ensure_my_identity",
            "get_my_identity_public",
            "export_my_public_keys",
            "encrypt_file_for_contact",
            "decrypt_file_for_me",
            "ensure_my_pq_identity",
        }
        self.assertTrue(retired.isdisjoint(defined))

    def test_normal_gui_and_v2_contact_core_remain_byte_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_v2_contact_slots.py": "fecdf24a92565a0f7c9ea601294edb9c8cfbeb56c034d3b7964e173f3cd508cc",
        }
        observed = {
            name: hashlib.sha256((PROJECT_ROOT / name).read_bytes()).hexdigest()
            for name in expected
        }
        self.assertEqual(observed, expected)

    def test_normal_gui_has_no_contacts_core_import_and_stays_fail_closed(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        )
        assignments = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        safety_mode = assignments.get("SAFETY_MODE")
        self.assertIsInstance(safety_mode, ast.Constant)
        self.assertIs(safety_mode.value, True)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertNotIn("contacts_core", imported)
        self.assertFalse((PROJECT_ROOT / "contacts_gui.py").exists())
        self.assertFalse((PROJECT_ROOT / "contact_crypto_gui.py").exists())


if __name__ == "__main__":
    unittest.main()
