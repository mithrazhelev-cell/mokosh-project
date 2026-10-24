import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUI_PATH = PROJECT_ROOT / "mokosh_gui.py"
PATHS_PATH = PROJECT_ROOT / "mokosh_paths.py"


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


def run_python(source, *, data_dir):
    environment = os.environ.copy()
    environment["MOKOSH_DATA_DIR"] = str(data_dir)
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


class RuntimePathInitializationProcessTests(unittest.TestCase):
    def test_normal_gui_import_does_not_create_absent_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                FAKE_ARGON2
                + """
import json
import os
from pathlib import Path
target = Path(os.environ['MOKOSH_DATA_DIR'])
before = target.exists()
import mokosh_gui
print(json.dumps([before, target.exists()]))
""",
                data_dir=target,
            )
            self.assertEqual(json.loads(output), [False, False])

    def test_normal_gui_import_does_not_chmod_existing_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing"
            target.mkdir(mode=0o755)
            target.chmod(0o755)
            before = stat.S_IMODE(target.stat().st_mode)
            output = run_python(
                FAKE_ARGON2
                + """
import os
import stat
from pathlib import Path
target = Path(os.environ['MOKOSH_DATA_DIR'])
import mokosh_gui
print(stat.S_IMODE(target.stat().st_mode))
""",
                data_dir=target,
            )
            self.assertEqual(int(output), before)

    def test_direct_paths_import_does_not_create_absent_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                """
import os
from pathlib import Path
target = Path(os.environ['MOKOSH_DATA_DIR'])
import mokosh_paths
print(target.exists())
""",
                data_dir=target,
            )
            self.assertEqual(output, "False")

    def test_explicit_ensure_creates_private_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                """
import os
import stat
from pathlib import Path
from mokosh_paths import ensure_private_data_dir
target = Path(os.environ['MOKOSH_DATA_DIR'])
result = ensure_private_data_dir()
print(result == target.resolve(), stat.S_IMODE(target.stat().st_mode))
""",
                data_dir=target,
            )
            self.assertEqual(output, "True 448")

    def test_explicit_ensure_tightens_existing_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing"
            target.mkdir(mode=0o755)
            target.chmod(0o755)
            output = run_python(
                """
import os
import stat
from pathlib import Path
from mokosh_paths import ensure_private_data_dir
target = Path(os.environ['MOKOSH_DATA_DIR'])
ensure_private_data_dir()
print(stat.S_IMODE(target.stat().st_mode))
""",
                data_dir=target,
            )
            self.assertEqual(output, "448")

    def test_main_prepares_runtime_directory_before_tk_root(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                FAKE_ARGON2
                + """
from unittest.mock import patch
import mokosh_gui
events = []
class Stop(Exception):
    pass
def prepared():
    events.append('ensure')
def tk_root():
    events.append('tk')
    raise Stop
with patch.object(mokosh_gui, 'ensure_private_data_dir', side_effect=prepared):
    with patch.object(mokosh_gui.tk, 'Tk', side_effect=tk_root):
        try:
            mokosh_gui.main()
        except Stop:
            pass
print(','.join(events))
""",
                data_dir=target,
            )
            self.assertEqual(output, "ensure,tk")

    def test_preparation_failure_blocks_tk_root(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                FAKE_ARGON2
                + """
from unittest.mock import patch
import mokosh_gui
with patch.object(
    mokosh_gui, 'ensure_private_data_dir', side_effect=OSError('blocked')
) as ensure:
    with patch.object(mokosh_gui.tk, 'Tk') as tk_root:
        try:
            mokosh_gui.main()
        except OSError as error:
            result = str(error)
print(result, ensure.call_count, tk_root.call_count)
""",
                data_dir=target,
            )
            self.assertEqual(output, "blocked 1 0")

    def test_invalid_conditional_binding_is_rejected_before_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            output = run_python(
                FAKE_ARGON2
                + """
from unittest.mock import patch
import mokosh_gui
with patch.object(mokosh_gui, 'ensure_private_data_dir') as ensure:
    try:
        mokosh_gui.main(object())
    except TypeError:
        result = 'rejected'
print(result, ensure.call_count)
""",
                data_dir=target,
            )
            self.assertEqual(output, "rejected 0")


class RuntimePathInitializationStaticTests(unittest.TestCase):
    def setUp(self):
        self.gui_source = GUI_PATH.read_text(encoding="utf-8")
        self.gui_tree = ast.parse(self.gui_source)
        self.paths_source = PATHS_PATH.read_text(encoding="utf-8")
        self.paths_tree = ast.parse(self.paths_source)
        self.gui_functions = {
            node.name: node
            for node in self.gui_tree.body
            if isinstance(node, ast.FunctionDef)
        }

    def test_paths_module_has_no_module_level_ensure_call(self):
        calls = [
            node
            for statement in self.paths_tree.body
            if not isinstance(statement, (ast.FunctionDef, ast.ClassDef))
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ensure_private_data_dir"
        ]
        self.assertEqual(calls, [])

    def test_paths_module_imports_only_stdlib_dependencies(self):
        imported = set()
        for node in self.paths_tree.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertEqual(imported, {"__future__", "os", "pathlib"})

    def test_gui_imports_exact_explicit_preparation_function(self):
        imports = [
            node
            for node in self.gui_tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "mokosh_paths"
        ]
        self.assertEqual(len(imports), 1)
        self.assertEqual(
            tuple(alias.name for alias in imports[0].names),
            ("ensure_private_data_dir",),
        )

    def test_only_main_calls_explicit_preparation(self):
        callers = []
        for name, function in self.gui_functions.items():
            count = sum(
                1
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ensure_private_data_dir"
            )
            callers.extend([name] * count)
        self.assertEqual(callers, ["main"])

    def test_main_prepares_after_binding_validation_and_before_tk(self):
        main = self.gui_functions["main"]
        ensure_call = next(
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ensure_private_data_dir"
        )
        tk_call = next(
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "tk"
            and node.func.attr == "Tk"
        )
        binding_guard = next(
            node
            for node in main.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "prepared_recovery_review_binding"
        )
        self.assertLess(binding_guard.lineno, ensure_call.lineno)
        self.assertLess(ensure_call.lineno, tk_call.lineno)

    def test_gui_contains_no_new_directory_mutation_primitive(self):
        attributes = {
            node.attr
            for node in ast.walk(self.gui_tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(attributes.isdisjoint({"mkdir", "makedirs", "chmod"}))

    def test_gui_text_registries_and_safety_mode_remain_exact(self):
        expected = {
            "_RECOVERY_REVIEW_WIDGET_TEXT": "ab32053a7cde7f680069f8527f024a8b177f880eb0cae71d97f6aeefbb918dd8",
            "STRINGS": "ea374dd896f179aa37e234c282c80d7e91865ae6a97902f145b79c81faf6aeca",
        }
        assignments = {
            target.id: node.value
            for node in self.gui_tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for name, digest in expected.items():
            encoded = ast.dump(assignments[name], include_attributes=False).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)
        self.assertIs(assignments["SAFETY_MODE"].value, True)

    def test_no_recovery_source_or_operation_import_is_added(self):
        imported = {
            node.module
            for node in ast.walk(self.gui_tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(
            imported.isdisjoint(
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

    def test_critical_legacy_recovery_and_runtime_files_remain_byte_exact(self):
        expected = {
            "seed_manager.py": "3b5b7c3d1b47338185a2fb8b28b9a7f621ce48698e31df6cdef429aadafe818e",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
            "mokosh_vault_recovery_entry_transition.py": "8558efa6b8b27c28969e55bc179e3da97796b14f3a06c1b6d8cee08cf91ed697",
            "mokosh_vault_recovery_locale.py": "4d4a2e4db1b2a41335a208d42b2aeb7fdcb2d08784f42c8e1d95f5d1a8dfa827",
            "mokosh_vault_recovery_main_gui_bridge.py": "0bd00a10a21a0e5d595dbacafe1f20bdcfb13ca516d1caba1d32af731eec8047",
            "mokosh_vault_recovery_review_controller.py": "88d1088fc53b92a71a96e019ee3ce6f33b7348ec5d7cf34bdbadfb265b8d33d5",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / filename).read_bytes()).hexdigest(),
                    digest,
                )

    def test_contract_documents_exact_boundary_and_limitations(self):
        source = (
            PROJECT_ROOT
            / "docs/MAIN_GUI_RUNTIME_PATH_INITIALIZATION_CONTRACT_BG.md"
        ).read_text(encoding="utf-8")
        for text in (
            "normal `import mokosh_gui`",
            "не създават и не",
            "conditional prepared-review binding се валидира преди",
            "не избира, не отваря и не подготвя recovery source",
            "operation authority",
            "SAFETY_MODE=True",
        ):
            with self.subTest(text=text):
                self.assertIn(text, source)


if __name__ == "__main__":
    unittest.main()
