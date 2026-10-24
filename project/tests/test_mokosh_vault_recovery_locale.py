import ast
import hashlib
import json
import pickle
import subprocess
import sys
import unittest
from pathlib import Path

import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_locale as locale
import mokosh_vault_recovery_localization as localization


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_python(source):
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def imported_mokosh_modules(target):
    source = f"""
import json
import sys
before = set(sys.modules)
__import__({target!r})
print(json.dumps(sorted(
    name for name in set(sys.modules) - before if name.startswith('mokosh')
)))
"""
    return json.loads(run_python(source))


class RecoveryLocaleLeafIdentityTests(unittest.TestCase):
    def test_exact_two_locale_members_and_values(self):
        self.assertEqual(
            tuple(locale.RecoveryLocalizationLocale),
            (
                locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
                locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
            ),
        )
        self.assertEqual(
            tuple(item.value for item in locale.RecoveryLocalizationLocale),
            ("bg-BG", "en-GB"),
        )

    def test_locale_enum_has_no_aliases_or_extra_members(self):
        self.assertEqual(
            tuple(locale.RecoveryLocalizationLocale.__members__),
            ("BULGARIAN_BULGARIA", "ENGLISH_UNITED_KINGDOM"),
        )

    def test_leaf_public_export_is_exact(self):
        self.assertEqual(locale.__all__, ("RecoveryLocalizationLocale",))

    def test_existing_localization_api_reexports_same_enum_object(self):
        self.assertIs(
            localization.RecoveryLocalizationLocale,
            locale.RecoveryLocalizationLocale,
        )

    def test_entry_contracts_share_same_enum_identity(self):
        self.assertIs(request.RecoveryLocalizationLocale, locale.RecoveryLocalizationLocale)
        self.assertIs(transition.RecoveryLocalizationLocale, locale.RecoveryLocalizationLocale)

    def test_existing_entry_request_behavior_is_unchanged(self):
        prepared = request.prepare_recovery_entry_request("bg-BG")
        outcome = prepared.decide_once(
            request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        )
        self.assertIs(
            outcome.locale,
            locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        )
        self.assertFalse(outcome.source_access_authorized)
        self.assertFalse(outcome.operation_authorized)

    def test_existing_entry_transition_behavior_is_unchanged(self):
        entry = request.prepare_recovery_entry_request("en-GB").decide_once(
            request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
        )
        outcome = transition.prepare_recovery_entry_transition(entry).decide_once(
            transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
        )
        self.assertIs(
            outcome.locale,
            locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        )
        self.assertFalse(outcome.source_selection_performed)
        self.assertFalse(outcome.operation_authorized)

    def test_locale_pickle_round_trip_keeps_exact_identity(self):
        value = locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
        self.assertIs(pickle.loads(pickle.dumps(value)), value)


class RecoveryLocaleLeafIsolationTests(unittest.TestCase):
    def test_leaf_import_loads_only_leaf_project_module(self):
        self.assertEqual(
            imported_mokosh_modules("mokosh_vault_recovery_locale"),
            ["mokosh_vault_recovery_locale"],
        )

    def test_entry_request_import_loads_only_request_and_leaf(self):
        self.assertEqual(
            imported_mokosh_modules("mokosh_vault_recovery_entry_request"),
            [
                "mokosh_vault_recovery_entry_request",
                "mokosh_vault_recovery_locale",
            ],
        )

    def test_entry_transition_import_loads_only_transition_request_and_leaf(self):
        self.assertEqual(
            imported_mokosh_modules("mokosh_vault_recovery_entry_transition"),
            [
                "mokosh_vault_recovery_entry_request",
                "mokosh_vault_recovery_entry_transition",
                "mokosh_vault_recovery_locale",
            ],
        )

    def test_entry_contracts_import_without_crypto_gui_or_privileged_recovery(self):
        source = """
import importlib.abc
import sys

blocked_prefixes = (
    'argon2',
    'cryptography',
    'tkinter',
    'mokosh_vault_storage',
    'mokosh_vault_recovery_storage',
    'mokosh_vault_recovery_reconciliation',
    'mokosh_vault_recovery_workflow',
    'mokosh_vault_recovery_review_controller',
    'mokosh_vault_recovery_main_gui_bridge',
)

class Blocked(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if any(fullname == item or fullname.startswith(item + '.') for item in blocked_prefixes):
            raise ImportError('blocked boundary dependency: ' + fullname)
        return None

sys.meta_path.insert(0, Blocked())
import mokosh_vault_recovery_locale
import mokosh_vault_recovery_entry_request
import mokosh_vault_recovery_entry_transition
print('PASS')
"""
        self.assertEqual(run_python(source), "PASS")

    def test_leaf_source_imports_only_future_and_enum(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_locale.py").read_text(
                encoding="utf-8"
            )
        )
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertEqual(imports, {"__future__", "enum"})

    def test_leaf_has_no_functions_dataclasses_or_operation_calls(self):
        tree = ast.parse(
            (PROJECT_ROOT / "mokosh_vault_recovery_locale.py").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(
            any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Call))
                for node in ast.walk(tree)
            )
        )

    def test_entry_contracts_import_leaf_not_heavy_localization(self):
        for filename in (
            "mokosh_vault_recovery_entry_request.py",
            "mokosh_vault_recovery_entry_transition.py",
        ):
            with self.subTest(filename=filename):
                source = (PROJECT_ROOT / filename).read_text(encoding="utf-8")
                self.assertIn("from mokosh_vault_recovery_locale import", source)
                self.assertNotIn("from mokosh_vault_recovery_localization import", source)

    def test_localization_catalog_source_is_behaviorally_unchanged_except_enum_import(self):
        self.assertEqual(len(localization._BG_MESSAGE_TEXTS), 24)
        self.assertEqual(len(localization._EN_MESSAGE_TEXTS), 24)
        self.assertEqual(
            localization._catalog_pairs(
                locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
            )[0],
            localization._BG_MESSAGE_TEXTS,
        )
        self.assertEqual(
            localization._catalog_pairs(
                locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM
            )[0],
            localization._EN_MESSAGE_TEXTS,
        )

    def test_safety_mode_and_critical_runtime_files_remain_byte_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
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
        gui_tree = ast.parse((PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8"))
        safety = next(
            node.value
            for node in gui_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "SAFETY_MODE"
        )
        self.assertIs(safety.value, True)

    def test_contract_documents_exact_dependency_boundary(self):
        source = (
            PROJECT_ROOT / "docs/VAULT_RECOVERY_LOCALE_LEAF_CONTRACT_BG.md"
        ).read_text(encoding="utf-8")
        for text in (
            "stdlib-only leaf",
            "не избира и не подготвя recovery source",
            "operation authority",
            "SAFETY_MODE=True",
        ):
            with self.subTest(text=text):
                self.assertIn(text, source)


if __name__ == "__main__":
    unittest.main()
