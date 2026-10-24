import ast
import unittest
from pathlib import Path
from unittest import mock

import mokosh_legacy_mok1_recovery_gui as legacy


ROOT = Path(__file__).resolve().parents[1]


class LegacyMOK1RecoveryBoundaryTests(unittest.TestCase):
    def test_locked_or_non_boolean_authorization_never_calls_decryptor(self):
        for authorized in (False, None, 1, "yes"):
            decryptor = mock.Mock()
            with self.subTest(authorized=authorized):
                with self.assertRaises(legacy.LegacyMOK1RecoveryGUIError):
                    legacy.recover_one_legacy_mok1(
                        "old.mok",
                        "new.bin",
                        "old password",
                        "old nickname",
                        authorized=authorized,
                        decryptor=decryptor,
                    )
                decryptor.assert_not_called()

    def test_incomplete_fields_are_rejected_before_decryptor(self):
        for index in range(4):
            values = ["old.mok", "new.bin", "old password", "old nickname"]
            values[index] = ""
            decryptor = mock.Mock()
            with self.subTest(index=index):
                with self.assertRaises(legacy.LegacyMOK1RecoveryGUIError):
                    legacy.recover_one_legacy_mok1(
                        *values,
                        authorized=True,
                        decryptor=decryptor,
                    )
                decryptor.assert_not_called()

    def test_exact_historical_credentials_and_explicit_output_are_forwarded(self):
        decryptor = mock.Mock(return_value="new.bin")
        result = legacy.recover_one_legacy_mok1(
            "old.mok",
            "new.bin",
            " old password ",
            "Old Nick",
            authorized=True,
            decryptor=decryptor,
        )
        self.assertEqual(result, "new.bin")
        decryptor.assert_called_once_with(
            "old.mok",
            "new.bin",
            " old password ",
            "Old Nick",
        )

    def test_decryptor_failure_is_not_relabelled_as_success(self):
        decryptor = mock.Mock(side_effect=RuntimeError("injected"))
        with self.assertRaises(RuntimeError):
            legacy.recover_one_legacy_mok1(
                "old.mok",
                "new.bin",
                "old password",
                "old nickname",
                authorized=True,
                decryptor=decryptor,
            )


class LegacyMOK1RecoveryStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "mokosh_legacy_mok1_recovery_gui.py").read_text(
            encoding="utf-8"
        )
        cls.tree = ast.parse(cls.source)

    def test_crypto_core_is_lazy_and_only_legacy_decrypt_is_referenced(self):
        top_imports = {
            node.module
            for node in self.tree.body
            if isinstance(node, ast.ImportFrom)
        }
        self.assertNotIn("crypto_core", top_imports)
        self.assertIn("from crypto_core import decrypt_file", self.source)
        self.assertNotIn("encrypt_file", self.source)

    def test_no_overwrite_prompt_or_destructive_filesystem_call_exists(self):
        self.assertIn("confirmoverwrite=False", self.source)
        called = {
            node.func.attr
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(called.isdisjoint({"unlink", "remove", "replace", "rename"}))

    def test_old_credentials_are_cleared_on_success_failure_and_close(self):
        self.assertGreaterEqual(self.source.count('self.password.set("")'), 3)
        self.assertGreaterEqual(self.source.count('self.nickname.set("")'), 2)


if __name__ == "__main__":
    unittest.main()
