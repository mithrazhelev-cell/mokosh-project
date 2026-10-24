import ast
import copy
import dataclasses
import hashlib
import importlib
import inspect
import json
import pickle
import subprocess
import sys
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import mokosh_vault_recovery_locale as locale
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_main_gui_bridge as bridge
import mokosh_vault_recovery_source_inspection_review_controller as controller
import mokosh_vault_recovery_source_inspection_review_window as review


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RECOVERY_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
VAULT_ID = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
SOURCE_HASH = hashlib.sha256(b"source-vault").digest()
RECORD_HASH = hashlib.sha256(b"recovery-record").digest()


def positive_execution(locale_id="bg-BG"):
    return execution.VaultRecoverySourceInspectionExecutionOutcome(
        locale=(
            locale.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
            if locale_id == "bg-BG"
            else locale.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM
        ),
        execution_decision=execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION,
        state=execution.RecoverySourceInspectionExecutionState.COMPLETED,
        recovery_id=RECOVERY_ID,
        vault_id=VAULT_ID,
        source_revision=7,
        source_vault_sha256=SOURCE_HASH,
        record_sha256=RECORD_HASH,
        encoded_size=777,
        secure_source_inspection_performed=True,
        preserved_and_stopped=False,
        header_structurally_validated=True,
    )


def make_session(locale_id="bg-BG"):
    return controller.prepare_recovery_source_inspection_review_session(
        positive_execution(locale_id)
    )


def make_binding(locale_id="bg-BG"):
    return bridge.prepare_main_gui_recovery_source_inspection_review_binding(
        make_session(locale_id)
    )


def headless_outcome(parent, presentation, adapter, *, acknowledge=False):
    del parent
    prepared = review.prepare_recovery_source_inspection_review_window(
        presentation,
        adapter,
    )
    if not acknowledge:
        return prepared.cancel_once(
            review.RecoverySourceInspectionReviewWindowCancelReason.CANCEL_BUTTON
        )
    prepared.mark_messages_visible_once(
        tuple(item.ordinal for item in prepared.localized_view.message_items)
    )
    for item in prepared.localized_view.confirmation_controls:
        prepared.record_confirmation_selection(
            item.ordinal,
            item.confirmation_key,
            True,
        )
    return prepared.acknowledge_visible_once()


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in dataclasses.fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


def complete_session_with(session, outcome):
    session._outcome = outcome
    session._state = controller.RecoverySourceInspectionReviewControllerState.COMPLETED
    session._presentation = None
    session._adapter = None


def run_python(source):
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
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


def load_main_gui():
    if "mokosh_gui" in sys.modules:
        return sys.modules["mokosh_gui"]
    fake_argon2 = types.ModuleType("argon2")
    fake_argon2.Type = types.SimpleNamespace(ID="ID")
    fake_low_level = types.ModuleType("argon2.low_level")
    fake_low_level.hash_secret = lambda *args, **kwargs: b""
    with mock.patch.dict(
        sys.modules,
        {"argon2": fake_argon2, "argon2.low_level": fake_low_level},
    ):
        return importlib.import_module("mokosh_gui")


class SourceInspectionMainGUIBridgeTests(unittest.TestCase):
    def test_01_supported_locales_bind_fresh_session(self):
        for locale_id in ("bg-BG", "en-GB"):
            with self.subTest(locale_id=locale_id):
                prepared = make_binding(locale_id)
                self.assertIs(
                    prepared.current_state,
                    bridge.RecoverySourceInspectionMainGUIBridgeState.READY,
                )
                self.assertEqual(prepared.locale.value, locale_id)
                self.assertIsNone(prepared.outcome)

    def test_02_only_exact_session_type_is_accepted(self):
        for invalid in (None, {}, True, positive_execution()):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    bridge.VaultRecoverySourceInspectionMainGUIBridgeSourceError
                ):
                    bridge.prepare_main_gui_recovery_source_inspection_review_binding(
                        invalid
                    )

    def test_03_nonfresh_or_substituted_session_is_rejected(self):
        session = make_session()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            session.show_once(object())
        with self.assertRaises(
            bridge.VaultRecoverySourceInspectionMainGUIBridgeSourceError
        ):
            bridge.prepare_main_gui_recovery_source_inspection_review_binding(session)

        prepared = make_binding()
        substitute = make_session()
        prepared._session = substitute
        with self.assertRaises(
            bridge.VaultRecoverySourceInspectionMainGUIBridgeSourceError
        ):
            prepared.show_once(object())
        self.assertIs(
            substitute.current_state,
            controller.RecoverySourceInspectionReviewControllerState.PREPARED,
        )
        self.assertIs(
            prepared.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.FAILED,
        )
        self.assertIsNone(prepared._session)
        self.assertIsNone(prepared._session_identity)

    def test_04_public_prepare_has_no_locale_or_other_authority_input(self):
        self.assertEqual(
            tuple(
                inspect.signature(
                    bridge.prepare_main_gui_recovery_source_inspection_review_binding
                ).parameters
            ),
            ("prepared_session",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    bridge.PreparedMainGUIRecoverySourceInspectionReviewBinding.show_once
                ).parameters
            ),
            ("self", "parent"),
        )

    def test_05_binding_cannot_be_copied_or_serialized(self):
        prepared = make_binding()
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(
                    bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
                ):
                    operation()

    def test_06_cancelled_outcome_is_exact_and_clears_session(self):
        prepared = make_binding()
        session = prepared._session
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            outcome = prepared.show_once(object())
        self.assertEqual(session.outcome, outcome)
        self.assertIsNot(session.outcome, outcome)
        self.assertIs(
            outcome.decision,
            review.RecoverySourceInspectionReviewWindowDecision.CANCELLED,
        )
        self.assertIsNone(prepared._session)
        self.assertIsNone(prepared._session_identity)
        self.assertIs(
            prepared.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.COMPLETED,
        )

    def test_07_acknowledged_outcome_remains_no_authority(self):
        prepared = make_binding("en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=lambda *args: headless_outcome(*args, acknowledge=True),
        ):
            outcome = prepared.show_once(object())
        self.assertIs(
            outcome.decision,
            review.RecoverySourceInspectionReviewWindowDecision.ACKNOWLEDGED,
        )
        self.assertIsNotNone(outcome.acknowledgement_receipt)
        self.assertFalse(outcome.operation_authorized)
        self.assertFalse(outcome.operation_performed)

    def test_08_returned_outcome_is_the_completed_session_identity(self):
        prepared = make_binding()
        session = prepared._session
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            outcome = prepared.show_once(object())
        self.assertIs(
            session.current_state,
            controller.RecoverySourceInspectionReviewControllerState.COMPLETED,
        )
        self.assertEqual(session.outcome, outcome)
        self.assertIsNot(session.outcome, outcome)
        self.assertIs(prepared.outcome, outcome)

    def test_09_non_outcome_is_rejected_and_consumes_binding(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            return_value=None,
        ):
            with self.assertRaises(
                bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
            ):
                prepared.show_once(object())
        self.assertIs(
            prepared.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.FAILED,
        )
        self.assertIsNone(prepared._session)

    def test_10_foreign_valid_same_locale_outcome_is_rejected(self):
        first_session = make_session()
        second_session = make_session()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            own = first_session.show_once(object())
            foreign = second_session.show_once(object())
        self.assertIsNot(own, foreign)
        prepared = make_binding()

        def return_foreign(session, parent):
            del parent
            complete_session_with(session, own)
            return foreign

        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            autospec=True,
            side_effect=return_foreign,
        ):
            with self.assertRaises(
                bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
            ):
                prepared.show_once(object())

    def test_11_foreign_wrong_locale_outcome_is_rejected(self):
        foreign_session = make_session("en-GB")
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            foreign = foreign_session.show_once(object())
        prepared = make_binding("bg-BG")

        def return_wrong_locale(session, parent):
            del parent
            complete_session_with(session, foreign)
            return foreign

        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            autospec=True,
            side_effect=return_wrong_locale,
        ):
            with self.assertRaises(
                bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
            ):
                prepared.show_once(object())

    def test_12_forged_authority_outcome_is_revalidated(self):
        valid_session = make_session()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            valid = valid_session.show_once(object())
        forged = forge_dataclass(valid, operation_authorized=True)
        prepared = make_binding()

        def return_forged(session, parent):
            del parent
            session._outcome = forged
            session._state = (
                controller.RecoverySourceInspectionReviewControllerState.COMPLETED
            )
            session._presentation = None
            session._adapter = None
            return forged

        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            autospec=True,
            side_effect=return_forged,
        ):
            with self.assertRaises(
                bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
            ):
                prepared.show_once(object())

    def test_13_successful_binding_cannot_be_replayed(self):
        prepared = make_binding()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            prepared.show_once(object())
        with self.assertRaises(
            bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
        ):
            prepared.show_once(object())

    def test_14_controller_failure_is_wrapped_and_consumed(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            side_effect=controller.VaultRecoverySourceInspectionReviewControllerDisplayError(
                "synthetic"
            ),
        ):
            with self.assertRaises(
                bridge.VaultRecoverySourceInspectionMainGUIBridgeDisplayError
            ):
                prepared.show_once(object())
        self.assertIsNone(prepared._session)
        self.assertIs(
            prepared.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.FAILED,
        )

    def test_15_keyboard_interrupt_consumes_and_propagates(self):
        prepared = make_binding()
        with mock.patch.object(
            controller.PreparedVaultRecoverySourceInspectionReviewSession,
            "show_once",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.show_once(object())
        self.assertIsNone(prepared._session)
        self.assertIs(
            prepared.current_state,
            bridge.RecoverySourceInspectionMainGUIBridgeState.FAILED,
        )

    def test_16_concurrent_attempts_allow_exactly_one_display(self):
        prepared = make_binding()
        entered = threading.Event()
        release = threading.Event()

        def blocking_display(*args):
            entered.set()
            self.assertTrue(release.wait(timeout=2))
            return headless_outcome(*args)

        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=blocking_display,
        ) as show:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(prepared.show_once, object())
                self.assertTrue(entered.wait(timeout=2))
                second = pool.submit(prepared.show_once, object())
                with self.assertRaises(
                    bridge.VaultRecoverySourceInspectionMainGUIBridgeOutcomeError
                ):
                    second.result(timeout=2)
                release.set()
                result = first.result(timeout=2)
        self.assertIs(
            result.decision,
            review.RecoverySourceInspectionReviewWindowDecision.CANCELLED,
        )
        self.assertEqual(show.call_count, 1)

    def test_17_parent_is_never_retained(self):
        prepared = make_binding()
        self.assertNotIn("_parent", prepared.__slots__)
        parent = object()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            prepared.show_once(parent)
        self.assertFalse(
            any(getattr(prepared, name) is parent for name in prepared.__slots__)
        )
        self.assertNotIn("parent", repr(prepared).lower())

    def test_18_outcome_schema_has_no_source_secret_or_capability(self):
        prepared = make_binding()
        with mock.patch.object(
            controller,
            "_show_recovery_source_inspection_review_window",
            side_effect=headless_outcome,
        ):
            outcome = prepared.show_once(object())
        names = {item.name for item in dataclasses.fields(outcome)}
        forbidden = {
            "password",
            "secret",
            "recovery_root",
            "recovery_id",
            "vault_id",
            "path",
            "filename",
            "callback",
            "executor",
            "operation_capability",
            "session",
            "parent",
            "presentation",
            "adapter",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_19_bridge_imports_only_bounded_review_types(self):
        source = (
            PROJECT_ROOT
            / "mokosh_vault_recovery_source_inspection_main_gui_bridge.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        forbidden = {
            "os",
            "pathlib",
            "shutil",
            "tempfile",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "logging",
            "importlib",
            "mokosh_gui",
            "mokosh_vault_recovery",
            "mokosh_vault_storage",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_recovery_reconciliation",
            "mokosh_vault_recovery_source_inspection_execution",
        }
        self.assertTrue(imports.isdisjoint(forbidden), imports & forbidden)

    def test_20_bridge_has_no_dynamic_filesystem_or_operation_calls(self):
        source = (
            PROJECT_ROOT
            / "mokosh_vault_recovery_source_inspection_main_gui_bridge.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        calls.update(
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        )
        forbidden = {
            "open",
            "eval",
            "exec",
            "compile",
            "__import__",
            "unlink",
            "remove",
            "replace",
            "rename",
            "run",
            "Popen",
            "encrypt_file",
            "decrypt_file",
            "prepare_recovery_source_inspection_execution",
            "publish_recovery_candidate",
        }
        self.assertTrue(calls.isdisjoint(forbidden), calls & forbidden)

    def test_21_only_one_public_module_function_exists(self):
        functions = [
            name
            for name, value in vars(bridge).items()
            if inspect.isfunction(value)
            and value.__module__ == bridge.__name__
            and not name.startswith("_")
        ]
        self.assertEqual(
            functions,
            ["prepare_main_gui_recovery_source_inspection_review_binding"],
        )

    def test_22_main_gui_conditional_helper_and_seam_are_exact(self):
        gui = load_main_gui()
        self.assertEqual(
            gui._recovery_source_inspection_review_bridge_contract(),
            (
                bridge.PreparedMainGUIRecoverySourceInspectionReviewBinding,
                bridge.RecoverySourceInspectionMainGUIBridgeState,
                bridge.VaultRecoverySourceInspectionMainGUIBridgeError,
            ),
        )
        with self.assertRaises(TypeError):
            gui.show_prepared_recovery_source_inspection_review(object(), None)
        prepared = make_binding()
        sentinel = object()
        parent = object()
        with mock.patch.object(
            bridge.PreparedMainGUIRecoverySourceInspectionReviewBinding,
            "show_once",
            return_value=sentinel,
        ) as show:
            returned = gui.show_prepared_recovery_source_inspection_review(
                parent,
                prepared,
            )
        self.assertIs(returned, sentinel)
        show.assert_called_once_with(parent)

    def test_23_normal_import_and_main_do_not_activate_new_bridge(self):
        output = run_python(
            FAKE_ARGON2
            + """
import ast
import inspect
import json
import pathlib
import sys
import mokosh_gui
tree = ast.parse(pathlib.Path(mokosh_gui.__file__).read_text(encoding='utf-8'))
functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
main_calls = {
    node.func.id
    for node in ast.walk(functions['main'])
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
}
print(json.dumps({
    'bridge_loaded': 'mokosh_vault_recovery_source_inspection_main_gui_bridge' in sys.modules,
    'seam_called': 'show_prepared_recovery_source_inspection_review' in main_calls,
    'loader_called': '_recovery_source_inspection_review_bridge_contract' in main_calls,
    'main_parameters': list(inspect.signature(mokosh_gui.main).parameters),
}, sort_keys=True))
"""
        )
        self.assertEqual(
            json.loads(output),
            {
                "bridge_loaded": False,
                "loader_called": True,
                "main_parameters": [
                    "prepared_recovery_review_binding",
                    "prepared_recovery_source_inspection_review_binding",
                ],
                "seam_called": False,
            },
        )

    def test_24_critical_boundaries_and_main_safety_remain_exact(self):
        expected_hashes = {
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_source_inspection_presentation.py": "747f6b2b3d5cc1c039c9449caae0c42688ab41fce3635641d02c57ce13e67b82",
            "mokosh_vault_recovery_source_inspection_acknowledgement.py": "dbbb810d1ac074e2274cf250d8fc4a21f90566eabfdb5d749337a6ddf9170dc4",
            "mokosh_vault_recovery_source_inspection_ui_adapter.py": "93addcafcbbeb8db5aba359e3772c415faac36e8a158f03da37c34a0409561c7",
            "mokosh_vault_recovery_source_inspection_localization.py": "104a1edcc05e9d59251c966d1af34a9cee19afed8cc405ef07b7890aad0d701f",
            "mokosh_vault_recovery_source_inspection_review_window.py": "ce8ae89d656ced0be35fcbeacfe743c2baa843d8cd9d6cd036990397612b6eea",
            "mokosh_vault_recovery_source_inspection_visual_harness.py": "082984d44c5871576247fac0f078dcff006f3db448d33a4216f5f11b0ee39d37",
            "mokosh_vault_recovery_source_inspection_review_controller.py": "330a6a79451a4fc8e4d982c7468b55faa3064afc08efe1c9eafa869db2b7fda2",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "docs/VAULT_RECOVERY_SOURCE_INSPECTION_REVIEW_CONTROLLER_CONTRACT_BG.md": "d2d50c2725da84f1bd5384c52552b1aff5483c7a65b14f17dfb33d32cee77116",
        }
        for relative, expected in expected_hashes.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest(),
                    expected,
                )

        gui_source = (PROJECT_ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        gui_tree = ast.parse(gui_source)
        assignments = {
            node.targets[0].id: node.value
            for node in gui_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        self.assertIs(assignments["SAFETY_MODE"].value, True)
        module_imports = {
            node.module
            for node in gui_tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn(
            "mokosh_vault_recovery_source_inspection_main_gui_bridge",
            module_imports,
        )
        type_checking = next(
            node
            for node in gui_tree.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        )
        type_modules = {
            node.module
            for node in ast.walk(type_checking)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertEqual(type_modules, {"mokosh_vault_recovery_main_gui_bridge"})


if __name__ == "__main__":
    unittest.main()
