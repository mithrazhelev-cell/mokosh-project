import ast
import copy
from dataclasses import fields
import hashlib
import inspect
from pathlib import Path
import pickle
import threading
import unittest

import mokosh_vault_recovery_entry_request as request
import mokosh_vault_recovery_entry_transition as transition
import mokosh_vault_recovery_source_selection as selection


ROOT = Path(__file__).resolve().parents[1]
BG_PATH = "/home/mitra/recovery/mokosh-vault-recovery-00112233445566778899aabbccddeeff.mokr"
EN_PATH = "/srv/private/recovery/mokosh-vault-recovery-ffeeddccbbaa99887766554433221100.mokr"


def transition_outcome(locale="bg-BG", *, proceeding=True):
    entry = request.prepare_recovery_entry_request(locale).decide_once(
        request.RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
    )
    decision = (
        transition.RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
        if proceeding
        else transition.RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
    )
    return transition.prepare_recovery_entry_transition(entry).decide_once(decision)


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class VaultRecoverySourceSelectionTests(unittest.TestCase):
    def test_01_bulgarian_positive_selection_records_only_path_metadata(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        outcome = prepared.decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        self.assertEqual(outcome.locale.value, "bg-BG")
        self.assertEqual(outcome.selected_path, BG_PATH)
        self.assertTrue(outcome.source_selected)
        self.assertTrue(outcome.source_path_metadata_received)
        self.assertTrue(outcome.contains_sensitive_path_metadata)
        self.assertFalse(outcome.source_opened)
        self.assertFalse(outcome.source_identity_validated)
        self.assertFalse(outcome.source_access_authorized)

    def test_02_english_positive_selection_preserves_exact_text(self):
        prepared = selection.prepare_recovery_source_selection(
            transition_outcome("en-GB")
        )
        outcome = prepared.decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            EN_PATH,
        )
        self.assertEqual(outcome.locale.value, "en-GB")
        self.assertEqual(outcome.selected_path, EN_PATH)
        self.assertIs(
            outcome.selection_decision,
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
        )
        self.assertIs(outcome.state, selection.RecoverySourceSelectionState.COMPLETED)

    def test_03_preserve_route_contains_no_path_metadata(self):
        outcome = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP)
        self.assertIsNone(outcome.selected_path)
        self.assertFalse(outcome.source_selected)
        self.assertTrue(outcome.preserved_and_stopped)
        self.assertFalse(outcome.source_path_metadata_received)
        self.assertFalse(outcome.contains_sensitive_path_metadata)

    def test_04_preserved_transition_cannot_prepare_selection(self):
        with self.assertRaises(selection.VaultRecoverySourceSelectionDecisionError):
            selection.prepare_recovery_source_selection(
                transition_outcome(proceeding=False)
            )

    def test_05_transition_source_requires_exact_outcome_type(self):
        exact = transition_outcome()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, exact.__dict__ if hasattr(exact, "__dict__") else (), derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    selection.prepare_recovery_source_selection(invalid)

    def test_06_forged_transition_claims_are_revalidated(self):
        exact = transition_outcome()
        changes = (
            {"future_source_selection_requested": False},
            {"source_access_authorized": True},
            {"source_selection_performed": True},
            {"filesystem_access_performed": True},
            {"transition_sequence": 2},
            {"format": "WRONG"},
            {"version": 2},
            {"one_shot": False},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    selection.prepare_recovery_source_selection(
                        forged_copy(exact, **change)
                    )

    def test_07_prepared_object_retains_no_original_outcome_or_path(self):
        source = transition_outcome()
        prepared = selection.prepare_recovery_source_selection(source)
        self.assertNotIn(source, (
            getattr(prepared, name)
            for name in prepared.__slots__
            if name != "_lock"
        ))
        self.assertNotIn("path", " ".join(prepared.__slots__))
        self.assertIsNone(prepared.outcome)

    def test_08_public_constants_enums_and_signatures_are_exact(self):
        self.assertEqual(
            selection.RECOVERY_SOURCE_SELECTION_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_SELECTION",
        )
        self.assertEqual(selection.RECOVERY_SOURCE_SELECTION_VERSION, 1)
        self.assertEqual(selection.RECOVERY_SOURCE_SELECTION_SEQUENCE, 1)
        self.assertEqual(selection.MAX_RECOVERY_SOURCE_PATH_UTF8_BYTES, 4096)
        self.assertEqual(
            tuple(selection.RecoverySourceSelectionDecision),
            (
                selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP,
                selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            ),
        )
        self.assertEqual(
            tuple(inspect.signature(selection.prepare_recovery_source_selection).parameters),
            ("transition_outcome",),
        )
        self.assertEqual(
            tuple(inspect.signature(
                selection.PreparedVaultRecoverySourceSelection.decide_once
            ).parameters),
            ("self", "decision", "selected_path"),
        )

    def test_09_invalid_decision_type_does_not_consume_fresh_object(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        for invalid in (None, "select_local_recovery_record", 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionDecisionError
                ):
                    prepared.decide_once(invalid, BG_PATH)
                self.assertIs(
                    prepared.current_state,
                    selection.RecoverySourceSelectionState.AWAITING_SELECTION_DECISION,
                )
        self.assertTrue(
            prepared.decide_once(
                selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                BG_PATH,
            ).source_selected
        )

    def test_10_selected_path_requires_exact_string_type(self):
        for invalid in (None, b"/tmp/a.mokr", Path("/tmp/a.mokr"), 1, True):
            prepared = selection.prepare_recovery_source_selection(
                transition_outcome()
            )
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    prepared.decide_once(
                        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                        invalid,
                    )
                self.assertIsNone(prepared.outcome)

    def test_11_empty_root_and_relative_paths_are_rejected(self):
        for invalid in ("", "/", "relative/file.mokr", "./file.mokr", "../file.mokr"):
            prepared = selection.prepare_recovery_source_selection(
                transition_outcome()
            )
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    prepared.decide_once(
                        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                        invalid,
                    )

    def test_12_lexically_ambiguous_posix_paths_are_rejected(self):
        for invalid in (
            "//tmp/file.mokr",
            "/tmp//file.mokr",
            "/tmp/./file.mokr",
            "/tmp/../file.mokr",
            "/tmp/recovery/",
        ):
            prepared = selection.prepare_recovery_source_selection(
                transition_outcome()
            )
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    prepared.decide_once(
                        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                        invalid,
                    )

    def test_13_utf8_path_bound_is_exact(self):
        accepted = "/" + ("a" * 4095)
        rejected = "/" + ("a" * 4096)
        outcome = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            accepted,
        )
        self.assertEqual(len(outcome.selected_path.encode("utf-8")), 4096)
        with self.assertRaises(selection.VaultRecoverySourceSelectionSourceError):
            selection.prepare_recovery_source_selection(
                transition_outcome()
            ).decide_once(
                selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                rejected,
            )

    def test_14_surrogate_control_and_bidi_path_text_is_rejected(self):
        for invalid in (
            "/tmp/\ud800.mokr",
            "/tmp/line\nbreak.mokr",
            "/tmp/tab\tname.mokr",
            "/tmp/\u202efile.mokr",
            "/tmp/\u2066file.mokr",
        ):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionSourceError
                ):
                    selection.prepare_recovery_source_selection(
                        transition_outcome()
                    ).decide_once(
                        selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                        invalid,
                    )

    def test_15_outcome_repr_never_contains_selected_path(self):
        outcome = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        rendered = repr(outcome)
        self.assertNotIn(BG_PATH, rendered)
        self.assertNotIn("selected_path=", rendered)
        self.assertEqual(outcome.selected_path, BG_PATH)

    def test_16_prepared_repr_contains_no_path_or_source_object(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        rendered = repr(prepared)
        self.assertIn("bg-BG", rendered)
        self.assertIn("awaiting_selection_decision", rendered)
        self.assertNotIn("VaultRecoveryEntryTransitionOutcome", rendered)
        self.assertNotIn("selected_path", rendered)

    def test_17_preserve_route_rejects_path_without_consumption(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        with self.assertRaises(selection.VaultRecoverySourceSelectionDecisionError):
            prepared.decide_once(
                selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP,
                BG_PATH,
            )
        self.assertIsNone(prepared.outcome)
        outcome = prepared.decide_once(
            selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP
        )
        self.assertTrue(outcome.preserved_and_stopped)

    def test_18_selected_prepared_object_is_one_shot(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        first = prepared.decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        with self.assertRaises(selection.VaultRecoverySourceSelectionReplayError):
            prepared.decide_once(
                selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                EN_PATH,
            )
        self.assertIs(prepared.outcome, first)

    def test_19_preserved_prepared_object_is_one_shot(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        first = prepared.decide_once(
            selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP
        )
        with self.assertRaises(selection.VaultRecoverySourceSelectionReplayError):
            prepared.decide_once(
                selection.RecoverySourceSelectionDecision.PRESERVE_AND_STOP
            )
        self.assertIs(prepared.outcome, first)

    def test_20_prepared_object_refuses_copy_deepcopy_and_pickle(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        for action in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(action=action.__name__):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionReplayError
                ):
                    action(prepared)

    def test_21_path_bearing_outcome_refuses_copy_deepcopy_and_pickle(self):
        outcome = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        for action in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(action=action.__name__):
                with self.assertRaises(TypeError):
                    action(outcome)

    def test_22_concurrent_selection_has_exactly_one_success(self):
        prepared = selection.prepare_recovery_source_selection(transition_outcome())
        barrier = threading.Barrier(12)
        outcomes = []
        errors = []
        guard = threading.Lock()

        def worker():
            barrier.wait()
            try:
                value = prepared.decide_once(
                    selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
                    BG_PATH,
                )
            except Exception as exc:
                with guard:
                    errors.append(exc)
            else:
                with guard:
                    outcomes.append(value)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for item in threads:
            item.start()
        for item in threads:
            item.join(timeout=3)
        self.assertTrue(all(not item.is_alive() for item in threads))
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(len(errors), 11)
        self.assertTrue(all(
            isinstance(error, selection.VaultRecoverySourceSelectionReplayError)
            for error in errors
        ))

    def test_23_forged_outcome_route_and_path_claims_are_rejected(self):
        exact = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        changes = (
            {"selected_path": None},
            {"source_selected": False},
            {"preserved_and_stopped": True},
            {"source_path_metadata_received": False},
            {"contains_sensitive_path_metadata": False},
            {"selection_sequence": 2},
            {"format": "WRONG"},
            {"version": 2},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionFormatError
                ):
                    selection._validate_source_selection_outcome(
                        forged_copy(exact, **change)
                    )

    def test_24_forged_outcome_authority_claims_are_rejected(self):
        exact = selection.prepare_recovery_source_selection(
            transition_outcome()
        ).decide_once(
            selection.RecoverySourceSelectionDecision.SELECT_LOCAL_RECOVERY_RECORD,
            BG_PATH,
        )
        false_flags = (
            "source_opened",
            "source_identity_validated",
            "source_access_authorized",
            "source_preparation_performed",
            "recovery_secret_received",
            "review_session_prepared",
            "operation_authorized",
            "operation_performed",
            "recovery_source_filesystem_access_performed",
            "recovery_source_filesystem_mutation_performed",
            "network_used",
            "automatic_transition",
        )
        for name in false_flags:
            with self.subTest(name=name):
                with self.assertRaises(
                    selection.VaultRecoverySourceSelectionFormatError
                ):
                    selection._validate_source_selection_outcome(
                        forged_copy(exact, **{name: True})
                    )

    def test_25_module_has_only_frozen_import_and_capability_boundary(self):
        path = ROOT / "mokosh_vault_recovery_source_selection.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_names.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called_names.add(node.func.attr)
        self.assertEqual(
            imported,
            {
                "__future__",
                "dataclasses",
                "enum",
                "posixpath",
                "threading",
                "typing",
                "unicodedata",
                "mokosh_vault_recovery_entry_request",
                "mokosh_vault_recovery_entry_transition",
                "mokosh_vault_recovery_locale",
            },
        )
        self.assertTrue({"open", "stat", "lstat", "realpath", "resolve"}.isdisjoint(called_names))
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "recovery_key",
            "password",
            "callback",
            "executor",
            "reconcile_recovery_publish",
            "prepare_recovery_workflow",
            "filedialog",
            "subprocess",
            "socket",
            "logging",
        ):
            self.assertNotIn(forbidden, source)

    def test_26_critical_runtime_and_recovery_files_remain_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "mokosh_vault_recovery_entry_request.py": "dac0b1ff779b6fd86403e8ec7ec84d2edc08d1ba1fc75da8f2ec29ab45bf15d1",
            "mokosh_vault_recovery_entry_transition.py": "8558efa6b8b27c28969e55bc179e3da97796b14f3a06c1b6d8cee08cf91ed697",
            "mokosh_vault_recovery_locale.py": "4d4a2e4db1b2a41335a208d42b2aeb7fdcb2d08784f42c8e1d95f5d1a8dfa827",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
        }
        for relative, digest in expected.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    digest,
                )
        gui = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")
        self.assertIn("SAFETY_MODE = True", gui)


if __name__ == "__main__":
    unittest.main()
