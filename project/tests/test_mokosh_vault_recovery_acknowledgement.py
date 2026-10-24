import ast
import copy
import inspect
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from pathlib import Path

import mokosh_vault_recovery_acknowledgement as acknowledgement
import mokosh_vault_recovery_presentation as presentation
import mokosh_vault_recovery_reconciliation as reconciler
import mokosh_vault_recovery_workflow as workflow
import mokosh_vault_storage as vault_storage


RECOVERY_ID = bytes(range(16))
VAULT_ID = bytes(range(16, 32))
SOURCE_SHA256 = b"S" * 32
RECORD_SHA256 = b"R" * 32
KEYRING_SHA256 = b"K" * 32
TARGET_SHA256 = b"T" * 32


def source_receipt(**overrides):
    values = {
        "directory_device": 11,
        "directory_inode": 12,
        "vault_id": VAULT_ID,
        "revision": 1,
        "sha256": SOURCE_SHA256,
        "file_device": 13,
        "file_inode": 14,
        "encoded_size": 256,
        "durable": True,
    }
    values.update(overrides)
    return vault_storage.VaultGenerationReceipt(**values)


def target_receipt(**overrides):
    values = {
        "directory_device": 11,
        "directory_inode": 12,
        "vault_id": VAULT_ID,
        "revision": 2,
        "sha256": TARGET_SHA256,
        "file_device": 15,
        "file_inode": 16,
        "encoded_size": 288,
        "durable": True,
    }
    values.update(overrides)
    return vault_storage.VaultGenerationReceipt(**values)


def absent_result(**overrides):
    values = {
        "classification": reconciler.RecoveryPublishClassification.TARGET_ABSENT,
        "recommended_action": (
            reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE
        ),
        "recovery_id": RECOVERY_ID,
        "vault_id": VAULT_ID,
        "source_revision": 1,
        "target_revision": 2,
        "source_vault_sha256": SOURCE_SHA256,
        "record_sha256": RECORD_SHA256,
        "keyring_sha256": KEYRING_SHA256,
        "source_receipt": source_receipt(),
        "target_receipt": None,
        "target_vault_sha256": None,
        "generation_count": 1,
        "finding_count": 1,
        "omitted_entries": 0,
        "storage_complete": True,
        "stable_observation": True,
    }
    values.update(overrides)
    return reconciler.VaultRecoveryReconciliationResult(**values)


def exact_result(**overrides):
    values = {
        "classification": (
            reconciler.RecoveryPublishClassification.TARGET_EXACT_DURABLE
        ),
        "recommended_action": (
            reconciler.RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY
        ),
        "recovery_id": RECOVERY_ID,
        "vault_id": VAULT_ID,
        "source_revision": 1,
        "target_revision": 2,
        "source_vault_sha256": SOURCE_SHA256,
        "record_sha256": RECORD_SHA256,
        "keyring_sha256": KEYRING_SHA256,
        "source_receipt": source_receipt(),
        "target_receipt": target_receipt(),
        "target_vault_sha256": TARGET_SHA256,
        "generation_count": 2,
        "finding_count": 2,
        "omitted_entries": 0,
        "storage_complete": True,
        "stable_observation": True,
        "new_password_verified": True,
        "keyring_verified": True,
    }
    values.update(overrides)
    return reconciler.VaultRecoveryReconciliationResult(**values)


def conflict_result(**overrides):
    values = {
        "classification": reconciler.RecoveryPublishClassification.CONFLICT,
        "recommended_action": (
            reconciler.RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW
        ),
        "recovery_id": RECOVERY_ID,
        "vault_id": VAULT_ID,
        "source_revision": 1,
        "target_revision": 2,
        "source_vault_sha256": SOURCE_SHA256,
        "record_sha256": RECORD_SHA256,
        "keyring_sha256": KEYRING_SHA256,
        "source_receipt": source_receipt(),
        "target_receipt": None,
        "target_vault_sha256": None,
        "generation_count": 1,
        "finding_count": 2,
        "omitted_entries": 0,
        "storage_complete": True,
        "stable_observation": True,
    }
    values.update(overrides)
    return reconciler.VaultRecoveryReconciliationResult(**values)


def workflow_state(result, decision):
    prepared = workflow.prepare_recovery_workflow(result)
    return prepared.review_once(result, decision)


def present(result, decision):
    state = workflow_state(result, decision)
    return presentation.prepare_recovery_workflow_presentation(state)


def absent_presentation():
    return present(
        absent_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
    )


def exact_presentation():
    return present(
        exact_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
    )


def conflict_presentation():
    return present(
        conflict_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
    )


def preserve_presentation(result=None):
    if result is None:
        result = absent_result()
    return present(result, workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP)


def prepare(value):
    return acknowledgement.prepare_recovery_presentation_acknowledgement(value)


def acknowledge(value):
    prepared = prepare(value)
    return prepared.acknowledge_once(value, value.confirmation_requirements)


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


class RecoveryAcknowledgementRouteTests(unittest.TestCase):
    def test_absent_route_acknowledges_exact_order_without_authority(self):
        value = absent_presentation()
        receipt = acknowledge(value)
        self.assertEqual(
            receipt.acknowledged_confirmations,
            value.confirmation_requirements,
        )
        self.assertFalse(receipt.terminal_stop)
        self.assertTrue(receipt.downstream_reverification_required)
        self.assertFalse(receipt.operation_performed)
        self.assertFalse(receipt.operation_authorized)

    def test_exact_route_preserves_unlock_then_setup_confirmation_order(self):
        value = exact_presentation()
        receipt = acknowledge(value)
        self.assertEqual(
            receipt.acknowledged_confirmations,
            (
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NO_OPERATION_PERFORMED,
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED,
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
            ),
        )
        self.assertFalse(receipt.gate_invoked)
        self.assertFalse(receipt.automatic_transition)

    def test_conflict_route_remains_terminal_without_repair(self):
        receipt = acknowledge(conflict_presentation())
        self.assertTrue(receipt.terminal_stop)
        self.assertFalse(receipt.downstream_reverification_required)
        self.assertEqual(
            receipt.state,
            workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        )
        self.assertFalse(receipt.gate_invoked)

    def test_preserve_route_for_each_classification_remains_terminal(self):
        for result in (absent_result(), exact_result(), conflict_result()):
            with self.subTest(classification=result.classification):
                receipt = acknowledge(preserve_presentation(result))
                self.assertTrue(receipt.terminal_stop)
                self.assertFalse(receipt.downstream_reverification_required)
                self.assertEqual(
                    receipt.state,
                    workflow.RecoveryWorkflowState.PRESERVED_STOP,
                )

    def test_prepared_state_changes_only_after_success(self):
        value = absent_presentation()
        prepared = prepare(value)
        self.assertFalse(prepared.acknowledged)
        self.assertIsNone(prepared.receipt)
        self.assertEqual(
            prepared.current_state,
            acknowledgement.RecoveryPresentationAcknowledgementState
            .AWAITING_CONFIRMATIONS,
        )
        receipt = prepared.acknowledge_once(
            value,
            value.confirmation_requirements,
        )
        self.assertTrue(prepared.acknowledged)
        self.assertIs(prepared.receipt, receipt)
        self.assertEqual(
            prepared.current_state,
            acknowledgement.RecoveryPresentationAcknowledgementState.ACKNOWLEDGED,
        )

    def test_failed_confirmation_does_not_consume_prepared_state(self):
        value = exact_presentation()
        prepared = prepare(value)
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementConfirmationError
        ):
            prepared.acknowledge_once(
                value,
                value.confirmation_requirements[:-1],
            )
        self.assertFalse(prepared.acknowledged)
        receipt = prepared.acknowledge_once(
            value,
            value.confirmation_requirements,
        )
        self.assertTrue(receipt.all_confirmations_acknowledged)

    def test_equivalent_reconstructed_presentation_is_accepted(self):
        first = exact_presentation()
        second = replace(first)
        prepared = prepare(first)
        receipt = prepared.acknowledge_once(
            second,
            second.confirmation_requirements,
        )
        self.assertEqual(receipt.confirmation_count, 4)


class RecoveryAcknowledgementConfirmationTests(unittest.TestCase):
    def assert_confirmation_rejected(self, value, confirmations):
        prepared = prepare(value)
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementConfirmationError
        ):
            prepared.acknowledge_once(value, confirmations)
        self.assertFalse(prepared.acknowledged)

    def test_none_list_and_empty_confirmations_are_rejected(self):
        value = absent_presentation()
        for confirmations in (None, [], (), list(value.confirmation_requirements)):
            with self.subTest(confirmations=confirmations):
                self.assert_confirmation_rejected(value, confirmations)

    def test_string_confirmation_values_are_rejected(self):
        value = absent_presentation()
        self.assert_confirmation_rejected(
            value,
            tuple(item.value for item in value.confirmation_requirements),
        )

    def test_partial_confirmation_is_rejected_for_every_route(self):
        values = (
            absent_presentation(),
            exact_presentation(),
            conflict_presentation(),
            preserve_presentation(),
        )
        for value in values:
            with self.subTest(state=value.state):
                self.assert_confirmation_rejected(
                    value,
                    value.confirmation_requirements[:-1],
                )

    def test_reordered_confirmations_are_rejected(self):
        value = exact_presentation()
        self.assert_confirmation_rejected(
            value,
            tuple(reversed(value.confirmation_requirements)),
        )

    def test_duplicate_confirmations_are_rejected(self):
        value = conflict_presentation()
        changed = value.confirmation_requirements[:-1] + (
            value.confirmation_requirements[0],
        )
        self.assert_confirmation_rejected(value, changed)

    def test_supported_but_wrong_route_confirmation_is_rejected(self):
        value = absent_presentation()
        wrong = conflict_presentation().confirmation_requirements
        self.assert_confirmation_rejected(value, wrong)

    def test_extra_confirmation_is_rejected(self):
        value = preserve_presentation()
        extra = value.confirmation_requirements + (
            presentation.RecoveryPresentationConfirmationKey
            .ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
        )
        self.assert_confirmation_rejected(value, extra)

    def test_confirmation_tuple_is_bounded_and_exact_enum_only(self):
        value = exact_presentation()
        prepared = prepare(value)
        self.assertLessEqual(
            len(prepared.required_confirmations),
            presentation.MAX_PRESENTATION_CONFIRMATIONS,
        )
        self.assertTrue(
            all(
                type(item)
                is presentation.RecoveryPresentationConfirmationKey
                for item in prepared.required_confirmations
            )
        )


class RecoveryAcknowledgementPresentationBindingTests(unittest.TestCase):
    def test_different_valid_route_is_a_mismatch(self):
        original = absent_presentation()
        prepared = prepare(original)
        changed = preserve_presentation()
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementMismatchError
        ):
            prepared.acknowledge_once(
                changed,
                changed.confirmation_requirements,
            )
        self.assertFalse(prepared.acknowledged)

    def test_changed_workflow_digest_is_a_mismatch(self):
        original = absent_presentation()
        prepared = prepare(original)
        changed = replace(original, workflow_state_sha256=b"Z" * 32)
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementMismatchError
        ):
            prepared.acknowledge_once(
                changed,
                changed.confirmation_requirements,
            )

    def test_non_presentation_and_subclass_are_rejected(self):
        for value in (None, {}, absent_presentation().confirmation_requirements):
            with self.subTest(value=value):
                with self.assertRaises(
                    acknowledgement.VaultRecoveryAcknowledgementPresentationError
                ):
                    prepare(value)

        class PresentationSubclass(
            presentation.VaultRecoveryWorkflowPresentation
        ):
            pass

        original = absent_presentation()
        subclass = object.__new__(PresentationSubclass)
        for item in fields(original):
            object.__setattr__(subclass, item.name, getattr(original, item.name))
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementPresentationError
        ):
            prepare(subclass)

    def test_forged_presentation_schema_is_rejected(self):
        original = absent_presentation()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"version": True},
            {"workflow_state_sha256": b"short"},
            {"confirmation_requirements": list(original.confirmation_requirements)},
            {"confirmation_requirements": original.confirmation_requirements[:-1]},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                forged = forge_dataclass(original, **changes)
                with self.assertRaises(
                    acknowledgement.VaultRecoveryAcknowledgementPresentationError
                ):
                    prepare(forged)

    def test_forged_presentation_authority_flags_are_rejected(self):
        original = exact_presentation()
        for name, changed in (
            ("workflow_state_validated", False),
            ("fixed_message_keys_only", False),
            ("raw_text_included", True),
            ("operation_performed", True),
            ("operation_authorized", True),
            ("secrets_retained", True),
            ("operation_authorized", 0),
        ):
            with self.subTest(name=name):
                forged = forge_dataclass(original, **{name: changed})
                with self.assertRaises(
                    acknowledgement.VaultRecoveryAcknowledgementPresentationError
                ):
                    prepare(forged)

    def test_presentation_digest_is_deterministic_and_route_bound(self):
        first = acknowledge(absent_presentation())
        second = acknowledge(absent_presentation())
        changed = acknowledge(preserve_presentation())
        self.assertEqual(first.presentation_sha256, second.presentation_sha256)
        self.assertNotEqual(first.presentation_sha256, changed.presentation_sha256)
        self.assertEqual(len(first.presentation_sha256), 32)


class RecoveryAcknowledgementOneShotTests(unittest.TestCase):
    def test_second_identical_acknowledgement_is_replay(self):
        value = absent_presentation()
        prepared = prepare(value)
        prepared.acknowledge_once(value, value.confirmation_requirements)
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementReplayError
        ):
            prepared.acknowledge_once(value, value.confirmation_requirements)

    def test_replay_check_precedes_changed_input(self):
        value = absent_presentation()
        prepared = prepare(value)
        prepared.acknowledge_once(value, value.confirmation_requirements)
        changed = conflict_presentation()
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementReplayError
        ):
            prepared.acknowledge_once(changed, changed.confirmation_requirements)

    def test_prepared_acknowledgement_cannot_be_copied_or_pickled(self):
        prepared = prepare(absent_presentation())
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(
                acknowledgement.VaultRecoveryAcknowledgementReplayError
            ):
                operation()

    def test_concurrent_attempts_have_exactly_one_success(self):
        value = exact_presentation()
        prepared = prepare(value)
        count = 8
        barrier = threading.Barrier(count)

        def attempt():
            barrier.wait()
            try:
                prepared.acknowledge_once(
                    value,
                    value.confirmation_requirements,
                )
                return "success"
            except acknowledgement.VaultRecoveryAcknowledgementReplayError:
                return "replay"

        with ThreadPoolExecutor(max_workers=count) as executor:
            observed = list(executor.map(lambda _: attempt(), range(count)))
        self.assertEqual(observed.count("success"), 1)
        self.assertEqual(observed.count("replay"), count - 1)

    def test_repr_does_not_expose_presentation_digest(self):
        value = exact_presentation()
        prepared = prepare(value)
        receipt = prepared.acknowledge_once(
            value,
            value.confirmation_requirements,
        )
        rendered = repr(prepared)
        self.assertNotIn(repr(receipt.presentation_sha256), rendered)
        self.assertNotIn(repr(value.workflow_state_sha256), rendered)


class RecoveryAcknowledgementReceiptValidationTests(unittest.TestCase):
    def valid(self):
        return acknowledge(exact_presentation())

    def assert_receipt_rejected(self, original, **changes):
        with self.assertRaises(
            acknowledgement.VaultRecoveryAcknowledgementFormatError
        ):
            replace(original, **changes)

    def test_receipt_format_version_digest_and_enum_types_are_strict(self):
        value = self.valid()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"version": True},
            {"presentation_sha256": b"short"},
            {"presentation_sha256": bytearray(32)},
            {"classification": value.classification.value},
            {"decision": value.decision.value},
            {"state": value.state.value},
            {"acknowledgement_state": value.acknowledgement_state.value},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_receipt_rejected(value, **changes)

    def test_receipt_confirmations_are_exact_unique_ordered_tuple(self):
        value = self.valid()
        cases = (
            {"acknowledged_confirmations": list(value.acknowledged_confirmations)},
            {"acknowledged_confirmations": value.acknowledged_confirmations[:-1]},
            {
                "acknowledged_confirmations": tuple(
                    reversed(value.acknowledged_confirmations)
                )
            },
            {
                "acknowledged_confirmations": value.acknowledged_confirmations
                + (value.acknowledged_confirmations[0],)
            },
            {
                "acknowledged_confirmations": tuple(
                    item.value for item in value.acknowledged_confirmations
                )
            },
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_receipt_rejected(value, **changes)

    def test_receipt_count_and_sequence_are_exact_integers(self):
        value = self.valid()
        for changes in (
            {"confirmation_count": 3},
            {"confirmation_count": True},
            {"acknowledgement_sequence": 2},
            {"acknowledgement_sequence": True},
        ):
            self.assert_receipt_rejected(value, **changes)

    def test_receipt_route_and_terminal_flags_cannot_be_mixed(self):
        value = self.valid()
        for changes in (
            {"classification": reconciler.RecoveryPublishClassification.CONFLICT},
            {"decision": workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP},
            {"state": workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP},
            {"terminal_stop": True},
            {"downstream_reverification_required": False},
        ):
            self.assert_receipt_rejected(value, **changes)

    def test_fixed_safety_flags_reject_false_claims_and_integer_booleans(self):
        value = self.valid()
        cases = (
            ("presentation_validated", False),
            ("confirmation_order_validated", False),
            ("all_confirmations_acknowledged", False),
            ("one_shot", False),
            ("read_only", False),
            ("operation_performed", True),
            ("operation_authorized", True),
            ("gate_invoked", True),
            ("automatic_transition", True),
            ("secrets_retained", True),
            ("operation_authorized", 0),
        )
        for name, changed in cases:
            with self.subTest(name=name):
                self.assert_receipt_rejected(value, **{name: changed})

    def test_receipt_has_no_secret_path_text_callback_or_executor_field(self):
        names = {
            item.name.lower()
            for item in fields(
                acknowledgement.VaultRecoveryPresentationAcknowledgementReceipt
            )
        }
        forbidden = (
            "password",
            "root",
            "keyring",
            "wrapping",
            "candidate",
            "session",
            "path",
            "filename",
            "plaintext",
            "exception",
            "error_text",
            "callback",
            "executor_ref",
            "recovery_id",
            "vault_id",
        )
        for token in forbidden:
            self.assertTrue(all(token not in name for name in names), token)

    def test_receipt_repr_hides_digest_and_source_identifiers(self):
        value = self.valid()
        rendered = repr(value)
        self.assertNotIn(repr(value.presentation_sha256), rendered)
        self.assertNotIn(repr(RECOVERY_ID), rendered)
        self.assertNotIn(repr(VAULT_ID), rendered)


class RecoveryAcknowledgementStaticBoundaryTests(unittest.TestCase):
    def test_only_one_public_module_function_is_exposed(self):
        public_functions = {
            name
            for name, item in inspect.getmembers(
                acknowledgement,
                inspect.isfunction,
            )
            if not name.startswith("_")
        }
        self.assertEqual(
            public_functions,
            {"prepare_recovery_presentation_acknowledgement"},
        )

    def test_prepare_api_accepts_only_one_presentation(self):
        signature = inspect.signature(
            acknowledgement.prepare_recovery_presentation_acknowledgement
        )
        self.assertEqual(tuple(signature.parameters), ("presentation",))

    def test_acknowledge_once_accepts_only_presentation_and_confirmations(self):
        signature = inspect.signature(
            acknowledgement.PreparedVaultRecoveryPresentationAcknowledgement
            .acknowledge_once
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("self", "presentation", "confirmations"),
        )
        rendered = str(signature).lower()
        for token in (
            "password",
            "root",
            "keyring",
            "path",
            "text",
            "callback",
            "executor",
            "authorization",
        ):
            self.assertNotIn(token, rendered)

    def test_module_imports_no_filesystem_network_gui_logging_clock_or_randomness(self):
        source_path = Path(acknowledgement.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        forbidden = {
            "os",
            "pathlib",
            "shutil",
            "tempfile",
            "socket",
            "urllib",
            "http",
            "requests",
            "tkinter",
            "logging",
            "time",
            "datetime",
            "random",
            "secrets",
            "subprocess",
        }
        self.assertTrue(imported.isdisjoint(forbidden), imported & forbidden)

    def test_module_has_no_filesystem_gate_executor_or_mutation_call(self):
        source_path = Path(acknowledgement.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_calls = {
            "open",
            "write",
            "unlink",
            "remove",
            "rename",
            "replace",
            "mkdir",
            "rmdir",
            "fsync",
            "publish",
            "unlock",
            "invoke_gate",
            "retry",
            "repair",
            "cleanup",
            "delete",
            "exec",
            "eval",
        }
        observed = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                observed.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                observed.add(node.func.attr)
        self.assertTrue(
            observed.isdisjoint(forbidden_calls),
            observed & forbidden_calls,
        )

    def test_module_does_not_import_recovery_executors_or_mutators(self):
        source = Path(acknowledgement.__file__).read_text(encoding="utf-8")
        forbidden = (
            "mokosh_vault_recovery_candidate",
            "mokosh_vault_recovery_publish",
            "mokosh_vault_recovery_storage",
            "mokosh_vault_format",
            "mokosh_vault_storage",
        )
        for name in forbidden:
            self.assertNotIn(f"import {name}", source)
            self.assertNotIn(f"from {name} import", source)

    def test_acknowledgement_does_not_change_the_presentation(self):
        for value in (
            absent_presentation(),
            exact_presentation(),
            conflict_presentation(),
            preserve_presentation(),
        ):
            before = tuple(getattr(value, item.name) for item in fields(value))
            acknowledge(value)
            after = tuple(getattr(value, item.name) for item in fields(value))
            self.assertEqual(before, after)

    def test_receipt_retains_no_presentation_or_message_sequence(self):
        value = acknowledge(absent_presentation())
        self.assertFalse(hasattr(value, "presentation"))
        self.assertFalse(hasattr(value, "workflow_state"))
        self.assertFalse(hasattr(value, "message_keys"))
        self.assertFalse(hasattr(value, "gate_message_keys"))
        self.assertFalse(hasattr(value, "__dict__"))
        self.assertFalse(value.secrets_retained)


if __name__ == "__main__":
    unittest.main()
