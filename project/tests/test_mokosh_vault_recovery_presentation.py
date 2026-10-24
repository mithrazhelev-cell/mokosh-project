import ast
import inspect
import unittest
from dataclasses import fields, replace
from pathlib import Path

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


def absent_state():
    return workflow_state(
        absent_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
    )


def exact_state():
    return workflow_state(
        exact_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
    )


def conflict_state():
    return workflow_state(
        conflict_result(),
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
    )


def preserve_state(result=None):
    if result is None:
        result = absent_result()
    return workflow_state(
        result,
        workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
    )


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


class RecoveryPresentationRouteTests(unittest.TestCase):
    def present(self, state):
        return presentation.prepare_recovery_workflow_presentation(state)

    def test_absent_route_has_only_fresh_stage_2_6_gate(self):
        value = self.present(absent_state())
        self.assertEqual(
            value.gate_message_keys,
            (
                presentation.RecoveryPresentationMessageKey.GATE_FRESH_STAGE_2_6_DECISION_REQUIRED,
            ),
        )
        self.assertEqual(
            value.confirmation_requirements,
            (
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NO_OPERATION_PERFORMED,
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED,
            ),
        )
        self.assertFalse(value.terminal_stop)
        self.assertTrue(value.downstream_reverification_required)

    def test_exact_route_orders_unlock_before_new_recovery_setup(self):
        value = self.present(exact_state())
        self.assertEqual(
            value.gate_message_keys,
            (
                presentation.RecoveryPresentationMessageKey.GATE_NORMAL_VAULT_UNLOCK_REQUIRED,
                presentation.RecoveryPresentationMessageKey
                .GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
            ),
        )
        self.assertEqual(
            value.confirmation_requirements,
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
        self.assertIn(
            presentation.RecoveryPresentationMessageKey.OLD_RECOVERY_RECORD_REMAINS_STALE,
            value.message_keys,
        )
        self.assertFalse(value.terminal_stop)

    def test_conflict_route_is_terminal_manual_review_only(self):
        value = self.present(conflict_state())
        self.assertEqual(
            value.gate_message_keys,
            (presentation.RecoveryPresentationMessageKey.GATE_MANUAL_REVIEW_ONLY,),
        )
        self.assertEqual(
            value.confirmation_requirements,
            (
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NO_OPERATION_PERFORMED,
                presentation.RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP,
                presentation.RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
            ),
        )
        self.assertTrue(value.terminal_stop)
        self.assertFalse(value.downstream_reverification_required)
        self.assertIn(
            presentation.RecoveryPresentationMessageKey.NO_AUTOMATIC_RETRY_REPAIR_OR_CLEANUP,
            value.message_keys,
        )

    def test_preserve_route_is_terminal_without_gate_for_all_classifications(self):
        for result in (absent_result(), exact_result(), conflict_result()):
            with self.subTest(classification=result.classification):
                value = self.present(preserve_state(result))
                self.assertEqual(value.gate_message_keys, ())
                self.assertTrue(value.terminal_stop)
                self.assertFalse(value.downstream_reverification_required)
                self.assertIn(
                    presentation.RecoveryPresentationMessageKey.RECOVERY_PROBLEM_NOT_RESOLVED,
                    value.message_keys,
                )

    def test_every_gate_is_visible_in_the_ordered_message_keys(self):
        for state in (absent_state(), exact_state(), conflict_state(), preserve_state()):
            with self.subTest(state=state.state):
                value = self.present(state)
                positions = [value.message_keys.index(item) for item in value.gate_message_keys]
                self.assertEqual(positions, sorted(positions))

    def test_all_routes_explicitly_say_no_operation_and_no_authority(self):
        required = {
            presentation.RecoveryPresentationMessageKey.NO_OPERATION_PERFORMED,
            presentation.RecoveryPresentationMessageKey.NO_OPERATION_AUTHORIZED,
        }
        for state in (absent_state(), exact_state(), conflict_state(), preserve_state()):
            with self.subTest(state=state.state):
                value = self.present(state)
                self.assertTrue(required.issubset(value.message_keys))
                self.assertFalse(value.operation_performed)
                self.assertFalse(value.operation_authorized)

    def test_message_and_confirmation_sequences_are_bounded_and_unique(self):
        for state in (absent_state(), exact_state(), conflict_state(), preserve_state()):
            value = self.present(state)
            self.assertLessEqual(
                len(value.message_keys),
                presentation.MAX_PRESENTATION_MESSAGE_KEYS,
            )
            self.assertLessEqual(
                len(value.gate_message_keys),
                presentation.MAX_PRESENTATION_GATE_KEYS,
            )
            self.assertLessEqual(
                len(value.confirmation_requirements),
                presentation.MAX_PRESENTATION_CONFIRMATIONS,
            )
            self.assertEqual(len(value.message_keys), len(set(value.message_keys)))
            self.assertEqual(
                len(value.confirmation_requirements),
                len(set(value.confirmation_requirements)),
            )


class RecoveryPresentationBindingTests(unittest.TestCase):
    def test_equivalent_state_produces_the_same_digest_and_presentation(self):
        first = exact_state()
        second = replace(first)
        left = presentation.prepare_recovery_workflow_presentation(first)
        right = presentation.prepare_recovery_workflow_presentation(second)
        self.assertEqual(left, right)
        self.assertEqual(len(left.workflow_state_sha256), 32)

    def test_digest_changes_for_a_different_valid_route(self):
        result = absent_result()
        absent = workflow_state(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        preserved = workflow_state(
            result,
            workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        )
        self.assertNotEqual(
            presentation.prepare_recovery_workflow_presentation(absent).workflow_state_sha256,
            presentation.prepare_recovery_workflow_presentation(preserved).workflow_state_sha256,
        )

    def test_digest_binds_non_secret_workflow_evidence(self):
        original = absent_state()
        baseline = presentation.prepare_recovery_workflow_presentation(
            original
        ).workflow_state_sha256
        evidence_variants = (
            replace(original.evidence, recovery_id=b"I" * 16),
            replace(original.evidence, vault_id=b"V" * 16),
            replace(original.evidence, source_vault_sha256=b"A" * 32),
            replace(original.evidence, record_sha256=b"B" * 32),
            replace(original.evidence, keyring_sha256=b"C" * 32),
            replace(original.evidence, reconciliation_result_sha256=b"D" * 32),
        )
        for evidence in evidence_variants:
            with self.subTest(field=evidence):
                changed = replace(original, evidence=evidence)
                observed = presentation.prepare_recovery_workflow_presentation(
                    changed
                ).workflow_state_sha256
                self.assertNotEqual(baseline, observed)

    def test_exact_target_digest_binding_includes_target_hash(self):
        original = exact_state()
        changed_evidence = replace(
            original.evidence,
            target_vault_sha256=b"Z" * 32,
        )
        changed = replace(original, evidence=changed_evidence)
        self.assertNotEqual(
            presentation.prepare_recovery_workflow_presentation(original).workflow_state_sha256,
            presentation.prepare_recovery_workflow_presentation(changed).workflow_state_sha256,
        )

    def test_digest_is_process_local_evidence_not_an_authority_flag(self):
        value = presentation.prepare_recovery_workflow_presentation(absent_state())
        self.assertIs(type(value.workflow_state_sha256), bytes)
        self.assertFalse(value.operation_authorized)
        self.assertFalse(value.operation_performed)


class RecoveryPresentationInputValidationTests(unittest.TestCase):
    def assert_state_rejected(self, value):
        with self.assertRaises(presentation.VaultRecoveryPresentationStateError):
            presentation.prepare_recovery_workflow_presentation(value)

    def test_non_state_and_state_subclass_are_rejected(self):
        self.assert_state_rejected(None)
        self.assert_state_rejected({})

        class StateSubclass(workflow.VaultRecoveryWorkflowState):
            pass

        original = absent_state()
        subclass = object.__new__(StateSubclass)
        for item in fields(original):
            object.__setattr__(subclass, item.name, getattr(original, item.name))
        self.assert_state_rejected(subclass)

    def test_forged_format_version_or_sequence_is_rejected(self):
        original = absent_state()
        for name, value in (
            ("format", "OTHER"),
            ("version", 2),
            ("version", True),
            ("transition_sequence", 0),
            ("transition_sequence", True),
        ):
            with self.subTest(name=name, value=value):
                self.assert_state_rejected(
                    forge_dataclass(original, **{name: value})
                )

    def test_forged_route_state_or_gates_are_rejected(self):
        original = absent_state()
        cases = (
            {"state": workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP},
            {"required_gates": ()},
            {"required_gates": [workflow.RecoveryWorkflowGate.MANUAL_REVIEW_ONLY]},
            {"terminal_stop": True},
            {"downstream_reverification_required": False},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_state_rejected(forge_dataclass(original, **changes))

    def test_forged_string_enums_are_rejected(self):
        original = absent_state()
        for changes in (
            {"decision": original.decision.value},
            {"state": original.state.value},
            {"required_gates": (original.required_gates[0].value,)},
        ):
            self.assert_state_rejected(forge_dataclass(original, **changes))

    def test_forged_safety_flags_and_boolean_integers_are_rejected(self):
        original = absent_state()
        for name, value in (
            ("reviewed_result_validated", False),
            ("user_decision_recorded", False),
            ("read_only", False),
            ("secrets_retained", True),
            ("mutation_authorized", True),
            ("candidate_creation_authorized", True),
            ("normal_unlock_authorized", True),
            ("recovery_setup_authorized", True),
            ("publish_authorized", True),
            ("retry_authorized", True),
            ("repair_authorized", True),
            ("cleanup_authorized", True),
            ("key_deletion_authorized", True),
            ("user_file_mutation_authorized", True),
            ("read_only", 1),
        ):
            with self.subTest(name=name):
                self.assert_state_rejected(
                    forge_dataclass(original, **{name: value})
                )

    def test_forged_evidence_type_and_schema_are_rejected(self):
        original = absent_state()
        self.assert_state_rejected(forge_dataclass(original, evidence={}))
        for changes in (
            {"format": "OTHER"},
            {"version": 2},
            {"reconciliation_result_sha256": b"short"},
            {"classification": "target_absent"},
            {"target_vault_sha256": b"T" * 32},
        ):
            forged_evidence = forge_dataclass(original.evidence, **changes)
            self.assert_state_rejected(
                forge_dataclass(original, evidence=forged_evidence)
            )


class RecoveryPresentationOutputValidationTests(unittest.TestCase):
    def valid(self):
        return presentation.prepare_recovery_workflow_presentation(exact_state())

    def assert_presentation_rejected(self, original, **changes):
        with self.assertRaises(presentation.VaultRecoveryPresentationFormatError):
            replace(original, **changes)

    def test_format_version_digest_and_enum_types_are_strict(self):
        value = self.valid()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"version": True},
            {"workflow_state_sha256": b"short"},
            {"workflow_state_sha256": bytearray(32)},
            {"classification": value.classification.value},
            {"decision": value.decision.value},
            {"state": value.state.value},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_presentation_rejected(value, **changes)

    def test_message_keys_require_exact_tuple_unique_enums_and_order(self):
        value = self.valid()
        cases = (
            {"message_keys": list(value.message_keys)},
            {"message_keys": value.message_keys[:-1]},
            {"message_keys": tuple(reversed(value.message_keys))},
            {"message_keys": value.message_keys + (value.message_keys[0],)},
            {"message_keys": tuple(item.value for item in value.message_keys)},
            {"message_keys": ()},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_presentation_rejected(value, **changes)

    def test_gate_keys_require_exact_mapping_and_visible_order(self):
        value = self.valid()
        cases = (
            {"gate_message_keys": ()},
            {"gate_message_keys": tuple(reversed(value.gate_message_keys))},
            {"gate_message_keys": list(value.gate_message_keys)},
            {"gate_message_keys": (value.gate_message_keys[0].value,)},
            {"gate_message_keys": value.gate_message_keys * 2},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_presentation_rejected(value, **changes)

    def test_confirmations_require_exact_tuple_unique_enums_and_order(self):
        value = self.valid()
        cases = (
            {"confirmation_requirements": list(value.confirmation_requirements)},
            {"confirmation_requirements": value.confirmation_requirements[:-1]},
            {"confirmation_requirements": tuple(reversed(value.confirmation_requirements))},
            {
                "confirmation_requirements": value.confirmation_requirements
                + (value.confirmation_requirements[0],)
            },
            {
                "confirmation_requirements": tuple(
                    item.value for item in value.confirmation_requirements
                )
            },
            {"confirmation_requirements": ()},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_presentation_rejected(value, **changes)

    def test_terminal_and_reverification_flags_cannot_contradict_route(self):
        value = self.valid()
        self.assert_presentation_rejected(value, terminal_stop=True)
        self.assert_presentation_rejected(
            value,
            downstream_reverification_required=False,
        )

    def test_fixed_safety_flags_cannot_be_changed_or_use_integer_booleans(self):
        value = self.valid()
        cases = (
            ("workflow_state_validated", False),
            ("fixed_message_keys_only", False),
            ("raw_text_included", True),
            ("operation_performed", True),
            ("operation_authorized", True),
            ("secrets_retained", True),
            ("operation_authorized", 0),
        )
        for name, changed in cases:
            with self.subTest(name=name):
                self.assert_presentation_rejected(value, **{name: changed})

    def test_cross_route_classification_decision_and_state_are_rejected(self):
        value = self.valid()
        self.assert_presentation_rejected(
            value,
            classification=reconciler.RecoveryPublishClassification.CONFLICT,
        )
        self.assert_presentation_rejected(
            value,
            decision=workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        )
        self.assert_presentation_rejected(
            value,
            state=workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        )


class RecoveryPresentationBoundaryTests(unittest.TestCase):
    def test_presentation_has_no_secret_path_text_or_executor_field(self):
        names = {item.name.lower() for item in fields(
            presentation.VaultRecoveryWorkflowPresentation
        )}
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
        )
        for token in forbidden:
            self.assertTrue(all(token not in name for name in names), token)

    def test_presentation_retains_no_raw_stage_2_9_evidence(self):
        value = presentation.prepare_recovery_workflow_presentation(absent_state())
        self.assertFalse(hasattr(value, "evidence"))
        self.assertFalse(hasattr(value, "workflow_state"))
        self.assertFalse(hasattr(value, "__dict__"))
        self.assertFalse(value.raw_text_included)
        self.assertFalse(value.secrets_retained)

    def test_repr_does_not_expose_the_state_digest_or_source_identifiers(self):
        value = presentation.prepare_recovery_workflow_presentation(absent_state())
        rendered = repr(value)
        self.assertNotIn(repr(value.workflow_state_sha256), rendered)
        self.assertNotIn(repr(RECOVERY_ID), rendered)
        self.assertNotIn(repr(VAULT_ID), rendered)

    def test_all_public_sequences_contain_only_exact_fixed_enums(self):
        for state in (absent_state(), exact_state(), conflict_state(), preserve_state()):
            value = presentation.prepare_recovery_workflow_presentation(state)
            self.assertTrue(
                all(
                    type(item) is presentation.RecoveryPresentationMessageKey
                    for item in value.message_keys + value.gate_message_keys
                )
            )
            self.assertTrue(
                all(
                    type(item)
                    is presentation.RecoveryPresentationConfirmationKey
                    for item in value.confirmation_requirements
                )
            )

    def test_no_callback_executor_or_mutation_api_is_exposed(self):
        public_functions = {
            name
            for name, item in inspect.getmembers(presentation, inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual(
            public_functions,
            {"prepare_recovery_workflow_presentation"},
        )
        fields_by_name = {
            item.name: item.type
            for item in fields(presentation.VaultRecoveryWorkflowPresentation)
        }
        self.assertFalse(any("callable" in str(item).lower() for item in fields_by_name.values()))

    def test_prepare_api_accepts_only_one_workflow_state(self):
        signature = inspect.signature(
            presentation.prepare_recovery_workflow_presentation
        )
        self.assertEqual(tuple(signature.parameters), ("workflow_state",))
        forbidden = (
            "password",
            "root",
            "keyring",
            "path",
            "text",
            "exception",
            "callback",
            "executor",
            "decision",
        )
        rendered = str(signature).lower()
        for token in forbidden:
            self.assertNotIn(token, rendered)

    def test_module_imports_no_filesystem_network_gui_logging_clock_or_randomness(self):
        source_path = Path(presentation.__file__)
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

    def test_module_has_no_filesystem_executor_or_mutation_call(self):
        source_path = Path(presentation.__file__)
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
        self.assertTrue(observed.isdisjoint(forbidden_calls), observed & forbidden_calls)

    def test_preparation_does_not_change_the_supplied_state(self):
        for state in (absent_state(), exact_state(), conflict_state(), preserve_state()):
            before = tuple(getattr(state, item.name) for item in fields(state))
            presentation.prepare_recovery_workflow_presentation(state)
            after = tuple(getattr(state, item.name) for item in fields(state))
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
