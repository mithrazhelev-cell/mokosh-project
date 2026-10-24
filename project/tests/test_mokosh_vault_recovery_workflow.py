import ast
import copy
import inspect
import os
import pickle
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_recovery_candidate as candidate
import mokosh_vault_recovery_publish as publisher
import mokosh_vault_recovery_reconciliation as reconciler
import mokosh_vault_recovery_storage as recovery_storage
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
        "recommended_action": reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
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


class RecoveryWorkflowRoutingTests(unittest.TestCase):
    def route(self, result, decision):
        prepared = workflow.prepare_recovery_workflow(result)
        return prepared, prepared.review_once(result, decision)

    def test_target_absent_routes_only_to_a_fresh_stage_2_6_decision(self):
        prepared, state = self.route(
            absent_result(),
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        self.assertTrue(prepared.transitioned)
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        )
        self.assertEqual(
            state.required_gates,
            (workflow.RecoveryWorkflowGate.STAGE_2_6_NEW_CANDIDATE_DECISION,),
        )
        self.assertFalse(state.terminal_stop)

    def test_exact_target_routes_to_normal_unlock_then_new_setup_decision(self):
        _, state = self.route(
            exact_result(),
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        )
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        )
        self.assertEqual(
            state.required_gates,
            (
                workflow.RecoveryWorkflowGate.NORMAL_VAULT_UNLOCK,
                workflow.RecoveryWorkflowGate.STAGE_2_5_NEW_RECOVERY_SETUP_DECISION,
            ),
        )
        self.assertFalse(state.terminal_stop)

    def test_conflict_is_a_terminal_read_only_manual_review_stop(self):
        _, state = self.route(
            conflict_result(),
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        )
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        )
        self.assertEqual(
            state.required_gates,
            (workflow.RecoveryWorkflowGate.MANUAL_REVIEW_ONLY,),
        )
        self.assertTrue(state.terminal_stop)
        self.assertFalse(state.downstream_reverification_required)

    def test_preserve_is_available_for_every_classification(self):
        for result in (absent_result(), exact_result(), conflict_result()):
            with self.subTest(classification=result.classification):
                _, state = self.route(
                    result,
                    workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
                )
                self.assertIs(
                    state.state,
                    workflow.RecoveryWorkflowState.PRESERVED_STOP,
                )
                self.assertEqual(state.required_gates, ())
                self.assertTrue(state.terminal_stop)
                self.assertFalse(state.downstream_reverification_required)

    def test_prepared_workflow_starts_only_in_awaiting_review(self):
        prepared = workflow.prepare_recovery_workflow(absent_result())
        self.assertFalse(prepared.transitioned)
        self.assertIs(
            prepared.current_state,
            workflow.RecoveryWorkflowState.AWAITING_USER_REVIEW,
        )

    def test_equivalent_exact_result_instance_matches_prepared_evidence(self):
        original = exact_result()
        equivalent = replace(original)
        prepared = workflow.prepare_recovery_workflow(original)
        state = prepared.review_once(
            equivalent,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        )
        self.assertIs(
            state.evidence.classification,
            reconciler.RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        )

    def test_successful_transition_is_one_shot(self):
        result = absent_result()
        prepared = workflow.prepare_recovery_workflow(result)
        prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        with self.assertRaises(workflow.VaultRecoveryWorkflowReplayError):
            prepared.review_once(
                result,
                workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
            )

    def test_incompatible_decisions_are_rejected_for_all_routes(self):
        cases = (
            (
                absent_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
            ),
            (
                exact_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
            ),
            (
                conflict_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
            ),
        )
        for result, decision in cases:
            with self.subTest(result=result.classification, decision=decision):
                prepared = workflow.prepare_recovery_workflow(result)
                with self.assertRaises(
                    workflow.VaultRecoveryWorkflowTransitionError
                ):
                    prepared.review_once(result, decision)
                self.assertFalse(prepared.transitioned)

    def test_string_or_other_enum_decision_is_rejected(self):
        result = absent_result()
        for decision in (
            "acknowledge_target_absent",
            reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
            None,
        ):
            with self.subTest(decision=decision):
                prepared = workflow.prepare_recovery_workflow(result)
                with self.assertRaises(
                    workflow.VaultRecoveryWorkflowTransitionError
                ):
                    prepared.review_once(result, decision)
                self.assertFalse(prepared.transitioned)

    def test_valid_but_different_result_is_mismatch(self):
        original = absent_result()
        different = replace(original, record_sha256=b"D" * 32)
        prepared = workflow.prepare_recovery_workflow(original)
        with self.assertRaises(workflow.VaultRecoveryWorkflowMismatchError):
            prepared.review_once(
                different,
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
            )
        self.assertFalse(prepared.transitioned)

    def test_mismatch_cannot_be_bypassed_with_preserve(self):
        prepared = workflow.prepare_recovery_workflow(absent_result())
        with self.assertRaises(workflow.VaultRecoveryWorkflowMismatchError):
            prepared.review_once(
                conflict_result(),
                workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
            )

    def test_invalid_attempt_does_not_hide_the_original_review_route(self):
        result = absent_result()
        prepared = workflow.prepare_recovery_workflow(result)
        with self.assertRaises(workflow.VaultRecoveryWorkflowTransitionError):
            prepared.review_once(
                result,
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
            )
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        )

    def test_every_route_keeps_all_operation_authority_false(self):
        routes = (
            (
                absent_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
            ),
            (
                exact_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
            ),
            (
                conflict_result(),
                workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
            ),
        )
        forbidden = (
            "mutation_authorized",
            "candidate_creation_authorized",
            "normal_unlock_authorized",
            "recovery_setup_authorized",
            "publish_authorized",
            "retry_authorized",
            "repair_authorized",
            "cleanup_authorized",
            "key_deletion_authorized",
            "user_file_mutation_authorized",
        )
        for result, decision in routes:
            with self.subTest(classification=result.classification):
                _, state = self.route(result, decision)
                self.assertTrue(state.read_only)
                self.assertFalse(state.secrets_retained)
                self.assertTrue(state.reviewed_result_validated)
                self.assertTrue(state.user_decision_recorded)
                for field_name in forbidden:
                    self.assertFalse(getattr(state, field_name), field_name)

    def test_prepared_workflow_cannot_be_copied_or_serialized(self):
        prepared = workflow.prepare_recovery_workflow(absent_result())
        with self.assertRaises(workflow.VaultRecoveryWorkflowReplayError):
            copy.copy(prepared)
        with self.assertRaises(workflow.VaultRecoveryWorkflowReplayError):
            copy.deepcopy(prepared)
        with self.assertRaises(workflow.VaultRecoveryWorkflowReplayError):
            pickle.dumps(prepared)

    def test_public_state_and_evidence_have_no_secret_or_path_field(self):
        evidence_names = {item.name for item in fields(workflow.VaultRecoveryWorkflowEvidence)}
        state_names = {item.name for item in fields(workflow.VaultRecoveryWorkflowState)}
        forbidden = {
            "password",
            "recovery_key",
            "keyring",
            "wrapping_key",
            "candidate",
            "path",
            "filename",
            "plaintext",
        }
        self.assertFalse(evidence_names & forbidden)
        self.assertFalse(state_names & forbidden)

    def test_evidence_digest_binds_receipts_counts_and_flags(self):
        base = absent_result()
        changes = (
            replace(base, record_sha256=b"D" * 32),
            replace(base, source_receipt=source_receipt(file_inode=99)),
            conflict_result(),
        )
        digest = workflow.prepare_recovery_workflow(
            base
        ).evidence.reconciliation_result_sha256
        for changed in changes:
            with self.subTest(changed=changed.classification):
                observed = workflow.prepare_recovery_workflow(
                    changed
                ).evidence.reconciliation_result_sha256
                self.assertNotEqual(digest, observed)


class RecoveryWorkflowResultValidationTests(unittest.TestCase):
    def assert_result_rejected(self, value):
        with self.assertRaises(workflow.VaultRecoveryWorkflowResultError):
            workflow.prepare_recovery_workflow(value)

    def test_non_result_and_result_subclass_are_rejected(self):
        self.assert_result_rejected(None)

        class ResultSubclass(reconciler.VaultRecoveryReconciliationResult):
            pass

        self.assert_result_rejected(ResultSubclass(**{
            item.name: getattr(absent_result(), item.name)
            for item in fields(reconciler.VaultRecoveryReconciliationResult)
        }))

    def test_classification_and_action_must_be_exact_enums(self):
        self.assert_result_rejected(replace(absent_result(), classification="target_absent"))
        self.assert_result_rejected(
            replace(absent_result(), recommended_action="prepare_new_candidate")
        )

    def test_action_must_match_each_classification(self):
        cases = (
            replace(
                absent_result(),
                recommended_action=(
                    reconciler.RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW
                ),
            ),
            replace(
                exact_result(),
                recommended_action=(
                    reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE
                ),
            ),
            replace(
                conflict_result(),
                recommended_action=(
                    reconciler.RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE
                ),
            ),
        )
        for value in cases:
            with self.subTest(classification=value.classification):
                self.assert_result_rejected(value)

    def test_binary_identifiers_and_hashes_are_exact_bytes(self):
        fields_and_values = (
            ("recovery_id", bytearray(RECOVERY_ID)),
            ("recovery_id", RECOVERY_ID[:-1]),
            ("vault_id", VAULT_ID + b"x"),
            ("source_vault_sha256", b"x" * 31),
            ("record_sha256", memoryview(RECORD_SHA256)),
            ("keyring_sha256", b"x" * 33),
        )
        for name, value in fields_and_values:
            with self.subTest(field=name, value_type=type(value)):
                self.assert_result_rejected(replace(absent_result(), **{name: value}))

    def test_revision_must_be_plain_exact_next_and_bounded(self):
        cases = (
            replace(absent_result(), source_revision=True),
            replace(absent_result(), source_revision=0),
            replace(absent_result(), target_revision=1),
            replace(absent_result(), target_revision=3),
            replace(
                absent_result(),
                source_revision=vault.MAX_VAULT_REVISION,
                target_revision=vault.MAX_VAULT_REVISION,
            ),
        )
        for value in cases:
            with self.subTest(source=value.source_revision, target=value.target_revision):
                self.assert_result_rejected(value)

    def test_counts_are_plain_bounded_and_consistent(self):
        cases = (
            replace(conflict_result(), generation_count=True),
            replace(conflict_result(), finding_count=-1),
            replace(
                conflict_result(),
                finding_count=vault_storage.MAX_STORAGE_ENTRIES + 1,
            ),
            replace(conflict_result(), omitted_entries=-1),
            replace(conflict_result(), omitted_entries=workflow.MAX_UINT64 + 1),
            replace(conflict_result(), generation_count=3, finding_count=2),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_result_rejected(value)

    def test_completeness_must_match_omitted_entries(self):
        self.assert_result_rejected(
            replace(conflict_result(), storage_complete=False, omitted_entries=0)
        )
        self.assert_result_rejected(
            replace(conflict_result(), storage_complete=True, omitted_entries=1)
        )

    def test_source_receipt_type_and_durable_policy_are_strict(self):
        self.assert_result_rejected(replace(absent_result(), source_receipt=None))
        self.assert_result_rejected(
            replace(absent_result(), source_receipt=source_receipt(durable=False))
        )

    def test_source_receipt_must_match_result_identity_revision_and_digest(self):
        cases = (
            source_receipt(vault_id=b"V" * 16),
            source_receipt(revision=2),
            source_receipt(sha256=b"D" * 32),
        )
        for receipt in cases:
            with self.subTest(receipt=receipt):
                self.assert_result_rejected(
                    replace(absent_result(), source_receipt=receipt)
                )

    def test_receipt_integer_fields_are_bounded(self):
        cases = (
            source_receipt(directory_device=workflow.MAX_UINT64 + 1),
            source_receipt(file_inode=workflow.MAX_UINT64 + 1),
            source_receipt(encoded_size=0),
            source_receipt(
                encoded_size=vault_storage.MAX_GENERATION_BYTES + 1
            ),
        )
        for receipt in cases:
            with self.subTest(receipt=receipt):
                self.assert_result_rejected(
                    replace(absent_result(), source_receipt=receipt)
                )

    def test_mandatory_read_only_verification_flags_cannot_be_false(self):
        for name in ("source_verified", "recovery_record_verified", "read_only"):
            with self.subTest(field=name):
                self.assert_result_rejected(
                    replace(absent_result(), **{name: False})
                )

    def test_no_mutation_or_mutation_outcome_flag_can_be_true(self):
        names = (
            "mutation_authorized",
            "publish_performed",
            "rollback_performed",
            "cleanup_performed",
            "key_deletion_performed",
            "user_file_mutation_performed",
        )
        for name in names:
            with self.subTest(field=name):
                self.assert_result_rejected(
                    replace(absent_result(), **{name: True})
                )

    def test_all_result_policy_flags_must_be_exact_booleans(self):
        self.assert_result_rejected(replace(absent_result(), read_only=1))
        self.assert_result_rejected(
            replace(absent_result(), stable_observation=1)
        )

    def test_absent_result_forbids_target_and_verification_claims(self):
        cases = (
            replace(absent_result(), target_receipt=target_receipt()),
            replace(absent_result(), target_vault_sha256=TARGET_SHA256),
            replace(absent_result(), new_password_verified=True),
            replace(absent_result(), keyring_verified=True),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_result_rejected(value)

    def test_absent_result_requires_stable_complete_clean_counts(self):
        cases = (
            replace(absent_result(), storage_complete=False, omitted_entries=1),
            replace(absent_result(), stable_observation=False),
            replace(absent_result(), generation_count=0, finding_count=0),
            replace(absent_result(), finding_count=2),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_result_rejected(value)

    def test_exact_result_requires_target_receipt_and_digest(self):
        self.assert_result_rejected(replace(exact_result(), target_receipt=None))
        self.assert_result_rejected(
            replace(exact_result(), target_vault_sha256=None)
        )
        self.assert_result_rejected(
            replace(exact_result(), target_vault_sha256=b"x" * 31)
        )

    def test_exact_target_receipt_must_match_directory_vault_revision_and_hash(self):
        cases = (
            target_receipt(directory_inode=99),
            target_receipt(vault_id=b"V" * 16),
            target_receipt(revision=3),
            target_receipt(sha256=b"D" * 32),
        )
        for receipt in cases:
            with self.subTest(receipt=receipt):
                self.assert_result_rejected(
                    replace(exact_result(), target_receipt=receipt)
                )

    def test_exact_result_requires_password_keyring_stability_and_clean_counts(self):
        cases = (
            replace(exact_result(), new_password_verified=False),
            replace(exact_result(), keyring_verified=False),
            replace(exact_result(), stable_observation=False),
            replace(exact_result(), generation_count=1, finding_count=1),
            replace(exact_result(), finding_count=3),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_result_rejected(value)

    def test_conflict_forbids_untrusted_target_and_positive_verification(self):
        cases = (
            replace(conflict_result(), target_receipt=target_receipt()),
            replace(conflict_result(), target_vault_sha256=TARGET_SHA256),
            replace(conflict_result(), new_password_verified=True),
            replace(conflict_result(), keyring_verified=True),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_result_rejected(value)

    def test_conflict_may_be_stable_or_changed_and_complete_or_incomplete(self):
        values = (
            conflict_result(),
            conflict_result(stable_observation=False),
            conflict_result(
                storage_complete=False,
                omitted_entries=5,
                generation_count=0,
                finding_count=0,
            ),
        )
        for value in values:
            with self.subTest(value=value):
                prepared = workflow.prepare_recovery_workflow(value)
                self.assertIs(
                    prepared.evidence.classification,
                    reconciler.RecoveryPublishClassification.CONFLICT,
                )

    def test_direct_evidence_construction_rejects_format_version_and_digest(self):
        evidence = workflow.prepare_recovery_workflow(absent_result()).evidence
        for changes in (
            {"format": "OTHER"},
            {"version": 2},
            {"reconciliation_result_sha256": b"x" * 31},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(workflow.VaultRecoveryWorkflowResultError):
                    replace(evidence, **changes)

    def test_direct_evidence_rejects_mapping_and_target_digest_conflicts(self):
        absent = workflow.prepare_recovery_workflow(absent_result()).evidence
        exact = workflow.prepare_recovery_workflow(exact_result()).evidence
        changes = (
            (
                absent,
                {
                    "recommended_action": (
                        reconciler.RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW
                    )
                },
            ),
            (absent, {"target_vault_sha256": TARGET_SHA256}),
            (exact, {"target_vault_sha256": None}),
        )
        for evidence, values in changes:
            with self.subTest(values=values):
                with self.assertRaises(workflow.VaultRecoveryWorkflowResultError):
                    replace(evidence, **values)

    def test_direct_state_rejects_false_policy_or_added_authority(self):
        result = absent_result()
        prepared = workflow.prepare_recovery_workflow(result)
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        changes = (
            {"reviewed_result_validated": False},
            {"secrets_retained": True},
            {"mutation_authorized": True},
            {"candidate_creation_authorized": True},
            {"normal_unlock_authorized": True},
            {"recovery_setup_authorized": True},
            {"retry_authorized": True},
        )
        for values in changes:
            with self.subTest(values=values):
                with self.assertRaises(
                    workflow.VaultRecoveryWorkflowTransitionError
                ):
                    replace(state, **values)

    def test_direct_state_rejects_wrong_route_gates_or_sequence(self):
        result = exact_result()
        prepared = workflow.prepare_recovery_workflow(result)
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        )
        changes = (
            {"transition_sequence": 2},
            {"state": workflow.RecoveryWorkflowState.PRESERVED_STOP},
            {"required_gates": ()},
            {"terminal_stop": True},
            {"downstream_reverification_required": False},
        )
        for values in changes:
            with self.subTest(values=values):
                with self.assertRaises(
                    workflow.VaultRecoveryWorkflowTransitionError
                ):
                    replace(state, **values)


OLD_PASSWORD = "Stage 2.9 old password"
NEW_PASSWORD = "Stage 2.9 explicit new password"
INTEGRATION_VAULT_ID = b"I" * 16
INTEGRATION_KEY = b"W" * 32
CREATED = "2026-08-15T08:00:00Z"
RECOVERY_CREATED = "2026-08-15T09:00:00Z"
CANDIDATE_UPDATED = "2026-08-15T10:00:00Z"


def integration_keyring():
    result = keyring.VaultKeyring(
        active_key_version=1,
        keys=(
            keyring.VaultKeyRecord(
                key_version=1,
                state=keyring.KEY_STATE_ACTIVE,
                created_utc=CREATED,
                retired_utc=None,
                wrapping_key=INTEGRATION_KEY,
            ),
        ),
    )
    keyring.validate_keyring(result)
    return result


class RecoveryWorkflowStage28IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-recovery-workflow-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.vault_path = self.parent / "vault"
        self.recovery_directory = self.parent / "offline-recovery"
        self.recovery_directory.mkdir(mode=0o700)
        os.chmod(self.recovery_directory, 0o700)
        self.store = vault_storage.VaultStorage.create(self.vault_path)
        encoded = vault.create_keyring_vault(
            OLD_PASSWORD,
            keyring=integration_keyring(),
            vault_id=INTEGRATION_VAULT_ID,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.session = vault.VaultSession(encoded)
        self.session.unlock(OLD_PASSWORD)
        self.source = self.store.publish(self.session)
        self.setup = recovery_storage.prepare_recovery_export(
            self.store,
            self.source,
            self.session,
            created_utc=RECOVERY_CREATED,
        )
        recovery_storage.export_recovery_record(
            self.setup,
            self.store,
            self.source,
            self.recovery_directory,
        )
        self.recovery_path = self.recovery_directory / (
            recovery_storage.recovery_record_name(self.setup.recovery_id)
        )

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.context.cleanup()

    def reconcile(self):
        return reconciler.reconcile_recovery_publish(
            self.recovery_path,
            self.setup.recovery_key,
            self.store,
            self.source,
            2,
            NEW_PASSWORD,
        )

    def snapshot(self):
        result = {}
        for root in (self.vault_path, self.recovery_directory):
            for path in sorted(root.iterdir()):
                observed = path.stat(follow_symlinks=False)
                result[str(path)] = (
                    path.read_bytes() if path.is_file() else None,
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_mode,
                    observed.st_nlink,
                    observed.st_size,
                )
        return result

    def test_real_absent_reconciliation_routes_without_filesystem_change(self):
        result = self.reconcile()
        before = self.snapshot()
        prepared = workflow.prepare_recovery_workflow(result)
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        )
        self.assertEqual(self.snapshot(), before)
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        )

    def test_real_exact_reconciliation_routes_without_unlock_or_new_setup(self):
        prepared_candidate = candidate.prepare_recovery_candidate(
            self.recovery_path,
            self.setup.recovery_key,
            self.store,
            self.source,
            NEW_PASSWORD,
            candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        publisher.publish_recovery_candidate(
            prepared_candidate,
            self.recovery_path,
            self.setup.recovery_key,
            self.store,
            self.source,
            NEW_PASSWORD,
            publisher.RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH,
        )
        result = self.reconcile()
        before = self.snapshot()
        prepared = workflow.prepare_recovery_workflow(result)
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        )
        self.assertEqual(self.snapshot(), before)
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        )
        self.assertFalse(state.normal_unlock_authorized)
        self.assertFalse(state.recovery_setup_authorized)

    def test_real_conflict_reconciliation_is_terminal_and_preserves_entry(self):
        unknown = self.vault_path / "manual-review-required"
        unknown.write_bytes(b"conflict")
        os.chmod(unknown, 0o600)
        result = self.reconcile()
        self.assertIs(
            result.classification,
            reconciler.RecoveryPublishClassification.CONFLICT,
        )
        before = self.snapshot()
        prepared = workflow.prepare_recovery_workflow(result)
        state = prepared.review_once(
            result,
            workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        )
        self.assertEqual(self.snapshot(), before)
        self.assertIs(
            state.state,
            workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        )


class RecoveryWorkflowStaticBoundaryTests(unittest.TestCase):
    def test_module_imports_no_filesystem_network_gui_logging_clock_or_randomness(self):
        source = inspect.getsource(workflow)
        tree = ast.parse(source)
        forbidden = {
            "os",
            "pathlib",
            "socket",
            "subprocess",
            "logging",
            "tkinter",
            "requests",
            "urllib",
            "time",
            "datetime",
            "secrets",
            "random",
        }
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(item.name.split(".")[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertFalse(imported & forbidden)

    def test_module_has_no_mutation_unlock_candidate_or_setup_call(self):
        source = inspect.getsource(workflow)
        tree = ast.parse(source)
        forbidden = {
            "open",
            "write",
            "publish",
            "unlink",
            "remove",
            "rename",
            "replace",
            "fsync",
            "unlock",
            "unlock_keyring_vault",
            "prepare_recovery_candidate",
            "prepare_recovery_export",
            "export_recovery_record",
            "reconcile_recovery_publish",
        }
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        calls.update(
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        )
        self.assertFalse(calls & forbidden)

    def test_public_prepare_api_accepts_only_reviewed_result(self):
        signature = inspect.signature(workflow.prepare_recovery_workflow)
        self.assertEqual(tuple(signature.parameters), ("reviewed_result",))
        self.assertFalse(
            set(signature.parameters)
            & {
                "password",
                "recovery_key",
                "keyring",
                "candidate",
                "storage",
                "path",
                "session",
            }
        )

    def test_review_transition_accepts_only_result_and_exact_decision(self):
        signature = inspect.signature(
            workflow.PreparedVaultRecoveryWorkflow.review_once
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("self", "reviewed_result", "decision"),
        )

    def test_workflow_module_does_not_import_executors(self):
        source = inspect.getsource(workflow)
        self.assertNotIn("mokosh_vault_recovery_candidate", source)
        self.assertNotIn("mokosh_vault_recovery_publish", source)
        self.assertNotIn("mokosh_vault_recovery_storage", source)

    def test_repr_contains_no_receipt_identity_or_digest_bytes(self):
        prepared = workflow.prepare_recovery_workflow(exact_result())
        rendered = repr(prepared)
        self.assertNotIn(SOURCE_SHA256.hex(), rendered)
        self.assertNotIn(RECORD_SHA256.hex(), rendered)
        self.assertNotIn(TARGET_SHA256.hex(), rendered)
        self.assertNotIn(str(source_receipt().file_inode), rendered)


if __name__ == "__main__":
    unittest.main()
