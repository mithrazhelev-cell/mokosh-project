import ast
import copy
import inspect
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from pathlib import Path

import mokosh_vault_recovery_presentation as presentation
import mokosh_vault_recovery_reconciliation as reconciler
import mokosh_vault_recovery_ui_adapter as adapter
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
            reconciler.RecoveryReconciliationAction
            .REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY
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


def present(result, decision):
    prepared = workflow.prepare_recovery_workflow(result)
    state = prepared.review_once(result, decision)
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
    return adapter.prepare_recovery_ui_adapter(value)


def valid_events(value):
    return tuple(
        adapter.RecoveryUIConfirmationEvent(
            ordinal=index,
            confirmation_key=key,
            visible=True,
            user_selected=True,
            user_initiated=True,
        )
        for index, key in enumerate(value.confirmation_requirements, start=1)
    )


def acknowledge(value):
    prepared = prepare(value)
    return prepared.acknowledge_visible_once(value, valid_events(value))


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


class RecoveryUIAdapterRouteTests(unittest.TestCase):
    def test_absent_route_builds_fixed_visible_items(self):
        value = absent_presentation()
        prepared = prepare(value)
        view = prepared.view
        self.assertEqual(
            tuple(item.message_key for item in view.message_items),
            value.message_keys,
        )
        self.assertEqual(
            tuple(item.confirmation_key for item in view.confirmation_controls),
            value.confirmation_requirements,
        )
        self.assertTrue(all(item.visible for item in view.message_items))
        self.assertTrue(all(item.visible for item in view.confirmation_controls))

    def test_exact_route_preserves_unlock_then_setup_gate_order(self):
        value = exact_presentation()
        view = prepare(value).view
        gates = tuple(
            item.message_key for item in view.message_items if item.is_gate_message
        )
        self.assertEqual(gates, value.gate_message_keys)
        self.assertEqual(
            gates,
            (
                presentation.RecoveryPresentationMessageKey
                .GATE_NORMAL_VAULT_UNLOCK_REQUIRED,
                presentation.RecoveryPresentationMessageKey
                .GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
            ),
        )

    def test_conflict_route_is_terminal_without_operation_controls(self):
        view = prepare(conflict_presentation()).view
        self.assertTrue(view.terminal_stop)
        self.assertFalse(view.downstream_reverification_required)
        self.assertFalse(view.operation_controls_included)
        self.assertFalse(view.auto_accept_available)

    def test_preserve_route_for_every_classification_is_terminal(self):
        for result in (absent_result(), exact_result(), conflict_result()):
            with self.subTest(classification=result.classification):
                view = prepare(preserve_presentation(result)).view
                self.assertTrue(view.terminal_stop)
                self.assertEqual(
                    view.state,
                    workflow.RecoveryWorkflowState.PRESERVED_STOP,
                )

    def test_controls_are_separate_initially_unselected_and_accessible(self):
        controls = prepare(exact_presentation()).view.confirmation_controls
        self.assertEqual(
            tuple(item.ordinal for item in controls),
            tuple(range(1, len(controls) + 1)),
        )
        self.assertTrue(all(item.required for item in controls))
        self.assertTrue(all(item.individually_selectable for item in controls))
        self.assertTrue(all(not item.default_selected for item in controls))
        self.assertTrue(all(item.accessible_label_key_bound for item in controls))

    def test_message_ordinals_are_stable_and_accessible(self):
        messages = prepare(absent_presentation()).view.message_items
        self.assertEqual(
            tuple(item.ordinal for item in messages),
            tuple(range(1, len(messages) + 1)),
        )
        self.assertTrue(all(item.accessible_label_key_bound for item in messages))

    def test_success_delegates_to_stage_2_11_without_authority(self):
        value = exact_presentation()
        receipt = acknowledge(value)
        self.assertEqual(
            receipt.acknowledged_confirmations,
            value.confirmation_requirements,
        )
        self.assertTrue(receipt.stage_2_11_acknowledgement_validated)
        self.assertFalse(receipt.operation_performed)
        self.assertFalse(receipt.operation_authorized)
        self.assertFalse(receipt.gate_invoked)

    def test_prepared_state_changes_only_after_success(self):
        value = absent_presentation()
        prepared = prepare(value)
        self.assertFalse(prepared.acknowledged)
        self.assertIsNone(prepared.receipt)
        self.assertEqual(
            prepared.current_state,
            adapter.RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS,
        )
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertTrue(prepared.acknowledged)
        self.assertIs(prepared.receipt, receipt)
        self.assertEqual(
            prepared.current_state,
            adapter.RecoveryUIAdapterState.ACKNOWLEDGED,
        )


class RecoveryUIAdapterInteractionTests(unittest.TestCase):
    def assert_interaction_rejected(self, value, events):
        prepared = prepare(value)
        with self.assertRaises(adapter.VaultRecoveryUIAdapterInteractionError):
            prepared.acknowledge_visible_once(value, events)
        self.assertFalse(prepared.acknowledged)

    def test_none_list_and_empty_events_are_rejected(self):
        value = absent_presentation()
        events = valid_events(value)
        for changed in (None, [], (), list(events)):
            with self.subTest(changed=changed):
                self.assert_interaction_rejected(value, changed)

    def test_partial_events_are_rejected_for_every_route(self):
        for value in (
            absent_presentation(),
            exact_presentation(),
            conflict_presentation(),
            preserve_presentation(),
        ):
            with self.subTest(state=value.state):
                self.assert_interaction_rejected(value, valid_events(value)[:-1])

    def test_reordered_events_are_rejected(self):
        value = exact_presentation()
        self.assert_interaction_rejected(
            value,
            tuple(reversed(valid_events(value))),
        )

    def test_duplicate_event_is_rejected(self):
        value = conflict_presentation()
        events = valid_events(value)
        self.assert_interaction_rejected(value, events[:-1] + (events[0],))

    def test_extra_event_is_rejected(self):
        value = preserve_presentation()
        events = valid_events(value)
        extra = adapter.RecoveryUIConfirmationEvent(
            ordinal=len(events) + 1,
            confirmation_key=(
                presentation.RecoveryPresentationConfirmationKey
                .ACKNOWLEDGE_NO_AUTOMATIC_REPAIR
            ),
            visible=True,
            user_selected=True,
            user_initiated=True,
        )
        self.assert_interaction_rejected(value, events + (extra,))

    def test_hidden_confirmation_is_rejected(self):
        value = absent_presentation()
        events = valid_events(value)
        changed = (replace(events[0], visible=False),) + events[1:]
        self.assert_interaction_rejected(value, changed)

    def test_unselected_confirmation_is_rejected(self):
        value = absent_presentation()
        events = valid_events(value)
        changed = events[:-1] + (replace(events[-1], user_selected=False),)
        self.assert_interaction_rejected(value, changed)

    def test_non_user_initiated_confirmation_is_rejected(self):
        value = exact_presentation()
        events = valid_events(value)
        changed = events[:1] + (
            replace(events[1], user_initiated=False),
        ) + events[2:]
        self.assert_interaction_rejected(value, changed)

    def test_wrong_ordinal_is_rejected(self):
        value = exact_presentation()
        events = valid_events(value)
        changed = (replace(events[0], ordinal=2),) + events[1:]
        self.assert_interaction_rejected(value, changed)

    def test_supported_key_from_other_route_is_rejected(self):
        value = absent_presentation()
        events = valid_events(value)
        changed = events[:-1] + (
            replace(
                events[-1],
                confirmation_key=(
                    presentation.RecoveryPresentationConfirmationKey
                    .ACKNOWLEDGE_MANUAL_REVIEW_STOP
                ),
            ),
        )
        self.assert_interaction_rejected(value, changed)

    def test_mapping_string_and_lookalike_events_are_rejected(self):
        value = absent_presentation()
        for changed in (
            tuple(item.confirmation_key.value for item in valid_events(value)),
            tuple({"key": item.confirmation_key} for item in valid_events(value)),
        ):
            with self.subTest(changed=changed):
                self.assert_interaction_rejected(value, changed)

    def test_failed_event_sequence_does_not_consume_adapter(self):
        value = exact_presentation()
        prepared = prepare(value)
        events = valid_events(value)
        with self.assertRaises(adapter.VaultRecoveryUIAdapterInteractionError):
            prepared.acknowledge_visible_once(value, events[:-1])
        receipt = prepared.acknowledge_visible_once(value, events)
        self.assertTrue(receipt.all_confirmations_user_selected)


class RecoveryUIAdapterBindingTests(unittest.TestCase):
    def test_different_valid_route_is_a_mismatch(self):
        original = absent_presentation()
        prepared = prepare(original)
        changed = preserve_presentation()
        with self.assertRaises(adapter.VaultRecoveryUIAdapterMismatchError):
            prepared.acknowledge_visible_once(changed, valid_events(changed))
        self.assertFalse(prepared.acknowledged)

    def test_changed_workflow_digest_is_a_mismatch(self):
        original = absent_presentation()
        prepared = prepare(original)
        changed = replace(original, workflow_state_sha256=b"Z" * 32)
        with self.assertRaises(adapter.VaultRecoveryUIAdapterMismatchError):
            prepared.acknowledge_visible_once(changed, valid_events(changed))

    def test_equivalent_reconstructed_presentation_is_accepted(self):
        first = exact_presentation()
        second = replace(first)
        prepared = prepare(first)
        receipt = prepared.acknowledge_visible_once(second, valid_events(second))
        self.assertEqual(receipt.confirmation_count, 4)

    def test_none_mapping_and_subclass_presentation_are_rejected(self):
        for value in (None, {}, absent_presentation().message_keys):
            with self.subTest(value=value):
                with self.assertRaises(
                    adapter.VaultRecoveryUIAdapterPresentationError
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
        with self.assertRaises(adapter.VaultRecoveryUIAdapterPresentationError):
            prepare(subclass)

    def test_forged_presentation_schema_and_authority_are_rejected(self):
        original = exact_presentation()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"workflow_state_sha256": b"short"},
            {"message_keys": list(original.message_keys)},
            {"confirmation_requirements": original.confirmation_requirements[:-1]},
            {"raw_text_included": True},
            {"operation_authorized": True},
            {"operation_authorized": 0},
            {"secrets_retained": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                forged = forge_dataclass(original, **changes)
                with self.assertRaises(
                    adapter.VaultRecoveryUIAdapterPresentationError
                ):
                    prepare(forged)

    def test_tampered_prepared_view_is_detected_before_acknowledgement(self):
        value = absent_presentation()
        prepared = prepare(value)
        object.__setattr__(prepared.view, "presentation_sha256", b"Z" * 32)
        with self.assertRaises(adapter.VaultRecoveryUIAdapterMismatchError):
            prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertFalse(prepared.acknowledged)


class RecoveryUIAdapterOneShotTests(unittest.TestCase):
    def test_second_identical_acknowledgement_is_replay(self):
        value = absent_presentation()
        prepared = prepare(value)
        prepared.acknowledge_visible_once(value, valid_events(value))
        with self.assertRaises(adapter.VaultRecoveryUIAdapterReplayError):
            prepared.acknowledge_visible_once(value, valid_events(value))

    def test_replay_check_precedes_changed_input(self):
        value = absent_presentation()
        prepared = prepare(value)
        prepared.acknowledge_visible_once(value, valid_events(value))
        changed = conflict_presentation()
        with self.assertRaises(adapter.VaultRecoveryUIAdapterReplayError):
            prepared.acknowledge_visible_once(changed, valid_events(changed))

    def test_prepared_adapter_cannot_be_copied_or_pickled(self):
        prepared = prepare(absent_presentation())
        for operation in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.assertRaises(adapter.VaultRecoveryUIAdapterReplayError):
                operation()

    def test_concurrent_attempts_have_exactly_one_success(self):
        value = exact_presentation()
        prepared = prepare(value)
        events = valid_events(value)
        count = 8
        barrier = threading.Barrier(count)

        def attempt():
            barrier.wait()
            try:
                prepared.acknowledge_visible_once(value, events)
                return "success"
            except adapter.VaultRecoveryUIAdapterReplayError:
                return "replay"

        with ThreadPoolExecutor(max_workers=count) as executor:
            observed = list(executor.map(lambda _: attempt(), range(count)))
        self.assertEqual(observed.count("success"), 1)
        self.assertEqual(observed.count("replay"), count - 1)

    def test_repr_hides_digests(self):
        value = exact_presentation()
        prepared = prepare(value)
        rendered = repr(prepared)
        self.assertNotIn(repr(prepared.view.presentation_sha256), rendered)
        self.assertNotIn(repr(value.workflow_state_sha256), rendered)


class RecoveryUIAdapterViewAndReceiptValidationTests(unittest.TestCase):
    def valid_view(self):
        return prepare(exact_presentation()).view

    def valid_receipt(self):
        return acknowledge(exact_presentation())

    def test_message_item_rejects_hidden_or_unlabelled_content(self):
        original = self.valid_view().message_items[0]
        for changes in (
            {"visible": False},
            {"accessible_label_key_bound": False},
            {"ordinal": True},
            {"message_key": original.message_key.value},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(original, **changes)

    def test_control_rejects_hidden_default_or_grouped_state(self):
        original = self.valid_view().confirmation_controls[0]
        for changes in (
            {"visible": False},
            {"required": False},
            {"individually_selectable": False},
            {"default_selected": True},
            {"accessible_label_key_bound": False},
            {"ordinal": True},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(original, **changes)

    def test_view_format_digest_enums_and_state_are_strict(self):
        value = self.valid_view()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"version": True},
            {"presentation_sha256": b"short"},
            {"presentation_sha256": bytearray(32)},
            {"classification": value.classification.value},
            {"decision": value.decision.value},
            {"state": value.state.value},
            {"adapter_state": adapter.RecoveryUIAdapterState.ACKNOWLEDGED},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(value, **changes)

    def test_view_rejects_reordered_items_and_false_safety_flags(self):
        value = self.valid_view()
        cases = (
            {"message_items": tuple(reversed(value.message_items))},
            {"confirmation_controls": tuple(reversed(value.confirmation_controls))},
            {"all_required_messages_visible": False},
            {"all_confirmation_controls_visible": False},
            {"confirmations_individually_selectable": False},
            {"confirmation_order_fixed": False},
            {"auto_accept_available": True},
            {"operation_controls_included": True},
            {"raw_text_included": True},
            {"operation_authorized": True},
            {"operation_authorized": 0},
            {"secrets_retained": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(value, **changes)

    def test_receipt_format_count_sequence_and_enums_are_strict(self):
        value = self.valid_receipt()
        cases = (
            {"format": "OTHER"},
            {"version": 2},
            {"presentation_sha256": b"short"},
            {"classification": value.classification.value},
            {"adapter_state": value.adapter_state.value},
            {"confirmation_count": 3},
            {"confirmation_count": True},
            {"acknowledgement_sequence": 2},
            {"acknowledgement_sequence": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(value, **changes)

    def test_receipt_rejects_partial_reordered_or_string_confirmations(self):
        value = self.valid_receipt()
        cases = (
            value.acknowledged_confirmations[:-1],
            tuple(reversed(value.acknowledged_confirmations)),
            tuple(item.value for item in value.acknowledged_confirmations),
            list(value.acknowledged_confirmations),
        )
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(value, acknowledged_confirmations=changed)

    def test_receipt_rejects_false_claims_and_authority(self):
        value = self.valid_receipt()
        cases = (
            ("presentation_revalidated", False),
            ("ui_view_revalidated", False),
            ("all_required_messages_visible", False),
            ("all_confirmation_controls_visible", False),
            ("confirmation_order_validated", False),
            ("all_confirmations_user_selected", False),
            ("user_initiated_events_reported", False),
            ("stage_2_11_acknowledgement_validated", False),
            ("read_only", False),
            ("auto_accept_used", True),
            ("hidden_confirmation_used", True),
            ("operation_performed", True),
            ("operation_authorized", True),
            ("gate_invoked", True),
            ("automatic_transition", True),
            ("secrets_retained", True),
            ("operation_authorized", 0),
        )
        for name, changed in cases:
            with self.subTest(name=name):
                with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                    replace(value, **{name: changed})

    def test_receipt_route_and_terminal_flags_cannot_be_mixed(self):
        value = self.valid_receipt()
        for changes in (
            {"classification": reconciler.RecoveryPublishClassification.CONFLICT},
            {"decision": workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP},
            {"state": workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP},
            {"terminal_stop": True},
            {"downstream_reverification_required": False},
        ):
            with self.assertRaises(adapter.VaultRecoveryUIAdapterFormatError):
                replace(value, **changes)

    def test_view_and_receipt_have_no_secret_text_callback_or_executor_field(self):
        names = {
            item.name.lower()
            for cls in (
                adapter.VaultRecoveryUIAdapterView,
                adapter.VaultRecoveryUIAdapterReceipt,
            )
            for item in fields(cls)
        }
        forbidden = (
            "password",
            "root",
            "keyring",
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


class RecoveryUIAdapterStaticBoundaryTests(unittest.TestCase):
    def test_only_one_public_module_function_is_exposed(self):
        public_functions = {
            name
            for name, item in inspect.getmembers(adapter, inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual(public_functions, {"prepare_recovery_ui_adapter"})

    def test_prepare_api_accepts_only_presentation(self):
        signature = inspect.signature(adapter.prepare_recovery_ui_adapter)
        self.assertEqual(tuple(signature.parameters), ("presentation",))

    def test_acknowledge_api_accepts_only_presentation_and_events(self):
        signature = inspect.signature(
            adapter.PreparedVaultRecoveryUIAdapter.acknowledge_visible_once
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("self", "presentation", "events"),
        )
        rendered = str(signature).lower()
        for token in (
            "password",
            "root",
            "keyring",
            "path",
            "callback",
            "executor",
            "authorization",
        ):
            self.assertNotIn(token, rendered)

    def test_module_imports_no_filesystem_network_gui_logging_clock_or_randomness(self):
        source_path = Path(adapter.__file__)
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
        source_path = Path(adapter.__file__)
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
        source = Path(adapter.__file__).read_text(encoding="utf-8")
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

    def test_adapter_does_not_change_the_presentation(self):
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

    def test_receipt_retains_no_view_presentation_event_or_executor(self):
        value = acknowledge(absent_presentation())
        for name in (
            "view",
            "presentation",
            "workflow_state",
            "message_items",
            "confirmation_controls",
            "events",
            "acknowledgement_receipt",
            "callback",
            "executor",
        ):
            self.assertFalse(hasattr(value, name), name)
        self.assertFalse(hasattr(value, "__dict__"))
        self.assertFalse(value.secrets_retained)

    def test_user_initiated_flag_is_documented_as_adapter_assertion_only(self):
        source = Path(adapter.__file__).read_text(encoding="utf-8")
        self.assertIn("bounded adapter assertion", source)
        self.assertIn("not biometric", source)
        self.assertIn("or operation authority", source)


if __name__ == "__main__":
    unittest.main()
