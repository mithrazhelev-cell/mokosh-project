import ast
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
import hashlib
import inspect
from pathlib import Path
import pickle
import subprocess
import sys
import threading
import unittest
from unittest import mock

import mokosh_vault_recovery_locale as localization
import mokosh_vault_recovery_source_inspection_acknowledgement as acknowledgement
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_presentation as presentation
import mokosh_vault_recovery_source_inspection_ui_adapter as adapter


ROOT = Path(__file__).resolve().parents[1]
RECOVERY_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
VAULT_ID = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
SOURCE_HASH = hashlib.sha256(b"source-vault").digest()
RECORD_HASH = hashlib.sha256(b"recovery-record").digest()


def positive_execution(locale="bg-BG", **changes):
    values = {
        "locale": (
            localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
            if locale == "bg-BG"
            else localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM
        ),
        "execution_decision": execution.RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION,
        "state": execution.RecoverySourceInspectionExecutionState.COMPLETED,
        "recovery_id": RECOVERY_ID,
        "vault_id": VAULT_ID,
        "source_revision": 7,
        "source_vault_sha256": SOURCE_HASH,
        "record_sha256": RECORD_HASH,
        "encoded_size": 777,
        "secure_source_inspection_performed": True,
        "preserved_and_stopped": False,
        "header_structurally_validated": True,
    }
    values.update(changes)
    return execution.VaultRecoverySourceInspectionExecutionOutcome(**values)


def source_presentation(locale="bg-BG", **changes):
    value = presentation.prepare_recovery_source_inspection_presentation(
        positive_execution(locale)
    )
    if changes:
        value = replace(value, **changes)
    return value


_DEFAULT_PRESENTATION = object()


def prepare(value=_DEFAULT_PRESENTATION):
    if value is _DEFAULT_PRESENTATION:
        value = source_presentation()
    return adapter.prepare_recovery_source_inspection_ui_adapter(value)


def valid_events(value=None):
    if value is None:
        value = source_presentation()
    return tuple(
        adapter.RecoverySourceInspectionUIConfirmationEvent(
            ordinal=index,
            confirmation_key=key,
            visible=True,
            user_selected=True,
            user_initiated=True,
        )
        for index, key in enumerate(value.confirmation_requirements, start=1)
    )


def acknowledge(value=None):
    if value is None:
        value = source_presentation()
    return prepare(value).acknowledge_visible_once(value, valid_events(value))


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class SourceInspectionUIAdapterTests(unittest.TestCase):
    def test_01_bulgarian_view_is_bounded(self):
        prepared = prepare(source_presentation("bg-BG"))
        self.assertEqual(prepared.view.locale.value, "bg-BG")
        self.assertEqual(len(prepared.view.message_items), 7)
        self.assertEqual(len(prepared.view.confirmation_controls), 3)

    def test_02_english_view_is_bounded(self):
        prepared = prepare(source_presentation("en-GB"))
        self.assertEqual(prepared.view.locale.value, "en-GB")
        self.assertTrue(prepared.view.fixed_localization_keys_only)
        self.assertFalse(prepared.view.raw_text_included)

    def test_03_seven_message_items_have_exact_stable_order(self):
        value = source_presentation()
        items = prepare(value).view.message_items
        self.assertEqual(tuple(item.ordinal for item in items), tuple(range(1, 8)))
        self.assertEqual(tuple(item.message_key for item in items), value.message_keys)
        self.assertTrue(all(item.visible is True for item in items))
        self.assertTrue(all(item.accessible_label_key_bound is True for item in items))

    def test_04_three_controls_are_separate_required_and_default_unselected(self):
        value = source_presentation()
        controls = prepare(value).view.confirmation_controls
        self.assertEqual(tuple(item.ordinal for item in controls), (1, 2, 3))
        self.assertEqual(
            tuple(item.confirmation_key for item in controls),
            value.confirmation_requirements,
        )
        self.assertTrue(all(item.visible and item.required for item in controls))
        self.assertTrue(all(item.individually_selectable for item in controls))
        self.assertTrue(all(item.default_selected is False for item in controls))

    def test_05_view_excludes_shortcuts_raw_text_and_operation_controls(self):
        view = prepare().view
        self.assertFalse(view.auto_accept_available)
        self.assertFalse(view.select_all_available)
        self.assertFalse(view.remembered_selection_used)
        self.assertFalse(view.raw_text_included)
        self.assertFalse(view.operation_controls_included)

    def test_06_source_requires_exact_stage233_type(self):
        exact = source_presentation()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, (), "presentation", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    adapter.VaultRecoverySourceInspectionUIAdapterPresentationError
                ):
                    prepare(invalid)

    def test_07_forged_stage233_schema_is_revalidated(self):
        exact = source_presentation()
        cases = (
            {"inspection_evidence_sha256": b"short"},
            {"message_keys": list(exact.message_keys)},
            {"confirmation_requirements": list(exact.confirmation_requirements)},
            {"raw_text_included": True},
            {"operation_authorized": True},
            {"inspection_completed": 1},
            {"format": "OTHER"},
            {"version": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(
                    adapter.VaultRecoverySourceInspectionUIAdapterPresentationError
                ):
                    prepare(forged_copy(exact, **changes))

    def test_08_arbitrary_valid_digest_is_only_a_process_local_binding(self):
        value = source_presentation(
            inspection_evidence_sha256=hashlib.sha256(b"arbitrary").digest()
        )
        prepared = prepare(value)
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertFalse(receipt.source_provenance_proven)
        self.assertFalse(receipt.cryptographic_authenticity_established)
        self.assertFalse(receipt.source_freshness_established)

    def test_09_public_constants_and_signatures_are_exact(self):
        self.assertEqual(
            adapter.RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_UI_ADAPTER",
        )
        self.assertEqual(adapter.RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_VERSION, 1)
        self.assertEqual(
            list(inspect.signature(adapter.prepare_recovery_source_inspection_ui_adapter).parameters),
            ["presentation"],
        )
        self.assertEqual(
            list(inspect.signature(adapter.PreparedVaultRecoverySourceInspectionUIAdapter.acknowledge_visible_once).parameters),
            ["self", "presentation", "events"],
        )

    def test_10_binding_covers_digest_locale_messages_and_confirmations(self):
        value = source_presentation()
        prepared = prepare(value)
        expected = acknowledgement._binding_from_presentation(value)
        self.assertEqual(prepared.view.presentation_sha256, expected.presentation_sha256)
        self.assertIs(prepared.view.locale, expected.locale)
        self.assertEqual(
            tuple(item.message_key for item in prepared.view.message_items),
            value.message_keys,
        )
        self.assertEqual(prepared.required_confirmations, expected.required_confirmations)

    def test_11_constructor_rejects_private_acknowledgement_for_other_binding(self):
        first = source_presentation("bg-BG")
        second = source_presentation("en-GB")
        prepared = prepare(first)
        wrong = acknowledgement.prepare_recovery_source_inspection_acknowledgement(second)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
            adapter.PreparedVaultRecoverySourceInspectionUIAdapter(
                prepared._binding,
                prepared.view,
                wrong,
            )

    def test_12_message_item_schema_is_strict(self):
        key = source_presentation().message_keys[0]
        cases = (
            {"ordinal": True, "message_key": key},
            {"ordinal": 0, "message_key": key},
            {"ordinal": 1, "message_key": key.value},
            {"ordinal": 1, "message_key": key, "visible": 1},
            {"ordinal": 1, "message_key": key, "accessible_label_key_bound": 1},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                    adapter.RecoverySourceInspectionUIMessageItem(**values)

    def test_13_confirmation_control_schema_is_strict(self):
        key = source_presentation().confirmation_requirements[0]
        cases = (
            {"ordinal": True, "confirmation_key": key},
            {"ordinal": 4, "confirmation_key": key},
            {"ordinal": 1, "confirmation_key": key.value},
            {"ordinal": 1, "confirmation_key": key, "visible": 1},
            {"ordinal": 1, "confirmation_key": key, "default_selected": True},
            {"ordinal": 1, "confirmation_key": key, "select_all_available": True},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                    adapter.RecoverySourceInspectionUIConfirmationControl(**values)

    def test_14_confirmation_event_shape_requires_exact_types(self):
        key = source_presentation().confirmation_requirements[0]
        base = {
            "ordinal": 1,
            "confirmation_key": key,
            "visible": True,
            "user_selected": True,
            "user_initiated": True,
        }
        cases = (
            {"ordinal": True},
            {"ordinal": 0},
            {"confirmation_key": key.value},
            {"visible": 1},
            {"user_selected": 1},
            {"user_initiated": 1},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
                    adapter.RecoverySourceInspectionUIConfirmationEvent(**(base | change))

    def test_15_view_schema_requires_exact_container_types_and_counts(self):
        view = prepare().view
        cases = (
            {"presentation_sha256": b"short"},
            {"message_items": list(view.message_items)},
            {"message_items": view.message_items[:-1]},
            {"confirmation_controls": list(view.confirmation_controls)},
            {"confirmation_controls": view.confirmation_controls[:-1]},
            {"format": "OTHER"},
            {"version": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                    adapter._validate_adapter_view(forged_copy(view, **change))

    def test_16_view_required_true_flags_are_strict(self):
        view = prepare().view
        names = (
            "presentation_validated",
            "fixed_localization_keys_only",
            "all_required_messages_visible",
            "all_confirmation_controls_visible",
            "confirmations_individually_selectable",
            "confirmation_order_fixed",
            "all_controls_default_unselected",
            "process_local",
        )
        for name in names:
            for invalid in (False, 1):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                        adapter._validate_adapter_view(forged_copy(view, **{name: invalid}))

    def test_17_view_required_false_flags_are_strict(self):
        view = prepare().view
        names = (
            "physical_gui_rendering_proven",
            "accessibility_conformance_proven",
            "auto_accept_available",
            "select_all_available",
            "remembered_selection_used",
            "raw_text_included",
            "operation_controls_included",
            "human_understanding_proven",
            "user_identity_verified",
            "informed_consent_proven",
            "operation_authorized",
            "secrets_retained",
        )
        for name in names:
            for invalid in (True, 0):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                        adapter._validate_adapter_view(forged_copy(view, **{name: invalid}))

    def test_18_events_require_one_exact_tuple(self):
        value = source_presentation()
        for invalid in (None, [], (), "events"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
                    prepare(value).acknowledge_visible_once(value, invalid)

    def test_19_partial_events_are_rejected(self):
        value = source_presentation()
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, valid_events(value)[:2])

    def test_20_reordered_events_are_rejected(self):
        value = source_presentation()
        events = valid_events(value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, (events[1], events[0], events[2]))

    def test_21_duplicate_events_are_rejected(self):
        value = source_presentation()
        events = valid_events(value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, (events[0], events[0], events[2]))

    def test_22_extra_events_are_rejected(self):
        value = source_presentation()
        events = valid_events(value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, events + (events[0],))

    def test_23_string_lookalike_events_are_rejected(self):
        value = source_presentation()
        events = list(valid_events(value))
        events[0] = forged_copy(events[0], confirmation_key=events[0].confirmation_key.value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, tuple(events))

    def test_24_hidden_confirmation_is_rejected(self):
        value = source_presentation()
        events = list(valid_events(value))
        events[0] = replace(events[0], visible=False)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, tuple(events))

    def test_25_unselected_confirmation_is_rejected(self):
        value = source_presentation()
        events = list(valid_events(value))
        events[1] = replace(events[1], user_selected=False)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, tuple(events))

    def test_26_non_user_initiated_confirmation_is_rejected(self):
        value = source_presentation()
        events = list(valid_events(value))
        events[2] = replace(events[2], user_initiated=False)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepare(value).acknowledge_visible_once(value, tuple(events))

    def test_27_wrong_ordinal_or_key_is_rejected(self):
        value = source_presentation()
        events = list(valid_events(value))
        cases = (
            replace(events[0], ordinal=2),
            replace(events[0], confirmation_key=events[1].confirmation_key),
        )
        for invalid in cases:
            attempt = [invalid, events[1], events[2]]
            with self.subTest(invalid=invalid):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
                    prepare(value).acknowledge_visible_once(value, tuple(attempt))

    def test_28_predelegation_event_failure_is_retryable(self):
        value = source_presentation()
        prepared = prepare(value)
        invalid = list(valid_events(value))
        invalid[0] = replace(invalid[0], visible=False)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterInteractionError):
            prepared.acknowledge_visible_once(value, tuple(invalid))
        self.assertFalse(prepared.terminal)
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertTrue(receipt.read_only)

    def test_29_predelegation_presentation_mismatch_is_retryable(self):
        value = source_presentation("bg-BG")
        prepared = prepare(value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterMismatchError):
            prepared.acknowledge_visible_once(source_presentation("en-GB"), valid_events(value))
        self.assertFalse(prepared.terminal)
        self.assertTrue(prepared.acknowledge_visible_once(value, valid_events(value)).read_only)

    def test_30_predelegation_digest_mismatch_is_retryable(self):
        value = source_presentation()
        other = replace(value, inspection_evidence_sha256=hashlib.sha256(b"other").digest())
        prepared = prepare(value)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterMismatchError):
            prepared.acknowledge_visible_once(other, valid_events(value))
        self.assertFalse(prepared.terminal)
        prepared.acknowledge_visible_once(value, valid_events(value))

    def test_31_predelegation_tampered_view_failure_is_retryable(self):
        value = source_presentation()
        prepared = prepare(value)
        object.__setattr__(prepared.view, "raw_text_included", True)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
            prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertFalse(prepared.terminal)
        object.__setattr__(prepared.view, "raw_text_included", False)
        prepared.acknowledge_visible_once(value, valid_events(value))

    def test_32_equivalent_reconstructed_presentation_is_accepted(self):
        first = source_presentation()
        second = replace(first)
        receipt = prepare(first).acknowledge_visible_once(second, valid_events(second))
        self.assertEqual(receipt.locale, first.locale)

    def test_33_private_acknowledgement_error_is_terminal_failed_closed(self):
        value = source_presentation()
        prepared = prepare(value)
        error = acknowledgement.VaultRecoverySourceInspectionAcknowledgementMismatchError("no")
        with mock.patch.object(
            acknowledgement.PreparedVaultRecoverySourceInspectionAcknowledgement,
            "acknowledge_once",
            side_effect=error,
        ):
            with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterMismatchError):
                prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertTrue(prepared.terminal)
        self.assertFalse(prepared.acknowledged)
        self.assertEqual(prepared.current_state, adapter.RecoverySourceInspectionUIAdapterState.FAILED_CLOSED)

    def test_34_baseexception_during_private_delegation_is_terminal(self):
        value = source_presentation()
        prepared = prepare(value)
        with mock.patch.object(
            acknowledgement.PreparedVaultRecoverySourceInspectionAcknowledgement,
            "acknowledge_once",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertEqual(prepared.current_state, adapter.RecoverySourceInspectionUIAdapterState.FAILED_CLOSED)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
            prepared.acknowledge_visible_once(value, valid_events(value))

    def test_35_interrupt_after_private_success_cannot_leave_outer_fresh(self):
        value = source_presentation()
        prepared = prepare(value)
        with mock.patch.object(
            adapter,
            "VaultRecoverySourceInspectionUIAdapterReceipt",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertTrue(prepared._acknowledgement.acknowledged)
        self.assertEqual(prepared.current_state, adapter.RecoverySourceInspectionUIAdapterState.FAILED_CLOSED)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
            prepared.acknowledge_visible_once(value, valid_events(value))

    def test_36_invalid_private_receipt_is_terminal_failed_closed(self):
        value = source_presentation()
        valid_but_uncommitted = acknowledgement.prepare_recovery_source_inspection_acknowledgement(
            value
        ).acknowledge_once(value, value.confirmation_requirements)
        for returned in (object(), valid_but_uncommitted):
            with self.subTest(returned=type(returned).__name__):
                prepared = prepare(value)
                with mock.patch.object(
                    acknowledgement.PreparedVaultRecoverySourceInspectionAcknowledgement,
                    "acknowledge_once",
                    return_value=returned,
                ):
                    with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterMismatchError):
                        prepared.acknowledge_visible_once(value, valid_events(value))
                self.assertEqual(
                    prepared.current_state,
                    adapter.RecoverySourceInspectionUIAdapterState.FAILED_CLOSED,
                )

    def test_37_success_is_one_shot_and_replay_is_rejected(self):
        value = source_presentation()
        prepared = prepare(value)
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        self.assertIs(prepared.receipt, receipt)
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
            prepared.acknowledge_visible_once(value, valid_events(value))

    def test_38_terminal_replay_check_precedes_new_input_validation(self):
        value = source_presentation()
        prepared = prepare(value)
        prepared.acknowledge_visible_once(value, valid_events(value))
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
            prepared.acknowledge_visible_once(None, None)

    def test_39_concurrency_allows_exactly_one_terminal_delegation(self):
        value = source_presentation()
        prepared = prepare(value)
        barrier = threading.Barrier(8)

        def attempt(_):
            barrier.wait()
            try:
                prepared.acknowledge_visible_once(value, valid_events(value))
                return "success"
            except adapter.VaultRecoverySourceInspectionUIAdapterReplayError:
                return "replay"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("replay"), 7)

    def test_40_lifecycle_uses_one_terminal_marker_and_rejects_invalid_marker(self):
        prepared = prepare()
        self.assertIn("_terminal", prepared.__slots__)
        self.assertNotIn("_receipt", prepared.__slots__)
        self.assertNotIn("_acknowledged", prepared.__slots__)
        object.__setattr__(prepared, "_terminal", object())
        with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
            _ = prepared.current_state

    def test_41_view_receipt_and_prepared_object_cannot_be_copied_or_pickled(self):
        value = source_presentation()
        prepared = prepare(value)
        view = prepared.view
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        for item in (view, receipt, prepared):
            with self.subTest(item=type(item).__name__):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
                    copy.copy(item)
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
                    copy.deepcopy(item)
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterReplayError):
                    pickle.dumps(item)

    def test_42_receipt_schema_is_exact_and_immutable(self):
        receipt = acknowledge()
        expected = {
            "presentation_sha256", "locale", "adapter_state",
            "acknowledged_confirmations", "confirmation_count",
            "acknowledgement_sequence", "presentation_revalidated",
            "ui_view_revalidated", "all_required_messages_visible_reported",
            "all_confirmation_controls_visible_reported",
            "confirmation_order_validated", "all_confirmations_user_selected_reported",
            "user_initiated_events_reported", "stage2_34_acknowledgement_validated",
            "read_only", "process_local", "ui_event_claims_are_adapter_assertions",
            "actual_gui_rendering_proven", "accessibility_conformance_proven",
            "human_understanding_proven", "user_identity_verified",
            "informed_consent_proven", "digital_signature_created",
            "source_provenance_proven", "cryptographic_authenticity_established",
            "source_freshness_established", "recovery_secret_received",
            "recovery_performed", "rehearsal_performed", "stage2_8_used",
            "review_session_prepared", "operation_authorized", "operation_performed",
            "gate_invoked", "automatic_transition", "filesystem_access_performed",
            "filesystem_mutation_performed", "network_used", "logging_used",
            "gui_used", "format", "version",
        }
        self.assertEqual({item.name for item in fields(receipt)}, expected)
        with self.assertRaises((AttributeError, TypeError)):
            receipt.operation_authorized = True

    def test_43_receipt_scalar_and_enum_fields_are_strict(self):
        receipt = acknowledge()
        cases = (
            {"presentation_sha256": b"short"},
            {"locale": receipt.locale.value},
            {"adapter_state": receipt.adapter_state.value},
            {"acknowledged_confirmations": list(receipt.acknowledged_confirmations)},
            {"confirmation_count": True},
            {"acknowledgement_sequence": True},
            {"format": "OTHER"},
            {"version": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                    adapter._validate_adapter_receipt(forged_copy(receipt, **change))

    def test_44_receipt_required_true_flags_are_strict(self):
        receipt = acknowledge()
        names = (
            "presentation_revalidated", "ui_view_revalidated",
            "all_required_messages_visible_reported",
            "all_confirmation_controls_visible_reported",
            "confirmation_order_validated", "all_confirmations_user_selected_reported",
            "user_initiated_events_reported", "stage2_34_acknowledgement_validated",
            "read_only", "process_local", "ui_event_claims_are_adapter_assertions",
        )
        for name in names:
            for invalid in (False, 1):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                        adapter._validate_adapter_receipt(forged_copy(receipt, **{name: invalid}))

    def test_45_receipt_false_flags_preserve_honest_no_authority_boundary(self):
        receipt = acknowledge()
        names = (
            "actual_gui_rendering_proven", "accessibility_conformance_proven",
            "human_understanding_proven", "user_identity_verified",
            "informed_consent_proven", "digital_signature_created",
            "source_provenance_proven", "cryptographic_authenticity_established",
            "source_freshness_established", "recovery_secret_received",
            "recovery_performed", "rehearsal_performed", "stage2_8_used",
            "review_session_prepared", "operation_authorized", "operation_performed",
            "gate_invoked", "automatic_transition", "filesystem_access_performed",
            "filesystem_mutation_performed", "network_used", "logging_used", "gui_used",
        )
        self.assertTrue(all(getattr(receipt, name) is False for name in names))
        for name in names:
            for invalid in (True, 0):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(adapter.VaultRecoverySourceInspectionUIAdapterFormatError):
                        adapter._validate_adapter_receipt(forged_copy(receipt, **{name: invalid}))

    def test_46_objects_retain_no_raw_evidence_or_capabilities(self):
        view = prepare().view
        receipt = acknowledge()
        forbidden = {
            "recovery_id", "vault_id", "source_path", "source_descriptor",
            "source_content", "source_revision", "source_vault_sha256",
            "record_sha256", "encoded_size", "recovery_secret", "callback",
            "executor", "gate", "rendered_text", "message_text",
        }
        for value in (view, receipt):
            self.assertTrue(forbidden.isdisjoint({item.name for item in fields(value)}))

    def test_47_repr_hides_digest_and_source_identifiers(self):
        value = source_presentation()
        prepared = prepare(value)
        receipt = prepared.acknowledge_visible_once(value, valid_events(value))
        for item in (prepared.view, receipt, prepared):
            rendered = repr(item)
            self.assertNotIn(prepared.view.presentation_sha256.hex(), rendered)
            self.assertNotIn(RECOVERY_ID.hex(), rendered)
            self.assertNotIn(VAULT_ID.hex(), rendered)

    def test_48_import_surface_and_fresh_import_are_capability_bounded(self):
        path = ROOT / "mokosh_vault_recovery_source_inspection_ui_adapter.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertEqual(
            imports,
            {
                "__future__", "hmac", "dataclasses", "enum", "threading", "typing",
                "mokosh_vault_recovery_locale",
                "mokosh_vault_recovery_source_inspection_acknowledgement",
                "mokosh_vault_recovery_source_inspection_presentation",
            },
        )
        self.assertTrue(
            {"os", "pathlib", "socket", "subprocess", "logging", "time", "random", "tkinter"}.isdisjoint(imports)
        )
        self.assertTrue({"open", "getattr", "setattr", "eval", "exec"}.isdisjoint(calls))
        code = (
            "import sys; import mokosh_vault_recovery_source_inspection_ui_adapter; "
            "forbidden={'tkinter','socket','subprocess','mokosh_vault_recovery_storage',"
            "'mokosh_gui','mokosh_crypto','mokosh_contacts'}; "
            "assert forbidden.isdisjoint(sys.modules)"
        )
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)

    def test_49_critical_predecessor_files_remain_byte_exact(self):
        expected = {
            "mokosh_vault_recovery_source_inspection_acknowledgement.py": "dbbb810d1ac074e2274cf250d8fc4a21f90566eabfdb5d749337a6ddf9170dc4",
            "mokosh_vault_recovery_source_inspection_presentation.py": "747f6b2b3d5cc1c039c9449caae0c42688ab41fce3635641d02c57ce13e67b82",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "mokosh_paths.py": "3c0d8acb92bfc3a24e5bef28f83b96f709da6e0c1547cd53d1a1d08b2bdc0dd2",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
        }
        observed = {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in expected
        }
        self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()
