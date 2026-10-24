import ast
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
import hashlib
import inspect
from pathlib import Path
import pickle
import struct
import subprocess
import sys
import threading
import unittest
from unittest import mock

import mokosh_vault_recovery_locale as localization
import mokosh_vault_recovery_source_inspection_acknowledgement as acknowledgement
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_presentation as presentation


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
    return acknowledgement.prepare_recovery_source_inspection_acknowledgement(
        value
    )


def acknowledge(value=_DEFAULT_PRESENTATION):
    if value is _DEFAULT_PRESENTATION:
        value = source_presentation()
    prepared = prepare(value)
    return prepared.acknowledge_once(value, value.confirmation_requirements)


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


def pack_enum(value):
    encoded = value.value.encode("ascii")
    return struct.pack(">H", len(encoded)) + encoded


def pack_enum_tuple(value):
    return struct.pack(">B", len(value)) + b"".join(
        pack_enum(item) for item in value
    )


def independent_transcript(value):
    locale_code = {
        localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA: 1,
        localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM: 2,
    }[value.locale]
    flags = tuple(
        getattr(value, name)
        for name in (
            "inspection_completed",
            "header_structurally_validated",
            "cryptographic_authenticity_established",
            "future_secure_source_reopen_required",
            "exact_execution_outcome_validated",
            "fixed_message_keys_only",
            "raw_text_included",
            "raw_evidence_included",
            "original_execution_outcome_retained",
            "source_path_metadata_retained",
            "source_descriptor_retained",
            "source_content_retained",
            "source_identifiers_retained",
            "source_revision_retained",
            "source_hashes_retained",
            "source_size_retained",
            "recovery_secret_received",
            "recovery_performed",
            "rehearsal_performed",
            "stage2_8_used",
            "review_session_prepared",
            "operation_authorized",
            "operation_performed",
            "filesystem_access_performed",
            "filesystem_mutation_performed",
            "network_used",
            "logging_used",
            "gui_used",
            "process_local",
            "evidence_digest_is_digital_signature",
            "evidence_digest_is_provenance_proof",
            "evidence_digest_is_anti_rollback_anchor",
        )
    )
    format_bytes = value.format.encode("ascii")
    return b"".join(
        (
            b"MOKOSH\x00VAULT-RECOVERY-SOURCE-INSPECTION-ACKNOWLEDGEMENT\x00PRESENTATION-V1\x00",
            struct.pack(">B", locale_code),
            value.inspection_evidence_sha256,
            pack_enum_tuple(value.message_keys),
            pack_enum_tuple(value.confirmation_requirements),
            struct.pack(">32?", *flags),
            struct.pack(">H", len(format_bytes)),
            format_bytes,
            struct.pack(">I", value.version),
        )
    )


class SourceInspectionAcknowledgementPositiveTests(unittest.TestCase):
    def test_01_bulgarian_acknowledgement_is_bounded(self):
        value = source_presentation("bg-BG")
        receipt = acknowledge(value)
        self.assertEqual(receipt.locale.value, "bg-BG")
        self.assertEqual(receipt.confirmation_count, 3)
        self.assertTrue(receipt.all_confirmations_acknowledged)

    def test_02_english_acknowledgement_is_bounded(self):
        value = source_presentation("en-GB")
        receipt = acknowledge(value)
        self.assertEqual(receipt.locale.value, "en-GB")
        self.assertTrue(receipt.process_local)
        self.assertFalse(receipt.operation_authorized)

    def test_03_prepared_state_commits_with_one_receipt_assignment(self):
        value = source_presentation()
        prepared = prepare(value)
        self.assertFalse(prepared.acknowledged)
        self.assertIsNone(prepared.receipt)
        self.assertEqual(
            prepared.current_state,
            acknowledgement.RecoverySourceInspectionAcknowledgementState.AWAITING_CONFIRMATIONS,
        )
        receipt = prepared.acknowledge_once(
            value, value.confirmation_requirements
        )
        self.assertTrue(prepared.acknowledged)
        self.assertIs(prepared.receipt, receipt)
        self.assertEqual(
            prepared.current_state,
            acknowledgement.RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED,
        )

    def test_04_equivalent_reconstructed_presentation_is_accepted(self):
        first = source_presentation()
        second = replace(first)
        receipt = prepare(first).acknowledge_once(
            second, second.confirmation_requirements
        )
        self.assertEqual(receipt.locale, first.locale)

    def test_05_public_constants_and_signatures_are_exact(self):
        self.assertEqual(
            acknowledgement.RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT",
        )
        self.assertEqual(
            acknowledgement.RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_VERSION,
            1,
        )
        self.assertEqual(
            list(
                inspect.signature(
                    acknowledgement.prepare_recovery_source_inspection_acknowledgement
                ).parameters
            ),
            ["presentation"],
        )
        self.assertEqual(
            list(
                inspect.signature(
                    acknowledgement.PreparedVaultRecoverySourceInspectionAcknowledgement.acknowledge_once
                ).parameters
            ),
            ["self", "presentation", "confirmations"],
        )


class SourceInspectionAcknowledgementSourceTests(unittest.TestCase):
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
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementPresentationError
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
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementPresentationError
                ):
                    prepare(forged_copy(exact, **changes))

    def test_08_stage233_direct_digest_construction_is_not_claimed_as_provenance(self):
        value = source_presentation(
            inspection_evidence_sha256=b"Z" * 32
        )
        receipt = acknowledge(value)
        self.assertFalse(receipt.source_provenance_proven)
        self.assertFalse(receipt.cryptographic_authenticity_established)
        self.assertFalse(receipt.source_freshness_established)


class SourceInspectionAcknowledgementConfirmationTests(unittest.TestCase):
    def assert_rejected(self, confirmations):
        value = source_presentation()
        prepared = prepare(value)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementConfirmationError
        ):
            prepared.acknowledge_once(value, confirmations)
        self.assertFalse(prepared.acknowledged)

    def test_09_none_list_empty_and_string_are_rejected(self):
        value = source_presentation()
        for confirmations in (
            None,
            [],
            (),
            list(value.confirmation_requirements),
            tuple(item.value for item in value.confirmation_requirements),
        ):
            with self.subTest(confirmations=confirmations):
                self.assert_rejected(confirmations)

    def test_10_partial_confirmations_are_rejected(self):
        value = source_presentation()
        self.assert_rejected(value.confirmation_requirements[:-1])

    def test_11_reordered_confirmations_are_rejected(self):
        value = source_presentation()
        self.assert_rejected(tuple(reversed(value.confirmation_requirements)))

    def test_12_duplicate_confirmations_are_rejected(self):
        value = source_presentation()
        self.assert_rejected(
            value.confirmation_requirements[:-1]
            + (value.confirmation_requirements[0],)
        )

    def test_13_extra_confirmations_are_rejected(self):
        value = source_presentation()
        self.assert_rejected(
            value.confirmation_requirements
            + (value.confirmation_requirements[0],)
        )

    def test_14_supported_but_wrong_exact_order_is_rejected(self):
        value = source_presentation()
        wrong = (
            value.confirmation_requirements[0],
            value.confirmation_requirements[2],
            value.confirmation_requirements[1],
        )
        self.assert_rejected(wrong)

    def test_15_failed_confirmation_does_not_consume(self):
        value = source_presentation()
        prepared = prepare(value)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementConfirmationError
        ):
            prepared.acknowledge_once(
                value, value.confirmation_requirements[:-1]
            )
        receipt = prepared.acknowledge_once(
            value, value.confirmation_requirements
        )
        self.assertTrue(receipt.exact_confirmation_tokens_received)


class SourceInspectionAcknowledgementBindingTests(unittest.TestCase):
    def test_16_digest_is_deterministic(self):
        first = acknowledge(source_presentation())
        second = acknowledge(source_presentation())
        self.assertEqual(first.presentation_sha256, second.presentation_sha256)

    def test_17_locale_is_bound(self):
        bg = acknowledge(source_presentation("bg-BG"))
        en = acknowledge(source_presentation("en-GB"))
        self.assertNotEqual(bg.presentation_sha256, en.presentation_sha256)

    def test_18_inspection_evidence_digest_is_bound(self):
        first = acknowledge(source_presentation())
        changed = acknowledge(
            source_presentation(inspection_evidence_sha256=b"Z" * 32)
        )
        self.assertNotEqual(
            first.presentation_sha256, changed.presentation_sha256
        )

    def test_19_digest_matches_independent_complete_transcript(self):
        value = source_presentation()
        receipt = acknowledge(value)
        self.assertEqual(
            receipt.presentation_sha256,
            hashlib.sha256(independent_transcript(value)).digest(),
        )

    def test_20_changed_valid_presentation_is_mismatch(self):
        original = source_presentation()
        changed = replace(
            original, inspection_evidence_sha256=b"Z" * 32
        )
        prepared = prepare(original)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementMismatchError
        ):
            prepared.acknowledge_once(
                changed, changed.confirmation_requirements
            )
        self.assertFalse(prepared.acknowledged)

    def test_21_locale_mismatch_is_rejected(self):
        original = source_presentation("bg-BG")
        changed = source_presentation("en-GB")
        prepared = prepare(original)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementMismatchError
        ):
            prepared.acknowledge_once(
                changed, changed.confirmation_requirements
            )

    def test_22_binding_retains_no_original_presentation(self):
        value = source_presentation()
        prepared = prepare(value)
        self.assertNotIn("_presentation", prepared.__slots__)
        self.assertFalse(
            any(
                getattr(prepared._binding, item.name) is value
                for item in fields(prepared._binding)
            )
        )

    def test_22a_private_binding_is_fully_revalidated(self):
        value = source_presentation()
        valid = acknowledgement._binding_from_presentation(value)
        cases = (
            None,
            forged_copy(valid, presentation_sha256=b"short"),
            forged_copy(valid, presentation_sha256=bytearray(b"Z" * 32)),
            forged_copy(valid, locale="bg-BG"),
            forged_copy(
                valid,
                required_confirmations=list(valid.required_confirmations),
            ),
            forged_copy(
                valid,
                required_confirmations=tuple(
                    item.value for item in valid.required_confirmations
                ),
            ),
        )
        for changed in cases:
            with self.subTest(changed=type(changed).__name__):
                with self.assertRaises(
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementFormatError
                ):
                    acknowledgement.PreparedVaultRecoverySourceInspectionAcknowledgement(
                        changed
                    )


class SourceInspectionAcknowledgementLifecycleTests(unittest.TestCase):
    def test_23_second_attempt_is_replay(self):
        value = source_presentation()
        prepared = prepare(value)
        prepared.acknowledge_once(value, value.confirmation_requirements)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementReplayError
        ):
            prepared.acknowledge_once(value, value.confirmation_requirements)

    def test_24_replay_precedes_changed_input_validation(self):
        value = source_presentation()
        prepared = prepare(value)
        prepared.acknowledge_once(value, value.confirmation_requirements)
        with self.assertRaises(
            acknowledgement.VaultRecoverySourceInspectionAcknowledgementReplayError
        ):
            prepared.acknowledge_once(None, None)

    def test_25_concurrent_attempts_have_exactly_one_success(self):
        value = source_presentation()
        prepared = prepare(value)
        count = 8
        barrier = threading.Barrier(count)

        def attempt():
            barrier.wait()
            try:
                prepared.acknowledge_once(
                    value, value.confirmation_requirements
                )
                return "success"
            except acknowledgement.VaultRecoverySourceInspectionAcknowledgementReplayError:
                return "replay"

        with ThreadPoolExecutor(max_workers=count) as pool:
            observed = list(pool.map(lambda _: attempt(), range(count)))
        self.assertEqual(observed.count("success"), 1)
        self.assertEqual(observed.count("replay"), count - 1)

    def test_26_exception_before_commit_leaves_fresh_state(self):
        value = source_presentation()
        prepared = prepare(value)
        with mock.patch.object(
            acknowledgement,
            "_binding_from_presentation",
            side_effect=RuntimeError("synthetic"),
        ):
            with self.assertRaises(RuntimeError):
                prepared.acknowledge_once(
                    value, value.confirmation_requirements
                )
        self.assertFalse(prepared.acknowledged)
        self.assertIsNotNone(
            prepared.acknowledge_once(
                value, value.confirmation_requirements
            )
        )

    def test_27_baseexception_before_commit_leaves_fresh_state(self):
        value = source_presentation()
        prepared = prepare(value)
        with mock.patch.object(
            acknowledgement,
            "VaultRecoverySourceInspectionAcknowledgementReceipt",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                prepared.acknowledge_once(
                    value, value.confirmation_requirements
                )
        self.assertFalse(prepared.acknowledged)
        self.assertIsNotNone(
            prepared.acknowledge_once(
                value, value.confirmation_requirements
            )
        )

    def test_28_prepared_and_receipt_refuse_copy_and_pickle(self):
        value = source_presentation()
        prepared = prepare(value)
        receipt = prepared.acknowledge_once(
            value, value.confirmation_requirements
        )
        for item in (prepared, receipt):
            for operation in (
                lambda item=item: copy.copy(item),
                lambda item=item: copy.deepcopy(item),
                lambda item=item: pickle.dumps(item),
            ):
                with self.assertRaises(
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementReplayError
                ):
                    operation()


class SourceInspectionAcknowledgementReceiptTests(unittest.TestCase):
    def test_29_receipt_schema_is_exact(self):
        receipt = acknowledge()
        self.assertEqual(
            tuple(item.name for item in fields(receipt)),
            (
                "presentation_sha256", "locale", "acknowledgement_state",
                "acknowledged_confirmations", "confirmation_count",
                "acknowledgement_sequence", "presentation_validated",
                "exact_confirmation_tokens_received",
                "confirmation_order_validated", "all_confirmations_acknowledged",
                "one_shot", "read_only", "process_local",
                "human_understanding_proven", "user_identity_verified",
                "informed_consent_proven", "digital_signature_created",
                "source_provenance_proven",
                "cryptographic_authenticity_established",
                "source_freshness_established", "recovery_secret_received",
                "recovery_performed", "rehearsal_performed", "stage2_8_used",
                "review_session_prepared", "operation_authorized",
                "operation_performed", "gate_invoked", "automatic_transition",
                "filesystem_access_performed", "filesystem_mutation_performed",
                "network_used", "logging_used", "gui_used", "format", "version",
            ),
        )

    def test_30_digest_locale_state_count_sequence_format_version_are_strict(self):
        receipt = acknowledge()
        cases = (
            {"presentation_sha256": b"short"},
            {"presentation_sha256": bytearray(receipt.presentation_sha256)},
            {"locale": "bg-BG"},
            {"acknowledgement_state": "acknowledged"},
            {"confirmation_count": True},
            {"acknowledgement_sequence": True},
            {"format": 1},
            {"format": "OTHER"},
            {"version": True},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementFormatError
                ):
                    acknowledgement._validate_source_inspection_acknowledgement_receipt(
                        forged_copy(receipt, **changes)
                    )

    def test_31_receipt_confirmation_tuple_is_exact(self):
        receipt = acknowledge()
        cases = (
            list(receipt.acknowledged_confirmations),
            receipt.acknowledged_confirmations[:-1],
            tuple(reversed(receipt.acknowledged_confirmations)),
            tuple(item.value for item in receipt.acknowledged_confirmations),
        )
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(
                    acknowledgement.VaultRecoverySourceInspectionAcknowledgementFormatError
                ):
                    acknowledgement._validate_source_inspection_acknowledgement_receipt(
                        forged_copy(
                            receipt, acknowledged_confirmations=changed
                        )
                    )

    def test_32_required_true_flags_reject_false_and_integer(self):
        receipt = acknowledge()
        for name in (
            "presentation_validated", "exact_confirmation_tokens_received",
            "confirmation_order_validated", "all_confirmations_acknowledged",
            "one_shot", "read_only", "process_local",
        ):
            for changed in (False, 1):
                with self.subTest(name=name, changed=changed):
                    with self.assertRaises(
                        acknowledgement.VaultRecoverySourceInspectionAcknowledgementFormatError
                    ):
                        acknowledgement._validate_source_inspection_acknowledgement_receipt(
                            forged_copy(receipt, **{name: changed})
                        )

    def test_33_required_false_flags_reject_true_and_integer(self):
        receipt = acknowledge()
        for name in (
            "human_understanding_proven", "user_identity_verified",
            "informed_consent_proven", "digital_signature_created",
            "source_provenance_proven", "cryptographic_authenticity_established",
            "source_freshness_established", "recovery_secret_received",
            "recovery_performed", "rehearsal_performed", "stage2_8_used",
            "review_session_prepared", "operation_authorized",
            "operation_performed", "gate_invoked", "automatic_transition",
            "filesystem_access_performed", "filesystem_mutation_performed",
            "network_used", "logging_used", "gui_used",
        ):
            for changed in (True, 0):
                with self.subTest(name=name, changed=changed):
                    with self.assertRaises(
                        acknowledgement.VaultRecoverySourceInspectionAcknowledgementFormatError
                    ):
                        acknowledgement._validate_source_inspection_acknowledgement_receipt(
                            forged_copy(receipt, **{name: changed})
                        )

    def test_34_receipt_has_no_source_secret_or_capability_fields(self):
        names = {item.name for item in fields(acknowledgement.VaultRecoverySourceInspectionAcknowledgementReceipt)}
        forbidden = {
            "presentation", "execution_outcome", "recovery_id", "vault_id",
            "source_revision", "source_vault_sha256", "record_sha256",
            "encoded_size", "path", "filename", "descriptor", "ciphertext",
            "recovery_secret", "password", "callback", "executor", "gate",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_35_receipt_claims_only_exact_tokens_not_human_or_legal_proof(self):
        receipt = acknowledge()
        self.assertTrue(receipt.exact_confirmation_tokens_received)
        self.assertFalse(receipt.human_understanding_proven)
        self.assertFalse(receipt.user_identity_verified)
        self.assertFalse(receipt.informed_consent_proven)
        self.assertFalse(receipt.digital_signature_created)

    def test_36_repr_hides_digests_and_raw_source_values(self):
        value = source_presentation()
        prepared = prepare(value)
        receipt = prepared.acknowledge_once(
            value, value.confirmation_requirements
        )
        rendered = repr(prepared) + repr(receipt)
        for sensitive in (
            receipt.presentation_sha256,
            value.inspection_evidence_sha256,
            RECOVERY_ID,
            VAULT_ID,
            SOURCE_HASH,
            RECORD_HASH,
        ):
            self.assertNotIn(repr(sensitive), rendered)


class SourceInspectionAcknowledgementIsolationTests(unittest.TestCase):
    def test_37_ast_has_no_dynamic_filesystem_network_process_or_logging_capability(self):
        tree = ast.parse(
            (ROOT / "mokosh_vault_recovery_source_inspection_acknowledgement.py").read_text(
                encoding="utf-8"
            )
        )
        forbidden_names = {
            "open", "exec", "eval", "compile", "__import__", "getattr", "setattr"
        }
        forbidden_attributes = {
            "open", "read", "read_bytes", "read_text", "stat", "lstat",
            "resolve", "unlink", "remove", "replace", "rename", "Popen", "run",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_names)
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, forbidden_attributes)

    def test_38_direct_import_closure_is_exact_and_unprivileged(self):
        tree = ast.parse(
            (ROOT / "mokosh_vault_recovery_source_inspection_acknowledgement.py").read_text(
                encoding="utf-8"
            )
        )
        modules = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        self.assertEqual(
            modules,
            {
                "__future__", "hashlib", "hmac", "struct", "dataclasses",
                "enum", "threading", "typing", "mokosh_vault_recovery_locale",
                "mokosh_vault_recovery_source_inspection_presentation",
            },
        )

    def test_39_fresh_import_loads_no_storage_gui_or_localization_renderer(self):
        code = (
            "import sys; import mokosh_vault_recovery_source_inspection_acknowledgement; "
            "print('mokosh_vault_recovery_storage' in sys.modules, "
            "'mokosh_gui' in sys.modules, "
            "'mokosh_vault_recovery_localization' in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), "False False False")

    def test_40_acknowledgement_never_invokes_stage232_reader(self):
        value = source_presentation()
        with mock.patch.object(execution, "_read_source_once") as reader:
            receipt = acknowledge(value)
        reader.assert_not_called()
        self.assertFalse(receipt.filesystem_access_performed)

    def test_41_critical_existing_files_remain_byte_exact(self):
        expected = {
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
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
