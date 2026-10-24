import ast
import copy
from dataclasses import fields
import hashlib
import inspect
from pathlib import Path
import pickle
import subprocess
import sys
import unittest
from unittest import mock

import mokosh_vault_recovery_locale as localization
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


def stopped_execution(locale="bg-BG"):
    return execution.VaultRecoverySourceInspectionExecutionOutcome(
        locale=(
            localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA
            if locale == "bg-BG"
            else localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM
        ),
        execution_decision=execution.RecoverySourceInspectionExecutionDecision.PRESERVE_AND_STOP,
        state=execution.RecoverySourceInspectionExecutionState.COMPLETED,
        recovery_id=None,
        vault_id=None,
        source_revision=None,
        source_vault_sha256=None,
        record_sha256=None,
        encoded_size=None,
        secure_source_inspection_performed=False,
        preserved_and_stopped=True,
        header_structurally_validated=False,
    )


def forged_copy(value, **changes):
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged,
            item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


class VaultRecoverySourceInspectionPresentationTests(unittest.TestCase):
    def prepare(self, locale="bg-BG", **changes):
        return presentation.prepare_recovery_source_inspection_presentation(
            positive_execution(locale, **changes)
        )

    def test_01_bulgarian_positive_presentation_is_bounded(self):
        result = self.prepare()
        self.assertEqual(result.locale.value, "bg-BG")
        self.assertTrue(result.inspection_completed)
        self.assertTrue(result.header_structurally_validated)

    def test_02_english_positive_presentation_is_bounded(self):
        result = self.prepare("en-GB")
        self.assertEqual(result.locale.value, "en-GB")
        self.assertTrue(result.future_secure_source_reopen_required)
        self.assertFalse(result.cryptographic_authenticity_established)

    def test_03_source_requires_exact_stage32_outcome_type(self):
        exact = positive_execution()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, (), "outcome", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationSourceError
                ):
                    presentation.prepare_recovery_source_inspection_presentation(invalid)

    def test_04_preserve_outcome_cannot_be_presented(self):
        for locale in ("bg-BG", "en-GB"):
            with self.subTest(locale=locale):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationSourceError
                ):
                    presentation.prepare_recovery_source_inspection_presentation(
                        stopped_execution(locale)
                    )

    def test_05_forged_stage32_claims_are_fully_revalidated(self):
        exact = positive_execution()
        for change in (
            {"secure_source_inspection_performed": False},
            {"header_structurally_validated": False},
            {"cryptographically_authenticated": True},
            {"recovery_secret_received": True},
            {"operation_authorized": True},
            {"filesystem_identity_future_validity_claimed": True},
            {"format": "WRONG"},
            {"version": 2},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationSourceError
                ):
                    presentation.prepare_recovery_source_inspection_presentation(
                        forged_copy(exact, **change)
                    )

    def test_06_presentation_retains_no_original_outcome(self):
        source = positive_execution()
        result = presentation.prepare_recovery_source_inspection_presentation(source)
        self.assertNotIn(
            source,
            (getattr(result, item.name) for item in fields(result)),
        )
        self.assertFalse(result.original_execution_outcome_retained)

    def test_07_public_constants_enums_and_signature_are_exact(self):
        self.assertEqual(
            presentation.RECOVERY_SOURCE_INSPECTION_PRESENTATION_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_PRESENTATION",
        )
        self.assertEqual(presentation.RECOVERY_SOURCE_INSPECTION_PRESENTATION_VERSION, 1)
        self.assertEqual(presentation.RECOVERY_SOURCE_INSPECTION_PRESENTATION_EVIDENCE_SHA256_LEN, 32)
        self.assertEqual(presentation.RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT, 7)
        self.assertEqual(presentation.RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT, 3)
        self.assertEqual(
            tuple(inspect.signature(presentation.prepare_recovery_source_inspection_presentation).parameters),
            ("execution_outcome",),
        )

    def test_08_presentation_schema_is_exact_and_bounded(self):
        self.assertEqual(
            tuple(item.name for item in fields(presentation.VaultRecoverySourceInspectionPresentation)),
            (
                "locale", "inspection_evidence_sha256", "message_keys",
                "confirmation_requirements", "inspection_completed",
                "header_structurally_validated", "cryptographic_authenticity_established",
                "future_secure_source_reopen_required", "exact_execution_outcome_validated",
                "fixed_message_keys_only", "raw_text_included", "raw_evidence_included",
                "original_execution_outcome_retained", "source_path_metadata_retained",
                "source_descriptor_retained", "source_content_retained",
                "source_identifiers_retained", "source_revision_retained",
                "source_hashes_retained", "source_size_retained", "recovery_secret_received",
                "recovery_performed", "rehearsal_performed", "stage2_8_used",
                "review_session_prepared", "operation_authorized", "operation_performed",
                "filesystem_access_performed", "filesystem_mutation_performed", "network_used",
                "logging_used", "gui_used", "process_local",
                "evidence_digest_is_digital_signature", "evidence_digest_is_provenance_proof",
                "evidence_digest_is_anti_rollback_anchor", "format", "version",
            ),
        )

    def test_09_message_keys_are_fixed_complete_and_ordered(self):
        result = self.prepare()
        self.assertEqual(result.message_keys, presentation._MESSAGE_KEYS)
        self.assertEqual(len(result.message_keys), 7)
        self.assertEqual(len(set(result.message_keys)), 7)
        self.assertTrue(all(type(item) is presentation.RecoverySourceInspectionPresentationMessageKey for item in result.message_keys))

    def test_10_confirmation_requirements_are_fixed_complete_and_ordered(self):
        result = self.prepare()
        self.assertEqual(result.confirmation_requirements, presentation._CONFIRMATION_REQUIREMENTS)
        self.assertEqual(len(result.confirmation_requirements), 3)
        self.assertEqual(len(set(result.confirmation_requirements)), 3)

    def test_11_same_exact_evidence_has_deterministic_digest(self):
        first = self.prepare()
        second = self.prepare()
        self.assertEqual(first.inspection_evidence_sha256, second.inspection_evidence_sha256)

    def test_12_locale_is_bound_into_evidence_digest(self):
        self.assertNotEqual(
            self.prepare("bg-BG").inspection_evidence_sha256,
            self.prepare("en-GB").inspection_evidence_sha256,
        )

    def test_13_recovery_identifier_is_bound_into_evidence_digest(self):
        changed = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(recovery_id=changed).inspection_evidence_sha256,
        )

    def test_14_vault_identifier_is_bound_into_evidence_digest(self):
        changed = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(vault_id=changed).inspection_evidence_sha256,
        )

    def test_15_source_revision_is_bound_into_evidence_digest(self):
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(source_revision=8).inspection_evidence_sha256,
        )

    def test_16_source_vault_hash_is_bound_into_evidence_digest(self):
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(source_vault_sha256=b"S" * 32).inspection_evidence_sha256,
        )

    def test_17_record_hash_is_bound_into_evidence_digest(self):
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(record_sha256=b"R" * 32).inspection_evidence_sha256,
        )

    def test_18_encoded_size_is_bound_into_evidence_digest(self):
        self.assertNotEqual(
            self.prepare().inspection_evidence_sha256,
            self.prepare(encoded_size=778).inspection_evidence_sha256,
        )

    def test_19_digest_is_sha256_of_domain_separated_fixed_transcript(self):
        source = positive_execution()
        transcript = presentation._evidence_transcript(source)
        self.assertTrue(transcript.startswith(presentation._EVIDENCE_DIGEST_DOMAIN))
        self.assertEqual(
            presentation.prepare_recovery_source_inspection_presentation(source).inspection_evidence_sha256,
            hashlib.sha256(transcript).digest(),
        )

    def test_20_presentation_schema_has_no_raw_evidence_or_capability_fields(self):
        names = {item.name for item in fields(presentation.VaultRecoverySourceInspectionPresentation)}
        self.assertTrue(
            names.isdisjoint(
                {
                    "path", "filename", "recovery_id", "vault_id", "source_revision",
                    "source_vault_sha256", "record_sha256", "encoded_size", "descriptor",
                    "record", "header_bytes", "nonce", "ciphertext", "recovery_key",
                    "password", "plaintext", "keyring", "callback", "executor",
                }
            )
        )

    def test_21_repr_hides_evidence_digest_and_raw_source_values(self):
        result = self.prepare()
        rendered = repr(result)
        for hidden in (
            result.inspection_evidence_sha256.hex(), RECOVERY_ID.hex(), VAULT_ID.hex(),
            SOURCE_HASH.hex(), RECORD_HASH.hex(),
        ):
            self.assertNotIn(hidden, rendered)

    def test_22_presentation_refuses_copy_deepcopy_and_pickle(self):
        result = self.prepare()
        for operation in (
            lambda: copy.copy(result),
            lambda: copy.deepcopy(result),
            lambda: pickle.dumps(result),
        ):
            with self.assertRaises(TypeError):
                operation()

    def test_23_forged_digest_type_or_length_is_rejected(self):
        exact = self.prepare()
        for digest in (bytearray(b"D" * 32), b"D" * 31, b"D" * 33, "digest"):
            with self.subTest(digest_type=type(digest).__name__, length=len(digest)):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationFormatError
                ):
                    presentation._validate_source_inspection_presentation(
                        forged_copy(exact, inspection_evidence_sha256=digest)
                    )

    def test_24_forged_locale_is_rejected(self):
        exact = self.prepare()
        for locale in ("bg-BG", None, 1):
            with self.subTest(locale=locale):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationFormatError
                ):
                    presentation._validate_source_inspection_presentation(
                        forged_copy(exact, locale=locale)
                    )

    def test_25_forged_message_keys_are_rejected(self):
        exact = self.prepare()
        variants = (
            list(exact.message_keys),
            exact.message_keys[:-1],
            tuple(reversed(exact.message_keys)),
            exact.message_keys[:-1] + (exact.message_keys[0],),
            tuple(item.value for item in exact.message_keys),
        )
        for value in variants:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationFormatError
                ):
                    presentation._validate_source_inspection_presentation(
                        forged_copy(exact, message_keys=value)
                    )

    def test_26_forged_confirmation_requirements_are_rejected(self):
        exact = self.prepare()
        variants = (
            list(exact.confirmation_requirements),
            exact.confirmation_requirements[:-1],
            tuple(reversed(exact.confirmation_requirements)),
            tuple(item.value for item in exact.confirmation_requirements),
        )
        for value in variants:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationFormatError
                ):
                    presentation._validate_source_inspection_presentation(
                        forged_copy(exact, confirmation_requirements=value)
                    )

    def test_27_required_true_flags_reject_boolean_integers_and_false(self):
        exact = self.prepare()
        for name in (
            "inspection_completed", "header_structurally_validated",
            "future_secure_source_reopen_required", "exact_execution_outcome_validated",
            "fixed_message_keys_only", "process_local",
        ):
            for invalid in (False, 1):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        presentation.VaultRecoverySourceInspectionPresentationFormatError
                    ):
                        presentation._validate_source_inspection_presentation(
                            forged_copy(exact, **{name: invalid})
                        )

    def test_28_forbidden_claim_flags_reject_true_and_boolean_integer(self):
        exact = self.prepare()
        for name in (
            "cryptographic_authenticity_established", "raw_text_included",
            "raw_evidence_included", "source_identifiers_retained",
            "recovery_secret_received", "recovery_performed", "stage2_8_used",
            "review_session_prepared", "operation_authorized", "filesystem_access_performed",
            "network_used", "gui_used", "evidence_digest_is_digital_signature",
            "evidence_digest_is_provenance_proof", "evidence_digest_is_anti_rollback_anchor",
        ):
            for invalid in (True, 0):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        presentation.VaultRecoverySourceInspectionPresentationFormatError
                    ):
                        presentation._validate_source_inspection_presentation(
                            forged_copy(exact, **{name: invalid})
                        )

    def test_29_format_and_version_are_exact(self):
        exact = self.prepare()
        for change in ({"format": "WRONG"}, {"format": 1}, {"version": 2}, {"version": True}):
            with self.subTest(change=change):
                with self.assertRaises(
                    presentation.VaultRecoverySourceInspectionPresentationFormatError
                ):
                    presentation._validate_source_inspection_presentation(
                        forged_copy(exact, **change)
                    )

    def test_30_structural_validation_is_not_authentication_and_reopen_is_mandatory(self):
        result = self.prepare()
        self.assertTrue(result.header_structurally_validated)
        self.assertFalse(result.cryptographic_authenticity_established)
        self.assertTrue(result.future_secure_source_reopen_required)
        self.assertIn(
            presentation.RecoverySourceInspectionPresentationMessageKey.CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED,
            result.message_keys,
        )

    def test_31_every_secret_recovery_and_authority_claim_is_false(self):
        result = self.prepare()
        for name in (
            "recovery_secret_received", "recovery_performed", "rehearsal_performed",
            "stage2_8_used", "review_session_prepared", "operation_authorized",
            "operation_performed", "filesystem_access_performed",
            "filesystem_mutation_performed", "network_used", "logging_used", "gui_used",
        ):
            self.assertIs(getattr(result, name), False, name)

    def test_32_ast_has_no_filesystem_network_process_logging_or_dynamic_capability(self):
        tree = ast.parse((ROOT / "mokosh_vault_recovery_source_inspection_presentation.py").read_text(encoding="utf-8"))
        forbidden_names = {"open", "exec", "eval", "compile", "__import__", "getattr", "setattr"}
        forbidden_attributes = {
            "open", "read", "read_bytes", "read_text", "stat", "lstat", "resolve",
            "unlink", "remove", "replace", "rename", "Popen", "run",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_names)
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, forbidden_attributes)

    def test_33_import_closure_is_exact_and_unprivileged(self):
        tree = ast.parse((ROOT / "mokosh_vault_recovery_source_inspection_presentation.py").read_text(encoding="utf-8"))
        modules = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        self.assertEqual(
            modules,
            {
                "__future__", "hashlib", "struct", "dataclasses", "enum", "typing",
                "mokosh_vault_recovery_locale",
                "mokosh_vault_recovery_source_inspection_execution",
            },
        )
        self.assertTrue(
            modules.isdisjoint(
                {
                    "mokosh_gui", "mokosh_vault_recovery_storage",
                    "mokosh_vault_recovery_reconciliation", "subprocess", "socket", "logging",
                }
            )
        )

    def test_34_fresh_import_does_not_load_privileged_storage_or_gui(self):
        code = (
            "import sys; import mokosh_vault_recovery_source_inspection_presentation; "
            "print('mokosh_vault_recovery_storage' in sys.modules, 'mokosh_gui' in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        self.assertEqual(result.stdout.strip(), "False False")

    def test_35_presentation_never_invokes_stage32_secure_reader(self):
        with mock.patch.object(execution, "_read_source_once") as reader:
            result = self.prepare()
        reader.assert_not_called()
        self.assertFalse(result.filesystem_access_performed)

    def test_36_critical_existing_files_remain_byte_exact(self):
        expected = {
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_reconciliation.py": "5a40fdced3fe5bbce19d6b20428e1e3511953e300189a86a692a5face0e27b6d",
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "crypto_core.py": "a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62",
            "contacts_core.py": "3c1e64ae4a2d86f73ffad167b8c00bb429407eb135d58d8c494ca86b659eb064",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
