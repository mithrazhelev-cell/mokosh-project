import ast
import copy
from dataclasses import fields, replace
import hashlib
import inspect
from pathlib import Path
import pickle
import struct
import subprocess
import sys
import unicodedata
import unittest
from unittest import mock

import mokosh_vault_recovery_locale as locale
import mokosh_vault_recovery_source_inspection_execution as execution
import mokosh_vault_recovery_source_inspection_localization as localization
import mokosh_vault_recovery_source_inspection_presentation as presentation
import mokosh_vault_recovery_source_inspection_ui_adapter as adapter


ROOT = Path(__file__).resolve().parents[1]
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


def source_presentation(locale_id="bg-BG", **changes):
    value = presentation.prepare_recovery_source_inspection_presentation(
        positive_execution(locale_id)
    )
    if changes:
        value = replace(value, **changes)
    return value


def source_view(locale_id="bg-BG"):
    value = source_presentation(locale_id)
    return adapter.prepare_recovery_source_inspection_ui_adapter(value).view


def localized(locale_id="bg-BG"):
    return localization.localize_recovery_source_inspection_ui_adapter_view(
        source_view(locale_id)
    )


def catalog(locale_id="bg-BG"):
    return localization.get_recovery_source_inspection_localization_catalog(
        locale_id
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


def length_prefixed(value):
    return struct.pack(">I", len(value)) + value


def independent_catalog_digest(value):
    parts = [
        b"MOKOSH\x00VAULT-RECOVERY-SOURCE-INSPECTION-LOCALIZATION\x00CATALOG-V1\x00",
        length_prefixed(value.locale.value.encode("ascii")),
    ]
    for kind, entries in (
        (b"M", value.message_translations),
        (b"C", value.confirmation_translations),
    ):
        parts.append(struct.pack(">cI", kind, len(entries)))
        for entry in entries:
            key = (
                entry.message_key
                if type(entry)
                is localization.RecoverySourceInspectionMessageTranslation
                else entry.confirmation_key
            )
            parts.append(length_prefixed(key.value.encode("ascii")))
            parts.append(length_prefixed(entry.text.encode("utf-8")))
    return hashlib.sha256(b"".join(parts)).digest()


class SourceInspectionLocalizationTests(unittest.TestCase):
    def test_01_supported_locale_ids_are_exact_and_ordered(self):
        self.assertEqual(
            localization.supported_recovery_source_inspection_locale_ids(),
            ("bg-BG", "en-GB"),
        )

    def test_02_bulgarian_catalog_is_complete(self):
        value = catalog("bg-BG")
        self.assertEqual(value.locale.value, "bg-BG")
        self.assertEqual(len(value.message_translations), 7)
        self.assertEqual(len(value.confirmation_translations), 3)
        self.assertTrue(value.complete)

    def test_03_english_catalog_is_complete(self):
        value = catalog("en-GB")
        self.assertEqual(value.locale.value, "en-GB")
        self.assertEqual(len(value.message_translations), 7)
        self.assertEqual(len(value.confirmation_translations), 3)
        self.assertTrue(value.fixed_reviewed_text)

    def test_04_every_message_key_occurs_once_in_exact_order(self):
        expected = tuple(presentation.RecoverySourceInspectionPresentationMessageKey)
        for locale_id in ("bg-BG", "en-GB"):
            with self.subTest(locale_id=locale_id):
                observed = tuple(
                    item.message_key
                    for item in catalog(locale_id).message_translations
                )
                self.assertEqual(observed, expected)

    def test_05_every_confirmation_key_occurs_once_in_exact_order(self):
        expected = tuple(
            presentation.RecoverySourceInspectionPresentationConfirmationKey
        )
        for locale_id in ("bg-BG", "en-GB"):
            with self.subTest(locale_id=locale_id):
                observed = tuple(
                    item.confirmation_key
                    for item in catalog(locale_id).confirmation_translations
                )
                self.assertEqual(observed, expected)

    def test_06_fixed_text_preserves_core_security_meanings(self):
        bg = tuple(item.text for item in catalog("bg-BG").message_translations)
        en = tuple(item.text for item in catalog("en-GB").message_translations)
        self.assertIn("Криптографската автентичност", bg[2])
        self.assertIn("не е установена", bg[2])
        self.assertIn("not been established", en[2])
        self.assertIn("No recovery", en[5])
        self.assertIn("No operation", en[6])

    def test_07_catalog_digests_are_independent_stable_and_distinct(self):
        bg = catalog("bg-BG")
        en = catalog("en-GB")
        self.assertEqual(bg.catalog_sha256, independent_catalog_digest(bg))
        self.assertEqual(en.catalog_sha256, independent_catalog_digest(en))
        self.assertNotEqual(bg.catalog_sha256, en.catalog_sha256)
        self.assertEqual(
            bg.catalog_sha256.hex(),
            "63e4bac80788bee467349b246689b3261d49565a184937041da1cfa1d4e41c81",
        )
        self.assertEqual(
            en.catalog_sha256.hex(),
            "60be08d87340af217694f8b8d355d0c394c0f1a53aa4a57864a9cc289e2619f6",
        )

    def test_08_public_constants_and_signatures_are_exact(self):
        self.assertEqual(
            localization.RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT,
            "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_LOCALIZATION",
        )
        self.assertEqual(
            localization.RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION, 1
        )
        self.assertEqual(
            list(
                inspect.signature(
                    localization.get_recovery_source_inspection_localization_catalog
                ).parameters
            ),
            ["locale_id"],
        )
        self.assertEqual(
            list(
                inspect.signature(
                    localization.localize_recovery_source_inspection_ui_adapter_view
                ).parameters
            ),
            ["view"],
        )

    def test_09_public_export_surface_is_explicit(self):
        self.assertEqual(len(localization.__all__), len(set(localization.__all__)))
        self.assertIn(
            "localize_recovery_source_inspection_ui_adapter_view",
            localization.__all__,
        )
        self.assertNotIn("_validate_text", localization.__all__)
        self.assertNotIn("_catalog_digest", localization.__all__)

    def test_10_bulgarian_view_is_localized(self):
        value = localized("bg-BG")
        self.assertEqual(value.locale.value, "bg-BG")
        self.assertEqual(len(value.message_items), 7)
        self.assertEqual(len(value.confirmation_controls), 3)
        self.assertTrue(value.fixed_user_facing_text_included)

    def test_11_english_view_is_localized(self):
        value = localized("en-GB")
        self.assertEqual(value.locale.value, "en-GB")
        self.assertTrue(value.message_items[0].text.startswith("The recovery"))
        self.assertTrue(value.confirmation_controls[0].text.startswith("I acknowledge"))

    def test_12_localization_uses_only_the_view_bound_locale(self):
        bg_source = source_view("bg-BG")
        en_source = source_view("en-GB")
        bg = localization.localize_recovery_source_inspection_ui_adapter_view(bg_source)
        en = localization.localize_recovery_source_inspection_ui_adapter_view(en_source)
        self.assertIs(bg.locale, bg_source.locale)
        self.assertIs(en.locale, en_source.locale)
        self.assertEqual(
            list(
                inspect.signature(
                    localization.localize_recovery_source_inspection_ui_adapter_view
                ).parameters
            ),
            ["view"],
        )

    def test_13_repeated_localization_is_deterministic(self):
        view = source_view()
        first = localization.localize_recovery_source_inspection_ui_adapter_view(view)
        second = localization.localize_recovery_source_inspection_ui_adapter_view(view)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_14_source_view_remains_byte_for_field_unchanged(self):
        view = source_view()
        before = tuple(getattr(view, item.name) for item in fields(view))
        localization.localize_recovery_source_inspection_ui_adapter_view(view)
        after = tuple(getattr(view, item.name) for item in fields(view))
        self.assertEqual(before, after)

    def test_15_arbitrary_valid_binding_digest_does_not_create_proof(self):
        source = source_presentation(
            inspection_evidence_sha256=hashlib.sha256(b"arbitrary").digest()
        )
        view = adapter.prepare_recovery_source_inspection_ui_adapter(source).view
        result = localization.localize_recovery_source_inspection_ui_adapter_view(view)
        self.assertFalse(result.actual_gui_rendering_proven)
        self.assertFalse(result.accessibility_conformance_proven)
        self.assertFalse(result.operation_authorized)

    def test_16_unsupported_locale_identifiers_are_rejected_without_fallback(self):
        for invalid in ("bg", "en", "en-US", "BG-bg", "bg-BG ", "ru-RU", ""):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationLocaleError
                ):
                    catalog(invalid)

    def test_17_locale_identifier_requires_exact_plain_string(self):
        class Derived(str):
            pass

        for invalid in (None, 1, b"bg-BG", Derived("bg-BG")):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationLocaleError
                ):
                    catalog(invalid)

    def test_18_registry_is_an_exact_immutable_ordered_tuple(self):
        registry = localization.RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY
        self.assertIs(type(registry), tuple)
        self.assertEqual(tuple(item.locale.value for item in registry), ("bg-BG", "en-GB"))
        self.assertEqual(len(registry), 2)

    def test_19_registry_missing_duplicate_reorder_and_wrong_type_are_rejected(self):
        original = localization.RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY
        cases = (list(original), original[:1], original + (original[0],), original[::-1])
        for invalid in cases:
            with self.subTest(invalid=type(invalid).__name__):
                with mock.patch.object(
                    localization,
                    "RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY",
                    invalid,
                ):
                    with self.assertRaises(
                        localization.VaultRecoverySourceInspectionLocalizationCatalogError
                    ):
                        localization.supported_recovery_source_inspection_locale_ids()

    def test_20_catalog_requires_exact_type(self):
        exact = catalog()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_catalog(invalid)

    def test_21_catalog_scalar_schema_is_strict(self):
        exact = catalog()
        cases = (
            {"locale": exact.locale.value},
            {"catalog_sha256": b"short"},
            {"message_translations": list(exact.message_translations)},
            {"confirmation_translations": list(exact.confirmation_translations)},
            {"format": "OTHER"},
            {"version": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_catalog(forged_copy(exact, **change))

    def test_22_message_translation_schema_is_strict(self):
        exact = catalog().message_translations[0]
        cases = (
            {"locale": exact.locale.value},
            {"message_key": exact.message_key.value},
            {"text": 1},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_message_translation(
                        forged_copy(exact, **change)
                    )

    def test_23_confirmation_translation_schema_is_strict(self):
        exact = catalog().confirmation_translations[0]
        cases = (
            {"locale": exact.locale.value},
            {"confirmation_key": exact.confirmation_key.value},
            {"text": 1},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_confirmation_translation(
                        forged_copy(exact, **change)
                    )

    def test_24_missing_duplicate_and_extra_messages_are_rejected(self):
        exact = catalog()
        cases = (
            exact.message_translations[:-1],
            exact.message_translations[:-1] + (exact.message_translations[0],),
            exact.message_translations + (exact.message_translations[0],),
        )
        for entries in cases:
            with self.subTest(count=len(entries)):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_catalog(
                        forged_copy(exact, message_translations=entries)
                    )

    def test_25_reordered_messages_are_rejected(self):
        exact = catalog()
        entries = (
            exact.message_translations[1],
            exact.message_translations[0],
        ) + exact.message_translations[2:]
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_catalog(
                forged_copy(exact, message_translations=entries)
            )

    def test_26_missing_duplicate_and_extra_confirmations_are_rejected(self):
        exact = catalog()
        cases = (
            exact.confirmation_translations[:-1],
            exact.confirmation_translations[:-1]
            + (exact.confirmation_translations[0],),
            exact.confirmation_translations + (exact.confirmation_translations[0],),
        )
        for entries in cases:
            with self.subTest(count=len(entries)):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_catalog(
                        forged_copy(exact, confirmation_translations=entries)
                    )

    def test_27_reordered_confirmations_are_rejected(self):
        exact = catalog()
        entries = (
            exact.confirmation_translations[1],
            exact.confirmation_translations[0],
            exact.confirmation_translations[2],
        )
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_catalog(
                forged_copy(exact, confirmation_translations=entries)
            )

    def test_28_mixed_locale_catalog_entries_are_rejected(self):
        bg = catalog("bg-BG")
        en = catalog("en-GB")
        messages = (en.message_translations[0],) + bg.message_translations[1:]
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_catalog(
                forged_copy(bg, message_translations=messages)
            )

    def test_29_altered_fixed_text_is_rejected(self):
        exact = catalog()
        first = forged_copy(exact.message_translations[0], text="Безопасен текст.")
        entries = (first,) + exact.message_translations[1:]
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_catalog(
                forged_copy(exact, message_translations=entries)
            )

    def test_30_catalog_digest_tamper_is_rejected(self):
        exact = catalog()
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_catalog(
                forged_copy(exact, catalog_sha256=b"x" * 32)
            )

    def test_31_catalog_policy_flags_are_exact_booleans(self):
        exact = catalog()
        true_names = ("complete", "fixed_reviewed_text")
        false_names = (
            "fallback_allowed",
            "dynamic_interpolation_allowed",
            "external_catalog_allowed",
        )
        for name in true_names:
            for invalid in (False, 1):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        localization.VaultRecoverySourceInspectionLocalizationCatalogError
                    ):
                        localization._validate_catalog(
                            forged_copy(exact, **{name: invalid})
                        )
        for name in false_names:
            for invalid in (True, 0):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        localization.VaultRecoverySourceInspectionLocalizationCatalogError
                    ):
                        localization._validate_catalog(
                            forged_copy(exact, **{name: invalid})
                        )

    def test_32_text_type_empty_and_codepoint_bounds_are_rejected(self):
        maximum = localization.MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_CODEPOINTS
        for invalid in (None, 1, "", "x" * (maximum + 1)):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")
        self.assertEqual(localization._validate_text("x" * maximum, "test"), "x" * maximum)

    def test_33_text_utf8_byte_bound_is_independent(self):
        limit = localization.MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_UTF8_LEN
        valid = "ж" * 240
        invalid = "😀" * 193
        self.assertLessEqual(len(valid.encode("utf-8")), limit)
        self.assertEqual(localization._validate_text(valid, "test"), valid)
        self.assertGreater(len(invalid.encode("utf-8")), limit)
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationCatalogError
        ):
            localization._validate_text(invalid, "test")

    def test_34_whitespace_and_non_nfc_text_are_rejected(self):
        decomposed = "e\u0301"
        self.assertNotEqual(decomposed, unicodedata.normalize("NFC", decomposed))
        for invalid in (" text", "text ", "text\n", decomposed):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_35_control_and_bidi_characters_are_rejected(self):
        for invalid in ("a\x00b", "a\tb", "a\u202eb", "a\u2066b"):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_36_template_marker_characters_are_rejected(self):
        for invalid in ("{name}", "value %s", "$value"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_37_source_requires_exact_stage235_view_type(self):
        exact = source_view()

        class Derived(type(exact)):
            pass

        derived = object.__new__(Derived)
        for item in fields(exact):
            object.__setattr__(derived, item.name, getattr(exact, item.name))
        for invalid in (None, {}, (), "view", derived):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationSourceError
                ):
                    localization.localize_recovery_source_inspection_ui_adapter_view(
                        invalid
                    )

    def test_38_forged_stage235_view_schema_is_revalidated(self):
        exact = source_view()
        cases = (
            {"presentation_sha256": b"short"},
            {"message_items": list(exact.message_items)},
            {"confirmation_controls": list(exact.confirmation_controls)},
            {"raw_text_included": True},
            {"operation_authorized": True},
            {"format": "OTHER"},
            {"version": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationSourceError
                ):
                    localization.localize_recovery_source_inspection_ui_adapter_view(
                        forged_copy(exact, **change)
                    )

    def test_39_hidden_or_reordered_source_message_is_rejected(self):
        exact = source_view()
        hidden = forged_copy(exact.message_items[0], visible=False)
        reordered = (exact.message_items[1], exact.message_items[0]) + exact.message_items[2:]
        for messages in ((hidden,) + exact.message_items[1:], reordered):
            with self.subTest(messages=messages[:2]):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationSourceError
                ):
                    localization.localize_recovery_source_inspection_ui_adapter_view(
                        forged_copy(exact, message_items=messages)
                    )

    def test_40_tampered_source_control_policy_is_rejected(self):
        exact = source_view()
        selected = forged_copy(exact.confirmation_controls[0], default_selected=True)
        select_all = forged_copy(exact.confirmation_controls[0], select_all_available=True)
        for first in (selected, select_all):
            controls = (first,) + exact.confirmation_controls[1:]
            with self.subTest(first=first):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationSourceError
                ):
                    localization.localize_recovery_source_inspection_ui_adapter_view(
                        forged_copy(exact, confirmation_controls=controls)
                    )

    def test_41_localized_message_item_schema_is_strict(self):
        exact = localized().message_items[0]
        cases = (
            {"ordinal": True},
            {"ordinal": 0},
            {"locale": exact.locale.value},
            {"message_key": exact.message_key.value},
            {"visible": 1},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_message_item(
                        forged_copy(exact, **change)
                    )

    def test_42_localized_message_text_and_accessible_text_are_exact(self):
        exact = localized().message_items[0]
        for change in ({"text": "Друг текст."}, {"accessible_text": "Друг текст."}):
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_message_item(
                        forged_copy(exact, **change)
                    )

    def test_43_localized_confirmation_control_schema_is_strict(self):
        exact = localized().confirmation_controls[0]
        cases = (
            {"ordinal": True},
            {"ordinal": 0},
            {"locale": exact.locale.value},
            {"confirmation_key": exact.confirmation_key.value},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_confirmation_control(
                        forged_copy(exact, **change)
                    )

    def test_44_localized_confirmation_policy_is_strict(self):
        exact = localized().confirmation_controls[0]
        cases = (
            {"visible": False},
            {"visible": 1},
            {"required": False},
            {"individually_selectable": False},
            {"default_selected": True},
            {"select_all_available": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_confirmation_control(
                        forged_copy(exact, **change)
                    )

    def test_45_localized_confirmation_text_and_accessible_text_are_exact(self):
        exact = localized().confirmation_controls[0]
        for change in ({"text": "Друг текст."}, {"accessible_text": "Друг текст."}):
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_confirmation_control(
                        forged_copy(exact, **change)
                    )

    def test_46_localized_view_scalar_schema_is_strict(self):
        exact = localized()
        cases = (
            {"presentation_sha256": b"short"},
            {"catalog_sha256": b"short"},
            {"locale": exact.locale.value},
            {"adapter_state": exact.adapter_state.value},
            {"format": "OTHER"},
            {"version": True},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_view(
                        forged_copy(exact, **change)
                    )

    def test_47_localized_view_containers_and_counts_are_strict(self):
        exact = localized()
        cases = (
            {"message_items": list(exact.message_items)},
            {"message_items": exact.message_items[:-1]},
            {"confirmation_controls": list(exact.confirmation_controls)},
            {"confirmation_controls": exact.confirmation_controls[:-1]},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_view(
                        forged_copy(exact, **change)
                    )

    def test_48_localized_view_required_true_flags_are_strict(self):
        exact = localized()
        names = (
            "source_view_validated", "catalog_validated",
            "exact_bound_locale_selected", "complete_fixed_text",
            "fixed_user_facing_text_included", "accessible_text_equals_visible_text",
            "all_required_messages_visible", "all_confirmation_controls_visible",
            "confirmations_individually_selectable", "all_controls_default_unselected",
        )
        for name in names:
            for invalid in (False, 1):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        localization.VaultRecoverySourceInspectionLocalizationFormatError
                    ):
                        localization._validate_localized_view(
                            forged_copy(exact, **{name: invalid})
                        )

    def test_49_localized_view_required_false_flags_are_strict(self):
        exact = localized()
        names = (
            "fallback_used", "dynamic_interpolation_used", "external_catalog_used",
            "selection_events_included", "acknowledgement_performed",
            "actual_gui_rendering_proven", "accessibility_conformance_proven",
            "human_understanding_proven", "user_identity_verified",
            "informed_consent_proven", "operation_controls_included",
            "operation_authorized", "operation_performed", "secrets_retained",
            "filesystem_access_performed", "filesystem_mutation_performed",
            "network_used", "logging_used", "gui_used",
        )
        for name in names:
            for invalid in (True, 0):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(
                        localization.VaultRecoverySourceInspectionLocalizationFormatError
                    ):
                        localization._validate_localized_view(
                            forged_copy(exact, **{name: invalid})
                        )

    def test_50_localized_view_catalog_digest_is_bound(self):
        exact = localized()
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationFormatError
        ):
            localization._validate_localized_view(
                forged_copy(exact, catalog_sha256=b"x" * 32)
            )

    def test_51_localized_view_rejects_mixed_locale_items(self):
        bg = localized("bg-BG")
        en = localized("en-GB")
        messages = (en.message_items[0],) + bg.message_items[1:]
        with self.assertRaises(
            localization.VaultRecoverySourceInspectionLocalizationFormatError
        ):
            localization._validate_localized_view(
                forged_copy(bg, message_items=messages)
            )

    def test_52_localized_view_rejects_wrong_order_and_ordinals(self):
        exact = localized()
        reordered = (exact.message_items[1], exact.message_items[0]) + exact.message_items[2:]
        wrong_ordinal = (
            forged_copy(exact.message_items[0], ordinal=2),
        ) + exact.message_items[1:]
        for messages in (reordered, wrong_ordinal):
            with self.subTest(messages=messages[:2]):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_view(
                        forged_copy(exact, message_items=messages)
                    )

    def test_53_localized_output_missing_extra_and_altered_items_are_rejected(self):
        exact = localized()
        altered = forged_copy(exact.confirmation_controls[0], text="Друг текст.")
        cases = (
            {"message_items": exact.message_items + (exact.message_items[0],)},
            {"confirmation_controls": exact.confirmation_controls + (exact.confirmation_controls[0],)},
            {"confirmation_controls": (altered,) + exact.confirmation_controls[1:]},
        )
        for change in cases:
            with self.subTest(change=tuple(change)):
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationFormatError
                ):
                    localization._validate_localized_view(
                        forged_copy(exact, **change)
                    )

    def test_54_localized_objects_exclude_events_acknowledgements_and_capabilities(self):
        result = localized()
        names = {item.name for item in fields(result)}
        forbidden = {
            "events", "receipt", "acknowledgement", "callback", "executor",
            "gate", "recovery_id", "vault_id", "source_path", "source_content",
            "recovery_secret", "password", "source_vault_sha256", "record_sha256",
        }
        self.assertTrue(names.isdisjoint(forbidden))
        self.assertFalse(result.selection_events_included)
        self.assertFalse(result.acknowledgement_performed)

    def test_55_catalog_and_localized_view_are_immutable_noncopyable_nonserializable(self):
        for value in (catalog(), localized()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises((AttributeError, TypeError)):
                    value.version = 2
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationReplayError
                ):
                    copy.copy(value)
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationReplayError
                ):
                    copy.deepcopy(value)
                with self.assertRaises(
                    localization.VaultRecoverySourceInspectionLocalizationReplayError
                ):
                    pickle.dumps(value)

    def test_56_repr_hides_digests_and_source_identifiers(self):
        result = localized()
        rendered = repr(catalog()) + repr(result)
        self.assertNotIn(catalog().catalog_sha256.hex(), rendered)
        self.assertNotIn(result.presentation_sha256.hex(), rendered)
        self.assertNotIn(RECOVERY_ID.hex(), rendered)
        self.assertNotIn(VAULT_ID.hex(), rendered)

    def test_57_import_and_runtime_capability_surface_is_bounded(self):
        path = ROOT / "mokosh_vault_recovery_source_inspection_localization.py"
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
                "__future__", "hashlib", "hmac", "struct", "unicodedata",
                "dataclasses", "typing", "mokosh_vault_recovery_locale",
                "mokosh_vault_recovery_source_inspection_presentation",
                "mokosh_vault_recovery_source_inspection_ui_adapter",
            },
        )
        self.assertTrue(
            {"os", "pathlib", "socket", "subprocess", "logging", "time", "random", "tkinter"}.isdisjoint(imports)
        )
        self.assertTrue({"open", "getattr", "setattr", "eval", "exec", "compile", "__import__"}.isdisjoint(calls))
        source = source_view()
        with mock.patch.object(execution, "_read_source_once") as reader:
            localization.localize_recovery_source_inspection_ui_adapter_view(source)
        reader.assert_not_called()
        code = (
            "import sys; import mokosh_vault_recovery_source_inspection_localization; "
            "forbidden={'tkinter','socket','subprocess','mokosh_vault_recovery_storage',"
            "'mokosh_vault_recovery_localization','mokosh_gui','crypto_core','contacts_core'}; "
            "assert forbidden.isdisjoint(sys.modules)"
        )
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)

    def test_58_critical_predecessor_files_remain_byte_exact(self):
        expected = {
            "mokosh_vault_recovery_source_inspection_ui_adapter.py": "93addcafcbbeb8db5aba359e3772c415faac36e8a158f03da37c34a0409561c7",
            "tests/test_mokosh_vault_recovery_source_inspection_ui_adapter.py": "ed60468ef0ed2b86fa8088a62a5752389f9a2e63e4df0d66ecf6883a1caa1ffc",
            "docs/VAULT_RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_CONTRACT_BG.md": "c6a764d48a4b67bfaa35966f6cf62b92b8cb0ac9a023bb2de95f91435f7a30cc",
            "mokosh_vault_recovery_source_inspection_acknowledgement.py": "dbbb810d1ac074e2274cf250d8fc4a21f90566eabfdb5d749337a6ddf9170dc4",
            "mokosh_vault_recovery_source_inspection_presentation.py": "747f6b2b3d5cc1c039c9449caae0c42688ab41fce3635641d02c57ce13e67b82",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_localization.py": "e32ef10fab3a93fe2392414a2f871b852787f614f3ef926dc3a156df3cac0f0e",
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
