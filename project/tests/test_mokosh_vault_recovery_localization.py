import ast
import copy
import dataclasses
import pickle
import unicodedata
import unittest
from pathlib import Path

import mokosh_vault_recovery_localization as localization
import mokosh_vault_recovery_presentation as presentation
import mokosh_vault_recovery_ui_adapter as adapter
import mokosh_vault_recovery_workflow as workflow
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification


DIGEST = b"p" * 32


ROUTES = (
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_TARGET_ABSENT,
        workflow.RecoveryWorkflowState.FRESH_CANDIDATE_DECISION_REQUIRED,
        False,
        True,
    ),
    (
        RecoveryPublishClassification.TARGET_EXACT_DURABLE,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_EXACT_TARGET,
        workflow.RecoveryWorkflowState.NORMAL_UNLOCK_REQUIRED,
        False,
        True,
    ),
    (
        RecoveryPublishClassification.CONFLICT,
        workflow.RecoveryWorkflowDecision.ACKNOWLEDGE_CONFLICT,
        workflow.RecoveryWorkflowState.MANUAL_REVIEW_STOP,
        True,
        False,
    ),
    (
        RecoveryPublishClassification.TARGET_ABSENT,
        workflow.RecoveryWorkflowDecision.PRESERVE_AND_STOP,
        workflow.RecoveryWorkflowState.PRESERVED_STOP,
        True,
        False,
    ),
)


def make_view(route=ROUTES[0]):
    classification, decision, state, terminal, reverification = route
    messages, gates, confirmations = presentation._presentation_components(
        classification,
        decision,
        state,
        terminal,
        reverification,
    )
    return adapter.VaultRecoveryUIAdapterView(
        presentation_sha256=DIGEST,
        classification=classification,
        decision=decision,
        state=state,
        message_items=tuple(
            adapter.RecoveryUIMessageItem(
                ordinal=index,
                message_key=key,
                is_gate_message=key in gates,
            )
            for index, key in enumerate(messages, start=1)
        ),
        confirmation_controls=tuple(
            adapter.RecoveryUIConfirmationControl(
                ordinal=index,
                confirmation_key=key,
            )
            for index, key in enumerate(confirmations, start=1)
        ),
        terminal_stop=terminal,
        downstream_reverification_required=reverification,
    )


def localize(route=ROUTES[0], locale_id="bg-BG"):
    return localization.localize_recovery_ui_adapter_view(
        make_view(route),
        locale_id,
    )


def forge_dataclass(value, **overrides):
    forged = object.__new__(type(value))
    for item in dataclasses.fields(value):
        object.__setattr__(
            forged,
            item.name,
            overrides.get(item.name, getattr(value, item.name)),
        )
    return forged


class RecoveryLocalizationRegistryTests(unittest.TestCase):
    def test_supported_locale_ids_are_exact_and_ordered(self):
        self.assertEqual(
            localization.supported_recovery_locale_ids(),
            ("bg-BG", "en-GB"),
        )

    def test_registry_is_an_exact_tuple_in_allowlist_order(self):
        registry = localization.RECOVERY_LOCALIZATION_REGISTRY
        self.assertIs(type(registry), tuple)
        self.assertEqual(
            tuple(item.locale.value for item in registry),
            localization.supported_recovery_locale_ids(),
        )
        self.assertIs(localization._validate_registry(registry), registry)

    def test_every_message_key_is_present_once_in_each_catalog(self):
        expected = tuple(presentation.RecoveryPresentationMessageKey)
        for locale_id in localization.supported_recovery_locale_ids():
            with self.subTest(locale_id=locale_id):
                catalog = localization.get_recovery_localization_catalog(locale_id)
                observed = tuple(
                    item.message_key for item in catalog.message_translations
                )
                self.assertEqual(observed, expected)
                self.assertEqual(len(observed), len(set(observed)))

    def test_every_confirmation_key_is_present_once_in_each_catalog(self):
        expected = tuple(presentation.RecoveryPresentationConfirmationKey)
        for locale_id in localization.supported_recovery_locale_ids():
            with self.subTest(locale_id=locale_id):
                catalog = localization.get_recovery_localization_catalog(locale_id)
                observed = tuple(
                    item.confirmation_key
                    for item in catalog.confirmation_translations
                )
                self.assertEqual(observed, expected)
                self.assertEqual(len(observed), len(set(observed)))

    def test_catalog_flags_forbid_fallback_and_interpolation(self):
        for catalog in localization.RECOVERY_LOCALIZATION_REGISTRY:
            with self.subTest(locale=catalog.locale):
                self.assertTrue(catalog.complete)
                self.assertTrue(catalog.fixed_reviewed_text)
                self.assertFalse(catalog.fallback_allowed)
                self.assertFalse(catalog.dynamic_interpolation_allowed)

    def test_catalog_digests_are_stable_and_locale_separated(self):
        bulgarian = localization.get_recovery_localization_catalog("bg-BG")
        english = localization.get_recovery_localization_catalog("en-GB")
        self.assertEqual(
            bulgarian.catalog_sha256.hex(),
            "26b87b48433fc2697d0669c8ad33b993d8e026c8c223ef3e59cbe5a4b6da84dd",
        )
        self.assertEqual(
            english.catalog_sha256.hex(),
            "a57f472c64d5d347c94832682fd7160f97353e386efe6bb7bdae5c5b7f9164f7",
        )
        self.assertNotEqual(bulgarian.catalog_sha256, english.catalog_sha256)

    def test_bulgarian_and_english_texts_are_distinct(self):
        bulgarian = localization.get_recovery_localization_catalog("bg-BG")
        english = localization.get_recovery_localization_catalog("en-GB")
        self.assertTrue(
            all(
                left.text != right.text
                for left, right in zip(
                    bulgarian.message_translations,
                    english.message_translations,
                    strict=True,
                )
            )
        )
        self.assertTrue(
            all(
                left.text != right.text
                for left, right in zip(
                    bulgarian.confirmation_translations,
                    english.confirmation_translations,
                    strict=True,
                )
            )
        )

    def test_exact_catalog_lookup_returns_registry_objects(self):
        self.assertIs(
            localization.get_recovery_localization_catalog("bg-BG"),
            localization.RECOVERY_LOCALIZATION_REGISTRY[0],
        )
        self.assertIs(
            localization.get_recovery_localization_catalog("en-GB"),
            localization.RECOVERY_LOCALIZATION_REGISTRY[1],
        )

    def test_unsupported_locale_has_no_fallback(self):
        for invalid in ("bg", "en", "en-US", "BG-bg", "bg-BG ", "", "ru-RU"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationLocaleError
                ):
                    localization.get_recovery_localization_catalog(invalid)

    def test_non_plain_locale_id_is_rejected(self):
        for invalid in (
            None,
            True,
            1,
            ["bg-BG"],
            localization.RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationLocaleError
                ):
                    localization.get_recovery_localization_catalog(invalid)

    def test_catalog_dataclasses_are_frozen(self):
        catalog = localization.get_recovery_localization_catalog("bg-BG")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            catalog.complete = False
        with self.assertRaises(dataclasses.FrozenInstanceError):
            catalog.message_translations[0].text = "Променено"


class RecoveryLocalizationTextSafetyTests(unittest.TestCase):
    def test_all_builtin_text_is_bounded_nfc_and_trimmed(self):
        for catalog in localization.RECOVERY_LOCALIZATION_REGISTRY:
            entries = catalog.message_translations + catalog.confirmation_translations
            for entry in entries:
                with self.subTest(locale=catalog.locale, key=entry):
                    self.assertEqual(entry.text, entry.text.strip())
                    self.assertEqual(entry.text, unicodedata.normalize("NFC", entry.text))
                    self.assertLessEqual(
                        len(entry.text),
                        localization.MAX_RECOVERY_LOCALIZED_TEXT_CODEPOINTS,
                    )
                    self.assertLessEqual(
                        len(entry.text.encode("utf-8")),
                        localization.MAX_RECOVERY_LOCALIZED_TEXT_UTF8_LEN,
                    )

    def test_all_builtin_text_has_no_control_format_or_bidi_override(self):
        for catalog in localization.RECOVERY_LOCALIZATION_REGISTRY:
            entries = catalog.message_translations + catalog.confirmation_translations
            for entry in entries:
                for character in entry.text:
                    with self.subTest(locale=catalog.locale, key=entry):
                        self.assertFalse(unicodedata.category(character).startswith("C"))
                        self.assertNotIn(
                            unicodedata.bidirectional(character),
                            localization._FORBIDDEN_BIDI_CLASSES,
                        )

    def test_all_builtin_text_has_no_template_braces(self):
        for catalog in localization.RECOVERY_LOCALIZATION_REGISTRY:
            entries = catalog.message_translations + catalog.confirmation_translations
            self.assertTrue(all("{" not in item.text for item in entries))
            self.assertTrue(all("}" not in item.text for item in entries))

    def test_empty_whitespace_and_non_string_text_are_rejected(self):
        for invalid in ("", " leading", "trailing ", "\nline", 1, None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_control_and_bidi_characters_are_rejected(self):
        for invalid in (
            "line\nfeed",
            "tab\there",
            "bad\x00text",
            "left\u202eright",
            "surrogate\ud800",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_non_nfc_text_is_rejected(self):
        value = "Cafe\u0301"
        self.assertNotEqual(value, unicodedata.normalize("NFC", value))
        with self.assertRaises(localization.VaultRecoveryLocalizationCatalogError):
            localization._validate_text(value, "test")

    def test_template_braces_are_rejected(self):
        for invalid in ("Hello {name}", "Стойност: {}"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationCatalogError
                ):
                    localization._validate_text(invalid, "test")

    def test_codepoint_and_utf8_bounds_are_enforced(self):
        with self.assertRaises(localization.VaultRecoveryLocalizationCatalogError):
            localization._validate_text(
                "a" * (localization.MAX_RECOVERY_LOCALIZED_TEXT_CODEPOINTS + 1),
                "test",
            )
        with self.assertRaises(localization.VaultRecoveryLocalizationCatalogError):
            localization._validate_text(
                "😀" * localization.MAX_RECOVERY_LOCALIZED_TEXT_CODEPOINTS,
                "test",
            )


class RecoveryLocalizationMalformedCatalogTests(unittest.TestCase):
    def setUp(self):
        self.bg = localization.get_recovery_localization_catalog("bg-BG")
        self.en = localization.get_recovery_localization_catalog("en-GB")

    def assertCatalogRejected(self, value):
        with self.assertRaises(localization.VaultRecoveryLocalizationCatalogError):
            localization._validate_catalog(value)

    def test_missing_message_is_rejected(self):
        self.assertCatalogRejected(
            forge_dataclass(
                self.bg,
                message_translations=self.bg.message_translations[:-1],
            )
        )

    def test_extra_message_is_rejected(self):
        self.assertCatalogRejected(
            forge_dataclass(
                self.bg,
                message_translations=(
                    self.bg.message_translations + (self.bg.message_translations[0],)
                ),
            )
        )

    def test_duplicate_message_is_rejected(self):
        entries = list(self.bg.message_translations)
        entries[-1] = entries[0]
        self.assertCatalogRejected(
            forge_dataclass(self.bg, message_translations=tuple(entries))
        )

    def test_reordered_messages_are_rejected(self):
        entries = list(self.bg.message_translations)
        entries[0], entries[1] = entries[1], entries[0]
        self.assertCatalogRejected(
            forge_dataclass(self.bg, message_translations=tuple(entries))
        )

    def test_missing_duplicate_and_extra_confirmation_are_rejected(self):
        variants = (
            self.bg.confirmation_translations[:-1],
            self.bg.confirmation_translations
            + (self.bg.confirmation_translations[0],),
            self.bg.confirmation_translations[:-1]
            + (self.bg.confirmation_translations[0],),
        )
        for entries in variants:
            with self.subTest(length=len(entries)):
                self.assertCatalogRejected(
                    forge_dataclass(
                        self.bg,
                        confirmation_translations=entries,
                    )
                )

    def test_mixed_locale_entry_is_rejected(self):
        entries = list(self.bg.message_translations)
        entries[0] = forge_dataclass(
            entries[0],
            locale=localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        )
        self.assertCatalogRejected(
            forge_dataclass(self.bg, message_translations=tuple(entries))
        )

    def test_altered_safe_text_is_rejected(self):
        entries = list(self.bg.message_translations)
        entries[0] = forge_dataclass(entries[0], text="Друг безопасен текст.")
        self.assertCatalogRejected(
            forge_dataclass(self.bg, message_translations=tuple(entries))
        )

    def test_altered_unsafe_text_is_rejected(self):
        entries = list(self.bg.message_translations)
        entries[0] = forge_dataclass(entries[0], text="лош\u202eтекст")
        self.assertCatalogRejected(
            forge_dataclass(self.bg, message_translations=tuple(entries))
        )

    def test_wrong_digest_version_and_flags_are_rejected(self):
        variants = (
            forge_dataclass(self.bg, catalog_sha256=b"x" * 32),
            forge_dataclass(self.bg, version=2),
            forge_dataclass(self.bg, complete=False),
            forge_dataclass(self.bg, fallback_allowed=True),
            forge_dataclass(self.bg, dynamic_interpolation_allowed=True),
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertCatalogRejected(value)

    def test_registry_missing_duplicate_reordered_and_list_are_rejected(self):
        invalid = (
            (self.bg,),
            (self.bg, self.bg),
            (self.en, self.bg),
            [self.bg, self.en],
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationCatalogError
                ):
                    localization._validate_registry(value)


class RecoveryLocalizationRenderingTests(unittest.TestCase):
    def test_every_route_localizes_in_every_supported_locale(self):
        for route in ROUTES:
            for locale_id in localization.supported_recovery_locale_ids():
                with self.subTest(route=route, locale_id=locale_id):
                    source = make_view(route)
                    result = localization.localize_recovery_ui_adapter_view(
                        source,
                        locale_id,
                    )
                    self.assertEqual(result.presentation_sha256, DIGEST)
                    self.assertEqual(result.locale.value, locale_id)
                    self.assertEqual(
                        tuple(item.message_key for item in result.message_items),
                        tuple(item.message_key for item in source.message_items),
                    )
                    self.assertEqual(
                        tuple(
                            item.confirmation_key
                            for item in result.confirmation_controls
                        ),
                        tuple(
                            item.confirmation_key
                            for item in source.confirmation_controls
                        ),
                    )

    def test_rendered_text_exactly_matches_selected_catalog(self):
        for locale_id in localization.supported_recovery_locale_ids():
            result = localize(ROUTES[1], locale_id)
            catalog = localization.get_recovery_localization_catalog(locale_id)
            message_map = {
                item.message_key: item.text for item in catalog.message_translations
            }
            confirmation_map = {
                item.confirmation_key: item.text
                for item in catalog.confirmation_translations
            }
            self.assertEqual(
                tuple(item.text for item in result.message_items),
                tuple(message_map[item.message_key] for item in result.message_items),
            )
            self.assertEqual(
                tuple(item.text for item in result.confirmation_controls),
                tuple(
                    confirmation_map[item.confirmation_key]
                    for item in result.confirmation_controls
                ),
            )

    def test_accessible_text_is_exactly_the_visible_text(self):
        result = localize(ROUTES[2], "bg-BG")
        self.assertTrue(
            all(item.accessible_text == item.text for item in result.message_items)
        )
        self.assertTrue(
            all(
                item.accessible_text == item.text
                for item in result.confirmation_controls
            )
        )

    def test_message_ordinals_visibility_and_gate_markers_are_preserved(self):
        source = make_view(ROUTES[1])
        result = localization.localize_recovery_ui_adapter_view(source, "en-GB")
        self.assertEqual(
            tuple(item.ordinal for item in result.message_items),
            tuple(range(1, len(result.message_items) + 1)),
        )
        self.assertTrue(all(item.visible for item in result.message_items))
        self.assertEqual(
            tuple(item.is_gate_message for item in result.message_items),
            tuple(item.is_gate_message for item in source.message_items),
        )

    def test_confirmations_remain_visible_required_and_default_false(self):
        result = localize(ROUTES[1], "bg-BG")
        self.assertEqual(
            tuple(item.ordinal for item in result.confirmation_controls),
            tuple(range(1, len(result.confirmation_controls) + 1)),
        )
        self.assertTrue(all(item.visible for item in result.confirmation_controls))
        self.assertTrue(all(item.required for item in result.confirmation_controls))
        self.assertTrue(
            all(item.individually_selectable for item in result.confirmation_controls)
        )
        self.assertTrue(
            all(not item.default_selected for item in result.confirmation_controls)
        )

    def test_rendering_does_not_mutate_source_view(self):
        source = make_view(ROUTES[0])
        before = dataclasses.astuple(source)
        localization.localize_recovery_ui_adapter_view(source, "bg-BG")
        localization.localize_recovery_ui_adapter_view(source, "en-GB")
        self.assertEqual(dataclasses.astuple(source), before)

    def test_locales_are_isolated_for_same_source(self):
        source = make_view(ROUTES[0])
        bg = localization.localize_recovery_ui_adapter_view(source, "bg-BG")
        en = localization.localize_recovery_ui_adapter_view(source, "en-GB")
        self.assertEqual(
            tuple(item.message_key for item in bg.message_items),
            tuple(item.message_key for item in en.message_items),
        )
        self.assertNotEqual(
            tuple(item.text for item in bg.message_items),
            tuple(item.text for item in en.message_items),
        )
        self.assertNotEqual(bg.catalog_sha256, en.catalog_sha256)

    def test_result_is_deterministic(self):
        source = make_view(ROUTES[3])
        first = localization.localize_recovery_ui_adapter_view(source, "bg-BG")
        second = localization.localize_recovery_ui_adapter_view(source, "bg-BG")
        self.assertEqual(first, second)

    def test_result_has_fixed_no_fallback_no_authority_flags(self):
        result = localize(ROUTES[0], "en-GB")
        self.assertTrue(result.source_view_validated)
        self.assertTrue(result.catalog_validated)
        self.assertTrue(result.exact_locale_selected)
        self.assertTrue(result.complete_fixed_text)
        self.assertTrue(result.fixed_user_facing_text_included)
        self.assertFalse(result.fallback_used)
        self.assertFalse(result.dynamic_interpolation_used)
        self.assertFalse(result.operation_controls_included)
        self.assertFalse(result.operation_performed)
        self.assertFalse(result.operation_authorized)
        self.assertFalse(result.secrets_retained)

    def test_localized_view_contains_no_callback_executor_or_secret_fields(self):
        names = {item.name.lower() for item in dataclasses.fields(
            localization.VaultRecoveryLocalizedUIAdapterView
        )}
        forbidden = {
            "password",
            "recovery_root",
            "keyring",
            "candidate",
            "path",
            "filename",
            "callback",
            "executor",
            "operation",
            "session",
        }
        self.assertTrue(names.isdisjoint(forbidden))

    def test_localization_does_not_acknowledge_or_consume_adapter(self):
        source = make_view(ROUTES[0])
        self.assertIs(
            source.adapter_state,
            adapter.RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS,
        )
        result = localization.localize_recovery_ui_adapter_view(source, "bg-BG")
        self.assertIs(
            result.adapter_state,
            adapter.RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS,
        )


class RecoveryLocalizationNegativeRenderingTests(unittest.TestCase):
    def test_non_view_input_is_rejected(self):
        for invalid in (None, {}, (), "view", object()):
            with self.subTest(invalid=invalid):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationSourceError
                ):
                    localization.localize_recovery_ui_adapter_view(
                        invalid,
                        "bg-BG",
                    )

    def test_malformed_source_digest_is_rejected(self):
        source = forge_dataclass(make_view(), presentation_sha256=b"short")
        with self.assertRaises(localization.VaultRecoveryLocalizationSourceError):
            localization.localize_recovery_ui_adapter_view(source, "bg-BG")

    def test_hidden_source_message_is_rejected(self):
        source = make_view()
        messages = list(source.message_items)
        messages[0] = forge_dataclass(messages[0], visible=False)
        source = forge_dataclass(source, message_items=tuple(messages))
        with self.assertRaises(localization.VaultRecoveryLocalizationSourceError):
            localization.localize_recovery_ui_adapter_view(source, "bg-BG")

    def test_unsupported_locale_does_not_return_partial_output(self):
        with self.assertRaises(localization.VaultRecoveryLocalizationLocaleError):
            localization.localize_recovery_ui_adapter_view(make_view(), "fr-FR")

    def test_forged_localized_message_text_is_rejected(self):
        result = localize()
        messages = list(result.message_items)
        messages[0] = forge_dataclass(messages[0], text="Подменен текст.")
        forged = forge_dataclass(result, message_items=tuple(messages))
        with self.assertRaises(localization.VaultRecoveryLocalizationFormatError):
            localization._validate_localized_view(forged)

    def test_mixed_locale_localized_message_is_rejected(self):
        result = localize()
        messages = list(result.message_items)
        messages[0] = forge_dataclass(
            messages[0],
            locale=localization.RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
        )
        forged = forge_dataclass(result, message_items=tuple(messages))
        with self.assertRaises(localization.VaultRecoveryLocalizationFormatError):
            localization._validate_localized_view(forged)

    def test_missing_reordered_and_duplicate_localized_items_are_rejected(self):
        result = localize()
        messages = result.message_items
        variants = (
            messages[:-1],
            (messages[1], messages[0]) + messages[2:],
            (messages[0], messages[0]) + messages[2:],
        )
        for items in variants:
            with self.subTest(length=len(items)):
                forged = forge_dataclass(result, message_items=items)
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationFormatError
                ):
                    localization._validate_localized_view(forged)

    def test_wrong_catalog_digest_is_rejected(self):
        result = forge_dataclass(localize(), catalog_sha256=b"x" * 32)
        with self.assertRaises(localization.VaultRecoveryLocalizationFormatError):
            localization._validate_localized_view(result)

    def test_fallback_dynamic_and_authority_flags_are_rejected(self):
        value = localize()
        variants = (
            forge_dataclass(value, fallback_used=True),
            forge_dataclass(value, dynamic_interpolation_used=True),
            forge_dataclass(value, operation_controls_included=True),
            forge_dataclass(value, operation_performed=True),
            forge_dataclass(value, operation_authorized=True),
            forge_dataclass(value, secrets_retained=True),
        )
        for forged in variants:
            with self.subTest(forged=forged):
                with self.assertRaises(
                    localization.VaultRecoveryLocalizationFormatError
                ):
                    localization._validate_localized_view(forged)

    def test_exact_boolean_policy_rejects_integer_substitution(self):
        result = forge_dataclass(localize(), fallback_used=0)
        with self.assertRaises(localization.VaultRecoveryLocalizationFormatError):
            localization._validate_localized_view(result)

    def test_copy_pickle_do_not_change_registry_or_result(self):
        catalog = localization.get_recovery_localization_catalog("bg-BG")
        result = localize()
        self.assertEqual(copy.copy(catalog), catalog)
        self.assertEqual(copy.deepcopy(result), result)
        self.assertEqual(pickle.loads(pickle.dumps(result)), result)


class RecoveryLocalizationStaticBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(localization.__file__)
        cls.source = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_module_has_no_forbidden_runtime_imports(self):
        forbidden = {
            "io",
            "logging",
            "os",
            "pathlib",
            "random",
            "requests",
            "secrets",
            "socket",
            "subprocess",
            "time",
            "tkinter",
            "urllib",
        }
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(item.name.split(".", 1)[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(imported.isdisjoint(forbidden))

    def test_module_has_no_file_process_network_or_dynamic_execution_calls(self):
        forbidden_names = {"compile", "eval", "exec", "input", "open", "print"}
        forbidden_attributes = {
            "connect",
            "download",
            "remove",
            "rename",
            "replace",
            "rmdir",
            "send",
            "unlink",
            "upload",
            "write",
        }
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden_names)
            elif isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden_attributes)

    def test_public_localize_function_accepts_no_template_or_callback_input(self):
        function = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "localize_recovery_ui_adapter_view"
        )
        self.assertEqual(
            tuple(item.arg for item in function.args.args),
            ("view", "locale_id"),
        )
        self.assertIsNone(function.args.vararg)
        self.assertIsNone(function.args.kwarg)

    def test_module_contains_no_gui_widget_or_operation_entrypoint(self):
        public_functions = {
            node.name
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
        }
        self.assertEqual(
            public_functions,
            {
                "get_recovery_localization_catalog",
                "localize_recovery_ui_adapter_view",
                "supported_recovery_locale_ids",
            },
        )


if __name__ == "__main__":
    unittest.main()
