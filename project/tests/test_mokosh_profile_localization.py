import unittest

import mokosh_profile_localization as localization


class ProfileLocalizationTests(unittest.TestCase):
    def test_user_locales_are_exact(self):
        self.assertEqual(
            {
                localization.ProfileLocale.ENGLISH.value,
                localization.ProfileLocale.BULGARIAN.value,
            },
            {"en", "bg"},
        )

    def test_every_public_key_renders_in_both_user_locales(self):
        for key in localization.PROFILE_MESSAGE_KEYS:
            values_by_key = {
                "status_unlocked": {"nickname": "Test"},
                "password_recovery_technical_details": {
                    "source_revision": "1",
                    "target_revision": "2",
                },
                "recovery_phrase_word_count": {"count": "24"},
            }
            values = values_by_key.get(key, {})
            for locale in ("en", "bg"):
                with self.subTest(key=key, locale=locale):
                    rendered = localization.profile_text(locale, key, **values)
                    self.assertIs(type(rendered), str)
                    self.assertTrue(rendered)

    def test_pseudo_locale_is_test_only_and_expands_text(self):
        ordinary = localization.profile_text("en", "create_intro")
        expanded = localization.profile_text(
            localization.ProfileLocale.PSEUDO,
            "create_intro",
        )
        self.assertGreater(len(expanded), len(ordinary))
        self.assertTrue(expanded.startswith("⟦ "))
        with self.assertRaises(localization.ProfileLocalizationError):
            localization.normalize_locale("qps-ploc")

    def test_unknown_locale_and_key_fail_closed(self):
        for locale in ("EN", "bg-BG", "", None, True):
            with self.subTest(locale=locale):
                with self.assertRaises(localization.ProfileLocalizationError):
                    localization.profile_text(locale, "title")
        for key in ("", "unknown", None, True):
            with self.subTest(key=key):
                with self.assertRaises(localization.ProfileLocalizationError):
                    localization.profile_text("en", key)

    def test_missing_or_extra_format_value_fails(self):
        with self.assertRaises(localization.ProfileLocalizationError):
            localization.profile_text("en", "status_unlocked")
        with self.assertRaises(localization.ProfileLocalizationError):
            localization.profile_text("en", "title", nickname="unused")

    def test_security_meaning_is_present_in_both_languages(self):
        self.assertIn("15 minutes", localization.profile_text("en", "status_unlocked", nickname="N"))
        self.assertIn("15 минути", localization.profile_text("bg", "status_unlocked", nickname="N"))
        self.assertIn("optional", localization.profile_text("en", "recovery_unavailable"))
        self.assertIn("по желание", localization.profile_text("bg", "recovery_unavailable"))
        self.assertIn("25", localization.profile_text("en", "recovery_setup_intro"))
        self.assertIn("25", localization.profile_text("bg", "recovery_setup_intro"))
        self.assertIn("separate", localization.profile_text("en", "recovery_setup_intro"))
        self.assertIn("отделни", localization.profile_text("bg", "recovery_setup_intro"))
        self.assertIn("FAT/exFAT", localization.profile_text("en", "recovery_phrase_help"))
        self.assertIn("FAT/exFAT", localization.profile_text("bg", "recovery_phrase_help"))

    def test_setup_explains_vault_and_physical_media_in_plain_language(self):
        en_reauth = localization.profile_text("en", "recovery_setup_reauth")
        bg_reauth = localization.profile_text("bg", "recovery_setup_reauth")
        self.assertIn("encrypted key store (Vault)", en_reauth)
        self.assertIn("защитеното хранилище с ключовете (Vault)", bg_reauth)

        for locale in ("en", "bg"):
            with self.subTest(locale=locale):
                self.assertNotIn(
                    "Vault",
                    localization.profile_text(locale, "recovery_finish_help"),
                )
                self.assertNotIn(
                    "Vault",
                    localization.profile_text(locale, "recovery_setup_failed"),
                )

        en_help = localization.profile_text("en", "recovery_phrase_help")
        bg_help = localization.profile_text("bg", "recovery_phrase_help")
        self.assertIn("USB drive", en_help)
        self.assertIn("external disk", en_help)
        self.assertIn("your user account", en_help)
        self.assertIn("флашка", bg_help)
        self.assertIn("външен диск", bg_help)
        self.assertIn("само до Вашия потребител", bg_help)

        en_error = localization.profile_text(
            "en", "recovery_storage_unsupported"
        )
        bg_error = localization.profile_text(
            "bg", "recovery_storage_unsupported"
        )
        self.assertIn("FAT/exFAT", en_error)
        self.assertIn("FAT/exFAT", bg_error)
        self.assertIn("USB drive", en_error)
        self.assertIn("флашка", bg_error)

    def test_bulgarian_clean_action_is_short_and_unambiguous(self):
        self.assertEqual(
            localization.profile_text("bg", "clean"),
            "Почисти оригинали...",
        )

    def test_local_v2_security_wording_is_explicit_in_both_languages(self):
        en_intro = localization.profile_text("en", "local_v2_encrypt_intro")
        bg_intro = localization.profile_text("bg", "local_v2_encrypt_intro")
        self.assertIn(".mok2", en_intro)
        self.assertIn("unsigned", en_intro)
        self.assertIn(".mok2", bg_intro)
        self.assertIn("неподписан", bg_intro)

        en_decrypt = localization.profile_text("en", "local_v2_decrypt_intro")
        bg_decrypt = localization.profile_text("bg", "local_v2_decrypt_intro")
        self.assertIn("bytes, not its extension", en_decrypt)
        self.assertIn("exact stored Vault key version", en_decrypt)
        self.assertIn("байтовете, не по разширението", bg_decrypt)
        self.assertIn("точно записаната версия", bg_decrypt)

        for locale, no_retry, preserve in (
            ("en", "Do not retry", "always kept"),
            ("bg", "Не повтаряйте", "винаги се запазват"),
        ):
            with self.subTest(locale=locale):
                self.assertIn(
                    no_retry,
                    localization.profile_text(
                        locale, "local_v2_published_warning"
                    ),
                )
                self.assertIn(
                    preserve,
                    localization.profile_text(locale, "local_v2_keep_originals"),
                )
                self.assertIn(
                    "MOK1",
                    localization.profile_text(locale, "local_v2_error_not_v2"),
                )

    def test_local_v2_and_historical_mok1_labels_are_distinct(self):
        for locale in ("en", "bg"):
            with self.subTest(locale=locale):
                self.assertNotEqual(
                    localization.profile_text(locale, "decrypt"),
                    localization.profile_text(locale, "legacy_decrypt"),
                )


if __name__ == "__main__":
    unittest.main()
