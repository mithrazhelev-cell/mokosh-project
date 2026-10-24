import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mokosh_profile_recovery_gui as gui
from mokosh_profile_localization import ProfileLocale
from mokosh_profile_recovery import (
    ProfileRecoveryAuthenticationError,
    ProfileRecoveryDecision,
    ProfileRecoveryInputError,
    ProfileRecoveryLifecyclePublishError,
    ProfileRecoveryPublishUncertainError,
    ProfileRecoverySeparationError,
    ProfileRecoveryStorageUnsupportedError,
)


ROOT = Path(__file__).resolve().parents[1]
WORDS = (
    "abandon", "ability", "able", "about", "above",
    "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve",
    "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt",
)


class FakeVariable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWidget:
    def __init__(self, text="", *, state=None, show="*"):
        self.options = {"show": show}
        if state is not None:
            self.options["state"] = state
        self.value = text
        self.focused = False
        self.packed = False

    def configure(self, **values):
        self.options.update(values)

    def cget(self, name):
        return self.options.get(name)

    def get(self, *_args):
        return self.value

    def delete(self, *_args):
        self.value = ""

    def focus_set(self):
        self.focused = True

    def pack(self, **_options):
        self.packed = True

    def pack_forget(self):
        self.packed = False


class RecoverySetupWindowLogicTests(unittest.TestCase):
    @staticmethod
    def window(plan=None):
        value = gui.RecoverySetupWindow.__new__(gui.RecoverySetupWindow)
        value.profile_root = Path("/synthetic/profile")
        value.locale = ProfileLocale.BULGARIAN
        value.current_password = FakeVariable("Current Stage 2.47 password")
        value.status = FakeVariable("initial")
        value.plan = plan
        value.paper_window = None
        value.phrase_labels = [FakeWidget() for _ in range(25)]
        value.widgets = {
            name: FakeWidget(state=gui.tk.NORMAL)
            for name in (
                "current_password", "current_password_toggle", "prepare",
                "record", "phrase", "paper", "finish",
            )
        }
        value.widgets["finish"].configure(state=gui.tk.DISABLED)
        value.window = object()
        value.t = lambda key, **_values: key
        value._completed = False
        value._closed = False
        value.on_closed = None
        value.on_completed = None
        return value

    def test_prepare_reauth_clears_password_masks_eye_and_reveals_25_words(self):
        plan = SimpleNamespace(phrase_words=WORDS)
        window = self.window()
        with mock.patch.object(
            gui, "begin_profile_recovery_setup", return_value=plan
        ) as begin:
            window.prepare()
        begin.assert_called_once_with(
            Path("/synthetic/profile"),
            "Current Stage 2.47 password",
            ProfileRecoveryDecision.AUTHORIZE,
        )
        self.assertEqual(window.current_password.get(), "")
        self.assertEqual(window.widgets["current_password"].cget("show"), "*")
        self.assertIs(window.plan, plan)
        self.assertEqual(
            [label.options["text"] for label in window.phrase_labels],
            [f"{index:02d}. {word}" for index, word in enumerate(WORDS, 1)],
        )
        self.assertEqual(window.widgets["record"].options["state"], gui.tk.NORMAL)
        for name in ("current_password", "current_password_toggle", "prepare"):
            self.assertEqual(window.widgets[name].options["state"], gui.tk.DISABLED)

    def test_wrong_current_password_has_specific_message_and_refocuses(self):
        window = self.window()
        with (
            mock.patch.object(
                gui,
                "begin_profile_recovery_setup",
                side_effect=ProfileRecoveryAuthenticationError("wrong"),
            ),
            mock.patch.object(gui, "show_action_notice") as notice,
        ):
            window.prepare()
        notice.assert_called_once_with(
            window.window,
            title="recovery_setup_title",
            text="recovery_current_password_failed",
            close_label="understand",
        )
        self.assertEqual(window.current_password.get(), "")
        self.assertEqual(window.widgets["current_password"].cget("show"), "*")
        self.assertTrue(window.widgets["current_password"].focused)

    def test_record_then_separate_phrase_are_user_selected_actions(self):
        plan = SimpleNamespace(
            record_exported=False,
            backup_verified=False,
            export_record=mock.Mock(),
            export_phrase=mock.Mock(),
        )
        window = self.window(plan)
        with mock.patch.object(
            gui.filedialog, "askdirectory", return_value="/chosen/record-parent"
        ):
            window.save_record()
        plan.export_record.assert_called_once_with("/chosen/record-parent")
        self.assertEqual(window.widgets["phrase"].options["state"], gui.tk.NORMAL)
        self.assertEqual(window.widgets["paper"].options["state"], gui.tk.NORMAL)

        plan.record_exported = True
        with mock.patch.object(
            gui.filedialog, "askdirectory", return_value="/chosen/phrase-parent"
        ):
            window.save_phrase()
        plan.export_phrase.assert_called_once_with("/chosen/phrase-parent")
        self.assertEqual(window.widgets["finish"].options["state"], gui.tk.NORMAL)

    def test_storage_failures_have_distinct_plain_language_messages(self):
        cases = (
            (ProfileRecoverySeparationError("same device"), "recovery_separation_failed"),
            (
                ProfileRecoveryStorageUnsupportedError("unsupported"),
                "recovery_storage_unsupported",
            ),
        )
        for error, expected in cases:
            with self.subTest(expected=expected):
                plan = SimpleNamespace(
                    record_exported=True,
                    backup_verified=False,
                    export_phrase=mock.Mock(side_effect=error),
                )
                window = self.window(plan)
                with (
                    mock.patch.object(
                        gui.filedialog,
                        "askdirectory",
                        return_value="/chosen/external-device",
                    ),
                    mock.patch.object(gui, "show_action_notice") as notice,
                ):
                    window.save_phrase()
                notice.assert_called_once_with(
                    window.window,
                    title="recovery_setup_title",
                    text=expected,
                    close_label="understand",
                )
                self.assertNotEqual(
                    window.widgets["finish"].options.get("state"), gui.tk.NORMAL
                )

    def test_force_close_clears_phrase_password_and_plan_once(self):
        plan = SimpleNamespace(close=mock.Mock())
        window = self.window(plan)
        for label, word in zip(window.phrase_labels, WORDS):
            label.configure(text=word)
        window.window = SimpleNamespace(destroy=mock.Mock())
        closed = mock.Mock()
        window.on_closed = closed

        window.force_close()
        window.force_close()

        self.assertEqual(window.current_password.get(), "")
        self.assertTrue(all(label.options["text"] == "—" for label in window.phrase_labels))
        self.assertIsNone(window.plan)
        plan.close.assert_called_once_with()
        window.window.destroy.assert_called_once_with()
        closed.assert_called_once_with()

    def test_receipt_publish_failure_is_terminal_and_cannot_repeat_finish(self):
        plan = SimpleNamespace(
            backup_verified=True,
            complete=mock.Mock(
                side_effect=ProfileRecoveryLifecyclePublishError("injected")
            ),
        )
        window = self.window(plan)
        window.force_close = mock.Mock()
        with mock.patch.object(gui, "show_action_notice") as notice:
            window.finish()
            window.finish()
        plan.complete.assert_called_once_with(ProfileRecoveryDecision.AUTHORIZE)
        self.assertIsNone(window.plan)
        self.assertEqual(window.widgets["finish"].options["state"], gui.tk.DISABLED)
        self.assertEqual(notice.call_args.kwargs["text"], "recovery_state_publish_failed")
        window.force_close.assert_called_once_with()


class PaperPhraseConfirmationWindowLogicTests(unittest.TestCase):
    @staticmethod
    def window(text):
        value = gui.PaperPhraseConfirmationWindow.__new__(
            gui.PaperPhraseConfirmationWindow
        )
        value.locale = ProfileLocale.BULGARIAN
        value.text = FakeWidget(text)
        value.window = object()
        value.verify_callback = mock.Mock()
        value.close = mock.Mock()
        value.t = lambda key, **_values: key
        return value

    def test_empty_one_24_and_26_words_report_exact_counts_and_remain_retryable(self):
        for count in (0, 1, 24, 26):
            with self.subTest(count=count):
                value = (
                    " ".join(WORDS[:count])
                    if count <= 25
                    else " ".join(WORDS + ("add",))
                )
                window = self.window(value)
                with mock.patch.object(gui, "show_action_notice") as notice:
                    window.verify()
                window.verify_callback.assert_not_called()
                self.assertEqual(window.text.value, "")
                self.assertTrue(window.text.focused)
                self.assertIn(
                    notice.call_args.kwargs["text"],
                    {
                        gui.profile_text(
                            ProfileLocale.BULGARIAN,
                            "recovery_phrase_missing",
                        ),
                        gui.profile_text(
                            ProfileLocale.BULGARIAN,
                            "recovery_phrase_word_count",
                            count=str(count),
                        ),
                    },
                )
                window.close.assert_not_called()

    def test_wrong_order_or_word_is_specific_and_exact_copy_succeeds(self):
        wrong_window = self.window(" ".join(WORDS))
        wrong_window.verify_callback.side_effect = gui.ProfileRecoveryBackupError(
            "mismatch"
        )
        with mock.patch.object(gui, "show_action_notice") as notice:
            wrong_window.verify()
        self.assertEqual(notice.call_args.kwargs["text"], "recovery_paper_not_match")
        self.assertEqual(wrong_window.text.value, "")
        wrong_window.close.assert_not_called()

        exact_window = self.window("  \n".join(WORDS))
        with mock.patch.object(gui, "show_action_notice") as notice:
            exact_window.verify()
        exact_window.verify_callback.assert_called_once_with(WORDS)
        self.assertEqual(exact_window.text.value, "")
        self.assertEqual(notice.call_args.kwargs["text"], "recovery_paper_verified")
        exact_window.close.assert_called_once_with()


class PasswordRecoveryWindowLogicTests(unittest.TestCase):
    @staticmethod
    def window(plan=None):
        value = gui.PasswordRecoveryWindow.__new__(gui.PasswordRecoveryWindow)
        value.profile_root = Path("/synthetic/profile")
        value.locale = ProfileLocale.BULGARIAN
        value.record_path = FakeVariable("/chosen/record.mokr")
        value.sheet_path = FakeVariable("/chosen/phrase.txt")
        value.mode = FakeVariable("words")
        value.new_password = FakeVariable("New Stage 2.47 password")
        value.confirmation = FakeVariable("New Stage 2.47 password")
        value.status = FakeVariable("initial")
        value.technical_details = FakeVariable("")
        value.widgets = {
            name: FakeWidget(state=gui.tk.NORMAL)
            for name in (
                "choose_record", "choose_record_path", "choose_sheet",
                "choose_sheet_path", "sheet_mode", "words_mode",
                "new_password", "new_password_toggle", "confirmation",
                "confirmation_toggle", "preview", "publish",
                "technical_details", "technical_toggle",
            )
        }
        value.widgets["words"] = FakeWidget(
            " ".join(WORDS), state=gui.tk.NORMAL, show=""
        )
        value.window = object()
        value.t = lambda key, **_values: key
        value.plan = plan
        value._closed = False
        value._technical_visible = False
        value.on_closed = None
        value.on_completed = None
        return value

    def test_manual_phrase_preview_is_read_only_and_clears_all_gui_secrets(self):
        plan = SimpleNamespace(
            preview=SimpleNamespace(source_revision=7, target_revision=8)
        )
        window = self.window()
        with mock.patch.object(
            gui, "prepare_profile_password_recovery_from_words", return_value=plan
        ) as prepare:
            window.prepare_preview()
        prepare.assert_called_once_with(
            Path("/synthetic/profile"),
            "/chosen/record.mokr",
            " ".join(WORDS),
            "New Stage 2.47 password",
            "New Stage 2.47 password",
            ProfileRecoveryDecision.AUTHORIZE,
        )
        self.assertEqual(window.new_password.get(), "")
        self.assertEqual(window.confirmation.get(), "")
        self.assertEqual(window.widgets["words"].value, "")
        self.assertEqual(window.widgets["new_password"].cget("show"), "*")
        self.assertEqual(window.widgets["confirmation"].cget("show"), "*")
        self.assertEqual(window.widgets["preview"].options["state"], gui.tk.DISABLED)
        self.assertEqual(window.widgets["publish"].options["state"], gui.tk.NORMAL)
        self.assertEqual(window.status.get(), "password_recovery_preview_ready")
        self.assertEqual(
            window.technical_details.get(), "password_recovery_technical_details"
        )
        self.assertTrue(window.widgets["technical_toggle"].packed)

    def test_password_mismatch_is_local_specific_and_core_is_not_called(self):
        window = self.window()
        window.confirmation.set("A different password")
        with (
            mock.patch.object(
                gui, "prepare_profile_password_recovery_from_words"
            ) as prepare,
            mock.patch.object(gui, "show_action_notice") as notice,
        ):
            window.prepare_preview()
        prepare.assert_not_called()
        self.assertEqual(
            notice.call_args.kwargs["text"],
            gui.profile_text(
                ProfileLocale.BULGARIAN,
                "password_recovery_password_mismatch",
            ),
        )
        self.assertEqual(window.new_password.get(), "")
        self.assertEqual(window.confirmation.get(), "")
        self.assertEqual(window.widgets["words"].value, "")
        self.assertTrue(window.widgets["confirmation"].focused)

    def test_core_source_mismatch_keeps_only_general_anti_oracle_message(self):
        window = self.window()
        with (
            mock.patch.object(
                gui,
                "prepare_profile_password_recovery_from_words",
                side_effect=ProfileRecoveryInputError("source mismatch"),
            ),
            mock.patch.object(gui, "show_action_notice") as notice,
        ):
            window.prepare_preview()
        self.assertEqual(notice.call_args.kwargs["text"], "password_recovery_failed")
        self.assertEqual(window.new_password.get(), "")
        self.assertEqual(window.confirmation.get(), "")
        self.assertEqual(window.widgets["words"].value, "")

    def test_manual_mode_clears_stale_sheet_and_sheet_mode_clears_words(self):
        window = self.window()
        window._sync_mode()
        self.assertEqual(window.sheet_path.get(), "")
        self.assertEqual(window.widgets["words"].options["state"], gui.tk.NORMAL)

        window.sheet_path.set("/chosen/phrase.txt")
        window.widgets["words"].value = "secret words"
        window.mode.set("sheet")
        window._sync_mode()
        self.assertEqual(window.widgets["words"].value, "")
        self.assertEqual(window.widgets["words"].options["state"], gui.tk.DISABLED)
        self.assertEqual(window.widgets["choose_sheet"].options["state"], gui.tk.NORMAL)

    def test_publish_defaults_to_back_and_uses_action_specific_labels(self):
        plan = SimpleNamespace(publish=mock.Mock())
        window = self.window(plan)
        with mock.patch.object(gui, "ask_action_decision", return_value=False) as ask:
            window.publish()
        plan.publish.assert_not_called()
        ask.assert_called_once_with(
            window.window,
            title="password_recovery_title",
            text="password_recovery_publish_warning",
            approve_label="password_recovery_publish",
            cancel_label="back_without_change",
        )

        completed = mock.Mock()
        window.on_completed = completed
        window.close = mock.Mock()
        with (
            mock.patch.object(gui, "ask_action_decision", return_value=True),
            mock.patch.object(gui, "show_action_notice") as notice,
        ):
            window.publish()
        plan.publish.assert_called_once_with(ProfileRecoveryDecision.AUTHORIZE)
        completed.assert_called_once_with()
        self.assertEqual(notice.call_args.kwargs["text"], "password_recovery_success")
        window.close.assert_called_once_with()

    def test_uncertain_publish_is_exactly_once_and_disables_retry(self):
        plan = SimpleNamespace(
            publish=mock.Mock(
                side_effect=ProfileRecoveryPublishUncertainError("uncertain")
            )
        )
        window = self.window(plan)
        with (
            mock.patch.object(gui, "ask_action_decision", return_value=True),
            mock.patch.object(gui, "show_action_notice") as notice,
        ):
            window.publish()
            window.publish()
        plan.publish.assert_called_once_with(ProfileRecoveryDecision.AUTHORIZE)
        self.assertIsNone(window.plan)
        self.assertEqual(window.widgets["publish"].options["state"], gui.tk.DISABLED)
        self.assertEqual(notice.call_args.kwargs["text"], "password_recovery_uncertain")


class ProfileRecoveryGUIStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "mokosh_profile_recovery_gui.py"
        cls.source = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_no_network_logging_clipboard_or_automatic_destination(self):
        imports = {
            alias.name.split(".", 1)[0]
            for node in self.tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {"socket", "urllib", "requests", "http", "ssl", "logging"}
            )
        )
        for token in ("clipboard_", "pyperclip", "Path.home", "expanduser"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.source)

    def test_native_messageboxes_and_transient_wm_hints_are_absent(self):
        self.assertNotIn("messagebox", self.source)
        self.assertNotIn(".transient(", self.source)
        self.assertNotIn("askyesno", self.source)
        self.assertEqual(self.source.count("ask_action_decision("), 1)

    def test_all_windows_use_resizable_contract_and_all_passwords_have_eyes(self):
        self.assertEqual(self.source.count("configure_resizable_window("), 3)
        # One direct setup-password eye plus the password-row helper, which is
        # invoked for both new-password fields.
        self.assertEqual(self.source.count("create_secret_toggle("), 2)
        self.assertEqual(self.source.count("self._password_row("), 2)
        for token in (
            "PAPER_WINDOW_MINIMUM", "RECOVERY_WINDOW_MINIMUM",
            "create_scrollable_region", "ResponsiveGrid", "ResponsivePair",
            "bind_responsive_wrap",
        ):
            self.assertIn(token, self.source)

    def test_setup_reauth_keeps_entry_and_eye_together_and_stacks_only_prepare(self):
        setup_source = self.source.split(
            "class RecoverySetupWindow:", 1
        )[1].split("class PasswordRecoveryWindow:", 1)[0]
        for token in (
            "password_fields.grid_columnconfigure(0, weight=1)",
            'entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))',
            'reveal.grid(row=0, column=1, sticky="e")',
            "self.reauth_row = ResponsivePair(",
            "password_fields,\n            prepare_controls,",
            "breakpoint=760",
            'secondary_stacked_sticky="e"',
            "fit_requested_widths=True",
            "prepare.pack()",
        ):
            with self.subTest(token=token):
                self.assertIn(token, setup_source)
        self.assertNotIn('prepare.pack(side="right")', setup_source)
        self.assertNotIn('entry.pack(side="left"', setup_source)

    def test_context_precedes_each_setup_action_and_phrase_is_numbered(self):
        for key in (
            "recovery_setup_reauth", "recovery_phrase_warning",
            "recovery_record_help", "recovery_phrase_help", "recovery_finish_help",
        ):
            with self.subTest(key=key):
                self.assertIn(key, self.source)
        self.assertIn("for index in range(25)", self.source)
        self.assertIn('text=f"{index + 1:02d}. —"', self.source)


if __name__ == "__main__":
    unittest.main()
