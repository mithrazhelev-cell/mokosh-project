import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import mokosh_profile_gui as gui
from mokosh_profile_recovery_state import (
    ProfileRecoveryAvailability,
    ProfileRecoveryLoginNotice,
    ProfileRecoveryStateInspection,
)
from mokosh_profile_session import (
    LoginResult,
    ProfileSessionState,
    capability_registry,
)
from mokosh_profile_storage import ProfileInspection, ProfileState


ROOT = Path(__file__).resolve().parents[1]


class FakeVariable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWidget:
    def __init__(self, *, show="*"):
        self.options = {"show": show}
        self.focused = False

    def configure(self, **values):
        self.options.update(values)

    def cget(self, name):
        return self.options.get(name)

    def focus_set(self):
        self.focused = True


class FakeRoot:
    def __init__(self):
        self.window_title = ""

    def title(self, value):
        self.window_title = value


class TransitionController:
    def __init__(self):
        self.inspection = ProfileInspection(ProfileState.READY, False)
        self.state = ProfileSessionState.LOCKED
        self.session = SimpleNamespace(nickname="VisualTest")
        self.login_calls = []
        self.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.CURRENT,
            "synthetic_current",
            source_revision=1,
            current_revision=1,
        )
        self.recovery_login_notice = None

    @property
    def capabilities(self):
        return capability_registry(self.state)

    def login(self, nickname, password):
        self.login_calls.append((nickname, password))
        self.state = ProfileSessionState.UNLOCKED
        return LoginResult(True, True, True)

    def lock(self, _reason):
        self.state = ProfileSessionState.LOCKED

    def consume_recovery_login_notice(self):
        notice = self.recovery_login_notice
        self.recovery_login_notice = None
        return notice


class ProfileApplicationControllerTests(unittest.TestCase):
    def test_absent_profile_does_not_load_or_create_automatically(self):
        inspection = ProfileInspection(ProfileState.ABSENT, False)
        with (
            mock.patch.object(gui, "inspect_profile", return_value=inspection) as inspect,
            mock.patch.object(gui, "load_profile") as load,
        ):
            controller = gui.ProfileApplicationController("/synthetic/profile")
        self.assertIs(controller.inspection, inspection)
        self.assertIsNone(controller.session)
        inspect.assert_called_once()
        load.assert_not_called()

    def test_ready_profile_builds_locked_session(self):
        inspection = ProfileInspection(ProfileState.READY, False)
        snapshot = object()
        session_object = SimpleNamespace(
            state=ProfileSessionState.LOCKED,
            capabilities={},
            close=lambda: None,
        )
        with (
            mock.patch.object(gui, "inspect_profile", return_value=inspection),
            mock.patch.object(gui, "load_profile", return_value=snapshot),
            mock.patch.object(gui, "SecureProfileSession", return_value=session_object) as factory,
        ):
            controller = gui.ProfileApplicationController("/synthetic/profile")
        factory.assert_called_once_with(snapshot)
        self.assertIs(controller.state, ProfileSessionState.LOCKED)

    def test_confirmation_mismatch_precedes_storage_mutation(self):
        inspection = ProfileInspection(ProfileState.ABSENT, False)
        with (
            mock.patch.object(gui, "inspect_profile", return_value=inspection),
            mock.patch.object(gui, "create_profile") as create,
        ):
            controller = gui.ProfileApplicationController("/synthetic/profile")
            with self.assertRaises(gui.ProfileValidationError):
                controller.create("Nick", "password A long enough", "password B long enough")
        create.assert_not_called()

    def test_successful_login_updates_and_exposes_one_recovery_notice(self):
        result = LoginResult(True, True, True)
        session = SimpleNamespace(unlock=mock.Mock(return_value=result))
        state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.REPLACEMENT_REQUIRED,
            "stale",
            source_revision=1,
            current_revision=2,
            replacement_reminders_shown=1,
        )
        notice = ProfileRecoveryLoginNotice(state, True, 1)
        controller = gui.ProfileApplicationController.__new__(
            gui.ProfileApplicationController
        )
        controller.profile_root = Path("/synthetic/profile")
        controller.session = session
        controller.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.MISSING, "missing"
        )
        controller.recovery_login_notice = None

        with mock.patch.object(
            gui, "note_successful_login_for_recovery", return_value=notice
        ) as update:
            self.assertIs(controller.login("Nick", "Password long enough"), result)
        update.assert_called_once_with(Path("/synthetic/profile"))
        self.assertIs(controller.recovery_state, state)
        self.assertIs(controller.consume_recovery_login_notice(), notice)
        self.assertIsNone(controller.consume_recovery_login_notice())


class ProfileMainWindowLogicTests(unittest.TestCase):
    @staticmethod
    def window(login_result):
        value = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        value.password = FakeVariable("Stage 2.46 password")
        value.nickname = FakeVariable("Nickname")
        value.root = object()
        value.t = lambda key, **_values: key
        value.refresh_view = mock.Mock()
        value.controller = SimpleNamespace(
            state=ProfileSessionState.LOCKED,
            login=mock.Mock(return_value=login_result),
        )
        return value

    def test_failed_login_clears_password_but_not_nickname(self):
        window = self.window(LoginResult(False, True, False))
        with mock.patch.object(gui, "show_action_notice") as error:
            window.login_or_lock()
        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "Nickname")
        error.assert_called_once()

    def test_successful_login_clears_password_and_nickname(self):
        window = self.window(LoginResult(True, True, True))
        with mock.patch.object(gui, "show_action_notice") as error:
            window.login_or_lock()
        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "")
        error.assert_not_called()

    def test_successful_login_updates_complete_visible_state_then_manual_lock(self):
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.password = FakeVariable("Temporary-Test-246!")
        window.nickname = FakeVariable("VisualTest")
        window.local_folder = FakeVariable("")
        window.folder_variable = FakeVariable("")
        window.status_variable = FakeVariable("")
        window.recovery_status_variable = FakeVariable("")
        window.root = FakeRoot()
        window.locale = gui.ProfileLocale.BULGARIAN
        window.controller = TransitionController()
        window.widgets = {
            name: FakeWidget()
            for name in (
                "language_label",
                "folder_label",
                "choose_folder",
                "password_label",
                "nickname_label",
                "create_profile",
                "encrypt",
                "decrypt",
                "clean",
                "contacts",
                "contact_crypto",
                "sandbox",
                "recovery_section",
                "recovery_main_help",
                "recovery_setup",
                "recovery_password",
                "recovery_legacy",
                "maintenance",
                "panic_hint",
                "status",
                "recovery_status",
                "login",
                "password_entry",
                "password_toggle",
                "nickname_entry",
                "nickname_toggle",
            )
        }

        with mock.patch.object(gui, "show_action_notice") as error:
            window.login_or_lock()

        self.assertEqual(
            window.controller.login_calls,
            [("VisualTest", "Temporary-Test-246!")],
        )
        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "")
        self.assertTrue(window.status_variable.get().startswith("ОТКЛЮЧЕНО —"))
        self.assertEqual(window.widgets["login"].options["text"], "ЗАКЛЮЧИ")
        self.assertEqual(
            window.widgets["password_entry"].options["state"], gui.tk.DISABLED
        )
        self.assertEqual(
            window.widgets["nickname_entry"].options["state"], gui.tk.DISABLED
        )
        self.assertEqual(
            window.widgets["recovery_setup"].options["state"], gui.tk.NORMAL
        )
        self.assertEqual(
            window.widgets["recovery_password"].options["state"], gui.tk.DISABLED
        )
        self.assertEqual(window.widgets["encrypt"].options["state"], gui.tk.NORMAL)
        self.assertEqual(window.widgets["decrypt"].options["state"], gui.tk.NORMAL)
        self.assertEqual(
            window.widgets["recovery_legacy"].options["state"], gui.tk.NORMAL
        )
        error.assert_not_called()

        window.login_or_lock()

        self.assertTrue(window.status_variable.get().startswith("ЗАКЛЮЧЕНО —"))
        self.assertEqual(window.widgets["login"].options["text"], "ВХОД")
        self.assertEqual(
            window.widgets["password_entry"].options["state"], gui.tk.NORMAL
        )
        self.assertEqual(
            window.widgets["nickname_entry"].options["state"], gui.tk.NORMAL
        )
        self.assertEqual(
            window.widgets["recovery_setup"].options["state"], gui.tk.DISABLED
        )
        self.assertEqual(
            window.widgets["recovery_password"].options["state"], gui.tk.NORMAL
        )
        self.assertEqual(window.widgets["encrypt"].options["state"], gui.tk.DISABLED)
        self.assertEqual(window.widgets["decrypt"].options["state"], gui.tk.DISABLED)
        self.assertEqual(
            window.widgets["recovery_legacy"].options["state"], gui.tk.DISABLED
        )

    def test_manual_lock_immediately_closes_visible_recovery_phrase(self):
        window = self.window(LoginResult(True, True, True))
        window.controller.state = ProfileSessionState.UNLOCKED
        window.controller.lock = mock.Mock(
            side_effect=lambda _reason: setattr(
                window.controller, "state", ProfileSessionState.LOCKED
            )
        )
        setup = SimpleNamespace(force_close=mock.Mock())
        window.recovery_setup_window = setup
        local_window = SimpleNamespace(force_close=mock.Mock())
        window.local_v2_window = local_window
        legacy_window = SimpleNamespace(close=mock.Mock())
        window.legacy_mok1_window = legacy_window

        window.login_or_lock()

        setup.force_close.assert_called_once_with()
        local_window.force_close.assert_called_once_with()
        legacy_window.close.assert_called_once_with()
        window.controller.lock.assert_called_once()
        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "")

    def test_successful_login_closes_forgotten_password_window(self):
        window = self.window(LoginResult(True, True, True))
        recovery_window = SimpleNamespace(close=mock.Mock())
        window.password_recovery_window = recovery_window

        window.login_or_lock()

        recovery_window.close.assert_called_once_with()

    def test_panic_lock_closes_both_recovery_windows_and_clears_fields(self):
        window = self.window(LoginResult(True, True, True))
        window.controller.state = ProfileSessionState.UNLOCKED
        window.controller.lock = mock.Mock()
        setup = SimpleNamespace(force_close=mock.Mock())
        password_recovery = SimpleNamespace(close=mock.Mock())
        local_window = SimpleNamespace(force_close=mock.Mock())
        window.recovery_setup_window = setup
        window.password_recovery_window = password_recovery
        window.local_v2_window = local_window
        legacy_window = SimpleNamespace(close=mock.Mock())
        window.legacy_mok1_window = legacy_window

        result = window._panic_lock()

        self.assertEqual(result, "break")
        setup.force_close.assert_called_once_with()
        password_recovery.close.assert_called_once_with()
        local_window.force_close.assert_called_once_with()
        legacy_window.close.assert_called_once_with()
        window.controller.lock.assert_called_once()
        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "")

    def test_local_v2_window_is_singleton_and_can_switch_mode(self):
        controller = TransitionController()
        controller.state = ProfileSessionState.UNLOCKED
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = controller
        window.root = object()
        window.locale = gui.ProfileLocale.BULGARIAN
        window.local_folder = FakeVariable("/synthetic")
        window.local_v2_window = None
        window._closed = False
        window._show_notice = mock.Mock()
        created = SimpleNamespace(
            is_open=mock.Mock(return_value=True),
            present=mock.Mock(),
        )
        factory = mock.Mock(return_value=created)
        synthetic_module = SimpleNamespace(
            LocalV2Mode=SimpleNamespace(ENCRYPT="encrypt", DECRYPT="decrypt"),
            LocalV2Window=factory,
        )

        with mock.patch.dict(sys.modules, {"mokosh_v2_local_gui": synthetic_module}):
            window.open_local_encrypt()
            window.open_local_encrypt()
            window.open_local_decrypt()

        factory.assert_called_once()
        self.assertEqual(factory.call_args.kwargs["mode"], "encrypt")
        self.assertEqual(factory.call_args.kwargs["initial_directory"], "/synthetic")
        self.assertEqual(
            [call.args[0] for call in created.present.call_args_list],
            ["encrypt", "decrypt"],
        )
        window._show_notice.assert_not_called()

    def test_sensitive_file_and_recovery_windows_are_mutually_exclusive(self):
        controller = TransitionController()
        controller.state = ProfileSessionState.UNLOCKED
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = controller
        window.root = object()
        window.locale = gui.ProfileLocale.ENGLISH
        window.local_folder = FakeVariable("/synthetic")
        window.local_v2_window = SimpleNamespace(
            is_open=mock.Mock(return_value=True)
        )
        window.recovery_setup_window = None
        window.legacy_mok1_window = None
        window._show_notice = mock.Mock()

        window.open_legacy_decrypt()
        window.open_recovery_setup()

        self.assertEqual(
            window._show_notice.call_args_list,
            [
                mock.call("profile_sensitive_window_busy"),
                mock.call("profile_sensitive_window_busy"),
            ],
        )

        window._show_notice.reset_mock()
        window.local_v2_window = None
        window.recovery_setup_window = SimpleNamespace(
            is_open=mock.Mock(return_value=True)
        )
        window._open_local_v2("encrypt")
        window._show_notice.assert_called_once_with(
            "profile_sensitive_window_busy"
        )

    def test_main_close_waits_for_local_worker_before_root_destroy(self):
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window._closed = False
        window.password = FakeVariable("secret")
        window.nickname = FakeVariable("nickname")
        window._mask_login_secrets = mock.Mock()
        window.first_run_window = None
        window._force_close_recovery_setup = mock.Mock()
        window._force_close_password_recovery = mock.Mock()
        controller = SimpleNamespace(close=mock.Mock())
        window.controller = controller
        root = SimpleNamespace(withdraw=mock.Mock(), destroy=mock.Mock())
        window.root = root
        local_window = SimpleNamespace(
            worker_drained=False,
            force_close=mock.Mock(),
        )
        window.local_v2_window = local_window

        window.close()

        controller.close.assert_called_once_with()
        local_window.force_close.assert_called_once_with()
        root.withdraw.assert_called_once_with()
        root.destroy.assert_not_called()

        window._local_v2_closed()
        root.destroy.assert_called_once_with()

    def test_recovery_windows_are_singleton_and_created_only_after_gate(self):
        controller = TransitionController()
        controller.profile_root = Path("/synthetic/profile")
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = controller
        window.root = object()
        window.locale = gui.ProfileLocale.BULGARIAN
        window.t = lambda key, **_values: key
        window.recovery_setup_window = None
        window.password_recovery_window = None
        setup = SimpleNamespace(is_open=mock.Mock(return_value=True), present=mock.Mock())
        forgot = SimpleNamespace(is_open=mock.Mock(return_value=True), present=mock.Mock())
        setup_factory = mock.Mock(return_value=setup)
        forgot_factory = mock.Mock(return_value=forgot)
        synthetic_module = SimpleNamespace(
            RecoverySetupWindow=setup_factory,
            PasswordRecoveryWindow=forgot_factory,
        )

        with mock.patch.dict(
            sys.modules, {"mokosh_profile_recovery_gui": synthetic_module}
        ):
            window.open_password_recovery()
            window.open_password_recovery()
            controller.state = ProfileSessionState.UNLOCKED
            window.open_recovery_setup()
            window.open_recovery_setup()

        forgot_factory.assert_called_once()
        forgot.present.assert_called_once_with()
        setup_factory.assert_called_once()
        setup.present.assert_called_once_with()

    @staticmethod
    def recovery_gate_window(availability, *, unlocked=False):
        value = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        state = (
            ProfileSessionState.UNLOCKED if unlocked else ProfileSessionState.LOCKED
        )
        value.controller = SimpleNamespace(
            inspection=ProfileInspection(ProfileState.READY, False),
            state=state,
            session=SimpleNamespace(nickname="Synthetic"),
            capabilities=capability_registry(state),
            recovery_state=ProfileRecoveryStateInspection(
                availability,
                "synthetic",
                source_revision=1 if availability is not ProfileRecoveryAvailability.MISSING else None,
                current_revision=1,
            ),
        )
        value.root = FakeRoot()
        value.locale = gui.ProfileLocale.BULGARIAN
        value.password = FakeVariable("")
        value.nickname = FakeVariable("")
        value.local_folder = FakeVariable("")
        value.folder_variable = FakeVariable("")
        value.status_variable = FakeVariable("")
        value.recovery_status_variable = FakeVariable("")
        value.widgets = {
            name: FakeWidget()
            for name in (
                "language_label", "folder_label", "choose_folder",
                "password_label", "nickname_label", "create_profile", "encrypt",
                "decrypt", "clean", "contacts", "contact_crypto", "sandbox",
                "recovery_section", "recovery_main_help", "recovery_setup",
                "recovery_password", "recovery_legacy", "maintenance", "panic_hint", "status",
                "recovery_status", "login", "password_entry", "password_toggle",
                "nickname_entry", "nickname_toggle",
            )
        }
        return value

    def test_forgotten_password_gate_is_current_state_only(self):
        for availability in ProfileRecoveryAvailability:
            with self.subTest(availability=availability.value):
                window = self.recovery_gate_window(availability)
                window.refresh_view()
                expected = (
                    gui.tk.NORMAL
                    if availability is ProfileRecoveryAvailability.CURRENT
                    else gui.tk.DISABLED
                )
                self.assertEqual(
                    window.widgets["recovery_password"].options["state"],
                    expected,
                )

    def test_authenticated_banner_distinguishes_missing_stale_and_invalid(self):
        expected_fragments = {
            ProfileRecoveryAvailability.MISSING: "още не е настроено",
            ProfileRecoveryAvailability.REPLACEMENT_REQUIRED: "вече не работи",
            ProfileRecoveryAvailability.INVALID: "Не може да се потвърди",
        }
        for availability, fragment in expected_fragments.items():
            with self.subTest(availability=availability.value):
                window = self.recovery_gate_window(availability, unlocked=True)
                window.refresh_view()
                self.assertIn(fragment, window.recovery_status_variable.get())
                self.assertEqual(
                    window.widgets["recovery_password"].options["state"],
                    gui.tk.DISABLED,
                )

    def test_replacement_reminder_uses_safe_default_and_can_open_setup(self):
        window = self.recovery_gate_window(
            ProfileRecoveryAvailability.REPLACEMENT_REQUIRED,
            unlocked=True,
        )
        notice = ProfileRecoveryLoginNotice(
            window.controller.recovery_state, True, 1
        )
        window.controller.consume_recovery_login_notice = mock.Mock(
            return_value=notice
        )
        window.open_recovery_setup = mock.Mock()
        with mock.patch.object(gui, "ask_action_decision", return_value=False) as ask:
            window._maybe_show_recovery_reminder()
        window.open_recovery_setup.assert_not_called()
        self.assertEqual(ask.call_args.kwargs["approve_label"], "НАСТРОЙ СЕГА")
        self.assertEqual(
            ask.call_args.kwargs["cancel_label"],
            "НАПОМНИ МИ СЛЕДВАЩИЯ ПЪТ",
        )

        window.controller.consume_recovery_login_notice.return_value = notice
        with mock.patch.object(gui, "ask_action_decision", return_value=True):
            window._maybe_show_recovery_reminder()
        window.open_recovery_setup.assert_called_once_with()

    def test_locked_activity_preserves_credentials_for_explicit_login(self):
        window = self.window(LoginResult(False, True, False))
        session = SimpleNamespace(touch=mock.Mock())
        window.controller.session = session

        window._user_activity(object())

        self.assertEqual(window.password.get(), "Stage 2.46 password")
        self.assertEqual(window.nickname.get(), "Nickname")
        session.touch.assert_not_called()
        window.refresh_view.assert_not_called()

    def test_unlocked_activity_touches_without_clearing_fields(self):
        window = self.window(LoginResult(True, True, True))
        window.controller.state = ProfileSessionState.UNLOCKED
        session = SimpleNamespace(touch=mock.Mock())
        window.controller.session = session

        window._user_activity(object())

        self.assertEqual(window.password.get(), "Stage 2.46 password")
        self.assertEqual(window.nickname.get(), "Nickname")
        session.touch.assert_called_once_with()
        window.refresh_view.assert_not_called()

    def test_activity_triggered_lock_clears_both_fields_and_refreshes(self):
        window = self.window(LoginResult(True, True, True))
        window.controller.state = ProfileSessionState.UNLOCKED

        def lock_during_touch():
            window.controller.state = ProfileSessionState.LOCKED

        session = SimpleNamespace(touch=mock.Mock(side_effect=lock_during_touch))
        window.controller.session = session

        window._user_activity(object())

        self.assertEqual(window.password.get(), "")
        self.assertEqual(window.nickname.get(), "")
        session.touch.assert_called_once_with()
        window.refresh_view.assert_called_once_with()


class ProfileFirstRunWindowLogicTests(unittest.TestCase):
    def test_constructor_returns_after_binding_map_without_sync_activation(self):
        events = []
        window = SimpleNamespace(
            title=lambda _value: events.append("title"),
            geometry=lambda _value: events.append("geometry"),
            minsize=lambda *_values: events.append("minsize"),
            resizable=lambda *_values: events.append("resizable"),
            protocol=lambda *_values: events.append("protocol"),
            bind=lambda *_values, **_options: events.append("bind"),
        )
        application = SimpleNamespace(
            root=object(),
            locale=gui.ProfileLocale.BULGARIAN,
        )

        with (
            mock.patch.object(gui.tk, "Toplevel", return_value=window),
            mock.patch.object(
                gui.tk,
                "StringVar",
                side_effect=(FakeVariable(), FakeVariable(), FakeVariable()),
            ),
            mock.patch.object(
                gui.FirstRunProfileWindow,
                "_build",
                autospec=True,
                side_effect=lambda _dialog: events.append("build"),
            ),
        ):
            dialog = gui.FirstRunProfileWindow(application)

        self.assertEqual(
            events,
            [
                "title",
                "geometry",
                "minsize",
                "resizable",
                "protocol",
                "bind",
                "build",
                "bind",
                "bind",
            ],
        )
        self.assertFalse(dialog._modal_active)
        self.assertIsNone(dialog._activation_after_id)

    @staticmethod
    def modal_fixture(*, viewable=True):
        events = []
        callbacks = []
        visibility = {"value": viewable}
        dialog = gui.FirstRunProfileWindow.__new__(gui.FirstRunProfileWindow)
        dialog._closed = False
        dialog._modal_active = False
        dialog._activation_after_id = None
        window = SimpleNamespace(
            after_idle=lambda callback: (
                callbacks.append(callback),
                events.append("scheduled"),
                f"after-{len(callbacks)}",
            )[-1],
            winfo_exists=lambda: True,
            winfo_viewable=lambda: visibility["value"],
            grab_set=lambda: events.append("grab"),
        )
        dialog.window = window
        dialog.widgets = {
            "nickname_entry": SimpleNamespace(
                focus_set=lambda: events.append("focus")
            )
        }
        return dialog, window, visibility, callbacks, events

    def test_map_schedules_nonblocking_activation_then_focuses_and_grabs(self):
        dialog, window, _visibility, callbacks, events = self.modal_fixture()

        dialog._on_map(SimpleNamespace(widget=object()))
        dialog._on_map(SimpleNamespace(widget=window))
        dialog._on_map(SimpleNamespace(widget=window))

        self.assertEqual(events, ["scheduled"])
        self.assertEqual(len(callbacks), 1)
        self.assertFalse(dialog._modal_active)

        callbacks.pop()()
        dialog._on_map(SimpleNamespace(widget=window))

        self.assertEqual(events, ["scheduled", "focus", "grab"])
        self.assertTrue(dialog._modal_active)
        self.assertEqual(callbacks, [])

    def test_unviewable_callback_returns_and_next_map_can_activate(self):
        dialog, window, visibility, callbacks, events = self.modal_fixture(
            viewable=False
        )

        dialog._on_map(SimpleNamespace(widget=window))
        callbacks.pop()()

        self.assertEqual(events, ["scheduled"])
        self.assertFalse(dialog._modal_active)
        self.assertIsNone(dialog._activation_after_id)

        visibility["value"] = True
        dialog._on_map(SimpleNamespace(widget=window))
        callbacks.pop()()

        self.assertEqual(
            events,
            ["scheduled", "scheduled", "focus", "grab"],
        )
        self.assertTrue(dialog._modal_active)

    def test_close_clears_all_fields_releases_grab_and_is_idempotent(self):
        dialog = gui.FirstRunProfileWindow.__new__(gui.FirstRunProfileWindow)
        dialog._closed = False
        dialog._modal_active = True
        dialog._activation_after_id = None
        dialog.nickname = FakeVariable("Nickname")
        dialog.password = FakeVariable("Stage 2.46 password")
        dialog.confirmation = FakeVariable("Stage 2.46 password")
        dialog.window = SimpleNamespace(
            after_cancel=mock.Mock(),
            grab_release=mock.Mock(),
            destroy=mock.Mock(),
        )
        dialog.application = SimpleNamespace(first_run_window=dialog)

        dialog.close()
        dialog.close()

        self.assertEqual(dialog.nickname.get(), "")
        self.assertEqual(dialog.password.get(), "")
        self.assertEqual(dialog.confirmation.get(), "")
        self.assertIsNone(dialog.application.first_run_window)
        dialog.window.grab_release.assert_called_once_with()
        dialog.window.destroy.assert_called_once_with()
        dialog.window.after_cancel.assert_not_called()
        self.assertFalse(dialog._modal_active)

    def test_close_cancels_pending_activation_and_late_callback_is_inert(self):
        dialog, _window, _visibility, callbacks, events = self.modal_fixture()
        dialog.nickname = FakeVariable("Nickname")
        dialog.password = FakeVariable("Stage 2.46 password")
        dialog.confirmation = FakeVariable("Stage 2.46 password")
        dialog.application = SimpleNamespace(first_run_window=dialog)
        dialog.window.after_cancel = mock.Mock()
        dialog.window.grab_release = mock.Mock()
        dialog.window.destroy = mock.Mock()

        dialog._on_map(SimpleNamespace(widget=dialog.window))
        callback = callbacks.pop()
        dialog.close()
        callback()

        dialog.window.after_cancel.assert_called_once_with("after-1")
        self.assertEqual(events, ["scheduled"])
        self.assertFalse(dialog._modal_active)

    def test_existing_first_run_dialog_is_presented_not_duplicated(self):
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = SimpleNamespace(
            inspection=ProfileInspection(ProfileState.ABSENT, False)
        )
        existing = SimpleNamespace(
            is_open=mock.Mock(return_value=True),
            present=mock.Mock(),
        )
        window.first_run_window = existing

        with mock.patch.object(gui, "FirstRunProfileWindow") as factory:
            window.open_first_run()

        existing.present.assert_called_once_with()
        factory.assert_not_called()

    def test_absent_profile_creates_one_retained_first_run_dialog(self):
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = SimpleNamespace(
            inspection=ProfileInspection(ProfileState.ABSENT, False)
        )
        window.first_run_window = None
        created = object()

        with mock.patch.object(
            gui, "FirstRunProfileWindow", return_value=created
        ) as factory:
            window.open_first_run()

        factory.assert_called_once_with(window)
        self.assertIs(window.first_run_window, created)

    def test_non_absent_profile_never_opens_first_run_dialog(self):
        window = gui.ProfileMainWindow.__new__(gui.ProfileMainWindow)
        window.controller = SimpleNamespace(
            inspection=ProfileInspection(ProfileState.READY, False)
        )
        window.first_run_window = None

        with mock.patch.object(gui, "FirstRunProfileWindow") as factory:
            window.open_first_run()

        factory.assert_not_called()


class ProfileGUIStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "mokosh_profile_gui.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        cls.dispatcher = (ROOT / "mokosh_gui.py").read_text(encoding="utf-8")

    def test_established_geometry_and_two_symmetric_action_rows_are_present(self):
        self.assertIn('PROFILE_GUI_GEOMETRY = "820x680"', self.source)
        for token in (
            '("encrypt", 0, 0',
            '("decrypt", 0, 1',
            '("clean", 0, 2',
            '("contacts", 1, 0',
            '("contact_crypto", 1, 1',
            '("sandbox", 1, 2',
            "ResponsiveGrid(",
            "ResponsivePair(",
            "column_rules=((700, 3), (460, 2), (0, 1))",
            "self.folder_row = ResponsivePair(",
            "self.password_row = ResponsivePair(",
            "self.nickname_row = ResponsivePair(",
            "self.footer_row = ResponsivePair(",
            "breakpoint=760",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        self.assertIn("fit_requested_widths=True", self.source)
        self.assertNotIn('uniform="nickname-controls"', self.source)
        self.assertNotIn("MIN_VISIBLE_NICKNAME_GLYPHS", self.source)
        self.assertNotIn("NICKNAME_ENTRY_HORIZONTAL_INSET", self.source)
        self.assertIn(
            'nickname_toggle.grid(row=0, column=2, sticky="e", padx=5)',
            self.source,
        )
        self.assertIn('secondary_stacked_sticky="e"', self.source)
        self.assertIn("width=22", self.source)
        self.assertIn("create.pack()", self.source)

    def test_explicit_login_and_lock_exist_without_auto_login(self):
        self.assertIn("command=self.login_or_lock", self.source)
        self.assertIn('self.root.bind("<Return>"', self.source)
        tree = self.tree
        init = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
            and any(arg.arg == "auto_first_run_prompt" for arg in node.args.args + node.args.kwonlyargs)
        )
        calls = {
            node.func.attr
            for node in ast.walk(init)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("login_or_lock", calls)

    def test_normal_module_has_no_network_imports(self):
        imported = {
            alias.name.split(".", 1)[0]
            for node in self.tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".", 1)[0]
            for node in self.tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(
            imported.isdisjoint({"socket", "urllib", "requests", "http", "ssl"})
        )

    def test_dispatcher_keeps_maintenance_harness_and_normal_script_route_separate(self):
        self.assertIn('sys.argv[1:] == ["--maintenance"]', self.dispatcher)
        self.assertIn("from mokosh_profile_gui import main as profile_main", self.dispatcher)
        self.assertIn("profile_main()", self.dispatcher)
        self.assertIn("main()", self.dispatcher)

    def test_profile_module_does_not_import_legacy_seed_manager(self):
        self.assertNotIn("seed_manager", self.source)
        top_imports = {
            node.module
            for node in ast.parse(self.dispatcher).body
            if isinstance(node, ast.ImportFrom)
        }
        self.assertNotIn("seed_manager", top_imports)

    def test_profile_recovery_gui_is_lazy_and_state_gated(self):
        top_imports = {
            node.module
            for node in self.tree.body
            if isinstance(node, ast.ImportFrom)
        }
        self.assertNotIn("mokosh_profile_recovery_gui", top_imports)
        for token in (
            "ProfileCapability.RECOVERY_PHRASE",
            "self.controller.state is ProfileSessionState.LOCKED",
            "self._force_close_recovery_setup()",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_panic_lock_close_timeout_and_scroll_are_wired(self):
        for token in (
            "<Control-Shift-L>",
            "configure_resizable_window(",
            "PROFILE_GUI_POLL_MILLISECONDS",
            'orient="vertical"',
            'fill="both"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        self.assertIn(
            'self.root.bind_all("<Control-Shift-L>"',
            self.source,
        )
        ui_source = (ROOT / "mokosh_profile_ui.py").read_text(encoding="utf-8")
        self.assertIn('protocol("WM_DELETE_WINDOW", close)', ui_source)

    def test_first_run_constructor_is_nonblocking_and_entries_are_retained(self):
        first_run = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "FirstRunProfileWindow"
        )
        init = next(
            node
            for node in first_run.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        calls = [
            node
            for node in ast.walk(init)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        ]
        build_line = next(
            node.lineno for node in calls if node.func.attr == "_build"
        )
        map_bind_line = next(
            node.lineno
            for node in calls
            if node.func.attr == "bind"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "<Map>"
        )
        self.assertLess(build_line, map_bind_line)
        constructor_calls = {node.func.attr for node in calls}
        self.assertTrue(
            constructor_calls.isdisjoint(
                {
                    "focus_set",
                    "grab_set",
                    "mainloop",
                    "update",
                    "update_idletasks",
                    "wait_visibility",
                    "wait_window",
                }
            )
        )
        self.assertNotIn("wait_visibility", self.source)
        self.assertIn(
            'self.window.bind("<Map>", self._on_map, add="+")',
            self.source,
        )
        self.assertIn("self.window.after_idle(", self.source)
        self.assertIn("self.window.winfo_viewable()", self.source)
        for widget_name in (
            "nickname_entry",
            "password_entry",
            "confirmation_entry",
        ):
            with self.subTest(widget_name=widget_name):
                self.assertIn(f'self.widgets["{widget_name}"]', self.source)


if __name__ == "__main__":
    unittest.main()
