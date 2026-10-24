#!/usr/bin/env python3
"""Open one synthetic, non-secret Stage 2.47 recovery visual case."""

from __future__ import annotations

import argparse
import hmac
import sys
from types import SimpleNamespace
from typing import Callable

sys.dont_write_bytecode = True

import tkinter as tk

import mokosh_profile_recovery_gui as recovery_gui
from mokosh_profile_gui import ProfileMainWindow
from mokosh_profile_localization import ProfileLocale, profile_text
from mokosh_profile_recovery import (
    ProfileRecoveryDecision,
    ProfileRecoverySeparationError,
)
from mokosh_profile_recovery_gui import PasswordRecoveryWindow, RecoverySetupWindow
from mokosh_profile_recovery_state import (
    ProfileRecoveryAvailability,
    ProfileRecoveryLoginNotice,
    ProfileRecoveryStateInspection,
)
from mokosh_profile_recovery_visual_harness import (
    PROFILE_RECOVERY_GUI_VISUAL_MATRIX,
    prepare_profile_recovery_gui_visual_case,
)
from mokosh_profile_session import (
    LoginResult,
    ProfileLockReason,
    ProfileSessionState,
    SessionCheckResult,
    capability_registry,
)
from mokosh_profile_storage import (
    ProfileInspection,
    ProfileState,
    ProfileValidationError,
    normalize_nickname,
    normalize_password,
)
from mokosh_profile_ui import ask_action_decision


SYNTHETIC_PROFILE_ROOT = "/synthetic/not-used"
SYNTHETIC_WORDS = (
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actress",
    "actual",
    "adapt",
)
SYNTHETIC_NICKNAME = "RecoveryVisual"
SYNTHETIC_OLD_PASSWORD = "Synthetic-Old-Password!"
SYNTHETIC_NEW_PASSWORD = "Synthetic-New-Password!"
RECOVERY_TRANSITION_CONSTRUCTED_MARKER = (
    "RECOVERY_TRANSITION_CONSTRUCTED=PASS"
)
RECOVERY_TRANSITION_MAIN_MAPPED_MARKER = "RECOVERY_TRANSITION_MAIN_MAPPED=PASS"
RECOVERY_TRANSITION_SETUP_MAPPED_MARKER = (
    "RECOVERY_TRANSITION_SETUP_MAPPED=PASS"
)
RECOVERY_TRANSITION_PASSWORD_MAPPED_MARKER = (
    "RECOVERY_TRANSITION_PASSWORD_MAPPED=PASS"
)
RECOVERY_SETUP_LAYOUT_AUDIT_MARKER = "RECOVERY_SETUP_LAYOUT_AUDIT=PASS"
RECOVERY_SETUP_LAYOUT_PREVIEW_OPEN_MARKER = (
    "RECOVERY_SETUP_LAYOUT_PREVIEW=OPEN"
)
RECOVERY_SETUP_LAYOUT_PREVIEW_CLOSED_MARKER = (
    "RECOVERY_SETUP_LAYOUT_PREVIEW=CLOSED_NO_PROJECT_MUTATION"
)


class _SyntheticRecoverySession:
    def __init__(self, state: ProfileSessionState) -> None:
        self.state = state
        self.nickname = SYNTHETIC_NICKNAME

    @property
    def capabilities(self):
        return capability_registry(self.state)

    def touch(self) -> None:
        return None

    def check(self) -> SessionCheckResult:
        return SessionCheckResult(False)

    def lock(self, _reason: ProfileLockReason) -> None:
        self.state = ProfileSessionState.LOCKED

    def close(self) -> None:
        self.state = ProfileSessionState.CLOSED


class _SyntheticRecoverySetupPlan:
    def __init__(self, controller: "_SyntheticRecoveryController") -> None:
        self.controller = controller
        self.record_exported = False
        self.backup_verified = False
        self.phrase_words = SYNTHETIC_WORDS
        self._phrase_attempts = 0
        self._closed = False

    def export_record(self, selected_parent: str) -> SimpleNamespace:
        if self._closed or selected_parent != "/synthetic/record-parent":
            raise RuntimeError("synthetic record selection is invalid")
        self.record_exported = True
        return SimpleNamespace(durable=True)

    def export_phrase(self, selected_parent: str) -> SimpleNamespace:
        if self._closed or not self.record_exported:
            raise RuntimeError("synthetic setup order is invalid")
        self._phrase_attempts += 1
        if self._phrase_attempts == 1:
            raise ProfileRecoverySeparationError("synthetic same-device refusal")
        if selected_parent != "/synthetic/separate-phrase-parent":
            raise RuntimeError("synthetic phrase selection is invalid")
        self.backup_verified = True
        return SimpleNamespace(durable=True)

    def confirm_paper_backup(self, entered_phrase: object) -> None:
        exact = (
            tuple(entered_phrase)
            if isinstance(entered_phrase, tuple)
            else tuple(str(entered_phrase).split())
        )
        if exact != SYNTHETIC_WORDS:
            raise RuntimeError("synthetic paper phrase differs")
        self.backup_verified = True

    def complete(self, decision: ProfileRecoveryDecision) -> SimpleNamespace:
        if (
            self._closed
            or decision is not ProfileRecoveryDecision.AUTHORIZE
            or not self.record_exported
            or not self.backup_verified
        ):
            raise RuntimeError("synthetic recovery setup is incomplete")
        self.controller.recovery_configured = True
        self.controller.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.CURRENT,
            "synthetic_current",
            source_revision=1,
            current_revision=1,
        )
        return SimpleNamespace(vault_publish_performed=False)

    def close(self) -> None:
        self._closed = True


class _SyntheticPasswordRecoveryPlan:
    def __init__(
        self,
        controller: "_SyntheticRecoveryController",
        new_password: str,
    ) -> None:
        self.controller = controller
        self.new_password = new_password
        self.preview = SimpleNamespace(source_revision=1, target_revision=2)
        self._closed = False

    def publish(self, decision: ProfileRecoveryDecision) -> SimpleNamespace:
        if self._closed or decision is not ProfileRecoveryDecision.AUTHORIZE:
            raise RuntimeError("synthetic recovery publish is invalid")
        self.controller.accepted_password = self.new_password
        self.controller.recovery_configured = False
        self.controller.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.REPLACEMENT_REQUIRED,
            "synthetic_password_replaced",
            source_revision=1,
            current_revision=2,
        )
        self._closed = True
        return SimpleNamespace(profile_locked_after_publish=True)

    def close(self) -> None:
        self._closed = True
        self.new_password = ""


class _SyntheticRecoveryController:
    """Full in-memory enrollment/recovery state; never opens a path."""

    def __init__(self) -> None:
        self.profile_root = SYNTHETIC_PROFILE_ROOT
        self.inspection = ProfileInspection(ProfileState.READY, False)
        self.session = _SyntheticRecoverySession(ProfileSessionState.UNLOCKED)
        self.accepted_password = SYNTHETIC_OLD_PASSWORD
        self.recovery_configured = False
        self.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.MISSING,
            "synthetic_missing",
            current_revision=1,
        )
        self._recovery_login_notice: ProfileRecoveryLoginNotice | None = None

    @property
    def state(self):
        return self.session.state

    @property
    def capabilities(self):
        return self.session.capabilities

    def refresh(self) -> ProfileInspection:
        self.session.close()
        self.session = _SyntheticRecoverySession(ProfileSessionState.LOCKED)
        self._recovery_login_notice = None
        return self.inspection

    def refresh_recovery_state(self) -> ProfileRecoveryStateInspection:
        return self.recovery_state

    def login(self, nickname: str, password: str) -> LoginResult:
        try:
            exact_nickname = normalize_nickname(nickname)
            exact_password = normalize_password(password)
        except ProfileValidationError:
            return LoginResult(False, True, False)
        matched = hmac.compare_digest(
            exact_nickname.encode("utf-8"), SYNTHETIC_NICKNAME.encode("utf-8")
        ) and hmac.compare_digest(
            exact_password.encode("utf-8"), self.accepted_password.encode("utf-8")
        )
        if not matched or self.state is not ProfileSessionState.LOCKED:
            return LoginResult(False, True, False)
        self.session.state = ProfileSessionState.UNLOCKED
        if self.recovery_state.replacement_required:
            reminder_number = min(
                self.recovery_state.replacement_reminders_shown + 1,
                2,
            )
            show = self.recovery_state.replacement_reminders_shown < 2
            self.recovery_state = ProfileRecoveryStateInspection(
                ProfileRecoveryAvailability.REPLACEMENT_REQUIRED,
                "synthetic_password_replaced",
                source_revision=1,
                current_revision=2,
                replacement_reminders_shown=reminder_number,
            )
            self._recovery_login_notice = ProfileRecoveryLoginNotice(
                self.recovery_state,
                show,
                reminder_number if show else 0,
            )
        return LoginResult(True, True, True)

    def consume_recovery_login_notice(self) -> ProfileRecoveryLoginNotice | None:
        notice = self._recovery_login_notice
        self._recovery_login_notice = None
        return notice

    def lock(self, reason: ProfileLockReason = ProfileLockReason.USER) -> None:
        self.session.lock(reason)

    def close(self) -> None:
        self.session.close()
        self.accepted_password = ""

    def begin_setup(
        self,
        profile_root: object,
        current_password: str,
        decision: ProfileRecoveryDecision,
    ) -> _SyntheticRecoverySetupPlan:
        if (
            str(profile_root) != SYNTHETIC_PROFILE_ROOT
            or self.state is not ProfileSessionState.UNLOCKED
            or decision is not ProfileRecoveryDecision.AUTHORIZE
            or not hmac.compare_digest(current_password, self.accepted_password)
        ):
            raise RuntimeError("synthetic setup authorization failed")
        return _SyntheticRecoverySetupPlan(self)

    def _prepare_password(
        self,
        profile_root: object,
        recovery_path: str,
        new_password: str,
        confirmation: str,
        decision: ProfileRecoveryDecision,
    ) -> _SyntheticPasswordRecoveryPlan:
        if (
            str(profile_root) != SYNTHETIC_PROFILE_ROOT
            or self.state is not ProfileSessionState.LOCKED
            or not self.recovery_configured
            or recovery_path != "/synthetic/record.mokr"
            or decision is not ProfileRecoveryDecision.AUTHORIZE
            or new_password != confirmation
        ):
            raise RuntimeError("synthetic password recovery input is invalid")
        return _SyntheticPasswordRecoveryPlan(
            self, normalize_password(new_password)
        )

    def prepare_from_sheet(
        self,
        profile_root: object,
        recovery_path: str,
        phrase_path: str,
        new_password: str,
        confirmation: str,
        decision: ProfileRecoveryDecision,
    ) -> _SyntheticPasswordRecoveryPlan:
        if phrase_path != "/synthetic/phrase.txt":
            raise RuntimeError("synthetic phrase sheet selection is invalid")
        return self._prepare_password(
            profile_root,
            recovery_path,
            new_password,
            confirmation,
            decision,
        )

    def prepare_from_words(
        self,
        profile_root: object,
        recovery_path: str,
        phrase: str,
        new_password: str,
        confirmation: str,
        decision: ProfileRecoveryDecision,
    ) -> _SyntheticPasswordRecoveryPlan:
        if tuple(phrase.split()) != SYNTHETIC_WORDS:
            raise RuntimeError("synthetic recovery phrase differs")
        return self._prepare_password(
            profile_root,
            recovery_path,
            new_password,
            confirmation,
            decision,
        )


def _transition_map_observer(
    root: tk.Misc,
    application_holder: dict[str, ProfileMainWindow],
    emit: Callable[[str], None],
):
    reported: set[str] = set()

    def observe(event: tk.Event) -> None:
        widget = getattr(event, "widget", None)
        if widget is root and "main" not in reported:
            reported.add("main")
            emit(RECOVERY_TRANSITION_MAIN_MAPPED_MARKER)
        application = application_holder.get("application")
        setup = None if application is None else application.recovery_setup_window
        password = (
            None if application is None else application.password_recovery_window
        )
        if (
            setup is not None
            and widget is setup.window
            and "setup" not in reported
        ):
            reported.add("setup")
            emit(RECOVERY_TRANSITION_SETUP_MAPPED_MARKER)
        if (
            password is not None
            and widget is password.window
            and "password" not in reported
        ):
            reported.add("password")
            emit(RECOVERY_TRANSITION_PASSWORD_MAPPED_MARKER)

    return observe


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MOKOSH Stage 2.47 synthetic recovery-GUI visual harness"
    )
    route = parser.add_mutually_exclusive_group()
    route.add_argument(
        "--case",
        type=int,
        default=None,
        choices=range(1, len(PROFILE_RECOVERY_GUI_VISUAL_MATRIX) + 1),
        help="one fixed workflow, EN/BG locale and UI scale",
    )
    route.add_argument(
        "--transition",
        action="store_true",
        help="full synthetic enrollment, recovery, new-login and lock workflow",
    )
    route.add_argument(
        "--setup-layout-audit",
        action="store_true",
        help="real-Tk recovery-setup reflow and responsive-wrap audit",
    )
    parser.add_argument(
        "--locale",
        choices=("en", "bg"),
        default="bg",
        help="transition locale (default: bg)",
    )
    parser.add_argument(
        "--scale",
        type=int,
        choices=(100, 125, 150, 200),
        default=100,
        help="transition UI scale percent (default: 100)",
    )
    return parser


def _no_operation() -> None:
    return None


def _synthetic_confirmation(parent: tk.Misc, locale: ProfileLocale) -> None:
    ask_action_decision(
        parent,
        title=profile_text(locale, "password_recovery_title"),
        text=profile_text(locale, "password_recovery_publish_warning"),
        approve_label=profile_text(locale, "password_recovery_publish"),
        cancel_label=profile_text(locale, "back_without_change"),
    )


def _prepare_setup_case(
    root: tk.Tk,
    locale: ProfileLocale,
) -> RecoverySetupWindow:
    window = RecoverySetupWindow(
        root,
        SYNTHETIC_PROFILE_ROOT,
        locale=locale,
        on_closed=root.destroy,
    )
    window.current_password.set("Synthetic-Masked-Password")
    window._set_phrase(SYNTHETIC_WORDS)
    window.status.set(profile_text(locale, "recovery_record_help"))
    for name in ("prepare", "record", "phrase", "paper", "finish"):
        window.widgets[name].configure(state=tk.NORMAL, command=_no_operation)
    return window


def _centers_aligned(
    first_y: int,
    first_height: int,
    second_y: int,
    second_height: int,
) -> bool:
    return abs(
        (2 * first_y + first_height) - (2 * second_y + second_height)
    ) <= 16


def _layout_box(
    widget: tk.Widget,
    *,
    origin_x: int,
    origin_y: int,
) -> tuple[int, int, int, int]:
    return (
        int(widget.winfo_rootx()) - origin_x,
        int(widget.winfo_rooty()) - origin_y,
        int(widget.winfo_width()),
        int(widget.winfo_height()),
    )


def _wrap_measurement(name: str, label: tk.Label) -> dict[str, int | str | bool]:
    width = int(label.winfo_width())
    requested = int(label.winfo_reqwidth())
    try:
        wraplength = int(float(str(label.cget("wraplength"))))
    except (TypeError, ValueError):
        wraplength = 0
    try:
        padx = int(label.winfo_pixels(label.cget("padx")))
    except (TypeError, ValueError, tk.TclError):
        padx = 0
    return {
        "name": name,
        "width": width,
        "requested": requested,
        "wraplength": wraplength,
        "padx": padx,
        "clearance": width - wraplength,
        "mapped": bool(label.winfo_ismapped()),
    }


def _measure_setup_layout(
    root: tk.Tk,
    application: ProfileMainWindow,
    setup: RecoverySetupWindow,
    *,
    width: int,
) -> dict[str, object]:
    root.geometry(f"{width}x680")
    setup.window.geometry(f"{width}x780")
    for _ in range(2):
        root.update_idletasks()
        root.update()
    container = setup.reauth_row.container
    setup.reauth_row.relayout(
        setup.reauth_row.stacked_for_width(container.winfo_width())
    )
    for _ in range(2):
        root.update_idletasks()
        root.update()

    origin_x = int(container.winfo_rootx())
    origin_y = int(container.winfo_rooty())
    container_width = int(container.winfo_width())
    container_height = int(container.winfo_height())
    entry = setup.widgets["current_password"]
    toggle = setup.widgets["current_password_toggle"]
    prepare = setup.widgets["prepare"]
    entry_box = _layout_box(entry, origin_x=origin_x, origin_y=origin_y)
    toggle_box = _layout_box(toggle, origin_x=origin_x, origin_y=origin_y)
    prepare_box = _layout_box(prepare, origin_x=origin_x, origin_y=origin_y)

    def in_bounds(box: tuple[int, int, int, int]) -> bool:
        x, y, widget_width, widget_height = box
        return (
            x >= 0
            and y >= 0
            and x + widget_width <= container_width
            and y + widget_height <= container_height
        )

    wrap_labels = (
        ("main_recovery_status", application.widgets["recovery_status"]),
        ("setup_phrase_warning", setup.widgets["phrase_warning"]),
        ("setup_phrase_help", setup.widgets["phrase_help"]),
    )
    return {
        "container_width": container_width,
        "container_height": container_height,
        "entry_box": entry_box,
        "entry_requested": int(entry.winfo_reqwidth()),
        "toggle_box": toggle_box,
        "toggle_requested": int(toggle.winfo_reqwidth()),
        "prepare_box": prepare_box,
        "prepare_requested": int(prepare.winfo_reqwidth()),
        "stacked": bool(setup.reauth_row.stacked),
        "entry_eye_row": _centers_aligned(
            entry_box[1], entry_box[3], toggle_box[1], toggle_box[3]
        ),
        "entry_prepare_row": _centers_aligned(
            entry_box[1], entry_box[3], prepare_box[1], prepare_box[3]
        ),
        "in_bounds": all(
            in_bounds(box) for box in (entry_box, toggle_box, prepare_box)
        ),
        "mapped": all(
            bool(widget.winfo_ismapped())
            for widget in (entry, toggle, prepare)
        ),
        "wraps": tuple(
            _wrap_measurement(name, label) for name, label in wrap_labels
        ),
    }


def _require_setup_layout_measurement(
    values: dict[str, object],
    *,
    expected_stacked: bool,
) -> None:
    if not bool(values["mapped"]):
        raise RuntimeError("setup controls are not mapped")
    if not bool(values["in_bounds"]):
        raise RuntimeError("setup controls leave the reauthentication row")
    if bool(values["stacked"]) is not expected_stacked:
        raise RuntimeError("unexpected setup reauthentication layout mode")
    if not bool(values["entry_eye_row"]):
        raise RuntimeError("current-password entry and eye are not one row")

    entry_box = values["entry_box"]
    toggle_box = values["toggle_box"]
    prepare_box = values["prepare_box"]
    if not all(
        isinstance(box, tuple)
        and len(box) == 4
        and all(type(item) is int for item in box)
        for box in (entry_box, toggle_box, prepare_box)
    ):
        raise RuntimeError("invalid setup geometry measurement")
    entry_x, entry_y, entry_width, _entry_height = entry_box
    toggle_x, _toggle_y, toggle_width, _toggle_height = toggle_box
    prepare_x, prepare_y, prepare_width, _prepare_height = prepare_box
    if entry_width < int(values["entry_requested"]):
        raise RuntimeError("current-password entry is narrower than requested")
    if toggle_width < int(values["toggle_requested"]):
        raise RuntimeError("current-password eye is clipped")
    if abs(prepare_width - int(values["prepare_requested"])) > 4:
        raise RuntimeError("prepare-recovery button is clipped or stretched")
    if toggle_x < entry_x + entry_width:
        raise RuntimeError("current-password eye overlaps the entry")

    if expected_stacked:
        if bool(values["entry_prepare_row"]) or prepare_y <= entry_y:
            raise RuntimeError("prepare-recovery button did not move below")
        right_gap = int(values["container_width"]) - (prepare_x + prepare_width)
        if right_gap < 0 or right_gap > 16:
            raise RuntimeError("stacked prepare-recovery button is not right aligned")
    elif not bool(values["entry_prepare_row"]):
        raise RuntimeError("prepare-recovery button left the default row")

    wraps = values["wraps"]
    if not isinstance(wraps, tuple) or len(wraps) != 3:
        raise RuntimeError("responsive warning inventory drift")
    for wrap in wraps:
        if not isinstance(wrap, dict):
            raise RuntimeError("invalid responsive warning measurement")
        if not bool(wrap["mapped"]):
            raise RuntimeError(f"responsive warning is not mapped: {wrap['name']}")
        label_width = int(wrap["width"])
        wraplength = int(wrap["wraplength"])
        padx = int(wrap["padx"])
        if label_width <= 1 or wraplength < 180:
            raise RuntimeError(f"responsive warning has invalid width: {wrap['name']}")
        if wraplength > label_width - (2 * padx):
            raise RuntimeError(f"responsive warning reaches its wall: {wrap['name']}")


def _emit_setup_layout_measurement(
    label: str,
    values: dict[str, object],
) -> None:
    entry = values["entry_box"]
    toggle = values["toggle_box"]
    prepare = values["prepare_box"]
    wraps = values["wraps"]
    wrap_text = ",".join(
        f"{item['name']}:{item['width']}/{item['wraplength']}/"
        f"{item['clearance']}"
        for item in wraps
    )
    print(
        f"RECOVERY_SETUP_LAYOUT_{label}="
        f"container={values['container_width']}x{values['container_height']} "
        f"entry={entry[2]}/{values['entry_requested']}@{entry[0]},{entry[1]} "
        f"eye={toggle[2]}/{values['toggle_requested']}@{toggle[0]},{toggle[1]} "
        f"prepare={prepare[2]}/{values['prepare_requested']}@{prepare[0]},{prepare[1]} "
        f"stacked={values['stacked']} entry_eye_row={values['entry_eye_row']} "
        f"entry_prepare_row={values['entry_prepare_row']} "
        f"in_bounds={values['in_bounds']} wraps={wrap_text}",
        flush=True,
    )


def _run_setup_layout_audit(
    root: tk.Tk,
    locale: ProfileLocale,
    scale_percent: int,
) -> None:
    controller = _SyntheticRecoveryController()
    _install_synthetic_transition_services(controller)
    application = ProfileMainWindow(
        root,
        controller,
        locale=locale,
        auto_first_run_prompt=False,
    )
    for name in ("choose_folder", "decrypt", "maintenance"):
        application.widgets[name].configure(command=_no_operation)
    setup = _prepare_setup_case(root, locale)
    setup.window.title("MOKOSH — ИЗОЛИРАН R7 SETUP REFLOW КАНДИДАТ")
    for label, width, expected_stacked in (
        ("BG100_DEFAULT", 900, False),
        ("BG100_WIDE", 1100, False),
        ("BG100_MINIMUM", 620, True),
    ):
        values = _measure_setup_layout(
            root,
            application,
            setup,
            width=width,
        )
        _emit_setup_layout_measurement(label, values)
        _require_setup_layout_measurement(
            values,
            expected_stacked=expected_stacked,
        )
    _measure_setup_layout(root, application, setup, width=620)
    root.withdraw()
    setup.window.deiconify()
    setup.window.lift()
    print(RECOVERY_SETUP_LAYOUT_AUDIT_MARKER, flush=True)
    print(
        f"{RECOVERY_SETUP_LAYOUT_PREVIEW_OPEN_MARKER} — проверете тесния "
        "прозорец: полето и окото остават на един ред; само бутонът "
        "„ПОДГОТВИ ВЪЗСТАНОВЯВАНЕ“ е отдолу вдясно; жълтият текст има "
        "видим вътрешен отстъп. Няма файлова или криптографска операция.",
        flush=True,
    )


def _prepare_password_case(
    root: tk.Tk,
    locale: ProfileLocale,
) -> PasswordRecoveryWindow:
    window = PasswordRecoveryWindow(
        root,
        SYNTHETIC_PROFILE_ROOT,
        locale=locale,
        on_closed=root.destroy,
    )
    window.record_path.set("Synthetic .mokr selection")
    window.sheet_path.set("Synthetic separate-sheet selection")
    window.new_password.set("Synthetic-Masked-New-Password")
    window.confirmation.set("Synthetic-Masked-New-Password")
    window.status.set(profile_text(locale, "password_recovery_preview_help"))
    window.widgets["choose_record"].configure(command=_no_operation)
    window.widgets["choose_sheet"].configure(command=_no_operation)
    window.widgets["preview"].configure(command=_no_operation)
    window.widgets["publish"].configure(
        state=tk.NORMAL,
        command=lambda: _synthetic_confirmation(window.window, locale),
    )
    return window


def _install_synthetic_transition_services(
    controller: _SyntheticRecoveryController,
) -> None:
    directory_choices = iter(
        (
            "/synthetic/record-parent",
            "/synthetic/same-device-parent",
            "/synthetic/separate-phrase-parent",
        )
    )
    record_choices = iter(
        ("/synthetic/wrong-record.mokr", "/synthetic/record.mokr")
    )
    phrase_choices = iter(
        (
            "/synthetic/phrase.txt",
            "/synthetic/wrong-phrase.txt",
            "/synthetic/phrase.txt",
        )
    )

    def choose_directory(**_options: object) -> str:
        return next(directory_choices, "/synthetic/separate-phrase-parent")

    def choose_file(**options: object) -> str:
        filetypes = repr(options.get("filetypes", ()))
        if "*.mokr" in filetypes:
            selected = next(record_choices, "/synthetic/record.mokr")
        else:
            selected = next(phrase_choices, "/synthetic/phrase.txt")
        print(f"SYNTHETIC_PICK={selected}", flush=True)
        return selected

    recovery_gui.begin_profile_recovery_setup = controller.begin_setup
    recovery_gui.prepare_profile_password_recovery_from_sheet = (
        controller.prepare_from_sheet
    )
    recovery_gui.prepare_profile_password_recovery_from_words = (
        controller.prepare_from_words
    )
    recovery_gui.filedialog.askdirectory = choose_directory
    recovery_gui.filedialog.askopenfilename = choose_file


def _run_transition(
    root: tk.Tk,
    locale: ProfileLocale,
    scale_percent: int,
) -> None:
    controller = _SyntheticRecoveryController()
    _install_synthetic_transition_services(controller)
    holder: dict[str, ProfileMainWindow] = {}
    root.bind_all(
        "<Map>",
        _transition_map_observer(
            root,
            holder,
            lambda marker: print(marker, flush=True),
        ),
        add="+",
    )
    print(
        "Synthetic recovery transition; no filesystem or cryptographic operation "
        "is performed.\n"
        f"Nickname: {SYNTHETIC_NICKNAME}\n"
        f"Current/setup password: {SYNTHETIC_OLD_PASSWORD}\n"
        f"New password: {SYNTHETIC_NEW_PASSWORD}\n"
        "1) Confirm Forgot password is disabled while unlocked. Open Set up "
        "recovery and test Cancel/reopen. Confirm the current-password eye is "
        "visible; reveal and re-mask it before Prepare. On every main, child "
        "and popup window test minimize, maximize/restore, move, narrow resize, "
        "reflow, scrolling, X and Escape without losing state.\n"
        "2) Save the synthetic .mokr. The first sheet attempt must show the "
        "same-device refusal; the second must succeed. Paper confirmation is "
        "an optional alternative using all 25 displayed sample words. Finish.\n"
        "3) Manually lock. Set up recovery must disable and Forgot password "
        "must enable. The first .mokr choice is deliberately wrong; verify the "
        "plain safe-stop message. Choose .mokr again, then the sheet; its second "
        "choice is deliberately wrong. Verify the same anti-oracle message, "
        "choose the sheet once more, and enter the new password twice.\n"
        "4) Also verify a mismatched repeated password gets its own exact message. "
        "Then verify the read-only preview and approve the final confirmation, "
        "then confirm the main window remains locked.\n"
        "5) Try the old password (must fail), then the new password (must "
        "unlock and clear both fields). Confirm the replacement banner and one "
        "reminder, and that Forgot password stays disabled until a new recovery "
        "set is completed. Then manually lock once more.\n"
        f"Transition: locale={locale.value}, scale={scale_percent}%.",
        flush=True,
    )
    application = ProfileMainWindow(
        root,
        controller,
        locale=locale,
        auto_first_run_prompt=False,
    )
    for name in ("choose_folder", "decrypt", "maintenance"):
        application.widgets[name].configure(command=_no_operation)
    holder["application"] = application
    print(RECOVERY_TRANSITION_CONSTRUCTED_MARKER, flush=True)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.transition or args.setup_layout_audit:
            locale = ProfileLocale(args.locale)
            scale_percent = args.scale
            case = None
        else:
            case = prepare_profile_recovery_gui_visual_case(args.case or 1)
            locale = ProfileLocale(case.locale)
            scale_percent = case.scale_percent
            print(
                "Synthetic non-secret recovery case. No profile, recovery file, "
                "phrase, or operation data is read or written.\n"
                "Check explanatory text, scrolling, focus order, masking, phrase "
                "layout, all password eyes, localized action labels, separate-"
                "storage warning, action order, text reflow and all window "
                "controls.\n"
                f"Case {case.case_number}: workflow={case.workflow}, "
                f"locale={case.locale}, scale={case.scale_percent}%.",
                flush=True,
            )
        root = tk.Tk()
        base_scaling = float(root.tk.call("tk", "scaling"))
        root.tk.call("tk", "scaling", base_scaling * scale_percent / 100.0)
        if args.setup_layout_audit:
            _run_setup_layout_audit(root, locale, scale_percent)
        elif args.transition:
            _run_transition(root, locale, scale_percent)
        elif case is not None and case.workflow == "setup":
            root.withdraw()
            _prepare_setup_case(root, locale)
        else:
            root.withdraw()
            _prepare_password_case(root, locale)
        root.mainloop()
        if args.setup_layout_audit:
            print(RECOVERY_SETUP_LAYOUT_PREVIEW_CLOSED_MARKER, flush=True)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"Recovery visual harness stopped safely: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
