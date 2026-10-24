#!/usr/bin/env python3
"""Open one synthetic, non-secret Stage 2.48 normal-GUI visual case."""

from __future__ import annotations

import argparse
import hmac
import sys
from typing import Callable

import tkinter as tk

from mokosh_profile_gui import ProfileMainWindow
from mokosh_profile_localization import ProfileLocale
from mokosh_profile_main_gui_visual_harness import (
    PROFILE_MAIN_GUI_VISUAL_MATRIX,
    prepare_profile_main_gui_visual_case,
)
from mokosh_profile_recovery_state import (
    ProfileRecoveryAvailability,
    ProfileRecoveryStateInspection,
)
from mokosh_profile_session import (
    LoginResult,
    ProfileLockReason,
    ProfileSessionState,
    capability_registry,
)
from mokosh_profile_storage import (
    ProfileInspection,
    ProfileState,
    ProfileValidationError,
    normalize_nickname,
    normalize_password,
)


ENTRY_TRANSITION_CONSTRUCTED_MARKER = "ENTRY_TRANSITION_CONSTRUCTED=PASS"
ENTRY_TRANSITION_MAIN_MAPPED_MARKER = "ENTRY_TRANSITION_MAIN_MAPPED=PASS"
ENTRY_TRANSITION_FIRST_RUN_MAPPED_MARKER = (
    "ENTRY_TRANSITION_FIRST_RUN_MAPPED=PASS"
)


def _entry_transition_map_observer(
    root: tk.Misc,
    application_holder: dict[str, ProfileMainWindow],
    emit: Callable[[str], None],
):
    """Return an idempotent observer for actual root and first-run map events."""
    reported: set[str] = set()

    def observe(event: tk.Event) -> None:
        widget = getattr(event, "widget", None)
        if widget is root and "main" not in reported:
            reported.add("main")
            emit(ENTRY_TRANSITION_MAIN_MAPPED_MARKER)
        application = application_holder.get("application")
        dialog = (
            None if application is None else application.first_run_window
        )
        if (
            dialog is not None
            and widget is dialog.window
            and "first_run" not in reported
        ):
            reported.add("first_run")
            emit(ENTRY_TRANSITION_FIRST_RUN_MAPPED_MARKER)

    return observe


class _SyntheticSession:
    def __init__(
        self,
        state: ProfileSessionState,
        nickname: str = "Synthetic profile",
    ) -> None:
        self.state = state
        self.nickname = nickname

    @property
    def capabilities(self):
        return capability_registry(self.state)

    def touch(self) -> None:
        return None

    def check(self):
        from mokosh_profile_session import SessionCheckResult

        return SessionCheckResult(False)

    def lock(self, _reason: ProfileLockReason) -> None:
        self.state = ProfileSessionState.LOCKED

    def close(self) -> None:
        self.state = ProfileSessionState.CLOSED


class _SyntheticController:
    def __init__(self, state: ProfileSessionState) -> None:
        self.inspection = ProfileInspection(ProfileState.READY, False)
        self.session = _SyntheticSession(state)
        self.profile_root = "/synthetic/not-used"
        self.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.CURRENT,
            "synthetic_current",
            source_revision=1,
            current_revision=1,
        )

    @property
    def state(self):
        return self.session.state

    @property
    def capabilities(self):
        return self.session.capabilities

    def login(self, _nickname: str, _password: str):
        return LoginResult(False, True, False)

    def lock(self, reason: ProfileLockReason = ProfileLockReason.USER) -> None:
        self.session.lock(reason)

    def close(self) -> None:
        self.session.close()


class _SyntheticEntryTransitionController:
    """In-memory first-run/login/lock route with no filesystem operations."""

    def __init__(self) -> None:
        self.inspection = ProfileInspection(ProfileState.ABSENT, False)
        self.session: _SyntheticSession | None = None
        self._nickname = ""
        self._password = ""
        self.recovery_state = ProfileRecoveryStateInspection(
            ProfileRecoveryAvailability.MISSING,
            "synthetic_missing",
        )

    @property
    def state(self):
        if self.session is None:
            return ProfileSessionState.LOCKED
        return self.session.state

    @property
    def capabilities(self):
        return capability_registry(self.state)

    def create(self, nickname: str, password: str, confirmation: str) -> None:
        if password != confirmation:
            raise ProfileValidationError("password confirmation differs")
        exact_nickname = normalize_nickname(nickname)
        exact_password = normalize_password(password)
        self._nickname = exact_nickname
        self._password = exact_password
        self.inspection = ProfileInspection(ProfileState.READY, False)
        self.session = _SyntheticSession(
            ProfileSessionState.LOCKED,
            exact_nickname,
        )

    def refresh(self):
        return self.inspection

    def refresh_recovery_state(self):
        return self.recovery_state

    def login(self, nickname: str, password: str):
        if self.session is None:
            return LoginResult(False, True, False)
        try:
            exact_nickname = normalize_nickname(nickname)
            exact_password = normalize_password(password)
        except ProfileValidationError:
            return LoginResult(False, True, False)
        matched = hmac.compare_digest(
            exact_nickname.encode("utf-8"), self._nickname.encode("utf-8")
        ) and hmac.compare_digest(
            exact_password.encode("utf-8"), self._password.encode("utf-8")
        )
        if not matched:
            return LoginResult(False, True, False)
        self.session.state = ProfileSessionState.UNLOCKED
        return LoginResult(True, True, True)

    def lock(self, reason: ProfileLockReason = ProfileLockReason.USER) -> None:
        if self.session is not None:
            self.session.lock(reason)

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
        self._nickname = ""
        self._password = ""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MOKOSH Stage 2.48 synthetic normal-GUI visual harness"
    )
    route = parser.add_mutually_exclusive_group()
    route.add_argument(
        "--case",
        type=int,
        default=None,
        choices=range(1, len(PROFILE_MAIN_GUI_VISUAL_MATRIX) + 1),
        help="one fixed EN/BG and 100/125/150/200 percent case",
    )
    route.add_argument(
        "--entry-transition",
        action="store_true",
        help="synthetic first-run, login, unlock and manual-lock workflow",
    )
    parser.add_argument(
        "--locale",
        choices=("en", "bg"),
        default="bg",
        help="entry-transition locale (default: bg)",
    )
    parser.add_argument(
        "--scale",
        type=int,
        choices=(100, 125, 150, 200),
        default=100,
        help="entry-transition UI scale percent (default: 100)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.entry_transition:
            locale = ProfileLocale(args.locale)
            scale_percent = args.scale
            controller = _SyntheticEntryTransitionController()
        else:
            case = prepare_profile_main_gui_visual_case(args.case or 1)
            state = ProfileSessionState(case.session_state)
            locale = ProfileLocale(case.locale)
            scale_percent = case.scale_percent
            controller = _SyntheticController(state)
        root = tk.Tk()
        base_scaling = float(root.tk.call("tk", "scaling"))
        root.tk.call("tk", "scaling", base_scaling * scale_percent / 100.0)
        application_holder: dict[str, ProfileMainWindow] = {}
        if args.entry_transition:
            print(
                "Synthetic non-secret entry transition. No profile or operation data "
                "is read or written.\n"
                "Check first-run typing and paste, every eye and remask, "
                "creation-to-locked, login clearing, unlocked status and manual "
                "lock. Shrink and enlarge each window; test minimize, "
                "maximize/restore, move, X, Escape and readable text reflow.\n"
                f"Entry transition: locale={locale.value}, scale={scale_percent}%."
            )
            root.bind_all(
                "<Map>",
                _entry_transition_map_observer(
                    root,
                    application_holder,
                    lambda marker: print(marker, flush=True),
                ),
                add="+",
            )
        else:
            print(
                "Synthetic non-secret case. No profile or operation data is read or written.\n"
                "Check text/reflow, symmetry, focus order, scrolling, resize, "
                "minimize/maximize/restore, masking, both eyes, recovery status, "
                "the locked/unlocked action gates, enabled local V2 actions, "
                "and the visibly separate historical MOK1 recovery action.\n"
                f"Case {case.case_number}: locale={case.locale}, "
                f"scale={case.scale_percent}%, state={case.session_state}."
            )
        application = ProfileMainWindow(
            root,
            controller,
            locale=locale,
            auto_first_run_prompt=args.entry_transition,
        )
        if args.entry_transition:
            application_holder["application"] = application
            print(ENTRY_TRANSITION_CONSTRUCTED_MARKER, flush=True)
        root.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Visual harness stopped safely: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
