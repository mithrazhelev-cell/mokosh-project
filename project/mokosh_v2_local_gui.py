"""Tk main-thread adapter for one session-bound local MOKOSH2 operation."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from dataclasses import dataclass, field
from enum import Enum
from tkinter import filedialog
from typing import Any, Callable

from mokosh_profile_localization import ProfileLocale, profile_text
from mokosh_profile_session import SecureProfileSession
from mokosh_profile_ui import (
    ask_action_decision,
    configure_resizable_window,
    create_responsive_label,
    create_scrollable_region,
    show_action_notice,
)
from mokosh_v2_cleanup_authorization import CleanupUserDecision
from mokosh_v2_local_service import (
    LocalV2ErrorCode,
    LocalV2Result,
    LocalV2Service,
    ResidueReview,
    ResidueReviewState,
    propose_decrypted_name,
    propose_encrypted_name,
)
from mokosh_v2_operation_lifecycle import (
    CancellationToken,
    OperationPhase,
    OperationProgressEvent,
)


LOCAL_V2_GUI_GEOMETRY = "760x620"
LOCAL_V2_GUI_MINIMUM = (560, 440)
LOCAL_V2_GUI_POLL_MILLISECONDS = 50


class LocalV2GUIError(RuntimeError):
    """The local GUI adapter cannot preserve its thread/state contract."""


class LocalV2Mode(str, Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class _WorkerKind(str, Enum):
    FILE_OPERATION = "file_operation"
    CLEANUP = "cleanup"


class _WorkerMessageKind(str, Enum):
    PROGRESS = "progress"
    RESULT = "result"
    INTERNAL_FAILURE = "internal_failure"


@dataclass(frozen=True, slots=True)
class _WorkerRequest:
    kind: _WorkerKind
    cancellation: CancellationToken
    mode: LocalV2Mode | None = None
    source_path: str | None = field(default=None, repr=False)
    output_path: str | None = field(default=None, repr=False)
    directory: str | None = field(default=None, repr=False)
    reviewed: ResidueReview | None = field(default=None, repr=False)
    operation_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _WorkerMessage:
    kind: _WorkerMessageKind
    progress: OperationProgressEvent | None = None
    result: LocalV2Result | None = None


def _run_worker(
    service: LocalV2Service,
    request: _WorkerRequest,
    messages: "queue.Queue[_WorkerMessage]",
) -> None:
    """Worker entry point: service calls and Queue writes only; never Tk."""

    try:
        if request.kind is _WorkerKind.FILE_OPERATION:
            if (
                request.mode is None
                or request.source_path is None
                or request.output_path is None
            ):
                raise LocalV2GUIError("file worker request is incomplete")

            def observe(event: OperationProgressEvent) -> None:
                messages.put(
                    _WorkerMessage(
                        _WorkerMessageKind.PROGRESS,
                        progress=event,
                    )
                )

            arguments = {
                "source_path": request.source_path,
                "output_path": request.output_path,
                "cancellation": request.cancellation,
                "observer": observe,
            }
            if request.mode is LocalV2Mode.ENCRYPT:
                result = service.encrypt(**arguments)
            else:
                result = service.decrypt(**arguments)
        else:
            if (
                request.directory is None
                or request.reviewed is None
                or request.operation_id is None
            ):
                raise LocalV2GUIError("cleanup worker request is incomplete")
            request.cancellation.checkpoint()
            result = service.cleanup_reviewed_residue(
                directory=request.directory,
                reviewed=request.reviewed,
                operation_id=request.operation_id,
                decision=CleanupUserDecision.AUTHORIZE_CLEANUP,
                cancellation=request.cancellation,
            )
        messages.put(_WorkerMessage(_WorkerMessageKind.RESULT, result=result))
    except (Exception, KeyboardInterrupt):
        messages.put(_WorkerMessage(_WorkerMessageKind.INTERNAL_FAILURE))


class LocalV2Window:
    """One non-modal local file window with one worker and bounded polling."""

    def __init__(
        self,
        parent: tk.Misc,
        profile_session: SecureProfileSession,
        *,
        locale: ProfileLocale = ProfileLocale.ENGLISH,
        mode: LocalV2Mode = LocalV2Mode.ENCRYPT,
        initial_directory: str = "",
        on_closed: Callable[[], None] | None = None,
    ) -> None:
        if not isinstance(profile_session, SecureProfileSession):
            raise LocalV2GUIError("secure profile session is required")
        if not isinstance(locale, ProfileLocale) or locale is ProfileLocale.PSEUDO:
            raise LocalV2GUIError("user-facing locale is invalid")
        if not isinstance(mode, LocalV2Mode):
            raise LocalV2GUIError("local operation mode is invalid")
        if on_closed is not None and not callable(on_closed):
            raise LocalV2GUIError("on_closed callback must be callable")
        self.parent = parent
        self.profile_session = profile_session
        self.service = LocalV2Service(profile_session)
        self.locale = locale
        self.mode = mode
        self.initial_directory = initial_directory
        self.on_closed = on_closed
        self.widgets: dict[str, tk.Widget] = {}
        self.source = tk.StringVar(value="")
        self.output = tk.StringVar(value="")
        self.status = tk.StringVar(value="")
        self._messages: queue.Queue[_WorkerMessage] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._cancellation: CancellationToken | None = None
        self._pending_result: LocalV2Result | None = None
        self._worker_internal_failure = False
        self._after_id: str | None = None
        self._close_requested = False
        self._destroyed = False
        self._closed_callback_sent = False
        self._review: ResidueReview | None = None
        self._review_directory: str | None = None
        self._run_locked_until_selection_change = False
        self.window = tk.Toplevel(parent)
        configure_resizable_window(
            self.window,
            geometry=LOCAL_V2_GUI_GEOMETRY,
            minimum=LOCAL_V2_GUI_MINIMUM,
            close=self.close,
        )
        self.window.bind("<Escape>", lambda _event: self.close(), add="+")
        self._build()
        self.refresh_text()
        self._schedule_poll()

    def t(self, key: str) -> str:
        return profile_text(self.locale, key)

    @property
    def busy(self) -> bool:
        return self._worker is not None

    @property
    def worker_drained(self) -> bool:
        return self._worker is None

    def _build(self) -> None:
        region = create_scrollable_region(self.window)
        outer = region.content
        intro = create_responsive_label(
            outer,
            text="",
            background="#d9f3f0",
            foreground="#124b47",
            bold=True,
        )
        intro.pack(fill="x", pady=(0, 10))
        self.widgets["intro"] = intro

        safety = create_responsive_label(
            outer,
            text="",
            background="#fff3cd",
            foreground="#5b4000",
            bold=True,
        )
        safety.pack(fill="x", pady=(0, 10))
        self.widgets["safety"] = safety

        for name, variable, command in (
            ("source", self.source, self.choose_source),
            ("output", self.output, self.choose_output),
        ):
            frame = tk.Frame(outer)
            frame.pack(fill="x", pady=5)
            label = tk.Label(frame, anchor="w")
            label.pack(fill="x")
            self.widgets[f"{name}_label"] = label
            row = tk.Frame(frame)
            row.pack(fill="x", pady=(3, 0))
            entry = tk.Entry(row, textvariable=variable, state="readonly")
            entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
            button = tk.Button(row, command=command)
            button.pack(side="right")
            self.widgets[f"{name}_entry"] = entry
            self.widgets[f"choose_{name}"] = button

        status = create_responsive_label(
            outer,
            textvariable=self.status,
            background="#eef2f7",
            foreground="#1d2b3a",
            bold=True,
        )
        status.pack(fill="x", pady=(12, 8))
        self.widgets["status"] = status

        cleanup = tk.Button(outer, command=self.cleanup_reviewed_residue)
        cleanup.pack(fill="x", pady=(0, 8))
        self.widgets["cleanup"] = cleanup

        actions = tk.Frame(outer)
        actions.pack(fill="x", pady=(8, 0))
        run = tk.Button(
            actions,
            command=self.start,
            font=("TkDefaultFont", 11, "bold"),
        )
        run.pack(fill="x", pady=(0, 5))
        cancel = tk.Button(actions, command=self.cancel)
        cancel.pack(fill="x", pady=(0, 5))
        close = tk.Button(actions, command=self.close)
        close.pack(fill="x")
        self.widgets["run"] = run
        self.widgets["cancel"] = cancel
        self.widgets["close"] = close

    def refresh_text(self) -> None:
        title_key = (
            "local_v2_encrypt_title"
            if self.mode is LocalV2Mode.ENCRYPT
            else "local_v2_decrypt_title"
        )
        intro_key = (
            "local_v2_encrypt_intro"
            if self.mode is LocalV2Mode.ENCRYPT
            else "local_v2_decrypt_intro"
        )
        run_key = (
            "local_v2_run_encrypt"
            if self.mode is LocalV2Mode.ENCRYPT
            else "local_v2_run_decrypt"
        )
        self.window.title(self.t(title_key))
        self.widgets["intro"].configure(text=self.t(intro_key))
        self.widgets["safety"].configure(text=self.t("local_v2_keep_originals"))
        self.widgets["source_label"].configure(text=self.t("local_v2_source"))
        self.widgets["output_label"].configure(text=self.t("local_v2_output"))
        self.widgets["choose_source"].configure(
            text=self.t("local_v2_choose_source")
        )
        self.widgets["choose_output"].configure(
            text=self.t("local_v2_choose_output")
        )
        self.widgets["run"].configure(text=self.t(run_key))
        self.widgets["cancel"].configure(
            text=self.t("local_v2_cancel_operation")
        )
        self.widgets["close"].configure(text=self.t("close"))
        self.widgets["cleanup"].configure(text=self.t("local_v2_cleanup"))
        if not self.status.get():
            self.status.set(self.t("local_v2_ready"))
        self._refresh_controls()

    def set_locale(self, locale: ProfileLocale) -> None:
        if not isinstance(locale, ProfileLocale) or locale is ProfileLocale.PSEUDO:
            raise LocalV2GUIError("user-facing locale is invalid")
        self.locale = locale
        if not self._destroyed:
            self.refresh_text()

    def set_mode(self, mode: LocalV2Mode) -> None:
        if not isinstance(mode, LocalV2Mode):
            raise LocalV2GUIError("local operation mode is invalid")
        if self.busy or self._close_requested:
            return
        if mode is not self.mode:
            self.mode = mode
            self.source.set("")
            self.output.set("")
            self.status.set("")
            self._review = None
            self._review_directory = None
            self._run_locked_until_selection_change = False
        self.refresh_text()

    def is_open(self) -> bool:
        if self._destroyed:
            return False
        try:
            return bool(self.window.winfo_exists())
        except tk.TclError:
            return False

    def present(self, mode: LocalV2Mode | None = None) -> None:
        if mode is not None:
            self.set_mode(mode)
        if not self.is_open() or self._close_requested:
            return
        try:
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
        except tk.TclError:
            pass

    def _dialog_initial_directory(self) -> str | None:
        for candidate in (
            self.initial_directory,
            os.path.dirname(self.source.get()) if self.source.get() else "",
        ):
            if candidate and os.path.isdir(candidate):
                return candidate
        return None

    def choose_source(self) -> None:
        if self.busy:
            return
        title_key = (
            "local_v2_choose_encrypt_source_title"
            if self.mode is LocalV2Mode.ENCRYPT
            else "local_v2_choose_decrypt_source_title"
        )
        options: dict[str, Any] = {
            "parent": self.window,
            "title": self.t(title_key),
        }
        initial = self._dialog_initial_directory()
        if initial is not None:
            options["initialdir"] = initial
        selected = filedialog.askopenfilename(**options)
        if selected:
            self.source.set(selected)
            self._review = None
            self._review_directory = None
            self._run_locked_until_selection_change = False
            self.status.set(self.t("local_v2_ready"))
            self._refresh_controls()

    def choose_output(self) -> None:
        if self.busy:
            return
        encrypting = self.mode is LocalV2Mode.ENCRYPT
        options: dict[str, Any] = {
            "parent": self.window,
            "title": self.t(
                "local_v2_choose_encrypt_output_title"
                if encrypting
                else "local_v2_choose_decrypt_output_title"
            ),
            "initialfile": (
                propose_encrypted_name()
                if encrypting
                else propose_decrypted_name()
            ),
            "confirmoverwrite": False,
        }
        if encrypting:
            options["defaultextension"] = ".mok2"
        initial = self._dialog_initial_directory()
        if initial is not None:
            options["initialdir"] = initial
        selected = filedialog.asksaveasfilename(**options)
        if selected:
            self.output.set(selected)
            self._review = None
            self._review_directory = None
            self._run_locked_until_selection_change = False
            self.status.set(self.t("local_v2_ready"))
            self._refresh_controls()

    def _set_status(self, key: str, *, warning: bool = False) -> None:
        self.status.set(self.t(key))
        self.widgets["status"].configure(
            bg="#fff3cd" if warning else "#eef2f7",
            fg="#5b4000" if warning else "#1d2b3a",
        )

    def start(self) -> None:
        if (
            self.busy
            or self._close_requested
            or self._run_locked_until_selection_change
        ):
            return
        source = self.source.get()
        output = self.output.get()
        if not source or not output:
            self._set_status("local_v2_error_selection", warning=True)
            return
        token = CancellationToken()
        request = _WorkerRequest(
            _WorkerKind.FILE_OPERATION,
            token,
            mode=self.mode,
            source_path=source,
            output_path=output,
        )
        self._begin_worker(request)

    def _begin_worker(self, request: _WorkerRequest) -> None:
        if self.busy:
            raise LocalV2GUIError("only one local worker is permitted")
        self._cancellation = request.cancellation
        self._pending_result = None
        self._worker_internal_failure = False
        worker = threading.Thread(
            target=_run_worker,
            args=(self.service, request, self._messages),
            name="mokosh-local-v2-worker",
            daemon=True,
        )
        self._worker = worker
        self._set_status("local_v2_phase_preflight")
        self._refresh_controls()
        try:
            worker.start()
        except Exception:
            self._worker = None
            self._cancellation = None
            self._worker_internal_failure = True
            self._finish_worker()

    def cancel(self) -> None:
        if self._cancellation is not None:
            self._cancellation.cancel()
        self._refresh_controls()

    @staticmethod
    def _phase_key(phase: OperationPhase) -> str:
        return {
            OperationPhase.PREFLIGHT: "local_v2_phase_preflight",
            OperationPhase.SCAN: "local_v2_phase_scan",
            OperationPhase.VERIFY_INPUT: "local_v2_phase_verify_input",
            OperationPhase.ENCRYPT: "local_v2_phase_encrypt",
            OperationPhase.DECRYPT: "local_v2_phase_decrypt",
            OperationPhase.VERIFY_OUTPUT: "local_v2_phase_verify_output",
            OperationPhase.PUBLISH: "local_v2_phase_publish",
            OperationPhase.COMPLETE: "local_v2_phase_complete",
            OperationPhase.CANCELLED: "local_v2_error_cancelled",
            OperationPhase.FAILED: "local_v2_error_generic",
        }[phase]

    def _schedule_poll(self) -> None:
        if self._destroyed or self._after_id is not None:
            return
        try:
            self._after_id = self.window.after(
                LOCAL_V2_GUI_POLL_MILLISECONDS,
                self._poll_worker,
            )
        except tk.TclError:
            self._after_id = None

    def _poll_worker(self) -> None:
        self._after_id = None
        if self._destroyed:
            return
        while True:
            try:
                message = self._messages.get_nowait()
            except queue.Empty:
                break
            if message.kind is _WorkerMessageKind.PROGRESS:
                assert message.progress is not None
                self._set_status(self._phase_key(message.progress.phase))
            elif message.kind is _WorkerMessageKind.RESULT:
                self._pending_result = message.result
            else:
                self._worker_internal_failure = True
        if self._worker is not None and not self._worker.is_alive():
            self._finish_worker()
        if not self._destroyed:
            self._schedule_poll()

    def _finish_worker(self) -> None:
        self._worker = None
        self._cancellation = None
        result = self._pending_result
        self._pending_result = None
        internal = self._worker_internal_failure
        self._worker_internal_failure = False
        if self._close_requested:
            self._destroy()
            return
        if internal or result is None:
            self._set_status("local_v2_error_generic", warning=True)
        else:
            self._handle_result(result)
        self._refresh_controls()

    @staticmethod
    def _result_locks_run(result: LocalV2Result) -> bool:
        return bool(
            result.warning is not None
            or (
                result.failure is not None
                and result.failure.code is LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED
            )
            or (
                result.residue is not None
                and result.residue.state is not ResidueReviewState.CLEAR
            )
        )

    def _handle_result(self, result: LocalV2Result) -> None:
        if self._result_locks_run(result):
            self._run_locked_until_selection_change = True
        self._review = result.residue
        if self.output.get():
            self._review_directory = os.path.dirname(
                os.path.abspath(self.output.get())
            )
        if result.ok:
            if result.warning is not None:
                if result.cleanup_status is None:
                    key = "local_v2_published_warning"
                elif (
                    result.residue is not None
                    and result.residue.state is ResidueReviewState.CLEANABLE
                ):
                    key = "local_v2_residue_cleanable"
                else:
                    key = "local_v2_residue_blocked"
                self._set_status(key, warning=True)
                show_action_notice(
                    self.window,
                    title=self.t(
                        "local_v2_encrypt_title"
                        if self.mode is LocalV2Mode.ENCRYPT
                        else "local_v2_decrypt_title"
                    ),
                    text=self.t(key),
                    close_label=self.t("understand"),
                )
            elif result.cleanup_status is not None:
                self._set_status("local_v2_cleanup_success")
            else:
                self._set_status(
                    "local_v2_encrypt_success"
                    if self.mode is LocalV2Mode.ENCRYPT
                    else "local_v2_decrypt_success"
                )
            return

        assert result.failure is not None
        code = result.failure.code
        key = {
            LocalV2ErrorCode.NOT_MOKOSH2: "local_v2_error_not_v2",
            LocalV2ErrorCode.AUTHENTICATION_FAILED: "local_v2_error_auth",
            LocalV2ErrorCode.OUTPUT_COLLISION: "local_v2_error_collision",
            LocalV2ErrorCode.INVALID_SELECTION: "local_v2_error_selection",
            LocalV2ErrorCode.SESSION_UNAVAILABLE: "local_v2_error_session",
            LocalV2ErrorCode.OPERATION_BUSY: "local_v2_error_busy",
            LocalV2ErrorCode.CANCELLED: "local_v2_error_cancelled",
            LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED: (
                "local_v2_residue_cleanable"
                if result.residue is not None
                and result.residue.state is ResidueReviewState.CLEANABLE
                else "local_v2_residue_blocked"
            ),
            LocalV2ErrorCode.CLEANUP_FAILED: "local_v2_cleanup_failed",
        }.get(code, "local_v2_error_generic")
        self._set_status(key, warning=True)

    def _refresh_controls(self) -> None:
        if self._destroyed:
            return
        ordinary = tk.DISABLED if self.busy or self._close_requested else tk.NORMAL
        run_allowed = (
            not self.busy
            and not self._close_requested
            and not self._run_locked_until_selection_change
        )
        cleanup_allowed = (
            not self.busy
            and not self._close_requested
            and self._review is not None
            and self._review.state is ResidueReviewState.CLEANABLE
            and bool(self._review.cleanup_operation_ids)
            and self._review_directory is not None
        )
        states = {
            "choose_source": ordinary,
            "choose_output": ordinary,
            "run": tk.NORMAL if run_allowed else tk.DISABLED,
            "cancel": tk.NORMAL if self.busy else tk.DISABLED,
            "cleanup": tk.NORMAL if cleanup_allowed else tk.DISABLED,
        }
        primed = None
        if not self._close_requested:
            try:
                focused = self.window.focus_get()
            except tk.TclError:
                focused = None
            focused_name = next(
                (
                    name
                    for name, widget in self.widgets.items()
                    if widget is focused and name in states
                ),
                None,
            )
            if focused_name is not None and states[focused_name] == tk.DISABLED:
                preference = (
                    ("cancel", "close")
                    if self.busy
                    else (
                        "run",
                        "cleanup",
                        "choose_source",
                        "choose_output",
                        "close",
                    )
                )
                for name in preference:
                    widget = self.widgets.get(name)
                    if widget is None or states.get(name, tk.NORMAL) != tk.NORMAL:
                        continue
                    try:
                        if name in states:
                            widget.configure(state=tk.NORMAL)
                        widget.focus_set()
                    except tk.TclError:
                        continue
                    primed = name
                    break
        for name, state in states.items():
            if name != primed:
                self.widgets[name].configure(state=state)

    def cleanup_reviewed_residue(self) -> None:
        if (
            self.busy
            or self._review is None
            or self._review.state is not ResidueReviewState.CLEANABLE
            or not self._review.cleanup_operation_ids
            or self._review_directory is None
        ):
            return
        approved = ask_action_decision(
            self.window,
            title=self.t("local_v2_cleanup"),
            text=self.t("local_v2_cleanup_confirm"),
            approve_label=self.t("local_v2_cleanup_approve"),
            cancel_label=self.t("local_v2_cleanup_preserve"),
        )
        if not approved:
            return
        token = CancellationToken()
        request = _WorkerRequest(
            _WorkerKind.CLEANUP,
            token,
            directory=self._review_directory,
            reviewed=self._review,
            operation_id=self._review.cleanup_operation_ids[0],
        )
        self._begin_worker(request)

    def close(self) -> None:
        if self._destroyed or self._close_requested:
            return
        self._close_requested = True
        if self._cancellation is not None:
            self._cancellation.cancel()
        if self.busy:
            try:
                self.window.withdraw()
            except tk.TclError:
                pass
            self._refresh_controls()
            return
        self._destroy()

    def force_close(self) -> None:
        self.close()

    def _destroy(self) -> None:
        if self._destroyed:
            return
        if self.busy:
            raise LocalV2GUIError("worker must drain before window destruction")
        self._destroyed = True
        pending = self._after_id
        self._after_id = None
        if pending is not None:
            try:
                self.window.after_cancel(pending)
            except tk.TclError:
                pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass
        if not self._closed_callback_sent and self.on_closed is not None:
            self._closed_callback_sent = True
            self.on_closed()


__all__ = [
    "LOCAL_V2_GUI_GEOMETRY",
    "LOCAL_V2_GUI_MINIMUM",
    "LOCAL_V2_GUI_POLL_MILLISECONDS",
    "LocalV2GUIError",
    "LocalV2Mode",
    "LocalV2Window",
]
