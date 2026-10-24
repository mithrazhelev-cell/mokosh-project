import ast
import inspect
import queue
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import mokosh_v2_local_gui as gui
from mokosh_profile_localization import ProfileLocale
from mokosh_v2_cleanup_executor import CleanupExecutionStatus
from mokosh_v2_local_service import (
    LocalV2ErrorCode,
    LocalV2Result,
    LocalV2WarningCode,
    ResidueReview,
    ResidueReviewState,
    SafeLocalV2Failure,
    SafeLocalV2Warning,
)
from mokosh_v2_operation_lifecycle import (
    CancellationToken,
    OperationKind,
    OperationPhase,
    OperationProgressEvent,
    ProgressState,
)
from mokosh_v2_operation_journal import journal_name_for, temporary_name_for
from mokosh_v2_reconciliation import (
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
)
from mokosh_v2_reconciliation_evidence import build_reconciliation_evidence


ROOT = Path(__file__).resolve().parents[1]


class FakeVariable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWidget:
    def __init__(self, *, name="", window=None, events=None):
        self.name = name
        self.window = window
        self.events = events
        self.options = {}

    def configure(self, **values):
        if self.events is not None and "state" in values:
            self.events.append(("state", self.name, values["state"]))
        self.options.update(values)

    def focus_set(self):
        if self.events is not None:
            self.events.append(("focus", self.name))
        if self.window is not None:
            self.window.focused = self


class FakeWindow:
    def __init__(self):
        self.withdrawn = False
        self.destroyed = False
        self.cancelled = []
        self.focused = None
        self.events = []

    def withdraw(self):
        self.withdrawn = True

    def destroy(self):
        self.destroyed = True

    def after_cancel(self, value):
        self.cancelled.append(value)

    def focus_get(self):
        return self.focused


class FakeThread:
    def __init__(self, alive=True):
        self.alive = alive

    def is_alive(self):
        return self.alive


def clear_review():
    return ResidueReview(ResidueReviewState.CLEAR, 0, 0, (), True, None)


def evidence_for(status):
    operation_id = "a" * 32
    return build_reconciliation_evidence(
        ReconciliationReport(
            (
                ReconciliationFinding(
                    status,
                    operation_id,
                    journal_name_for(operation_id),
                    temporary_name_for(operation_id),
                ),
            ),
            2,
            11,
            12,
        )
    )


def cleanable_review():
    return ResidueReview(
        ResidueReviewState.CLEANABLE,
        1,
        0,
        ("a" * 32,),
        True,
        evidence_for(ReconciliationStatus.RECORDED_INODE_MATCH),
    )


def blocked_review():
    return ResidueReview(
        ResidueReviewState.BLOCKED,
        1,
        1,
        (),
        True,
        evidence_for(ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED),
    )


class WorkerBoundaryTests(unittest.TestCase):
    def test_file_worker_emits_only_safe_progress_and_result_messages(self):
        result = LocalV2Result(ok=True, residue=clear_review())
        calls = []

        class Service:
            def encrypt(self, **kwargs):
                calls.append((threading.get_ident(), kwargs))
                kwargs["observer"](
                    OperationProgressEvent(
                        OperationKind.ENCRYPT,
                        OperationPhase.ENCRYPT,
                        ProgressState.STARTED,
                        1,
                    )
                )
                return result

        messages = queue.Queue()
        token = CancellationToken()
        request = gui._WorkerRequest(
            gui._WorkerKind.FILE_OPERATION,
            token,
            mode=gui.LocalV2Mode.ENCRYPT,
            source_path="/private/source-name",
            output_path="/private/output-name.mok2",
        )
        gui._run_worker(Service(), request, messages)
        first = messages.get_nowait()
        second = messages.get_nowait()
        self.assertIs(first.kind, gui._WorkerMessageKind.PROGRESS)
        self.assertIs(second.kind, gui._WorkerMessageKind.RESULT)
        self.assertIs(second.result, result)
        self.assertIs(calls[0][1]["cancellation"], token)
        self.assertNotIn("source-name", repr(request))
        self.assertNotIn("output-name", repr(request))

    def test_worker_converts_unexpected_exception_without_exception_text(self):
        class Service:
            def decrypt(self, **_kwargs):
                raise RuntimeError("private path and secret text")

        messages = queue.Queue()
        request = gui._WorkerRequest(
            gui._WorkerKind.FILE_OPERATION,
            CancellationToken(),
            mode=gui.LocalV2Mode.DECRYPT,
            source_path="/private/source",
            output_path="/private/output",
        )
        gui._run_worker(Service(), request, messages)
        message = messages.get_nowait()
        self.assertIs(message.kind, gui._WorkerMessageKind.INTERNAL_FAILURE)
        self.assertNotIn("private", repr(message))
        self.assertNotIn("secret", repr(message))

    def test_cleanup_worker_passes_the_same_cancellation_token_to_service(self):
        result = LocalV2Result(ok=True, residue=clear_review())
        calls = []

        class Service:
            def cleanup_reviewed_residue(self, **kwargs):
                calls.append(kwargs)
                return result

        token = CancellationToken()
        messages = queue.Queue()
        request = gui._WorkerRequest(
            gui._WorkerKind.CLEANUP,
            token,
            directory="/private/reviewed",
            reviewed=cleanable_review(),
            operation_id="a" * 32,
        )
        gui._run_worker(Service(), request, messages)
        message = messages.get_nowait()
        self.assertIs(message.kind, gui._WorkerMessageKind.RESULT)
        self.assertIs(message.result, result)
        self.assertIs(calls[0]["cancellation"], token)
        self.assertIs(
            calls[0]["decision"],
            gui.CleanupUserDecision.AUTHORIZE_CLEANUP,
        )

    def test_worker_function_contains_no_tk_access(self):
        source = inspect.getsource(gui._run_worker)
        for forbidden in (
            "tk.",
            "filedialog",
            "show_action_notice",
            "ask_action_decision",
            ".window",
            ".widgets",
            "StringVar",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


class WindowStateTests(unittest.TestCase):
    @staticmethod
    def bare_window(*, worker=None):
        value = gui.LocalV2Window.__new__(gui.LocalV2Window)
        value._worker = worker
        value._cancellation = CancellationToken()
        value._pending_result = None
        value._worker_internal_failure = False
        value._after_id = None
        value._close_requested = False
        value._destroyed = False
        value._closed_callback_sent = False
        value._review = None
        value._review_directory = None
        value._run_locked_until_selection_change = False
        value.on_closed = Mock()
        value.window = FakeWindow()
        value.widgets = {
            name: FakeWidget(
                name=name,
                window=value.window,
                events=value.window.events,
            )
            for name in (
                "choose_source",
                "choose_output",
                "run",
                "cancel",
                "cleanup",
                "close",
                "status",
            )
        }
        value.source = FakeVariable("")
        value.output = FakeVariable("")
        value.status = FakeVariable("")
        value.mode = gui.LocalV2Mode.ENCRYPT
        value.locale = ProfileLocale.ENGLISH
        value.initial_directory = ""
        value.t = lambda key: key
        return value

    def test_close_cancels_hides_and_defers_destroy_until_worker_drains(self):
        window = self.bare_window(worker=FakeThread(alive=True))
        token = window._cancellation
        window.close()
        self.assertTrue(token.cancelled)
        self.assertTrue(window._close_requested)
        self.assertTrue(window.window.withdrawn)
        self.assertFalse(window.window.destroyed)

        window._worker = None
        window._finish_worker()
        self.assertTrue(window.window.destroyed)
        window.on_closed.assert_called_once_with()

    def test_idle_close_destroys_once_and_notifies_once(self):
        window = self.bare_window(worker=None)
        window.close()
        window.close()
        self.assertTrue(window.window.destroyed)
        window.on_closed.assert_called_once_with()

    def test_second_worker_is_refused_before_thread_creation(self):
        window = self.bare_window(worker=FakeThread(alive=True))
        request = gui._WorkerRequest(
            gui._WorkerKind.FILE_OPERATION,
            CancellationToken(),
            mode=gui.LocalV2Mode.ENCRYPT,
            source_path="source",
            output_path="output.mok2",
        )
        with self.assertRaises(gui.LocalV2GUIError):
            window._begin_worker(request)

    def test_refresh_moves_focus_before_disabling_the_focused_action(self):
        window = self.bare_window(worker=FakeThread(alive=True))
        window.window.focused = window.widgets["run"]

        window._refresh_controls()

        self.assertIs(window.window.focused, window.widgets["cancel"])
        self.assertLess(
            window.window.events.index(("focus", "cancel")),
            window.window.events.index(("state", "run", gui.tk.DISABLED)),
        )

        window._worker = None
        window.window.events.clear()
        window.window.focused = window.widgets["cancel"]

        window._refresh_controls()

        self.assertIs(window.window.focused, window.widgets["run"])
        self.assertLess(
            window.window.events.index(("focus", "run")),
            window.window.events.index(("state", "cancel", gui.tk.DISABLED)),
        )

    def test_cleanup_requires_explicit_approval_and_uses_one_reviewed_id(self):
        window = self.bare_window(worker=None)
        window._review = cleanable_review()
        window._review_directory = "/private/reviewed"
        window._begin_worker = Mock()

        with patch.object(gui, "ask_action_decision", return_value=False):
            window.cleanup_reviewed_residue()
        window._begin_worker.assert_not_called()

        with patch.object(gui, "ask_action_decision", return_value=True):
            window.cleanup_reviewed_residue()
        request = window._begin_worker.call_args.args[0]
        self.assertIs(request.kind, gui._WorkerKind.CLEANUP)
        self.assertEqual(request.operation_id, "a" * 32)
        self.assertIs(request.reviewed, window._review)
        self.assertNotIn("/private/reviewed", repr(request))

    def test_published_warning_says_not_to_retry_and_never_shows_path(self):
        window = self.bare_window(worker=None)
        window.output.set("/private/sensitive/output.mok2")
        warning = SafeLocalV2Warning(
            LocalV2WarningCode.PUBLISHED_REVIEW_REQUIRED,
            "local_v2.warning.published_review_required",
        )
        result = LocalV2Result(ok=True, warning=warning, residue=clear_review())
        real_text = gui.profile_text
        window.t = lambda key: real_text("en", key)
        with patch.object(gui, "show_action_notice") as notice:
            window._handle_result(result)
        displayed = notice.call_args.kwargs["text"]
        self.assertIn("Do not retry", displayed)
        self.assertNotIn("sensitive", displayed)
        window._refresh_controls()
        self.assertTrue(window._run_locked_until_selection_change)
        self.assertEqual(window.widgets["run"].options["state"], gui.tk.DISABLED)

    def test_cleanable_and_blocked_residue_lock_run_fail_closed(self):
        failure = SafeLocalV2Failure(
            LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
            False,
            "local_v2.error.residue_review_required",
        )
        for review in (cleanable_review(), blocked_review()):
            with self.subTest(state=review.state):
                window = self.bare_window(worker=None)
                window.source.set("/private/source.bin")
                window.output.set("/private/new.mok2")
                window._handle_result(
                    LocalV2Result(ok=False, failure=failure, residue=review)
                )
                window._refresh_controls()
                self.assertTrue(window._run_locked_until_selection_change)
                self.assertEqual(
                    window.widgets["run"].options["state"],
                    gui.tk.DISABLED,
                )
                window._begin_worker = Mock()
                window.start()
                window._begin_worker.assert_not_called()

    def test_preserve_keeps_run_locked(self):
        window = self.bare_window(worker=None)
        window.source.set("/private/source.bin")
        window.output.set("/private/new.mok2")
        failure = SafeLocalV2Failure(
            LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
            False,
            "local_v2.error.residue_review_required",
        )
        window._handle_result(
            LocalV2Result(
                ok=False,
                failure=failure,
                residue=cleanable_review(),
            )
        )
        with patch.object(gui, "ask_action_decision", return_value=False):
            window.cleanup_reviewed_residue()
        window._refresh_controls()
        self.assertTrue(window._run_locked_until_selection_change)
        self.assertEqual(window.widgets["run"].options["state"], gui.tk.DISABLED)

    def test_explicit_new_selection_clears_run_lock(self):
        source_window = self.bare_window(worker=None)
        source_window._run_locked_until_selection_change = True
        with patch.object(
            gui.filedialog,
            "askopenfilename",
            return_value="/synthetic/new-source.bin",
        ):
            source_window.choose_source()
        self.assertFalse(source_window._run_locked_until_selection_change)
        self.assertEqual(
            source_window.widgets["run"].options["state"],
            gui.tk.NORMAL,
        )

        output_window = self.bare_window(worker=None)
        output_window._run_locked_until_selection_change = True
        with patch.object(
            gui.filedialog,
            "asksaveasfilename",
            return_value="/synthetic/new-output.mok2",
        ):
            output_window.choose_output()
        self.assertFalse(output_window._run_locked_until_selection_change)
        self.assertEqual(
            output_window.widgets["run"].options["state"],
            gui.tk.NORMAL,
        )

    def test_residue_failure_enables_cleanup_only_for_cleanable_review(self):
        window = self.bare_window(worker=None)
        window.output.set("/private/new.mok2")
        failure = SafeLocalV2Failure(
            LocalV2ErrorCode.RESIDUE_REVIEW_REQUIRED,
            False,
            "local_v2.error.residue_review_required",
        )
        window._handle_result(
            LocalV2Result(
                ok=False,
                failure=failure,
                residue=cleanable_review(),
            )
        )
        window._refresh_controls()
        self.assertEqual(window.widgets["cleanup"].options["state"], gui.tk.NORMAL)

    def test_cleanup_partial_result_remains_success_with_review_warning(self):
        warning = SafeLocalV2Warning(
            LocalV2WarningCode.CLEANUP_REVIEW_REQUIRED,
            "local_v2.warning.cleanup_review_required",
        )
        result = LocalV2Result(
            ok=True,
            warning=warning,
            residue=ResidueReview(
                ResidueReviewState.BLOCKED,
                1,
                1,
                (),
                True,
                evidence_for(
                    ReconciliationStatus.TEMPORARY_LINK_COUNT_CHANGED
                ),
            ),
            cleanup_status=CleanupExecutionStatus.TEMPORARY_REMOVED_JOURNAL_RETAINED,
        )
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.warning)

    def test_cleanup_warning_keeps_remaining_exact_residue_cleanable(self):
        window = self.bare_window(worker=None)
        window.output.set("/private/new.mok2")
        warning = SafeLocalV2Warning(
            LocalV2WarningCode.CLEANUP_REVIEW_REQUIRED,
            "local_v2.warning.cleanup_review_required",
        )
        result = LocalV2Result(
            ok=True,
            warning=warning,
            residue=cleanable_review(),
            cleanup_status=CleanupExecutionStatus.COMPLETED,
        )
        real_text = gui.profile_text
        window.t = lambda key: real_text("en", key)
        with patch.object(gui, "show_action_notice") as notice:
            window._handle_result(result)
        self.assertIn("exact inode identity", notice.call_args.kwargs["text"])
        window._refresh_controls()
        self.assertEqual(
            window.widgets["cleanup"].options["state"],
            gui.tk.NORMAL,
        )


class LocalV2GUIStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "mokosh_v2_local_gui.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_exactly_one_worker_thread_creation_site_uses_queue_target(self):
        calls = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Thread"
        ]
        self.assertEqual(len(calls), 1)
        rendered = ast.unparse(calls[0])
        self.assertIn("target=_run_worker", rendered)
        self.assertIn("daemon=True", rendered)
        self.assertIn("queue.Queue", self.source)
        self.assertIn("get_nowait", self.source)
        self.assertIn("window.after(", self.source)

    def test_scope_has_no_network_logging_clipboard_or_raw_exception_rendering(self):
        for forbidden in (
            "socket",
            "requests",
            "urllib",
            "logging",
            "clipboard",
            "traceback",
            "str(exc)",
            "repr(exc)",
            "print(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.source)

    def test_close_contract_cancels_before_destroy_and_checks_worker(self):
        close_source = inspect.getsource(gui.LocalV2Window.close)
        destroy_source = inspect.getsource(gui.LocalV2Window._destroy)
        self.assertIn("self._cancellation.cancel()", close_source)
        self.assertIn("self.window.withdraw()", close_source)
        self.assertIn("if self.busy", destroy_source)
        self.assertIn("worker must drain", destroy_source)


if __name__ == "__main__":
    unittest.main()
