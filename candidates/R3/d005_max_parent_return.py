"""Isolated candidate for the observed maximized-parent X11 mismatch.

Request application-window activation once; keep UI_R3/R2 control focus,
decisions, geometry, workers and scroll code unchanged. This is not acceptance.
The native request uses a real input timestamp and an independently checked
own active child. Unknown input or native state delegates the existing restore.
"""
from __future__ import annotations

import itertools
import json
import os
from functools import wraps
from pathlib import Path
import subprocess
import sys


_tags = itertools.count(1)


def emit(report, event, **fields):
    try:
        report(event, **fields)
    except Exception:
        pass


class UserPress:
    """Remember timestamp only, before existing widget/class bindings execute.

    No characters, keys, text, selections, window titles or secrets are stored.
    The tag returns None and leaves the original binding order intact.
    """
    def __init__(self, window):
        self.window = window
        self.timestamp = 0
        self.closed = False
        self.tag = 'MokoshD005UserPress' + str(next(_tags))
        self.commands = []
        self.tagged = []
        try:
            for sequence in ('<KeyPress>', '<ButtonPress>'):
                command = window.bind_class(self.tag, sequence, self.record)
                self.commands.append((sequence, command))
            pending = [window]
            while pending:
                widget = pending.pop()
                original = tuple(widget.bindtags())
                widget.bindtags((self.tag, *original))
                self.tagged.append((widget, original))
                pending.extend(widget.winfo_children())
            self.destroy_binding = window.bind('<Destroy>', self.destroyed, add='+')
        except Exception:
            self.cleanup()
            raise

    def record(self, event):
        if self.closed or getattr(event, 'send_event', False):
            return
        try:
            value = event.time
            if isinstance(value, bool):
                return
            stamp = int(value)
            if 0 < stamp < 2**32:
                self.timestamp = stamp
        except (AttributeError, TypeError, ValueError, OverflowError):
            return

    def destroyed(self, event):
        if event.widget is self.window:
            self.cleanup()

    def cleanup(self):
        if self.closed:
            return
        self.closed = True
        for widget, original in self.tagged:
            try:
                # Remove our tag only; do not overwrite bindings added later.
                widget.bindtags(tuple(t for t in widget.bindtags() if t != self.tag))
            except Exception:
                pass
        self.tagged.clear()
        for sequence, command in self.commands:
            try:
                self.window.unbind_class(self.tag, sequence)
                if command:
                    self.window._root().deletecommand(command)
            except Exception:
                pass
        self.commands.clear()


def native_request(helper, parent_inner, child_inner, timestamp):
    """Run bounded read-only queries plus one EWMH request in a private process.

    An Xlib/tool failure cannot install a global X error handler in the Tk
    process or prevent its existing close/restore path from being delegated.
    """
    try:
        completed = subprocess.run(
            [sys.executable, '-I', '-B', str(helper), '--parent', str(parent_inner),
             '--child', str(child_inner), '--timestamp', str(timestamp),
             '--owner-pid', str(os.getpid())],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=0.8, check=False,
        )
        if completed.returncode != 0 or len(completed.stdout) > 16384:
            return {'status': 'NATIVE_HELPER_FAILED'}
        value = json.loads(completed.stdout)
        if not isinstance(value, dict) or value.get('status') not in (
                'REQUEST_SENT_NOT_ACCEPTANCE', 'DECLINED', 'UNAVAILABLE'):
            return {'status': 'NATIVE_HELPER_INVALID_RESULT'}
        return value
    except subprocess.TimeoutExpired:
        return {'status': 'NATIVE_HELPER_TIMEOUT'}
    except Exception as error:
        return {'status': 'NATIVE_HELPER_UNAVAILABLE', 'error_type': type(error).__name__}


def wrap_init(original, report):
    @wraps(original)
    def construct(dialog, *args, **kwargs):
        value = original(dialog, *args, **kwargs)
        try:
            if str(dialog.window.tk.call('tk', 'windowingsystem')) == 'x11':
                dialog._d005_user_press = UserPress(dialog.window)
        except Exception as error:
            emit(report, 'D005_MAX_INPUT_CAPTURE_DECLINED', error_type=type(error).__name__)
        return value
    return construct


def wrap_restore(original, request, report):
    @wraps(original)
    def restore(dialog):
        if getattr(dialog, '_closed', False) and not getattr(dialog, '_d005_max_attempted', False):
            dialog._d005_max_attempted = True
            try:
                parent, child = dialog.parent, dialog.window
                capture = getattr(dialog, '_d005_user_press', None)
                if capture is None or capture.closed or not capture.timestamp:
                    outcome = {'status': 'DECLINED', 'reason': 'NO_CAPTURED_USER_PRESS'}
                elif (not parent.winfo_exists() or not child.winfo_exists()
                      or parent.winfo_toplevel() is not parent or parent.tk is not child.tk
                      or str(parent.tk.call('tk', 'windowingsystem')) != 'x11'
                      or str(parent.state()) != 'normal'):
                    outcome = {'status': 'DECLINED', 'reason': 'TK_OWNER_OR_STATE'}
                else:
                    focus = str(child.tk.call('focus', '-displayof', str(child)))
                    grabbed = child.grab_current()
                    if (focus != str(child) and not focus.startswith(str(child) + '.')) or (
                            grabbed is not None and grabbed is not child):
                        outcome = {'status': 'DECLINED', 'reason': 'CHILD_NOT_CURRENT_INTERACTION_OWNER'}
                    else:
                        parent_id, child_id = int(parent.winfo_id()), int(child.winfo_id())
                        if not (0 < parent_id < 2**32 and 0 < child_id < 2**32 and parent_id != child_id):
                            outcome = {'status': 'DECLINED', 'reason': 'INVALID_OWN_IDS'}
                        else:
                            outcome = request(parent_id, child_id, capture.timestamp)
                emit(report, 'D005_MAX_NATIVE_REQUEST', **outcome)
            except Exception as error:
                emit(report, 'D005_MAX_NATIVE_REQUEST', status='UNAVAILABLE', error_type=type(error).__name__)
        # No decision, return value, exception, control focus or repeat-restore
        # semantics are replaced. Each invocation delegates exactly once.
        return original(dialog)
    return restore


def install(trace, helper, *, request=None):
    import mokosh_profile_ui as ui
    if getattr(ui.ActionDialog, '_d005_max_return_installed', False):
        raise RuntimeError('Maximized parent candidate already installed')
    report = trace.journal.emit
    helper = Path(helper)
    transport = request if request is not None else (
        lambda parent, child, stamp: native_request(helper, parent, child, stamp))
    ui.ActionDialog.__init__ = wrap_init(ui.ActionDialog.__init__, report)
    ui.ActionDialog._restore_parent = wrap_restore(ui.ActionDialog._restore_parent, transport, report)
    ui.ActionDialog._d005_max_return_installed = True
    emit(report, 'D005_MAX_RETURN_INSTALLED',
         scope='EXPERIMENTAL_MAXIMIZED_NATIVE_HIDDEN_PARENT; INPUT_TIMESTAMP_REQUIRED',
         control_focus_helper='UNCHANGED_R2', physical_acceptance='PENDING_REQUIRED')
