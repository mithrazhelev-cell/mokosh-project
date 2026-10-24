"""Observe Tk callback reporting and require a clean explicit final receipt.

Only the known synthetic GUI process is in scope. No Tk bindings, Tcl commands,
after jobs, widget decisions, focus, geometry, or application data are changed.
The original Misc._report_exception is called exactly once with its existing
exception context, preserving the root's report_callback_exception behavior.
"""
from __future__ import annotations

import atexit
import collections
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = 1
SCOPE = 'MOKOSH_SYNTHETIC_GUI_CALLBACK_REPORTING_ONLY'
TARGET = 'tkinter.Misc._report_exception'
MAX_CALLBACK_RECORDS = 256
MAX_JOURNAL_BYTES = 512 * 1024
MARKER = '_mokosh_callback_reporting_guard_owner'


class CallbackGuardError(ValueError):
    def __init__(self, message, summary=None):
        super().__init__(message)
        self.summary = summary


def require(condition, message):
    if not condition:
        raise CallbackGuardError(message)


def source_sha256():
    loader = globals().get('__loader__')
    source = loader.get_source(__name__) if loader is not None and hasattr(loader, 'get_source') else None
    raw = source.encode('utf-8') if source is not None else Path(__file__).read_bytes()
    return hashlib.sha256(raw).hexdigest()


def exception_name(kind):
    name = getattr(kind, '__name__', '')
    return name if isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', name) else 'UnknownException'


def private_parent(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute safe callback journal path required')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'Callback journal symlink rejected')
    info = path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'Callback evidence directory must be private and owned')
    return path


class CallbackGuard:
    def __init__(self, path, *, scope=SCOPE):
        import tkinter
        misc_class = tkinter.Misc
        require(scope == SCOPE, 'Unsupported callback observation scope')
        require(getattr(misc_class, MARKER, None) is None, 'Callback reporting guard already installed')
        self.path = private_parent(path)
        self.scope = scope
        self.target = misc_class
        self.original = misc_class._report_exception
        self.callback_count = 0
        self.callback_types = collections.Counter()
        self.reporter_failures = 0
        self.write_errors = 0
        self.dropped_callbacks = 0
        self.closed = False
        self.registered = False
        self.descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.bytes = 0
        try:
            info = os.fstat(self.descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                    'Unsafe callback journal')
            self._write_line({'event': 'CALLBACK_GUARD_START', 'schema': SCHEMA,
                'scope': scope, 'target': TARGET, 'observer_source_sha256': source_sha256(),
                'policy': 'OBSERVE_REPORT_PATH_AND_DELEGATE_ORIGINAL_ONCE'})

            @functools.wraps(self.original)
            def observed(widget):
                kind, _value, _traceback = sys.exc_info()
                self.callback_count += 1
                name = exception_name(kind)
                self.callback_types[name] += 1
                if self.callback_count <= MAX_CALLBACK_RECORDS:
                    self._observe({'event': 'TK_CALLBACK_EXCEPTION',
                                   'ordinal': self.callback_count, 'exception_type': name})
                else:
                    self.dropped_callbacks += 1
                try:
                    return self.original(widget)
                except BaseException as reporter_error:
                    self.reporter_failures += 1
                    if self.callback_count <= MAX_CALLBACK_RECORDS:
                        self._observe({'event': 'TK_CALLBACK_REPORTER_FAILURE',
                            'ordinal': self.callback_count,
                            'exception_type': exception_name(type(reporter_error))})
                    raise

            self.wrapper = observed
            setattr(misc_class, MARKER, self)
            misc_class._report_exception = observed
            atexit.register(self._at_exit)
            self.registered = True
        except BaseException:
            if getattr(misc_class, '_report_exception', None) is getattr(self, 'wrapper', None):
                misc_class._report_exception = self.original
            if getattr(misc_class, MARKER, None) is self:
                delattr(misc_class, MARKER)
            self.closed = True
            os.close(self.descriptor)
            raise

    def _write_line(self, record):
        raw = (json.dumps(record, sort_keys=True) + '\n').encode('utf-8')
        require(self.bytes + len(raw) <= MAX_JOURNAL_BYTES, 'Callback journal byte limit exceeded')
        remaining = raw
        while remaining:
            count = os.write(self.descriptor, remaining)
            if count <= 0:
                raise OSError('Callback journal short write')
            remaining = remaining[count:]
        self.bytes += len(raw)

    def _observe(self, record):
        try:
            self._write_line(record)
        except BaseException:
            # Observation failure must not replace Tk's original reporting.
            self.write_errors += 1

    def _at_exit(self):
        self.close(unregister=False)

    def close(self, *, unregister=True):
        if self.closed:
            return
        self.closed = True
        owned = getattr(self.target, '_report_exception', None) is self.wrapper
        if owned:
            self.target._report_exception = self.original
        if getattr(self.target, MARKER, None) is self:
            delattr(self.target, MARKER)
        if unregister and self.registered:
            atexit.unregister(self._at_exit)
        self.registered = False
        clean = (self.callback_count == 0 and self.reporter_failures == 0 and
                 self.write_errors == 0 and self.dropped_callbacks == 0 and owned)
        try:
            self._write_line({'event': 'CALLBACK_GUARD_FINISH', 'schema': SCHEMA,
                'scope': self.scope, 'status': 'PASS' if clean else 'FAIL',
                'callback_count': self.callback_count, 'callback_types': dict(self.callback_types),
                'reporter_failure_count': self.reporter_failures, 'write_error_count': self.write_errors,
                'dropped_callback_records': self.dropped_callbacks,
                'owned_handler_intact': owned, 'own_handler_restored': owned})
        except BaseException:
            self.write_errors += 1
        finally:
            os.close(self.descriptor)


def install(path, *, scope=SCOPE):
    return CallbackGuard(path, scope=scope)


def read_receipt(path):
    path = private_parent(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= MAX_JOURNAL_BYTES, 'Unsafe callback receipt')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'Callback receipt replaced')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_JOURNAL_BYTES + 1)
        after = os.fstat(descriptor)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns,
                            x.st_ctime_ns, x.st_mode, x.st_uid, x.st_nlink)
        require(fields(before) == fields(after) and len(raw) == after.st_size, 'Callback receipt changed while read')
    finally:
        os.close(descriptor)
    require(raw.endswith(b'\n'), 'Incomplete callback receipt line')
    rows = [json.loads(line) for line in raw.decode('utf-8').splitlines()]
    require(2 <= len(rows) <= 2 + 2 * MAX_CALLBACK_RECORDS and all(isinstance(r, dict) for r in rows),
            'Callback receipt inventory differs')
    return raw, rows


def review(path, *, expected_scope=SCOPE, expected_source_sha256=None):
    raw, rows = read_receipt(path)
    require(rows[0].get('event') == 'CALLBACK_GUARD_START' and rows[-1].get('event') == 'CALLBACK_GUARD_FINISH'
            and sum(r.get('event') == 'CALLBACK_GUARD_START' for r in rows) == 1
            and sum(r.get('event') == 'CALLBACK_GUARD_FINISH' for r in rows) == 1,
            'Callback receipt endpoints differ')
    begin, end = rows[0], rows[-1]
    require(set(begin) == {'event', 'schema', 'scope', 'target', 'observer_source_sha256', 'policy'}
            and set(end) == {'event', 'schema', 'scope', 'status', 'callback_count', 'callback_types',
                'reporter_failure_count', 'write_error_count', 'dropped_callback_records',
                'owned_handler_intact', 'own_handler_restored'}, 'Callback receipt fields differ')
    require(type(begin.get('schema')) is int and begin['schema'] == SCHEMA
            and type(end.get('schema')) is int and end['schema'] == SCHEMA
            and begin.get('scope') == end.get('scope') == expected_scope == SCOPE,
            'Callback receipt scope differs')
    require(begin.get('target') == TARGET
            and begin.get('policy') == 'OBSERVE_REPORT_PATH_AND_DELEGATE_ORIGINAL_ONCE'
            and begin.get('observer_source_sha256') == (expected_source_sha256 or source_sha256()),
            'Callback observer source or policy binding differs')
    for key in ('callback_count', 'reporter_failure_count', 'write_error_count', 'dropped_callback_records'):
        require(type(end.get(key)) is int and end[key] >= 0, 'Invalid callback receipt counter: ' + key)
    require(type(end.get('callback_types')) is dict, 'Invalid callback type inventory')
    require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', name)
                and type(count) is int and count > 0 for name, count in end['callback_types'].items())
            and sum(end['callback_types'].values()) == end['callback_count'], 'Invalid callback type counts')
    require(type(end.get('owned_handler_intact')) is bool and type(end.get('own_handler_restored')) is bool,
            'Invalid callback handler ownership')
    callbacks = []; reporter_failures = []
    for row in rows[1:-1]:
        require(set(row) == {'event', 'ordinal', 'exception_type'}
                and type(row.get('ordinal')) is int and row['ordinal'] > 0
                and isinstance(row.get('exception_type'), str)
                and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', row['exception_type']),
                'Invalid callback exception metadata')
        if row['event'] == 'TK_CALLBACK_EXCEPTION':
            callbacks.append(row)
        elif row['event'] == 'TK_CALLBACK_REPORTER_FAILURE':
            reporter_failures.append(row)
        else:
            require(False, 'Unresolved callback observer event')
    if end['write_error_count'] == 0:
        require([r['ordinal'] for r in callbacks] == list(range(1, min(end['callback_count'], MAX_CALLBACK_RECORDS) + 1))
                and len(callbacks) + end['dropped_callback_records'] == end['callback_count'],
                'Callback record counters differ')
        if end['dropped_callback_records'] == 0:
            require(dict(collections.Counter(r['exception_type'] for r in callbacks)) == end['callback_types']
                    and len(reporter_failures) == end['reporter_failure_count'], 'Callback error inventory differs')
    clean = (end['callback_count'] == end['reporter_failure_count'] == end['write_error_count']
             == end['dropped_callback_records'] == 0 and end['owned_handler_intact'] and end['own_handler_restored'])
    require(end.get('status') == ('PASS' if clean else 'FAIL'), 'Callback completion status contradicts evidence')
    return {'result': 'PASS_NO_REPORTED_TK_CALLBACK_EXCEPTIONS' if clean else 'FAIL_TK_CALLBACK_REPORTING',
        'callback_count': end['callback_count'], 'callback_types': end['callback_types'],
        'reporter_failure_count': end['reporter_failure_count'], 'write_error_count': end['write_error_count'],
        'owned_handler_intact': end['owned_handler_intact'], 'own_handler_restored': end['own_handler_restored'],
        'journal_sha256': hashlib.sha256(raw).hexdigest(), 'journal_records': len(rows),
        'observer_source_sha256': begin['observer_source_sha256'], 'scope': expected_scope,
        'physical_acceptance': 'NOT_ESTABLISHED_BY_CALLBACK_RECEIPT'}


def validate(path, **kwargs):
    summary = review(path, **kwargs)
    if summary['result'] != 'PASS_NO_REPORTED_TK_CALLBACK_EXCEPTIONS':
        raise CallbackGuardError('Tk callback exception or reporting failure recorded', summary)
    return summary
