"""Opt-in bounded metadata observations, never an alternative read guard.

Only the separate Windows diagnostic entry point creates a Collector. Its
three processes have fixed 16/32/16 record allocations, including one reserved
summary each: at most 64 records of 4096 bytes across the prescribed job.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import PurePosixPath
import platform
import re
import sys

PREFIX = 'MOKOSH_STAT_DIAGNOSTIC_V1 '
MAX_RECORD_BYTES = 4096
CAPS = {'BOOTSTRAP': 16, 'AUDIT': 32, 'STAGE': 16}
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
    'st_mtime_ns', 'st_ctime_ns', 'st_birthtime_ns', 'st_file_attributes', 'st_reparse_tag')
PHASES = {'BOOTSTRAP_MANIFEST', 'BOOTSTRAP_LOCK', 'BOOTSTRAP_BEFORE', 'BOOTSTRAP_FINAL',
    'AUDIT_MANIFEST', 'FROZEN_BEFORE', 'COPY_BEFORE', 'COPY_FINAL', 'FROZEN_FINAL', 'STAGE'}
FIXED = {'BOOTSTRAP_MANIFEST': 'SOURCE_MANIFEST.json', 'AUDIT_MANIFEST': 'SOURCE_MANIFEST.json',
    'BOOTSTRAP_LOCK': 'ci/runtime-dependencies.lock'}
GUARDS = {'Symlink path component rejected': 'SYMLINK_PATH_COMPONENT',
    'Non-regular, linked or oversized source file': 'NON_REGULAR_LINKED_OR_OVERSIZED',
    'Source replaced while opening': 'SOURCE_REPLACED_WHILE_OPENING',
    'Source changed while reading': 'SOURCE_CHANGED_WHILE_READING',
    'Artifact file exceeds bound': 'ARTIFACT_FILE_SIZE_BOUND',
    'Approved report budget exceeded': 'APPROVED_REPORT_BUDGET'}


def reason_code(error):
    if type(error) is ValueError:
        return GUARDS.get(str(error), 'OTHER_VALUE_ERROR')
    if isinstance(error, FileNotFoundError):
        return 'FILE_NOT_FOUND'
    if isinstance(error, PermissionError):
        return 'PERMISSION_DENIED'
    if isinstance(error, OSError):
        return 'OS_ERROR'
    return 'OTHER_READ_ERROR'


def safe_name(name):
    return (type(name) is str and 0 < len(name) <= 240
        and re.fullmatch(r'[A-Za-z0-9_. /-]+', name) is not None
        and not PurePosixPath(name).is_absolute() and ':' not in name
        and all(part not in ('', '.', '..', '.git', '__pycache__') for part in name.split('/')))


class Collector:
    def __init__(self, channel, stream=None):
        if channel not in CAPS:
            raise ValueError('Unknown diagnostic channel')
        self.channel = channel
        self.stream = sys.stdout if stream is None else stream
        self.limit = CAPS[channel]
        self.records = 0
        self.attempts = 0
        self.bytes = 0
        self.incomplete = False
        self.reasons = set()
        self.sources = {}
        self.reports = frozenset()
        self.copy_snapshot_completed = False
        self.finished = False

    def mark_incomplete(self, reason='COLLECTOR_ERROR'):
        self.incomplete = True
        self.reasons.add(reason if reason in {'COLLECTOR_ERROR', 'BUDGET_EXHAUSTED',
            'INVALID_CONTEXT', 'INVALID_METADATA', 'RECORD_TOO_LARGE', 'WRITE_FAILED',
            'POST_PATH_STAT_UNAVAILABLE', 'GUARD_POST_PATH_STAT_UNAVAILABLE'} else 'COLLECTOR_ERROR')

    def register_sources(self, wanted):
        # Keep only names authorized by the validated source manifest. Invalid
        # log names are never emitted, even if a future manifest accepts them.
        for name, row in wanted.items():
            if not safe_name(name) or type(row.get('bytes')) is not int or not re.fullmatch(
                    '[0-9a-f]{64}', row.get('sha256', '')):
                self.mark_incomplete('INVALID_CONTEXT')
                continue
            self.sources[name] = (row['bytes'], row['sha256'])

    def register_reports(self, names):
        self.reports = frozenset(name for name in names if safe_name(name))
        if len(self.reports) != len(names):
            self.mark_incomplete('INVALID_CONTEXT')

    def _context(self, context):
        if type(context) is not tuple or len(context) != 5:
            raise ValueError('Invalid diagnostic context')
        kind, phase, name, size, sha = context
        if phase not in PHASES or not safe_name(name):
            raise ValueError('Invalid diagnostic context')
        if (kind == 'SOURCE' and phase in {'BOOTSTRAP_BEFORE', 'BOOTSTRAP_FINAL',
                'FROZEN_BEFORE', 'FROZEN_FINAL', 'COPY_BEFORE', 'COPY_FINAL'}
                and self.sources.get(name) == (size, sha)):
            return {'kind': kind, 'phase': phase, 'name': name,
                'expected_bytes': size, 'expected_sha256': sha}
        if kind == 'FIXED' and FIXED.get(phase) == name and size is None and sha is None:
            return {'kind': kind, 'phase': phase, 'name': name}
        if kind == 'REPORT' and phase == 'STAGE' and name in self.reports and size is None and sha is None:
            return {'kind': kind, 'phase': phase, 'name': name}
        raise ValueError('Unbound diagnostic context')

    def _stat(self, value):
        if value is None:
            return None
        result = {}
        for key in FIELDS:
            number = getattr(value, key, None)
            if number is not None and (type(number) is not int or abs(number) >= 2 ** 128):
                raise ValueError('Invalid numeric stat field')
            result[key] = number
        return result

    def _emit(self, value, *, final=False):
        try:
            if self.finished or self.attempts >= self.limit - (0 if final else 1):
                self.mark_incomplete('BUDGET_EXHAUSTED')
                return
            header = {'schema': 1, 'channel': self.channel, 'sequence': self.records + 1,
                'python': list(sys.version_info[:3]), 'os_name': os.name,
                'windows_version': list(sys.getwindowsversion()[:3]) if hasattr(sys, 'getwindowsversion') else None,
                'machine': platform.machine() if platform.machine() in ('AMD64', 'x86_64', 'arm64', 'aarch64') else 'OTHER'}
            header.update(value)
            line = PREFIX + json.dumps(header, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n'
            encoded = line.encode('ascii')
            if len(encoded) > MAX_RECORD_BYTES:
                self.mark_incomplete('RECORD_TOO_LARGE')
                return
            self.attempts += 1
            written = self.stream.write(line)
            if written != len(line):
                self.mark_incomplete('WRITE_FAILED')
                return
            self.stream.flush()
            self.records += 1
            self.bytes += len(encoded)
        except BaseException:
            self.mark_incomplete('WRITE_FAILED')

    def read_failure(self, context, path, error, before, opened, after, raw, guard_after=None,
            guard_after_attempted=False):
        # Failure observation must never replace the original read exception.
        try:
            bound = self._context(context)
            if guard_after_attempted and guard_after is None:
                self.mark_incomplete('GUARD_POST_PATH_STAT_UNAVAILABLE')
            post = None
            post_error = None
            try:
                post = path.lstat()
            except OSError:
                post_error = 'POST_PATH_STAT_UNAVAILABLE'
                self.mark_incomplete(post_error)
            stats = {'lstat_before': self._stat(before), 'fstat_opened': self._stat(opened),
                'fstat_after_read': self._stat(after), 'lstat_guard_after': self._stat(guard_after),
                'lstat_failure_probe': self._stat(post)}
            differences = {}
            for label, left, right in [('path_vs_opened', 'lstat_before', 'fstat_opened'),
                    ('same_handle_during_read', 'fstat_opened', 'fstat_after_read'),
                    ('path_before_vs_guard_after', 'lstat_before', 'lstat_guard_after'),
                    ('path_before_vs_failure_probe', 'lstat_before', 'lstat_failure_probe')]:
                a, b = stats[left], stats[right]
                differences[label] = None if a is None or b is None else [k for k in FIELDS if a[k] != b[k]]
            self._emit({'event': 'READ_REJECTED', 'context': bound, 'guard': reason_code(error),
                'observation_contract': 'LIKE_API_GUARD_PAIRS_V2',
                'guard_post_path': {'status': 'OBSERVED' if guard_after is not None
                    else 'FAILED' if guard_after_attempted else 'NOT_REACHED',
                    'error': reason_code(error) if guard_after_attempted and guard_after is None else None},
                'observations': stats, 'differing_fields': differences, 'post_path_error': post_error,
                'read_bytes': None if raw is None else len(raw),
                'read_sha256': None if raw is None else hashlib.sha256(raw).hexdigest()})
        except BaseException:
            self.mark_incomplete('INVALID_CONTEXT')

    def event(self, code):
        if code not in {'DIAGNOSTIC_STARTED', 'COPY_SNAPSHOT_COMPLETE', 'QUALIFICATION_FAILED',
                'APPROVED_REPORT_REJECTED'}:
            self.mark_incomplete('INVALID_CONTEXT')
            return
        if code == 'COPY_SNAPSHOT_COMPLETE':
            self.copy_snapshot_completed = True
        self._emit({'event': code})

    def report_rejection(self, name, code):
        try:
            context = self._context(('REPORT', 'STAGE', name, None, None))
            allowed_codes = set(GUARDS.values()) | {'OTHER_VALUE_ERROR', 'FILE_NOT_FOUND',
                'PERMISSION_DENIED', 'OS_ERROR', 'OTHER_READ_ERROR'}
            if code not in allowed_codes:
                raise ValueError('Unknown rejection code')
            self._emit({'event': 'APPROVED_REPORT_REJECTED', 'context': context, 'guard': code})
        except BaseException:
            self.mark_incomplete('INVALID_CONTEXT')

    def summary(self):
        return {'collection': 'DIAGNOSTIC_INCOMPLETE' if self.incomplete else 'DIAGNOSTIC_COLLECTION_COMPLETE',
            'reason_codes': sorted(self.reasons), 'copy_snapshot_completed': self.copy_snapshot_completed,
            'records_emitted': self.records, 'records_attempted': self.attempts,
            'bytes_emitted': self.bytes, 'record_limit': self.limit,
            'job_record_budget': 64, 'record_byte_bound_including_prefix_newline': MAX_RECORD_BYTES,
            'compatibility_acceptance': 'NOT_ASSESSED'}

    def finish(self):
        if not self.finished:
            self._emit({'event': 'DIAGNOSTIC_SUMMARY',
                'receipt_contract': 'COMPLETE_LINE_AND_ENTRY_EXIT_NOT_2_REQUIRED', **self.summary()}, final=True)
            self.finished = True
        return self.summary()
