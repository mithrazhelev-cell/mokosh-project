"""Synthetic opt-in observation controls; no native Windows acceptance claim."""
from pathlib import Path
import hashlib
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_venv as bootstrap
import run_preliminary as m
import stage_report_artifacts as artifacts
import stat_diagnostics as d
import test_ci_guards as baseline
import validate_windows_diagnostic_workflow as workflow
import windows_stat_diagnostic as entry


class DiagnosticGuards(unittest.TestCase):
    def setUp(self):
        baseline.Guards.setUp(self)
        self.log = io.StringIO()
        self.observer = d.Collector('AUDIT', self.log)
        self.observer.register_sources(m.validate_manifest(self.manifest))
        row = self.manifest['records'][0]
        self.context = ('SOURCE', 'COPY_BEFORE', 'app.py', row['bytes'], row['sha256'])

    def records(self):
        return [json.loads(line[len(d.PREFIX):]) for line in self.log.getvalue().splitlines()]

    def changed_stat(self, value, **changes):
        values = {key: getattr(value, key, None) for key in d.FIELDS}
        values.update(changes)
        return types.SimpleNamespace(**values)

    def ctime_mismatch(self, *args):
        value = self.real_fstat(*args)
        return self.changed_stat(value, st_ctime_ns=value.st_ctime_ns + 100)

    def reject_with_ctime(self, observer):
        # Negative logger/privacy controls retain a real same-handle change;
        # the measured stable cross-API mismatch is now the positive below.
        real = os.fstat
        calls = []
        def changed(fd):
            value = real(fd)
            calls.append(1)
            return self.changed_stat(value, st_ctime_ns=value.st_ctime_ns + 100 * len(calls))
        with patch.object(m.os, 'fstat', side_effect=changed), \
                self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
            m.read_file(self.project / 'app.py', diagnostic=observer, context=self.context)

    def test_01_observer_off_on_return_exact_same_bytes(self):
        path = self.project / 'app.py'
        before = path.read_bytes()
        self.assertEqual(m.read_file(path), before)
        self.assertEqual(m.read_file(path, diagnostic=self.observer, context=self.context), before)
        self.assertEqual(self.log.getvalue(), '', 'Successful reads must not exhaust the failure budget')
        self.assertEqual(path.read_bytes(), before)

    def test_02_stable_cross_api_ctime_difference_returns_exact_bytes(self):
        # Approved alignment: Windows path creation time and fd ChangeTime
        # may differ without any in-read change. Keep both ctime pairs strict.
        self.real_fstat = os.fstat
        raw = (self.project / 'app.py').read_bytes()
        with patch.object(m.os, 'fstat', side_effect=self.ctime_mismatch):
            self.assertEqual(m.read_file(self.project / 'app.py'), raw)
            self.assertEqual(m.read_file(self.project / 'app.py', diagnostic=self.observer,
                context=self.context), raw)
        self.assertEqual(self.log.getvalue(), '')
        self.assertFalse(self.observer.incomplete)

    def test_03_same_handle_change_is_distinct_from_cross_api_only(self):
        real = os.fstat
        calls = []
        def changed(fd):
            value = real(fd)
            calls.append(1)
            return self.changed_stat(value, st_mtime_ns=value.st_mtime_ns + 1) if len(calls) == 2 else value
        with patch.object(m.os, 'fstat', side_effect=changed), self.assertRaisesRegex(ValueError, 'Source changed'):
            m.read_file(self.project / 'app.py', diagnostic=self.observer, context=self.context)
        self.assertEqual(self.records()[0]['differing_fields']['same_handle_during_read'], ['st_mtime_ns'])

    def test_04_path_replacement_while_opening_remains_rejected(self):
        real = os.fstat
        with patch.object(m.os, 'fstat', side_effect=lambda fd: self.changed_stat(real(fd), st_ino=0)), \
                self.assertRaisesRegex(ValueError, 'Source replaced while opening'):
            m.read_file(self.project / 'app.py', diagnostic=self.observer, context=self.context)
        self.assertEqual(self.records()[0]['guard'], 'SOURCE_REPLACED_WHILE_OPENING')
        self.assertIsNone(self.records()[0]['read_sha256'])

    def test_05_hardlink_rejection_is_not_weakened(self):
        os.link(self.project / 'app.py', self.root / 'linked')
        with self.assertRaisesRegex(ValueError, 'linked or oversized'):
            m.read_file(self.project / 'app.py', diagnostic=self.observer, context=self.context)
        self.assertEqual(self.records()[0]['guard'], 'NON_REGULAR_LINKED_OR_OVERSIZED')

    def test_06_symlink_rejection_is_not_weakened(self):
        link = self.root / 'link'
        link.symlink_to(self.project / 'app.py')
        with self.assertRaisesRegex(ValueError, 'Symlink path component'):
            m.read_file(link, diagnostic=self.observer, context=self.context)
        self.assertEqual(self.records()[0]['guard'], 'SYMLINK_PATH_COMPONENT')

    def test_07_unknown_or_unsafe_context_never_leaks(self):
        for name in ('/secret/home/key', '../private', 'app.py\n::warning::secret', 'unknown.txt'):
            self.context = ('SOURCE', 'COPY_BEFORE', name, 1, '0' * 64)
            self.reject_with_ctime(self.observer)
        self.assertEqual(self.log.getvalue(), '')
        self.assertTrue(self.observer.incomplete)
        self.observer.finish()
        self.assertEqual(self.records()[-1]['collection'], 'DIAGNOSTIC_INCOMPLETE')
        self.assertNotIn('secret', self.log.getvalue())

    def test_08_collector_overflow_has_reserved_incomplete_receipt(self):
        for _ in range(200):
            self.observer.event('DIAGNOSTIC_STARTED')
        self.observer.finish()
        records = self.records()
        self.assertEqual(len(records), 32)
        self.assertEqual(records[-1]['event'], 'DIAGNOSTIC_SUMMARY')
        self.assertEqual(records[-1]['collection'], 'DIAGNOSTIC_INCOMPLETE')
        self.assertTrue(all(len(line.encode('ascii')) <= 4096 for line in self.log.getvalue().splitlines(keepends=True)))
        self.assertLessEqual(len(self.log.getvalue().encode('ascii')), 32 * 4096)

    def test_09_sink_failure_does_not_replace_original_guard(self):
        class Broken:
            def write(self, line):
                raise OSError('private-error-must-not-be-logged')
            def flush(self):
                raise AssertionError('not reached')
        self.observer.stream = Broken()
        self.reject_with_ctime(self.observer)
        self.assertTrue(self.observer.incomplete)
        self.assertEqual(self.observer.summary()['collection'], 'DIAGNOSTIC_INCOMPLETE')

    def test_10_repeated_short_write_and_flush_fault_attempts_are_bounded(self):
        for fault in ('short', 'flush'):
            class Broken:
                def __init__(self):
                    self.calls = 0
                    self.chars = 0
                def write(self, line):
                    self.calls += 1
                    self.chars += len(line)
                    return 1 if fault == 'short' else len(line)
                def flush(self):
                    raise OSError('sink failed')
            sink = Broken()
            observer = d.Collector('AUDIT', sink)
            for _ in range(200):
                observer.event('DIAGNOSTIC_STARTED')
            observer.finish()
            with self.subTest(fault=fault):
                self.assertLessEqual(sink.calls, 32)
                self.assertLessEqual(sink.chars, 32 * 4096)
                self.assertTrue(observer.incomplete)

    def test_11_observer_raising_base_exception_does_not_replace_guard(self):
        class Broken:
            incomplete = False
            def read_failure(self, *args):
                raise KeyboardInterrupt()
            def mark_incomplete(self, reason):
                self.incomplete = True
        observer = Broken()
        self.reject_with_ctime(observer)
        self.assertTrue(observer.incomplete)

    def test_12_diagnostic_stop_never_reaches_compile_probe_worker(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('Diagnostic crossed the pre-execution boundary')
        with patch.object(m, 'compile', side_effect=forbidden, create=True):
            status = m.run_audit(self.project, self.manifest_path, self.output, 'portability-probe',
                self.worker, diagnostic=self.observer, diagnostic_only=True, probe=forbidden, process_run=forbidden)
        self.assertEqual(status, 1)
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(report['result'], 'DIAGNOSTIC_NON_REPRODUCED')
        self.assertEqual(report['diagnostic_stop'], 'BEFORE_COMPILE_RUNTIME_PROBE_WORKER')
        self.assertTrue(report['frozen_source_unchanged'])
        self.assertFalse(report['temporary_copy_retained'])
        self.assertNotIn('runtime', report)
        self.assertNotIn('compiled_python_files', report)
        self.assertFalse((self.output / 'worker').exists())

    def test_13_copy_failure_still_checks_frozen_source_and_cleanup(self):
        snapshot = m.snapshot
        def fail_copy(project, manifest, **kwargs):
            if kwargs.get('phase') == 'COPY_BEFORE':
                (self.project / 'app.py').write_bytes(b'changed source\n')
                raise ValueError('Synthetic initial copy failure')
            return snapshot(project, manifest, **kwargs)
        with patch.object(m, 'snapshot', side_effect=fail_copy):
            self.assertEqual(m.run_audit(self.project, self.manifest_path, self.output, 'portability-probe',
                self.worker, diagnostic=self.observer, diagnostic_only=True), 1)
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(report['result'], 'FAIL_PRELIMINARY_ANALYSIS')
        self.assertIn('final_source_error', report)
        self.assertFalse(report['temporary_copy_retained'])

    def test_14_rejected_approved_report_identified_and_bytes_blocked(self):
        root = self.root / 'artifacts'
        (root / 'bootstrap-runtime').mkdir(parents=True)
        (root / 'bootstrap-runtime/pip_install.log').write_text('rejected-private-body')
        (root / 'JOB_STATUS.json').write_text('{}\n')
        (root / 'private-unknown-key.bin').write_text('unapproved-private-body')
        read = artifacts.read_file
        def reject(path, **kwargs):
            if path.name == 'pip_install.log':
                raise ValueError('Source changed while reading')
            return read(path, **kwargs)
        target = self.root / 'sealed'
        with patch.object(artifacts, 'read_file', side_effect=reject):
            result = artifacts.stage(root, target, diagnostic=self.observer)
        receipt = json.loads((target / 'ARTIFACT_SCOPE_FAILURE.json').read_text())
        self.assertTrue(result['result'].startswith('FAIL_'))
        self.assertEqual(receipt['approved_report_rejections'], [
            {'name': 'bootstrap-runtime/pip_install.log', 'reason': 'SOURCE_CHANGED_WHILE_READING'}])
        self.assertFalse((target / 'bootstrap-runtime/pip_install.log').exists())
        self.assertFalse((target / 'private-unknown-key.bin').exists())
        self.assertNotIn('private-unknown-key', json.dumps(receipt))
        rejected = [r for r in self.records() if r['event'] == 'APPROVED_REPORT_REJECTED']
        self.assertEqual(rejected[0]['context']['name'], 'bootstrap-runtime/pip_install.log')
        self.assertEqual(rejected[0]['guard'], 'SOURCE_CHANGED_WHILE_READING')

    def test_15_workflow_template_rejects_added_command_or_step(self):
        original = Path(__file__).resolve().parents[1] / '.github/workflows/windows-stat-diagnostic.yml'
        self.assertTrue(workflow.check(original)['result'].startswith('PASS_'))
        for suffix in ('\n      - run: echo unapproved-command\n', '\n# altered template\n'):
            altered = self.root / 'altered.yml'
            altered.write_bytes(original.read_bytes() + suffix.encode())
            with self.assertRaises(ValueError):
                workflow.check(altered)

    def test_16_unqualified_runtime_never_invokes_bootstrap(self):
        with patch.object(entry, 'qualified_runtime', return_value=False), \
                patch.object(entry.bootstrap_venv, 'bootstrap') as forbidden, \
                patch.object(sys, 'stdout', self.log):
            self.assertEqual(entry.main(['bootstrap', '--project', str(self.project), '--manifest',
                str(self.manifest_path), '--destination', str(self.root / 'venv'), '--requirements',
                str(self.root / 'runtime.lock'), '--output', str(self.output)]), 2)
        forbidden.assert_not_called()
        self.assertIn('QUALIFICATION_FAILED', self.log.getvalue())

    def test_17_bootstrap_with_observation_preserves_lock_and_original_contract(self):
        requirements = self.root / 'runtime.lock'
        requirements.write_text('example==1.0 --hash=sha256:' + '0' * 64 + '\n')
        def create(destination):
            (destination / 'bin').mkdir(parents=True)
        def success(*args, **kwargs):
            kwargs['stdout'].write('synthetic pip log\n')
            return types.SimpleNamespace(returncode=0)
        observer = d.Collector('BOOTSTRAP', self.log)
        self.real_fstat = os.fstat
        with patch.object(bootstrap.venv.EnvBuilder, 'create', side_effect=create), \
                patch.object(bootstrap, 'run_owned', side_effect=success), \
                patch.object(m.os, 'fstat', side_effect=self.ctime_mismatch):
            status = bootstrap.bootstrap(self.project, self.manifest_path, self.root / 'venv',
                requirements, self.output, diagnostic=observer)
        self.assertEqual(status, 0)
        report = json.loads((self.output / 'RESULT.json').read_text())
        self.assertTrue(report['frozen_source_unchanged'])
        self.assertEqual(report['requirements_sha256'], hashlib.sha256(requirements.read_bytes()).hexdigest())
        self.assertFalse(observer.incomplete)

    def test_18_wrong_source_phase_is_incomplete_without_misleading_record(self):
        self.context = ('SOURCE', 'STAGE', *self.context[2:])
        self.reject_with_ctime(self.observer)
        self.assertEqual(self.log.getvalue(), '')
        self.assertTrue(self.observer.incomplete)

    def test_19_final_receipt_failure_cannot_leave_artifact_claiming_complete(self):
        class FinalReceiptFailure:
            def write(self, line):
                if '"event":"DIAGNOSTIC_SUMMARY"' in line:
                    raise OSError('synthetic final receipt failure')
                return len(line)
            def flush(self):
                pass
        observer = d.Collector('AUDIT', FinalReceiptFailure())
        with patch.object(entry, 'qualified_runtime', return_value=True), \
                patch.object(entry, 'Collector', return_value=observer):
            status = entry.main(['audit', '--project', str(self.project), '--manifest',
                str(self.manifest_path), '--output', str(self.output)])
        self.assertEqual(status, 2)
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(report['result'], 'DIAGNOSTIC_NON_REPRODUCED')
        self.assertEqual(report['diagnostic']['collection'], 'PENDING_FINAL_RECEIPT')
        self.assertEqual(observer.summary()['collection'], 'DIAGNOSTIC_INCOMPLETE')
        self.assertIn('WRITE_FAILED', observer.summary()['reason_codes'])

    def test_20_complete_receipt_written_then_flush_fails_has_distinct_exit_two(self):
        class FinalFlushFailure:
            def __init__(self):
                self.lines = []
                self.final = False
            def write(self, line):
                self.lines.append(line)
                self.final = '"event":"DIAGNOSTIC_SUMMARY"' in line
                return len(line)
            def flush(self):
                if self.final:
                    raise OSError('synthetic final flush failure after write')
        sink = FinalFlushFailure()
        observer = d.Collector('AUDIT', sink)
        with patch.object(entry, 'qualified_runtime', return_value=True), \
                patch.object(entry, 'Collector', return_value=observer):
            status = entry.main(['audit', '--project', str(self.project), '--manifest',
                str(self.manifest_path), '--output', str(self.output)])
        final = json.loads(sink.lines[-1][len(d.PREFIX):])
        self.assertEqual(final['collection'], 'DIAGNOSTIC_COLLECTION_COMPLETE')
        self.assertEqual(final['receipt_contract'], 'COMPLETE_LINE_AND_ENTRY_EXIT_NOT_2_REQUIRED')
        self.assertEqual(status, 2, 'Collection error must be distinguishable from preserved guard exit 1')
        self.assertEqual(observer.summary()['collection'], 'DIAGNOSTIC_INCOMPLETE')
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(report['diagnostic']['collection'], 'PENDING_FINAL_RECEIPT')

    def test_21_actual_guard_post_snapshot_is_distinct_from_failure_probe(self):
        real = Path.lstat
        target = self.project / 'app.py'
        value = real(target)
        calls = []
        def samples(path):
            if path != target:
                return real(path)
            calls.append(1)
            return self.changed_stat(value, st_ctime_ns=value.st_ctime_ns + len(calls) - 1)
        with patch.object(m, 'safe_path', return_value=target), \
                patch.object(Path, 'lstat', autospec=True, side_effect=samples), \
                self.assertRaisesRegex(ValueError, 'Source changed while reading'):
            m.read_file(target, diagnostic=self.observer, context=self.context)
        record = self.records()[0]
        self.assertEqual(len(calls), 3)
        self.assertEqual(record['guard_post_path'], {'status': 'OBSERVED', 'error': None})
        self.assertEqual(record['observation_contract'], 'LIKE_API_GUARD_PAIRS_V2')
        self.assertEqual(record['observations']['lstat_guard_after']['st_ctime_ns'], value.st_ctime_ns + 1)
        self.assertEqual(record['observations']['lstat_failure_probe']['st_ctime_ns'], value.st_ctime_ns + 2)
        self.assertEqual(record['differing_fields']['path_before_vs_guard_after'], ['st_ctime_ns'])
        self.assertEqual(record['differing_fields']['path_before_vs_failure_probe'], ['st_ctime_ns'])

    def test_22_guard_post_missing_is_failed_not_later_diagnostic_success(self):
        real = Path.lstat
        target = self.project / 'app.py'
        calls = []
        def samples(path):
            if path != target:
                return real(path)
            calls.append(1)
            if len(calls) == 2:
                raise FileNotFoundError('private-missing-path')
            return real(path)
        with patch.object(m, 'safe_path', return_value=target), \
                patch.object(Path, 'lstat', autospec=True, side_effect=samples), \
                self.assertRaisesRegex(FileNotFoundError, 'private-missing-path'):
            m.read_file(target, diagnostic=self.observer, context=self.context)
        record = self.records()[0]
        self.assertEqual(record['guard_post_path'], {'status': 'FAILED', 'error': 'FILE_NOT_FOUND'})
        self.assertIsNone(record['observations']['lstat_guard_after'])
        self.assertIsNotNone(record['observations']['lstat_failure_probe'])
        self.assertNotIn('private-missing-path', self.log.getvalue())
        self.assertTrue(self.observer.incomplete)
        self.assertIn('GUARD_POST_PATH_STAT_UNAVAILABLE', self.observer.summary()['reason_codes'])

    def test_23_guard_post_not_reached_on_open_binding_refusal(self):
        real = os.fstat
        with patch.object(m.os, 'fstat', side_effect=lambda fd: self.changed_stat(real(fd), st_ino=0)), \
                self.assertRaisesRegex(ValueError, 'Source replaced while opening'):
            m.read_file(self.project / 'app.py', diagnostic=self.observer, context=self.context)
        record = self.records()[0]
        self.assertEqual(record['guard_post_path'], {'status': 'NOT_REACHED', 'error': None})
        self.assertIsNone(record['observations']['lstat_guard_after'])
        self.assertIsNotNone(record['observations']['lstat_failure_probe'])

    def test_24_same_handle_ctime_change_keeps_exact_hash_and_bounded_record(self):
        self.reject_with_ctime(self.observer)
        record = self.records()[0]
        self.assertEqual(record['guard'], 'SOURCE_CHANGED_WHILE_READING')
        self.assertEqual(record['differing_fields']['same_handle_during_read'], ['st_ctime_ns'])
        self.assertEqual(record['read_sha256'], self.manifest['records'][0]['sha256'])
        self.assertEqual(record['read_bytes'], self.manifest['records'][0]['bytes'])
        self.assertEqual(record['guard_post_path']['status'], 'OBSERVED')
        self.assertLessEqual(len(self.log.getvalue().encode('ascii')), 4096)
        self.assertNotIn('value = 1', self.log.getvalue())

    def test_25_maximal_numeric_metadata_stays_within_record_budget(self):
        # Five distinct snapshots must still obey the original record bound.
        # Extremely large valid integer fields must not exceed the log bound.
        snapshots = [types.SimpleNamespace(**{key: 2 ** 127 - 1 - i for key in d.FIELDS})
            for i in range(5)]
        with patch.object(Path, 'lstat', return_value=snapshots[4]):
            self.observer.read_failure(self.context, self.project / 'app.py',
                ValueError('Source changed while reading'), *snapshots[:3],
                b'value = 1\n', snapshots[3], True)
        self.observer.finish()
        self.assertTrue(all(len(line.encode('ascii')) <= 4096
            for line in self.log.getvalue().splitlines(keepends=True)))
        self.assertLessEqual(len(self.log.getvalue().encode('ascii')), 32 * 4096)
        self.assertFalse(self.observer.incomplete)
        self.assertEqual(self.records()[0]['event'], 'READ_REJECTED')

    def test_26_long_bound_name_and_maximal_metadata_refuse_oversized_record(self):
        name = 'a' * 237 + '.py'
        row = self.manifest['records'][0]
        self.observer.register_sources({name: row})
        context = ('SOURCE', 'COPY_BEFORE', name, row['bytes'], row['sha256'])
        snapshots = [types.SimpleNamespace(**{key: 2 ** 127 - 1 - i for key in d.FIELDS})
            for i in range(5)]
        with patch.object(Path, 'lstat', return_value=snapshots[4]):
            self.observer.read_failure(context, self.project / 'app.py',
                ValueError('Source changed while reading'), *snapshots[:3],
                b'value = 1\n', snapshots[3], True)
        self.assertEqual(self.log.getvalue(), '', 'Oversized record must not be partially written')
        self.observer.finish()
        self.assertTrue(self.observer.incomplete)
        self.assertIn('RECORD_TOO_LARGE', self.observer.summary()['reason_codes'])
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.records()[0]['collection'], 'DIAGNOSTIC_INCOMPLETE')
        self.assertLessEqual(len(self.log.getvalue().encode('ascii')), 4096)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DiagnosticGuards)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 26
        and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses) else 1)
