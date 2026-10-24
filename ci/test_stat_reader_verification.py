"""Portable controls for future native fixtures/receipts; no Windows acceptance."""
from pathlib import Path
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_preliminary as controller
import run_reported_step as wrapper
import verify_stat_reader as native
import validate_stat_reader_workflow as workflow
import stage_report_artifacts as artifacts


class VerificationGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_01_real_child_zero_one_two_are_recorded_and_propagated(self):
        for status in (0, 1, 2):
            log = io.StringIO()
            observed = wrapper.run_step([sys.executable, '-I', '-B', '-c', 'raise SystemExit(' + str(status) + ')'],
                step='CONTROL', timeout=10, stream=log)
            record = json.loads(log.getvalue()[len(wrapper.PREFIX):])
            self.assertEqual(observed, status)
            self.assertEqual(record['actual_child_exit'], status)
            self.assertEqual(record['completion'], 'CHILD_COMPLETED')
            self.assertNotIn('SystemExit', log.getvalue())

    def test_02_real_child_timeout_cannot_report_complete(self):
        log = io.StringIO()
        self.assertEqual(wrapper.run_step([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(30)'],
            step='CONTROL', timeout=1, stream=log), 124)
        record = json.loads(log.getvalue()[len(wrapper.PREFIX):])
        self.assertEqual(record['completion'], 'INCOMPLETE')
        self.assertIsNone(record['actual_child_exit'])
        self.assertEqual(record['reason'], 'CHILD_TIMEOUT')

    def test_03_short_write_and_flush_failure_cannot_mask_failure_or_pass(self):
        for fault in ('short', 'flush'):
            class Broken:
                def write(self, line):
                    return 1 if fault == 'short' else len(line)
                def flush(self):
                    raise OSError('private-sink-error')
            for child_exit in (0, 1, 2):
                process = lambda *args, **kwargs: types.SimpleNamespace(returncode=child_exit)
                self.assertEqual(wrapper.run_step(['fixed'], step='CONTROL', timeout=1,
                    stream=Broken(), process_run=process), 125)

    def test_04_invalid_or_missing_child_result_remains_incomplete(self):
        for result in (False, None, '0'):
            log = io.StringIO()
            process = lambda *args, **kwargs: types.SimpleNamespace(returncode=result)
            self.assertEqual(wrapper.run_step(['fixed'], step='CONTROL', timeout=1,
                stream=log, process_run=process), 125)
            record = json.loads(log.getvalue()[len(wrapper.PREFIX):])
            self.assertEqual(record['completion'], 'INCOMPLETE')
            self.assertNotIn('fixed', log.getvalue())

    def test_05_child_environment_retains_output_contract_without_tokens(self):
        seen = []
        def process(*args, **kwargs):
            seen.append(kwargs['env'])
            return types.SimpleNamespace(returncode=0)
        environment = {'GITHUB_OUTPUT': str(self.root / 'runner-output'), 'GITHUB_TOKEN': 'private-token',
            'ACTIONS_RUNTIME_TOKEN': 'private-runtime', 'UNREVIEWED_VARIABLE': 'private-other',
            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        with patch.dict(os.environ, environment):
            self.assertEqual(wrapper.run_step(['fixed'], step='CONTROL', timeout=1,
                stream=io.StringIO(), process_run=process), 0)
        for key in ('GITHUB_OUTPUT', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
            self.assertEqual(seen[0][key], environment[key])
        for key in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'UNREVIEWED_VARIABLE'):
            self.assertNotIn(key, seen[0])

    def test_06_actual_cli_exit_two_is_not_wrapped_as_success(self):
        process = subprocess.run([sys.executable, '-I', '-B', str(Path(wrapper.__file__)),
            '--step', 'CONTROL', '--timeout', '10', '--', sys.executable, '-I', '-B', '-c',
            'raise SystemExit(2)'], capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(process.returncode, 2)
        record = json.loads(process.stdout[len(wrapper.PREFIX):])
        self.assertEqual(record['actual_child_exit'], 2)

    def test_07_unqualified_runtime_does_not_exercise_or_claim_native_pass(self):
        output = self.root / 'artifacts/controls/CI_GUARDS.log'
        with patch.object(native, 'qualified_runtime', return_value=False), \
                patch.object(native, 'exercise_reader') as forbidden, patch.object(sys, 'stdout', io.StringIO()):
            self.assertEqual(native.main(['--project', str(self.root / 'project'), '--output', str(output)]), 2)
        forbidden.assert_not_called()
        record = json.loads(output.read_text())
        self.assertEqual(record['native_fixture_execution'], 'NOT_EXECUTED')
        self.assertEqual(record['result'], 'FAIL_RUNTIME_QUALIFICATION')

    def test_08_local_real_metadata_positive_and_ctime_fault_are_exercised(self):
        record = native.exercise_reader(self.root, require_windows=False)
        self.assertEqual(record['result'], 'PASS_OWNED_STAT_FIXTURES_LOCAL_ONLY')
        self.assertEqual(record['negative_descriptor_changed_fields'], ['st_ctime_ns'])
        self.assertTrue(record['negative_control']['refused'])
        self.assertEqual(record['native_GUI_acceptance'], 'NOT_TESTED')

    def test_09_reader_that_swallows_real_change_is_caught(self):
        def broken(path):
            try:
                return controller.read_file(path)
            except ValueError:
                return native.CONTENT
        with self.assertRaisesRegex(ValueError, 'was not rejected'):
            native.exercise_reader(self.root, require_windows=False, reader=broken)

    def test_10_missing_kernel_observation_is_unexercised_not_pass(self):
        with self.assertRaises(native.Unexercised):
            native.exercise_reader(self.root, require_windows=False, reader=lambda path: native.CONTENT)

    def test_11_workflow_mutated_trigger_pin_command_and_permission_are_rejected(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/windows-stat-reader-verification.yml'
        raw = path.read_bytes()
        self.assertTrue(workflow.check(path)['result'].startswith('PASS_'))
        changes = ((b'workflow_dispatch:', b'push:'), (b'contents: read', b'contents: write'),
            (b'python-version: \'3.12.3\'', b'python-version: \'3.12\''),
            (b'--mode portability-probe', b'--mode linux-baseline'),
            (b'checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', b'checkout@main'))
        for old, new in changes:
            changed = self.root / 'changed.yml'
            self.assertIn(old, raw)
            changed.write_bytes(raw.replace(old, new))
            with self.assertRaises(ValueError):
                workflow.check(changed)

    def test_12_new_reports_use_existing_allowlist_and_preserve_failure_bytes(self):
        root = self.root / 'artifacts'
        (root / 'controls').mkdir(parents=True)
        reports = {'controls/CI_GUARDS.log': '{"result":"UNEXERCISED_NATIVE_STAT_READER_FIXTURE"}\n',
            'controls/WORKFLOW_REVIEW.json': '{"result":"FAIL_READER_VERIFICATION_WORKFLOW_TEMPLATE"}\n',
            'JOB_STATUS.json': '{"native_reader":"failure"}\n'}
        for name, text in reports.items():
            (root / name).write_text(text)
        target = self.root / 'sealed'
        record = artifacts.stage(root, target)
        self.assertEqual(record['result'], 'PASS_EXPLICIT_REPORT_ARTIFACT_ALLOWLIST')
        for name, text in reports.items():
            self.assertEqual((target / name).read_text(), text)
        self.assertEqual(record['content_secret_scan'], 'NOT_PERFORMED_BY_THIS_PATH_ALLOWLIST')

    def test_13_report_inside_frozen_project_is_rejected_before_fixture(self):
        project = self.root / 'project'
        project.mkdir()
        with patch.object(native, 'exercise_reader') as forbidden, self.assertRaisesRegex(ValueError, 'outside frozen project'):
            native.main(['--project', str(project), '--output', str(project / 'report')])
        forbidden.assert_not_called()

    def test_14_unexercised_native_metadata_stops_with_exit_two_and_raw_receipt(self):
        output = self.root / 'artifacts/controls/CI_GUARDS.log'
        with patch.object(native, 'qualified_runtime', return_value=True), \
                patch.object(native, 'exercise_reader', side_effect=native.Unexercised('FIXTURE_NOT_EXERCISED')), \
                patch.object(sys, 'stdout', io.StringIO()):
            self.assertEqual(native.main(['--project', str(self.root / 'project'), '--output', str(output)]), 2)
        self.assertEqual(json.loads(output.read_text())['result'], 'UNEXERCISED_NATIVE_STAT_READER_FIXTURE')

    def test_15_cleanup_failure_after_child_zero_cannot_leave_success(self):
        class BrokenCleanup:
            def __enter__(context):
                return str(self.root / 'private-wrapper')
            def __exit__(context, *args):
                raise OSError('private-cleanup-error')
        log = io.StringIO()
        with patch.object(wrapper.tempfile, 'TemporaryDirectory', return_value=BrokenCleanup()):
            self.assertEqual(wrapper.run_step(['fixed'], step='CONTROL', timeout=1, stream=log,
                process_run=lambda *args, **kwargs: types.SimpleNamespace(returncode=0)), 125)
        record = json.loads(log.getvalue()[len(wrapper.PREFIX):])
        self.assertEqual(record['actual_child_exit'], 0)
        self.assertEqual(record['completion'], 'INCOMPLETE')
        self.assertNotIn('private-cleanup-error', log.getvalue())

    def test_16_synthetic_entry_control_cannot_keep_not_executed_after_success(self):
        output = self.root / 'artifacts/controls/CI_GUARDS.log'
        def synthetic(directory, *, report):
            report.update(result='PASS_NATIVE_WINDOWS_STAT_READER_FIXTURES',
                native_fixture_execution='COMPLETED_OWNED_FIXTURES',
                test_scope='SYNTHETIC_ENTRY_CONTROL_NOT_NATIVE_EXECUTION')
            return report
        with patch.object(native, 'qualified_runtime', return_value=True), \
                patch.object(native, 'exercise_reader', side_effect=synthetic), \
                patch.object(sys, 'stdout', io.StringIO()):
            self.assertEqual(native.main(['--project', str(self.root / 'project'), '--output', str(output)]), 0)
        record = json.loads(output.read_text())
        self.assertEqual(record['native_fixture_execution'], 'COMPLETED_OWNED_FIXTURES')
        self.assertEqual(record['test_scope'], 'SYNTHETIC_ENTRY_CONTROL_NOT_NATIVE_EXECUTION')

    def test_17_synthetic_entry_incomplete_fixture_cannot_report_success(self):
        output = self.root / 'artifacts/controls/CI_GUARDS.log'
        def incomplete(directory, *, report):
            report.update(result='PASS_NATIVE_WINDOWS_STAT_READER_FIXTURES')
            return report
        with patch.object(native, 'qualified_runtime', return_value=True), \
                patch.object(native, 'exercise_reader', side_effect=incomplete), \
                patch.object(sys, 'stdout', io.StringIO()):
            self.assertEqual(native.main(['--project', str(self.root / 'project'), '--output', str(output)]), 1)
        record = json.loads(output.read_text())
        self.assertEqual(record['result'], 'FAIL_NATIVE_STAT_READER_FIXTURES')
        self.assertEqual(record['native_fixture_execution'], 'PREPARATION_STARTED')

    def test_18_unrepresentable_child_exit_cannot_wrap_to_shell_success(self):
        for actual, expected in ((0, 0), (1, 1), (2, 2), (255, 255), (256, 125),
                (512, 125), (0xC0000005, 125), (-9, 137), (-128, 125), (-999, 125)):
            log = io.StringIO()
            self.assertEqual(wrapper.run_step(['fixed'], step='CONTROL', timeout=1, stream=log,
                process_run=lambda *args, **kwargs: types.SimpleNamespace(returncode=actual)), expected)
            record = json.loads(log.getvalue()[len(wrapper.PREFIX):])
            self.assertEqual(record['actual_child_exit'], actual)
            self.assertEqual(record['completion'], 'CHILD_COMPLETED')
            if expected == 125:
                self.assertEqual(record['reason'], 'CHILD_EXIT_NOT_REPRESENTABLE_IN_PORTABLE_SHELL_STATUS')

    def test_19_synthetic_windows_nonisolated_fault_is_unexercised_not_native_pass(self):
        import copy
        base = {key: 10 for key in native.FIELDS}
        opened, after = dict(base, st_ctime_ns=20), dict(base, st_ctime_ns=30)
        positive = {'fixture_lstat_before': base, 'fixture_lstat_after': base,
            'fstat_opened': opened, 'fstat_after_read': opened, 'refused': False,
            'returned_expected_bytes': True}
        negative = {'fixture_lstat_before': base, 'fixture_lstat_after': base,
            'fstat_opened': opened, 'fstat_after_read': after, 'refused': True,
            'returned_expected_bytes': False}
        cases = (('fixture_lstat_after', 'st_ctime_ns', 99),
            ('fixture_lstat_after', 'st_mtime_ns', 99),
            ('fstat_opened', 'st_dev', 99), ('fstat_after_read', 'st_ctime_ns', 20))
        for index, (sample, key, value) in enumerate(cases):
            changed = copy.deepcopy(negative)
            changed[sample] = dict(changed[sample], **{key: value})
            owned = self.root / str(index)
            owned.mkdir()
            with patch.object(native, 'capture_read', side_effect=[positive, changed]), \
                    self.assertRaises(native.Unexercised):
                native.exercise_reader(owned, require_windows=True)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VerificationGuards)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 19
        and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses) else 1)
