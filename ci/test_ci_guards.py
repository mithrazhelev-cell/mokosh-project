"""Controller failure/scope/artifact contracts, using isolated synthetic trees."""
import contextlib
import copy
import hashlib
import json
import os
import signal
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_preliminary as m
import stage_report_artifacts as artifacts
import bootstrap_venv as bootstrap


class Guards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        raw = b'value = 1\n'
        (self.project / 'app.py').write_bytes(raw)
        (self.project / 'app.py').chmod(0o644)
        encoded = b'app.py'
        self.sha = hashlib.sha256(len(encoded).to_bytes(4, 'big') + encoded + len(raw).to_bytes(8, 'big') + raw).hexdigest()
        self.manifest = {'schema': 2, 'file_count': 1, 'total_bytes': len(raw),
            'verified_canonical_sha256': self.sha, 'product_mutation_allowed': False,
            'records': [{'path': 'app.py', 'bytes': len(raw), 'sha256': m.digest(raw), 'user_executable': False}],
            'metadata_contract': {'name': m.METADATA_CONTRACT, 'trusted_core_index_sha256': m.CORE_INDEX_SHA,
                'required_executable_paths': [], 'full_posix_modes_preserved_by_git': False}}
        self.manifest_path = self.root / 'SOURCE_MANIFEST.json'
        m.write_json(self.manifest_path, self.manifest)
        for name, value in (('SOURCE_SHA', self.sha), ('SOURCE_FILES', 1), ('SOURCE_BYTES', len(raw)), ('EXECUTABLE_PATHS', ())):
            replacement = patch.object(m, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.worker = self.root / 'worker.py'
        self.worker.write_text('# worker fixture\n')
        self.output = self.root / 'reports'

    def valid_record(self):
        source = {'files': 1, 'bytes': len(b'value = 1\n'), 'canonical_sha256': self.sha}
        return {'result': 'PASS_FROZEN_BASELINE_2509', 'test_modules': 92, 'discovered': 2509,
            'tests_run': 2509, 'successful_test_ids': [f'test_{i}' for i in range(2509)],
            'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [], 'unexpected_successes': [],
            'source_files_unchanged': True, 'R3_candidate_tested': False, 'source_overlay_applied': False,
            'live_apply': False, 'source_before': source, 'source_after': copy.deepcopy(source),
            'native_GUI_acceptance': 'NOT_TESTED', 'physical_GUI': 'NOT_TESTED',
            'callback_reporting_acceptance': 'NOT_TESTED_BY_THIS_UNIT_SUITE'}

    def process(self, argv, **kwargs):
        output = Path(argv[argv.index('--output') + 1])
        output.mkdir()
        m.write_json(output / 'RESULT.json', self.valid_record())
        (output / 'FULL_TESTS.log').write_text('synthetic test result fixture\n')
        kwargs['stdout'].write('fixture stdout retained\n')
        kwargs['stderr'].write('fixture stderr retained\n')
        return types.SimpleNamespace(returncode=0)

    def run_fixture(self, process=None, mode='linux-baseline'):
        runtime = lambda directory: {'python': '3.12.14', 'matches_Dell': {'Python': False, 'Tk': False},
            'Tk': None, 'Tk_display_probe': 'NOT_EXECUTED_HEADLESS', 'probe_errors': []}
        return m.run_audit(self.project, self.manifest_path, self.output, mode, self.worker,
            probe=runtime, process_run=process or self.process)

    def test_01_source_and_copy_positive_without_native_overclaim(self):
        self.assertEqual(self.run_fixture(), 0)
        result = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertTrue(result['frozen_source_unchanged'] and result['temporary_copy_unchanged'])
        self.assertEqual(result['native_GUI_acceptance'], 'NOT_EXECUTED')
        self.assertEqual(result['callback_cleanliness'], 'NOT_ESTABLISHED_BY_UNITTEST_OR_CHILD_EXIT_ZERO')
        self.assertFalse(result['runtime']['matches_Dell']['Python'])

    def test_02_wrong_source_hash_rejected_before_worker(self):
        (self.project / 'app.py').write_text('changed = True\n')
        called = []
        self.assertEqual(self.run_fixture(lambda *a, **k: called.append(True)), 1)
        self.assertEqual(called, [])

    def test_03_extra_source_path_rejected(self):
        (self.project / 'extra').write_text('x')
        with self.assertRaises(ValueError):
            m.snapshot(self.project, self.manifest)

    def test_04_symlink_source_rejected(self):
        link = self.project / 'link'
        link.symlink_to(self.worker)
        with self.assertRaises(ValueError):
            m.snapshot(self.project, self.manifest)

    def test_05_hardlinked_source_rejected(self):
        os.link(self.project / 'app.py', self.root / 'linked')
        with self.assertRaises(ValueError):
            m.snapshot(self.project, self.manifest)

    def test_06_copy_mutation_fails_and_frozen_original_stays_unchanged(self):
        def mutate(argv, **kwargs):
            value = self.process(argv, **kwargs)
            copy_path = Path(argv[argv.index('--project') + 1])
            (copy_path / 'app.py').write_text('injected_copy_mutation = True\n')
            return value
        self.assertEqual(self.run_fixture(mutate), 1)
        result = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertTrue(result['frozen_source_unchanged'])
        self.assertIn('Source bytes differ', result['error']['detail'])

    def test_07_frozen_source_mutation_is_detected_in_finally(self):
        def mutate(argv, **kwargs):
            value = self.process(argv, **kwargs)
            (self.project / 'app.py').write_text('injected_frozen_mutation = True\n')
            return value
        self.assertEqual(self.run_fixture(mutate), 1)
        self.assertIn('final_source_error', json.loads((self.output / 'AUDIT_RESULT.json').read_text()))

    def test_08_failure_error_skip_and_expected_failure_are_never_green(self):
        for name in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'):
            value = self.valid_record()
            value[name] = ['injected']
            with self.subTest(name=name), self.assertRaises(ValueError):
                m.validate_worker(value)

    def test_09_missing_or_duplicate_success_is_rejected(self):
        for change in (lambda r: r['successful_test_ids'].pop(),
                       lambda r: r['successful_test_ids'].__setitem__(0, r['successful_test_ids'][1])):
            value = self.valid_record()
            change(value)
            with self.assertRaises(ValueError):
                m.validate_worker(value)

    def test_10_false_exit_and_missing_worker_receipt_fail(self):
        def missing(argv, **kwargs):
            kwargs['stderr'].write('missing receipt raw detail\n')
            return types.SimpleNamespace(returncode=0)
        self.assertEqual(self.run_fixture(missing), 1)
        self.assertIn('missing receipt', (self.output / 'worker_stderr.log').read_text())
        self.output = self.root / 'false_exit_reports'
        def false_exit(argv, **kwargs):
            self.process(argv, **kwargs)
            return types.SimpleNamespace(returncode=False)
        self.assertEqual(self.run_fixture(false_exit), 1)

    def test_11_timeout_preserves_partial_raw_logs_and_final_source_check(self):
        def timeout(argv, **kwargs):
            kwargs['stderr'].write('partial traceback before timeout\n')
            raise subprocess.TimeoutExpired(argv, 300)
        self.assertEqual(self.run_fixture(timeout), 1)
        self.assertIn('partial traceback', (self.output / 'worker_stderr.log').read_text())
        self.assertTrue(json.loads((self.output / 'AUDIT_RESULT.json').read_text())['frozen_source_unchanged'])

    def test_12_native_callback_clean_claim_is_rejected(self):
        value = self.valid_record()
        value['callback_reporting_acceptance'] = 'PASS'
        with self.assertRaises(ValueError):
            m.validate_worker(value)

    def test_13_portability_probe_never_invokes_full_suite(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('Full suite is forbidden in portability mode')
        self.assertEqual(self.run_fixture(forbidden, 'portability-probe'), 0)
        value = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(value['full_2509'], 'NOT_EXECUTED_ON_THIS_PLATFORM')

    def test_14_child_environment_has_no_GitHub_token(self):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'secret-fixture', 'ACTIONS_RUNTIME_TOKEN': 'runtime-fixture'}):
            environment = m.child_environment(self.root)
        self.assertNotIn('GITHUB_TOKEN', environment)
        self.assertNotIn('ACTIONS_RUNTIME_TOKEN', environment)

    def test_15_artifact_allowlist_retains_fail_and_excludes_synthetic_data(self):
        root = self.root / 'artifacts'
        (root / 'report/worker/isolated_test_data').mkdir(parents=True)
        (root / 'report/AUDIT_RESULT.json').write_text('{"result":"FAIL"}\n')
        (root / 'report/worker/isolated_test_data/private_fixture.json').write_text('synthetic-not-for-upload')
        target = self.root / 'upload'
        value = artifacts.stage(root, target)
        self.assertEqual((target / 'report/AUDIT_RESULT.json').read_text(), '{"result":"FAIL"}\n')
        self.assertEqual(value['known_excluded_synthetic_data_or_cache_files'], 1)
        self.assertFalse((target / 'report/worker/isolated_test_data').exists())

    def test_16_unknown_artifact_is_blocked_but_approved_failure_logs_are_sealed(self):
        root = self.root / 'artifacts'
        root.mkdir()
        (root / 'unapproved-key.bin').write_bytes(b'fixture')
        (root / 'JOB_STATUS.json').write_text('{"result":"FAIL"}\n')
        target = self.root / 'upload'
        report = artifacts.stage(root, target)
        self.assertTrue(report['result'].startswith('FAIL_'))
        self.assertTrue((target / 'ARTIFACT_SCOPE_FAILURE.json').is_file())
        self.assertTrue((target / 'JOB_STATUS.json').is_file(), 'Approved failure report was dropped')
        self.assertEqual((target / 'JOB_STATUS.json').read_text(), '{"result":"FAIL"}\n')
        self.assertFalse((target / 'unapproved-key.bin').exists())
        with patch.object(artifacts, 'MAX_APPROVED_BYTES', 1):
            overflow = self.root / 'overflow_upload'
            value = artifacts.stage(root, overflow)
        self.assertTrue(value['result'].startswith('FAIL_'))
        receipt = json.loads((overflow / 'ARTIFACT_SCOPE_FAILURE.json').read_text())
        self.assertFalse(receipt['approved_failure_logs_preserved'])
        self.assertEqual(receipt['approved_raw_file_count'], 0)

    def test_17_artifact_symlink_blocks_staging(self):
        root = self.root / 'artifacts'
        root.mkdir()
        (root / 'JOB_STATUS.json').symlink_to(self.worker)
        target = self.root / 'upload'
        report = artifacts.stage(root, target)
        self.assertTrue(report['result'].startswith('FAIL_'))
        self.assertFalse((target / 'JOB_STATUS.json').exists())

    def test_18_bootstrap_failure_preserves_pip_log_and_source_identity(self):
        requirements = self.root / 'runtime.lock'
        requirements.write_text('example==1.0 --hash=sha256:' + '0' * 64 + '\n')
        def create(destination):
            (destination / 'bin').mkdir(parents=True)
            (destination / 'bin/python').write_text('fixture')
        def fail(*args, **kwargs):
            kwargs['stdout'].write('fixture pip failure retained\n')
            return types.SimpleNamespace(returncode=1)
        with patch.object(bootstrap.venv.EnvBuilder, 'create', side_effect=create), \
             patch.object(bootstrap, 'run_owned', side_effect=fail):
            self.assertEqual(bootstrap.bootstrap(self.project, self.manifest_path,
                self.root / 'venv', requirements, self.output), 1)
        result = json.loads((self.output / 'RESULT.json').read_text())
        self.assertTrue(result['frozen_source_unchanged'])
        self.assertIn('pip failure', (self.output / 'pip_install.log').read_text())

    def test_19_reports_inside_product_are_forbidden(self):
        with self.assertRaises(ValueError):
            m.run_audit(self.project, self.manifest_path, self.project / 'reports',
                'portability-probe', self.worker)

    def test_20_boolean_manifest_schema_rejected(self):
        value = copy.deepcopy(self.manifest)
        value['schema'] = True
        with self.assertRaises(ValueError):
            m.validate_manifest(value)

    def test_21_private_profile_and_config_environment_are_owned(self):
        with patch.dict(os.environ, {'HOME': '/host/home', 'USERPROFILE': '/host/profile',
            'APPDATA': '/host/roaming', 'LOCALAPPDATA': '/host/local', 'XDG_CONFIG_HOME': '/host/config'}):
            env = m.child_environment(self.root / 'owned')
        for key in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
                    'XDG_DATA_HOME', 'TEMP', 'TMP', 'TMPDIR'):
            self.assertIn(key, env, 'Required owned profile location missing')
            self.assertTrue(Path(env[key]).is_relative_to(self.root / 'owned'))
            self.assertTrue(Path(env[key]).is_dir())
        real = self.root / 'canonical_temp'
        real.mkdir()
        alias = self.root / 'temp_alias'
        alias.symlink_to(real, target_is_directory=True)
        with patch.dict(os.environ, {'RUNNER_TEMP': str(alias)}):
            self.assertEqual(m.private_temp_base(self.project), real.resolve())

    def test_22_same_content_chmod_is_caught_by_final_metadata(self):
        def mutate(argv, **kwargs):
            value = self.process(argv, **kwargs)
            original = self.project / 'app.py'
            original.chmod(original.stat().st_mode ^ stat.S_IXUSR)
            return value
        self.assertEqual(self.run_fixture(mutate), 1)
        self.assertIn('final_source_error', json.loads((self.output / 'AUDIT_RESULT.json').read_text()))

    def test_23_owned_timeout_stops_grandchild_heartbeat(self):
        if os.name == 'nt':
            self.fail('This fixture is explicitly a Linux CI control; Windows full-suite mode is not enabled')
        import time
        heartbeat = self.root / 'heartbeat.log'
        child = "import pathlib,time; p=pathlib.Path(" + repr(str(heartbeat)) + "); f=p.open('a');\nwhile True: f.write('x'); f.flush(); time.sleep(.02)"
        parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-I","-B","-c",' + repr(child) + ']); time.sleep(30)'
        owned_pid = None
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                m.run_owned([sys.executable, '-I', '-B', '-c', parent], timeout=.3,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=m.child_environment(self.root / 'owned_process'))
            owned_pid = caught.exception.owned_pid
            self.assertTrue(heartbeat.exists(), 'Grandchild did not exercise the process-tree fixture')
            size = heartbeat.stat().st_size
            time.sleep(.15)
            self.assertEqual(heartbeat.stat().st_size, size, 'Grandchild remained active after timeout cleanup')
        finally:
            if owned_pid is not None:
                try: os.killpg(owned_pid, signal.SIGKILL)
                except ProcessLookupError: pass


    def declare_executable_fixture(self):
        self.manifest['records'][0]['user_executable'] = True
        self.manifest['metadata_contract']['required_executable_paths'] = ['app.py']
        m.write_json(self.manifest_path, self.manifest)
        replacement = patch.object(m, 'EXECUTABLE_PATHS', ('app.py',))
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_24_missing_executable_declaration_is_rejected(self):
        del self.manifest['records'][0]['user_executable']
        with self.assertRaisesRegex(ValueError, 'Executable metadata must be a boolean'):
            m.validate_manifest(self.manifest)

    def test_25_executable_declaration_requires_actual_boolean(self):
        for invalid in (0, 1, None, 'false', 'true', [], {}):
            value = copy.deepcopy(self.manifest)
            value['records'][0]['user_executable'] = invalid
            with self.subTest(invalid=repr(invalid)), self.assertRaisesRegex(ValueError, 'must be a boolean'):
                m.validate_manifest(value)

    def test_26_untrusted_metadata_contract_is_rejected(self):
        for key, invalid in (('name', 'IGNORE_MODES'), ('trusted_core_index_sha256', '0' * 64),
                             ('full_posix_modes_preserved_by_git', True), ('required_executable_paths', ['other.py'])):
            value = copy.deepcopy(self.manifest)
            value['metadata_contract'][key] = invalid
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'metadata contract or trusted binding'):
                m.validate_manifest(value)

    def test_27_declared_executable_set_cannot_drift(self):
        self.manifest['records'][0]['user_executable'] = True
        with self.assertRaisesRegex(ValueError, 'Declared executable path set differs'):
            m.validate_manifest(self.manifest)

    def test_28_missing_physical_executable_bit_stops_before_runtime_and_worker(self):
        self.declare_executable_fixture()
        calls = []
        def forbidden(*args, **kwargs):
            calls.append('runtime_or_worker')
            raise AssertionError('Metadata omission reached execution')
        self.assertEqual(m.run_audit(self.project, self.manifest_path, self.output, 'linux-baseline',
            self.worker, probe=forbidden, process_run=forbidden), 1)
        self.assertEqual(calls, [], 'Metadata omission was not rejected before execution')
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertIn('Source user-executable metadata differs: app.py', report['error']['detail'])
        self.assertFalse((self.output / 'worker').exists())

    def test_29_extra_physical_executable_bit_stops_before_runtime_and_worker(self):
        (self.project / 'app.py').chmod(0o744)
        calls = []
        def forbidden(*args, **kwargs):
            calls.append('runtime_or_worker')
            raise AssertionError('Extra executable bit reached execution')
        self.assertEqual(m.run_audit(self.project, self.manifest_path, self.output, 'linux-baseline',
            self.worker, probe=forbidden, process_run=forbidden), 1)
        self.assertEqual(calls, [], 'Unexpected executable bit was not rejected before execution')
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertIn('Source user-executable metadata differs: app.py', report['error']['detail'])

    def test_30_expected_executable_bit_is_preserved_in_positive_copy(self):
        self.declare_executable_fixture()
        (self.project / 'app.py').chmod(0o700)
        copies = []
        def check_copy(argv, **kwargs):
            copy_path = Path(argv[argv.index('--project') + 1]) / 'app.py'
            self.assertTrue(copy_path.stat().st_mode & stat.S_IXUSR)
            copies.append(True)
            return self.process(argv, **kwargs)
        self.assertEqual(self.run_fixture(check_copy), 0)
        self.assertEqual(copies, [True])
        report = json.loads((self.output / 'AUDIT_RESULT.json').read_text())
        self.assertEqual(report['source_before']['executable_metadata']['status'], 'VERIFIED_POSIX_USER_EXECUTABLE_BITS')
        self.assertTrue(report['frozen_source_unchanged'] and report['temporary_copy_unchanged'])

    def test_31_windows_metadata_status_is_explicitly_unverified(self):
        self.declare_executable_fixture()
        self.assertFalse((self.project / 'app.py').stat().st_mode & stat.S_IXUSR)
        with patch.object(m, 'metadata_platform', return_value='nt'):
            _, receipt = m.snapshot(self.project, self.manifest)
        status = receipt['executable_metadata']
        self.assertEqual(status['status'], 'NOT_VERIFIED_POSIX_BITS_ON_WINDOWS_FILESYSTEM')
        self.assertEqual(status['declared_executable_paths'], ['app.py'])
        self.assertEqual(status['full_posix_permissions_or_ownership_reproduction'], 'NOT_CLAIMED')
        self.assertFalse((self.project / 'app.py').stat().st_mode & stat.S_IXUSR, 'Windows probe must not fake chmod')

    def test_32_unqualified_metadata_platform_is_rejected(self):
        with patch.object(m, 'metadata_platform', return_value='unknown'), \
             self.assertRaisesRegex(ValueError, 'Unqualified filesystem metadata platform'):
            m.snapshot(self.project, self.manifest)


    def test_33_missing_executable_metadata_stops_bootstrap_before_environment_creation(self):
        self.declare_executable_fixture()
        requirements = self.root / 'runtime.lock'
        requirements.write_text('example==1.0 --hash=sha256:' + '0' * 64 + '\n')
        called = []
        def forbidden(*args, **kwargs):
            called.append('environment_creation')
            raise AssertionError('Metadata omission reached environment creation')
        with patch.object(bootstrap.venv.EnvBuilder, 'create', side_effect=forbidden):
            self.assertEqual(bootstrap.bootstrap(self.project, self.manifest_path,
                self.root / 'venv', requirements, self.output), 1)
        self.assertEqual(called, [], 'Bootstrap did not reject executable metadata before installation')
        record = json.loads((self.output / 'RESULT.json').read_text())
        self.assertIn('Source user-executable metadata differs: app.py', record['error']['detail'])
        self.assertFalse((self.root / 'venv').exists())

    def stat_fixture(self, value, **changes):
        values = {key: getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode',
            'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        values.update(changes)
        return types.SimpleNamespace(**values)

    @contextlib.contextmanager
    def reader_samples(self, before, opened, after, post):
        # These deterministic shape controls complement the separately prepared
        # native test. They do not claim a real Windows kernel observation.
        path = self.project / 'app.py'
        with patch.object(m, 'safe_path', return_value=path), \
                patch.object(Path, 'lstat', autospec=True, side_effect=[before, post]), \
                patch.object(m.os, 'fstat', side_effect=[opened, after]):
            yield path

    def test_34_stable_windows_shaped_cross_api_ctime_is_positive(self):
        value = (self.project / 'app.py').stat()
        fd = self.stat_fixture(value, st_ctime_ns=value.st_ctime_ns + 100)
        with self.reader_samples(value, fd, fd, value) as path:
            self.assertEqual(m.read_file(path), b'value = 1\n')

    def test_35_same_handle_ctime_only_change_is_rejected(self):
        value = (self.project / 'app.py').stat()
        opened = self.stat_fixture(value, st_ctime_ns=value.st_ctime_ns + 100)
        after = self.stat_fixture(value, st_ctime_ns=value.st_ctime_ns + 101)
        with self.reader_samples(value, opened, after, value) as path, \
                self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
            m.read_file(path)

    def test_36_posix_preopen_ctime_change_is_rejected_even_with_stable_fd(self):
        before = (self.project / 'app.py').stat()
        later = self.stat_fixture(before, st_ctime_ns=before.st_ctime_ns + 100)
        with self.reader_samples(before, later, later, later) as path, \
                self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
            m.read_file(path)

    def test_37_post_path_changed_fields_are_all_rejected(self):
        value = (self.project / 'app.py').stat()
        cases = {'st_dev': value.st_dev + 1, 'st_ino': value.st_ino + 1,
            'st_mode': stat.S_IFLNK | 0o644, 'st_nlink': 2, 'st_size': value.st_size + 1,
            'st_mtime_ns': value.st_mtime_ns + 1, 'st_ctime_ns': value.st_ctime_ns + 1}
        for key, changed in cases.items():
            with self.subTest(field=key), self.reader_samples(value, value, value,
                    self.stat_fixture(value, **{key: changed})) as path, \
                    self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
                m.read_file(path)

    def test_38_opened_descriptor_type_link_and_bound_are_checked(self):
        value = (self.project / 'app.py').stat()
        cases = ({'st_mode': stat.S_IFDIR | 0o700}, {'st_nlink': 2},
            {'st_size': 32 * 1024 * 1024 + 1}, {'st_size': -1})
        for changes in cases:
            with self.subTest(changes=changes), self.reader_samples(value,
                    self.stat_fixture(value, **changes), value, value) as path, \
                    self.assertRaisesRegex(ValueError, '^Non-regular, linked or oversized source file$'):
                m.read_file(path)

    def test_39_opened_descriptor_comparable_metadata_is_bound_before_read(self):
        value = (self.project / 'app.py').stat()
        for key, changed in (('st_mode', value.st_mode ^ stat.S_IXUSR),
                ('st_size', value.st_size + 1), ('st_mtime_ns', value.st_mtime_ns + 1)):
            with self.subTest(field=key), self.reader_samples(value,
                    self.stat_fixture(value, **{key: changed}), value, value) as path, \
                    self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
                m.read_file(path)

    def test_40_same_handle_changed_fields_are_all_rejected(self):
        value = (self.project / 'app.py').stat()
        cases = {'st_dev': value.st_dev + 1, 'st_ino': value.st_ino + 1,
            'st_mode': value.st_mode ^ stat.S_IXUSR, 'st_nlink': 2, 'st_size': value.st_size + 1,
            'st_mtime_ns': value.st_mtime_ns + 1, 'st_ctime_ns': value.st_ctime_ns + 1}
        for key, changed in cases.items():
            with self.subTest(field=key), self.reader_samples(value, value,
                    self.stat_fixture(value, **{key: changed}), value) as path, \
                    self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
                m.read_file(path)

    def test_41_guard_post_path_sample_occurs_while_descriptor_held(self):
        path = self.project / 'app.py'
        real_fstat, real_lstat = os.fstat, Path.lstat
        held = []
        samples = []
        def capture(fd):
            held.append(fd)
            return real_fstat(fd)
        def sample(target):
            samples.append(1)
            if len(samples) == 2:
                self.assertEqual(len(held), 2)
                self.assertEqual(real_fstat(held[0]).st_ino, real_lstat(target).st_ino)
            return real_lstat(target)
        with patch.object(m, 'safe_path', return_value=path), \
                patch.object(m.os, 'fstat', side_effect=capture), \
                patch.object(Path, 'lstat', autospec=True, side_effect=sample):
            self.assertEqual(m.read_file(path), b'value = 1\n')
        self.assertEqual(len(samples), 2)
        with self.assertRaises(OSError):
            real_fstat(held[0])

    def test_42_same_length_content_mutation_restored_mtime_fails_manifest_hash(self):
        path = self.project / 'app.py'
        value = path.stat()
        path.write_bytes(b'value = 2\n')
        os.utime(path, ns=(value.st_atime_ns, value.st_mtime_ns))
        self.assertEqual(path.stat().st_size, value.st_size)
        self.assertEqual(path.stat().st_mtime_ns, value.st_mtime_ns)
        with self.assertRaisesRegex(ValueError, '^Source bytes differ: app.py$'):
            m.snapshot(self.project, self.manifest)

    def test_43_read_length_and_bounded_request_are_enforced(self):
        path = self.project / 'app.py'
        real = path.open
        requests = []
        class Stream:
            def __init__(self, stream, raw):
                self.stream, self.raw = stream, raw
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def read(self, limit):
                requests.append(limit)
                return self.raw
        for raw in (b'', b'value = 1', b'value = 1\nX'):
            stream = Stream(real('rb'), raw)
            with patch.object(m, 'safe_path', return_value=path), \
                    patch.object(Path, 'open', return_value=stream), \
                    self.assertRaisesRegex(ValueError, '^Source changed while reading$'):
                m.read_file(path)
        self.assertEqual(requests, [32 * 1024 * 1024 + 1] * 3)

    def test_44_stager_accepts_unchanged_approved_report_with_cross_api_ctime(self):
        root = self.root / 'artifacts'
        root.mkdir()
        (root / 'JOB_STATUS.json').write_bytes(b'{}\n')
        real_fstat = os.fstat
        def different_api_ctime(fd):
            value = real_fstat(fd)
            return self.stat_fixture(value, st_ctime_ns=value.st_ctime_ns + 100)
        with patch.object(m.os, 'fstat', side_effect=different_api_ctime):
            result = artifacts.stage(root, self.root / 'sealed')
        self.assertEqual(result['result'], 'PASS_EXPLICIT_REPORT_ARTIFACT_ALLOWLIST')
        self.assertEqual((self.root / 'sealed/JOB_STATUS.json').read_bytes(), b'{}\n')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Guards)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 44
        and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses) else 1)
