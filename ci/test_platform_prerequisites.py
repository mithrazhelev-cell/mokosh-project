"""Stdlib-only prerequisite protocol guards with explicit synthetic observations.

These fixtures do not qualify product storage, Linux/Windows/macOS support, GUI,
or power-loss durability. A COMPLETE diagnostic receipt can contain findings.
"""
from pathlib import Path
from contextlib import redirect_stdout
import copy
import hashlib
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
import functional_cohort_contract as runtime_contract
import platform_prerequisites_contract as contract
import platform_prerequisites_probes as probes
import platform_prerequisites_worker as worker
import run_platform_prerequisites as controller
import stage_report_artifacts as artifacts
import validate_platform_prerequisites_workflow as workflow

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_GUARD_TESTS = 49
RUN_METADATA = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA',
    'RUNNER_OS', 'ImageOS', 'ImageVersion')


def synthetic_source():
    rows = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))['records']
    names = [row['path'] for row in rows]
    directories = {'.', 'docs', 'tests', 'third_party', 'third_party/bip39'}
    return {'files': 263, 'bytes': 5223645,
        'canonical_sha256': '92e159ed818bc6fbf858549452ad78fd0b238f9d8193ac9842147555afb3dcca',
        'per_file_sha256': {row['path']: row['sha256'] for row in rows},
        'observed_file_modes': {name: 0o644 for name in names},
        'non_atime_metadata': {name: {'fixture': 'SYNTHETIC_NOT_NATIVE'}
            for name in [*names, *sorted(directories)]}}


def synthetic_runtime(target='linux-x64'):
    platform, os_name, machine = {'linux-x64': ('linux', 'posix', 'x86_64'),
        'windows-x64': ('win32', 'nt', 'amd64'),
        'macos-arm64': ('darwin', 'posix', 'arm64')}[target]
    return {'python': '3.12.3', 'sys_platform': platform, 'os_name': os_name,
        'machine': machine, 'dependencies': dict(contract.load_contract()['dependency_pins']),
        'isolated': True, 'dont_write_bytecode': True, 'target': target,
        'qualification': 'CI_EXACT_PY3123', 'CI_runtime_qualified': True,
        'python_ssl_openssl': 'synthetic stdlib runtime observation',
        'cryptography_openssl': 'synthetic crypto runtime observation'}


def synthetic_log(target='linux-x64'):
    ids = contract.expected_ids(target)
    lines = [test_id.rsplit('.', 1)[-1] + ' (' + test_id + ') ... ok' for test_id in ids]
    return '\n'.join([*lines, '', '-' * 70,
        'Ran ' + str(len(ids)) + ' tests in 0.001s', '', 'OK', ''])


def synthetic_probe_rows(target='linux-x64'):
    """Fabricated observations, including fabricated metadata; never native evidence."""
    metadata = {'device': 1, 'inode': 2, 'st_mode': 0o100600, 'mode': 0o600,
        'size': len(probes.PAYLOAD), 'mtime_ns': 100, 'ctime_ns': 100,
        'uid': 1000, 'gid': 1000, 'uid_present': True, 'gid_present': True,
        'birthtime_ns': None, 'links': 1}
    directory = dict(metadata, inode=3, st_mode=0o40700, mode=0o700, size=0)
    integrity = {'payload_sha256': hashlib.sha256(probes.PAYLOAD).hexdigest(),
        'collision_sha256': hashlib.sha256(probes.COLLISION).hexdigest(),
        'sibling_sha256': hashlib.sha256(probes.SIBLING).hexdigest(),
        'owned_temporary_removed': True}
    observations = [
        {'path_before': copy.deepcopy(metadata), 'fd_before': copy.deepcopy(metadata),
         'fd_after': copy.deepcopy(metadata), 'path_after': copy.deepcopy(metadata),
         'same_api_path_unchanged': True, 'same_api_fd_unchanged': True,
         'cross_api_identity_deltas': [], 'verified_source_outcome': 'READ_AND_VERIFIED',
         'verified_source_exception': None, 'bytes_read': len(probes.PAYLOAD),
         'evidence_scope': 'INDEPENDENT_CALL_NOT_INTERNAL_STAT_TRACE'},
        {'file_before': copy.deepcopy(metadata), 'file_after': copy.deepcopy(metadata),
         'directory_before': copy.deepcopy(directory), 'directory_after': copy.deepcopy(directory),
         'chmod_file_returned': True, 'chmod_directory_returned': True,
         'fchmod_available': False, 'fchmod_returned': None,
         'permission_model': 'WINDOWS_READONLY_FLAG_ONLY_NO_ACL_ACCEPTANCE'
             if target == 'windows-x64' else 'POSIX_MODE_OBSERVATION_ONLY'},
        {'file_result': 'RETURNED', 'directory_open_result': 'OPENED',
         'directory_fsync_result': 'RETURNED', 'crash_durability': 'NOT_TESTED',
         'file_descriptor_regular': True, 'directory_descriptor_verified': True},
        {'declared_dir_fd': {name: False for name in ('open', 'stat', 'unlink', 'link')},
         'declared_follow_symlinks': {name: False for name in ('stat', 'link')},
         'declared_fd': {'listdir': False},
         'flags': {name: False for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC')},
         'fchmod_available': False, 'getuid_available': False, 'getgid_available': False,
         'capability_scope': 'DECLARED_API_MEMBERSHIP_NOT_NATIVE_GUARANTEE', 'tested_operations': []},
        {'profile_require': 'RETURNED' if target == 'linux-x64' else 'EXPECTED_UNSUPPORTED',
         'profile_inspect': {'state': 'ABSENT' if target == 'linux-x64' else 'UNSUPPORTED',
             'reason': '' if target == 'linux-x64' else 'platform',
             'legacy_login_records_present': False},
         'profile_create_invalid_nickname': 'EXPECTED_VALIDATION_REFUSAL'
             if target == 'linux-x64' else 'EXPECTED_UNSUPPORTED',
         'phrase_filesystem_magic': {'result': 'LINUX_MAGIC' if target == 'linux-x64'
             else 'EXPECTED_UNSUPPORTED', 'value': 0xef53 if target == 'linux-x64' else None},
         'local_v2_gate': 'RETURNED' if target == 'linux-x64' else 'EXPECTED_UNSUPPORTED',
         'private_tree_unchanged': True}]
    for value in observations:
        value['integrity'] = copy.deepcopy(integrity)
    return [{'id': name, 'execution': 'COMPLETE_OBSERVATION', 'observations': value,
        'os_errors': [], 'product_support': 'NOT_ACCEPTED'}
        for name, value in zip(contract.PROBE_IDS, observations)]


def synthetic_probe_stdout(rows):
    return ''.join(contract.PROBE_PREFIX + json.dumps(row, sort_keys=True, ensure_ascii=True,
        allow_nan=False) + '\n' for row in rows)


def synthetic_record(*, runtime=None, source=None, worker_sha='a' * 64, probes_sha='b' * 64):
    runtime = synthetic_runtime() if runtime is None else runtime
    source = synthetic_source() if source is None else source
    target = runtime['target']
    ids = contract.expected_ids(target)
    modules = sorted({'.'.join(name.split('.')[:2]) for name in ids})
    bindings = {name: {'path': name.replace('.', '/') + '.py',
        'sha256': source['per_file_sha256'][name.replace('.', '/') + '.py']} for name in modules}
    return {'schema': 1, 'scope': contract.SCOPE,
        'result': contract.CI_PASS if runtime['CI_runtime_qualified'] else contract.LAB_PASS,
        'contract_sha256': contract.CONTRACT_SHA256, 'worker_sha256': worker_sha,
        'probes_sha256': probes_sha, 'runtime': copy.deepcopy(runtime), 'target': target,
        'local_lab': not runtime['CI_runtime_qualified'], 'test_modules': len(modules),
        'test_module_names': modules, 'discovered': len(ids), 'tests_run': len(ids),
        'discovered_test_ids': ids[:], 'successful_test_ids': ids[:],
        'successful_test_count': len(ids), 'unique_successful_test_count': len(ids),
        'probe_count': 5, 'probe_rows': synthetic_probe_rows(target),
        'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
        'unexpected_successes': [], 'discovery_errors': [],
        'source_before': copy.deepcopy(source), 'source_after': copy.deepcopy(source),
        'source_files_unchanged': True, 'tool_files_unchanged': True,
        'source_overlay_applied': False, 'R3_candidate_tested': False, 'live_apply': False,
        'product_support': 'NOT_ACCEPTED', 'native_GUI_acceptance': 'NOT_TESTED',
        'physical_GUI': 'NOT_TESTED', 'product_storage_acceptance': 'NOT_TESTED',
        'full2509': 'NOT_EXECUTED_BY_THIS_SUITE', 'prior248': 'NOT_EXECUTED_BY_THIS_SUITE',
        'loaded_test_module_bindings': copy.deepcopy(bindings),
        'loaded_product_module_bindings': copy.deepcopy(bindings)}


class ContractGuards(unittest.TestCase):
    def setUp(self):
        self.runtime = synthetic_runtime()
        self.source = synthetic_source()
        self.record = synthetic_record(runtime=self.runtime, source=self.source)

    def validate(self, record=None, *, runtime=None, raw_log=None, raw_probes=None):
        record = self.record if record is None else record
        runtime = self.runtime if runtime is None else runtime
        return contract.validate_worker_result(record,
            synthetic_log(runtime['target']).encode('ascii') if raw_log is None else raw_log,
            expected_runtime=runtime, expected_source=self.source,
            expected_worker_sha256='a' * 64, expected_probes_sha256='b' * 64,
            raw_probe_stdout=synthetic_probe_stdout(record['probe_rows']).encode('ascii')
                if raw_probes is None else raw_probes)

    def test_01_manifest_selects_fixed_distinct_35_posix_and_21_windows_cases(self):
        value = contract.load_contract()
        self.assertEqual({target: len(contract.expected_ids(target)) for target in
            ('linux-x64', 'windows-x64', 'macos-arm64')},
            {'linux-x64': 35, 'windows-x64': 21, 'macos-arm64': 35})
        self.assertEqual(contract.expected_ids('linux-x64'), contract.expected_ids('macos-arm64'))
        self.assertEqual(len(value['probe_ids']), 5)
        with self.assertRaisesRegex(ValueError, '^Unknown platform prerequisites target$'):
            contract.expected_ids('unknown')

    def test_02_modified_manifest_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve(strict=True) / 'changed.json'
            path.write_bytes(contract.CONTRACT_PATH.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, '^Pinned platform prerequisites manifest bytes differ$'):
                contract.load_contract(path)

    def test_03_complete_synthetic_receipts_validate_for_each_fixed_target(self):
        for target, count in (('linux-x64', 35), ('windows-x64', 21), ('macos-arm64', 35)):
            runtime = synthetic_runtime(target)
            with self.subTest(target=target):
                self.assertEqual(self.validate(synthetic_record(runtime=runtime), runtime=runtime), count)

    def test_04_external_stat_samples_do_not_claim_internal_constructor_causality(self):
        for change in ('refusal_without_externaldelta', 'read_with_externaldelta'):
            record = copy.deepcopy(self.record)
            value = record['probe_rows'][0]['observations']
            if change == 'refusal_without_externaldelta':
                value['verified_source_outcome'] = 'CONSTRUCTOR_IDENTITY_REFUSAL'
                value['verified_source_exception'] = 'SourceChangedError'
                value['bytes_read'] = 0
            else:
                value['fd_before']['ctime_ns'] += 1
                value['fd_after']['ctime_ns'] += 1
                value['cross_api_identity_deltas'] = ['ctime_ns']
            with self.subTest(change=change):
                self.assertEqual(self.validate(record), 35)
        self.assertEqual(self.record['product_support'], 'NOT_ACCEPTED')

    def test_05_missing_duplicate_and_reordered_probe_rows_are_rejected(self):
        for change in ('missing', 'duplicate', 'reordered'):
            value = copy.deepcopy(self.record)
            if change == 'missing':
                value['probe_rows'].pop()
            elif change == 'duplicate':
                value['probe_rows'][1] = copy.deepcopy(value['probe_rows'][0])
            else:
                value['probe_rows'].reverse()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_06_forged_product_pass_at_row_receipt_or_result_is_rejected(self):
        for level in ('row', 'receipt', 'result'):
            value = copy.deepcopy(self.record)
            if level == 'row':
                value['probe_rows'][0]['product_support'] = 'PASS'
            elif level == 'receipt':
                value['product_support'] = 'PASS'
            else:
                value['result'] = 'PASS_PRODUCT_PLATFORM'
            with self.subTest(level=level), self.assertRaises(ValueError):
                self.validate(value)

    def test_07_typed_counts_and_complete_execution_are_required(self):
        for field in ('discovered', 'tests_run', 'successful_test_count',
                      'unique_successful_test_count', 'probe_count'):
            for wrong in (False, '35', 0):
                value = copy.deepcopy(self.record)
                value[field] = wrong
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError):
                    self.validate(value)
        self.record['probe_rows'][0]['execution'] = 'SKIPPED'
        with self.assertRaises(ValueError):
            self.validate()

    def test_08_failure_error_skip_xfail_xpass_or_discovery_error_cannot_complete(self):
        for field in ('failures', 'errors', 'skipped', 'expected_failures',
                      'unexpected_successes', 'discovery_errors'):
            value = copy.deepcopy(self.record)
            value[field] = ['SYNTHETIC_FAULT']
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_09_missing_duplicate_or_substituted_selected_id_is_rejected(self):
        for field in ('discovered_test_ids', 'successful_test_ids'):
            for change in ('missing', 'duplicate', 'substituted'):
                value = copy.deepcopy(self.record)
                if change == 'missing':
                    value[field].pop()
                elif change == 'duplicate':
                    value[field][0] = value[field][1]
                else:
                    value[field][0] = 'tests.test_synthetic_only.Fixture.test_unlisted'
                with self.subTest(field=field, change=change), self.assertRaises(ValueError):
                    self.validate(value)

    def test_10_selected_test_and_product_module_origins_must_match_source_bytes(self):
        for change in ('missing', 'ambient', 'wronghash', 'alias'):
            value = copy.deepcopy(self.record)
            name = next(iter(value['loaded_test_module_bindings']))
            if change == 'missing':
                value['loaded_product_module_bindings'].pop(name)
            elif change == 'ambient':
                value['loaded_product_module_bindings'][name]['path'] = '/ambient/test.py'
            elif change == 'wronghash':
                value['loaded_product_module_bindings'][name]['sha256'] = '0' * 64
            else:
                value['loaded_product_module_bindings']['ambient_alias'] = copy.deepcopy(
                    value['loaded_product_module_bindings'][name])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_11_runtime_contract_worker_and_probe_hashes_are_bound(self):
        for field in ('contract_sha256', 'worker_sha256', 'probes_sha256', 'runtime'):
            value = copy.deepcopy(self.record)
            if field == 'runtime':
                value['runtime']['python'] = '3.12.14'
            else:
                value[field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_12_raw_test_log_rejects_missing_duplicate_failed_skipped_and_wrong_summary(self):
        raw = synthetic_log().encode('ascii')
        lines = raw.splitlines()
        changed = (b'\n'.join(lines[1:]) + b'\n', raw.replace(lines[0], lines[1], 1),
            raw.replace(b'... ok', b'... FAIL', 1),
            raw.replace(b'... ok', b"... skipped 'synthetic'", 1),
            raw.replace(b'Ran 35 tests', b'Ran 34 tests'), raw[:-1], raw + b'OK\n')
        for value in changed:
            with self.subTest(tail=value[-80:]), self.assertRaises(ValueError):
                self.validate(raw_log=value)
        self.assertEqual(self.validate(raw_log=raw.replace(b'\n', b'\r\n')), 35)

    def test_13_raw_probe_stdout_must_match_all_five_strict_rows_exactly(self):
        raw = synthetic_probe_stdout(self.record['probe_rows']).encode('ascii')
        lines = raw.splitlines()
        changed = (b'\n'.join(lines[1:]) + b'\n', raw.replace(lines[0], lines[1], 1),
            raw + b'COMPLETE\n', raw[:-1], raw.replace(b'{', b'{"id":"forged",', 1))
        for value in changed:
            with self.subTest(tail=value[-60:]), self.assertRaises(ValueError):
                self.validate(raw_probes=value)
        rows = copy.deepcopy(self.record['probe_rows'])
        rows[3]['observations']['flags']['O_CLOEXEC'] = True
        with self.assertRaises(ValueError):
            self.validate(raw_probes=synthetic_probe_stdout(rows).encode('ascii'))

    def test_14_omitted_invented_delta_or_internal_trace_overclaim_is_rejected(self):
        for change in ('omitteddelta', 'inventeddelta', 'causaloverclaim'):
            value = copy.deepcopy(self.record)
            observed = value['probe_rows'][0]['observations']
            if change == 'omitteddelta':
                observed['fd_before']['ctime_ns'] += 1
                observed['fd_after']['ctime_ns'] += 1
            elif change == 'inventeddelta':
                observed['cross_api_identity_deltas'] = ['ctime_ns']
            else:
                observed['evidence_scope'] = 'INTERNAL_PRODUCT_CONSTRUCTOR_STAT_TRACE'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_15_supported_fsync_os_error_is_recorded_and_masked_error_is_rejected(self):
        import errno
        value = copy.deepcopy(self.record)
        row = value['probe_rows'][2]
        row['observations']['file_result'] = 'OS_ERROR'
        row['os_errors'] = [{'operation': 'fsync_file', 'exception': 'OSError',
            'errno': errno.EINVAL, 'winerror': None, 'expected': True}]
        self.assertEqual(self.validate(value), 35)
        row['observations']['file_result'] = 'RETURNED'
        with self.assertRaises(ValueError):
            self.validate(value)
        row['observations']['file_result'] = 'OS_ERROR'
        row['os_errors'][0]['errno'] = errno.EIO
        with self.assertRaises(ValueError):
            self.validate(value)
        row['os_errors'] = []
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_16_non_linux_product_gate_cannot_be_reported_as_supported(self):
        for target in ('windows-x64', 'macos-arm64'):
            runtime = synthetic_runtime(target)
            for field in ('profile_require', 'local_v2_gate'):
                value = synthetic_record(runtime=runtime)
                value['probe_rows'][4]['observations'][field] = 'RETURNED'
                with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                    self.validate(value, runtime=runtime)

    def test_17_capability_membership_cannot_claim_tested_operations_or_durability(self):
        for change in ('operations', 'durability'):
            value = copy.deepcopy(self.record)
            if change == 'operations':
                value['probe_rows'][3]['observations']['tested_operations'] = ['hardlink']
            else:
                value['probe_rows'][2]['observations']['crash_durability'] = 'PASS'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_18_full_source_pair_and_probe_integrity_are_required(self):
        for change in ('source', 'payload', 'cleanup'):
            value = copy.deepcopy(self.record)
            if change == 'source':
                value['source_after']['non_atime_metadata']['.']['fixture'] = 'changed'
            elif change == 'payload':
                value['probe_rows'][0]['observations']['integrity']['payload_sha256'] = '0' * 64
            else:
                value['probe_rows'][0]['observations']['integrity']['owned_temporary_removed'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_19_overlay_live_apply_gui_storage_and_prior_suite_overclaims_are_rejected(self):
        changes = {'source_overlay_applied': True, 'R3_candidate_tested': True,
            'live_apply': True, 'native_GUI_acceptance': 'PASS', 'physical_GUI': 'PASS',
            'product_storage_acceptance': 'PASS', 'full2509': 'PASS', 'prior248': 'PASS'}
        for field, wrong in changes.items():
            value = copy.deepcopy(self.record)
            value[field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_20_probe_schema_unknown_fields_nonfinite_or_unexpected_os_errors_are_rejected(self):
        for change in ('unknown', 'nan', 'oserror'):
            value = copy.deepcopy(self.record)
            row = value['probe_rows'][0]
            if change == 'unknown':
                row['observations']['arbitrary'] = True
            elif change == 'nan':
                row['observations']['bytes_read'] = float('nan')
            else:
                row['os_errors'] = [{'operation': 'open_directory', 'exception': 'PermissionError',
                    'errno': 13, 'winerror': None, 'expected': True}]
            message = {'unknown': '^Native identity observation incomplete$',
                'nan': '^Probe observation number is non-finite$',
                'oserror': '^Unexpected OS error outside fsync observation$'}[change]
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                # A NaN fixture cannot be serialized; use a valid raw stream
                # only in that case, then require the actual schema's refusal.
                self.validate(value, raw_probes=synthetic_probe_stdout(
                    self.record['probe_rows']).encode('ascii') if change == 'nan' else None)


class RuntimeGuards(unittest.TestCase):
    def qualify_synthetic(self, *, version='3.12.3', target='linux-x64', os_name='posix',
            sys_platform='linux', machine='x86_64', local_lab=False, environment=None,
            dependencies=None):
        new_pinned, old_pinned = contract.load_contract(), runtime_contract.load_contract()
        dependencies = old_pinned['dependency_pins'] if dependencies is None else dependencies
        with patch.object(runtime_contract.platform, 'python_version', return_value=version), \
             patch.object(runtime_contract.sys, 'version_info', tuple(map(int, version.split('.'))) + ('final', 0)), \
             patch.object(runtime_contract.sys, 'platform', sys_platform), \
             patch.object(runtime_contract.os, 'name', os_name), \
             patch.object(runtime_contract.platform, 'machine', return_value=machine), \
             patch.object(contract, 'load_contract', return_value=new_pinned), \
             patch.object(runtime_contract, '_pinned_contract', return_value=old_pinned), \
             patch.object(runtime_contract, 'dependency_versions', return_value=dependencies), \
             patch.object(runtime_contract, 'crypto_openssl_version', return_value='SYNTHETIC_NOT_NATIVE'), \
             patch.dict(os.environ, {} if environment is None else environment, clear=True):
            return contract.qualify_runtime(target, local_lab=local_lab)

    def test_21_lab_is_explicit_linux_only_and_runner_identity_blocks_it(self):
        value = self.qualify_synthetic(version='3.12.14', local_lab=True)
        self.assertFalse(value['CI_runtime_qualified'])
        self.assertEqual(value['qualification'], 'LOCAL_LAB_NOT_CI_QUALIFIED')
        for name in ('CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.qualify_synthetic(version='3.12.14', local_lab=True, environment={name: '0'})
        with self.assertRaises(ValueError):
            self.qualify_synthetic(version='3.12.14', target='windows-x64', os_name='nt',
                sys_platform='win32', machine='amd64', local_lab=True)

    def test_22_wrong_version_platform_machine_or_dependency_cannot_qualify(self):
        self.assertTrue(self.qualify_synthetic()['CI_runtime_qualified'])
        for values in ({'version': '3.12.14'}, {'target': 'macos-arm64'}, {'machine': 'arm64'},
            {'dependencies': dict(contract.load_contract()['dependency_pins'], cryptography='50.0.0')}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.qualify_synthetic(**values)


class WorkflowGuards(unittest.TestCase):
    def test_23_exact_reviewed_workflow_positive_and_protected_scope(self):
        path = ROOT / '.github/workflows/platform-prerequisites.yml'
        self.assertEqual(workflow.check(path)['sha256'], workflow.EXPECTED_SHA256)

    def test_24_changed_policy_pin_command_target_or_lab_flag_is_rejected(self):
        raw = (ROOT / '.github/workflows/platform-prerequisites.yml').read_bytes()
        changes = ((b'workflow_dispatch:', b'push:'), (b'contents: read', b'contents: write'),
            (b"python-version: '3.12.3'", b"python-version: '3.12'"),
            (b'architecture: arm64', b'architecture: x64'),
            (b'fail-fast: false', b'fail-fast: true'), (b'--target', b'--local-lab --target'),
            (b'checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', b'checkout@main'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            path = root / 'changed.yml'
            for before, after in changes:
                self.assertIn(before, raw)
                path.write_bytes(raw.replace(before, after))
                with self.subTest(before=before), self.assertRaisesRegex(ValueError,
                        '^Platform prerequisite workflow differs from the exact reviewed template$'):
                    workflow.check(path)

    def test_25_workflow_review_cannot_write_inside_product(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            project = root / 'project'
            project.mkdir()
            with self.assertRaisesRegex(ValueError, '^Workflow review output must be outside frozen project$'):
                workflow.main(['--workflow', str(ROOT / '.github/workflows/platform-prerequisites.yml'),
                    '--project', str(project), '--output', str(project / 'injected.json')])
            self.assertEqual(list(project.iterdir()), [])

    def test_26_existing_allowlist_keeps_prerequisite_failure_reports_and_no_source(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory).resolve(strict=True)
            root = temporary_root / 'artifacts'
            (root / 'report/worker').mkdir(parents=True)
            (root / 'report/AUDIT_RESULT.json').write_text('{"result":"FAIL_PREREQUISITES"}\n')
            (root / 'report/worker/RESULT.json').write_text('{"result":"FAIL_WORKER"}\n')
            (root / 'report/worker/FULL_TESTS.log').write_text('synthetic failed product test detail\n')
            (root / 'report/worker_stdout.log').write_text('synthetic partial probe stdout\n')
            (root / 'report/worker_stderr.log').write_text('synthetic child error detail\n')
            result = artifacts.stage(root, temporary_root / 'sealed')
            self.assertEqual(result['result'], 'PASS_EXPLICIT_REPORT_ARTIFACT_ALLOWLIST')
            self.assertEqual(set(result['files']), {'report/AUDIT_RESULT.json',
                'report/worker/RESULT.json', 'report/worker/FULL_TESTS.log',
                'report/worker_stdout.log', 'report/worker_stderr.log'})



class ControllerGuards(unittest.TestCase):
    """Synthetic process/snapshot seams prove refusal and final-check control flow."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.manifest = self.root / 'SOURCE_MANIFEST.json'
        self.manifest.write_bytes((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
        self.output = self.root / 'reports'
        self.runtime = synthetic_runtime()
        self.source = synthetic_source()
        self.snapshots = []
        self.invocations = []

    def snapshot(self, project, manifest, *, phase, **kwargs):
        self.snapshots.append((Path(project), phase))
        return {'mokosh_v2_format.py': b'# SYNTHETIC CONTROLLER COPY FIXTURE\n'}, copy.deepcopy(self.source)

    def process(self, argv, **kwargs):
        self.invocations.append((argv, kwargs))
        output = Path(argv[argv.index('--output') + 1])
        output.mkdir()
        value = synthetic_record(runtime=self.runtime, source=self.source,
            worker_sha=hashlib.sha256(controller.WORKER_PATH.read_bytes()).hexdigest(),
            probes_sha=hashlib.sha256(controller.PROBES_PATH.read_bytes()).hexdigest())
        value['GitHub_run'] = {key: os.environ.get(key) for key in ('GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}
        (output / 'RESULT.json').write_text(json.dumps(value) + '\n')
        (output / 'FULL_TESTS.log').write_text(synthetic_log(), encoding='ascii')
        kwargs['stdout'].write(synthetic_probe_stdout(value['probe_rows']))
        kwargs['stderr'].write('SYNTHETIC CHILD STDERR\n')
        return types.SimpleNamespace(returncode=0)

    def run_fixture(self, process=None, snapshot=None):
        with patch.object(controller, 'snapshot', side_effect=snapshot or self.snapshot), \
             patch.object(controller, 'qualify_runtime', return_value=self.runtime):
            return controller.run_prerequisites(self.project, self.manifest, self.output, 'linux-x64',
                process_run=process or self.process)

    def receipt(self):
        return json.loads((self.output / 'AUDIT_RESULT.json').read_text())

    def test_27_synthetic_parent_positive_checks_final_source_copy_and_cleanup(self):
        self.assertEqual(self.run_fixture(), 0)
        value = self.receipt()
        self.assertEqual(value['result'], controller.CI_RESULT)
        self.assertTrue(value['frozen_source_unchanged'] and value['temporary_copy_unchanged'])
        self.assertTrue(value['owned_temporary_removed'] and value['tool_files_unchanged'])
        self.assertFalse(value['temporary_copy_retained'])
        self.assertEqual(value['native_GUI_acceptance'], 'NOT_TESTED')
        self.assertEqual([phase for path, phase in self.snapshots],
            ['FROZEN_BEFORE', 'COPY_BEFORE', 'COPY_FINAL', 'FROZEN_FINAL'])

    def test_28_actual_typed_worker_exit_is_required_even_with_complete_record(self):
        for code in (1, 2, False, None, '0'):
            self.output = self.root / ('exit_' + str(code))
            def changed(argv, **kwargs):
                self.process(argv, **kwargs)
                return types.SimpleNamespace(returncode=code)
            with self.subTest(code=code):
                self.assertEqual(self.run_fixture(changed), 1)
                self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_29_missing_receipt_cannot_pass_and_partial_raw_log_is_retained(self):
        def missing(argv, **kwargs):
            kwargs['stderr'].write('synthetic partial child detail before missing receipt\n')
            return types.SimpleNamespace(returncode=0)
        self.assertEqual(self.run_fixture(missing), 1)
        self.assertIn('partial child detail', (self.output / 'worker_stderr.log').read_text())
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_30_timeout_is_failure_with_source_and_copy_final_checks(self):
        def timeout(argv, **kwargs):
            kwargs['stderr'].write('synthetic timeout partial child evidence\n')
            raise subprocess.TimeoutExpired(argv, 300)
        self.assertEqual(self.run_fixture(timeout), 1)
        value = self.receipt()
        self.assertTrue(value['frozen_source_unchanged'] and value['temporary_copy_unchanged'])
        self.assertTrue(value['owned_temporary_removed'])
        self.assertIn('timeout partial', (self.output / 'worker_stderr.log').read_text())

    def test_31_invalid_raw_log_cannot_be_rescued_by_green_worker_json(self):
        def badlog(argv, **kwargs):
            result = self.process(argv, **kwargs)
            output = Path(argv[argv.index('--output') + 1])
            (output / 'FULL_TESTS.log').write_text('OK\n')
            return result
        self.assertEqual(self.run_fixture(badlog), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_32_final_frozen_metadata_change_overrides_worker_success(self):
        def changed(project, manifest, *, phase, **kwargs):
            files, value = self.snapshot(project, manifest, phase=phase)
            if phase == 'FROZEN_FINAL':
                value['non_atime_metadata']['.']['fixture'] = 'mutated'
            return files, value
        self.assertEqual(self.run_fixture(snapshot=changed), 1)
        self.assertFalse(self.receipt()['frozen_source_unchanged'])
        self.assertIn('final_source_error', self.receipt())

    def test_33_final_copy_metadata_change_overrides_worker_success(self):
        def changed(project, manifest, *, phase, **kwargs):
            files, value = self.snapshot(project, manifest, phase=phase)
            if phase == 'COPY_FINAL':
                value['non_atime_metadata']['.']['fixture'] = 'mutated'
            return files, value
        self.assertEqual(self.run_fixture(snapshot=changed), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertFalse(self.receipt()['temporary_copy_unchanged'])

    def test_34_cleanup_exception_after_valid_child_cannot_leave_success(self):
        original = tempfile.TemporaryDirectory
        class BrokenCleanup:
            def __init__(context, *args, **kwargs):
                context.real = original(*args, **kwargs)
            def __enter__(context):
                return context.real.__enter__()
            def __exit__(context, *args):
                context.real.__exit__(*args)
                raise OSError('synthetic cleanup refusal after successful child')
        with patch.object(controller.tempfile, 'TemporaryDirectory', BrokenCleanup):
            self.assertEqual(self.run_fixture(), 1)
        self.assertTrue(self.receipt()['owned_temporary_removed'])
        self.assertEqual(self.receipt()['result'], controller.FAIL_RESULT)

    def test_35_ci_tool_binding_change_overrides_worker_success(self):
        original = controller.tool_bindings
        calls = []
        def changed(path):
            value = original(path)
            calls.append(True)
            if len(calls) > 1:
                value['ci/platform_prerequisites_worker.py'] = '0' * 64
            return value
        with patch.object(controller, 'tool_bindings', side_effect=changed):
            self.assertEqual(self.run_fixture(), 1)
        self.assertFalse(self.receipt()['tool_files_unchanged'])

    def test_36_output_inside_frozen_project_is_rejected_before_process(self):
        self.output = self.project / 'reports'
        with self.assertRaises(ValueError):
            self.run_fixture()
        self.assertEqual(self.invocations, [])
        self.assertFalse(self.output.exists())

    def test_37_worker_environment_keeps_identity_but_omits_tokens_and_outputs(self):
        values = {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40,
            'GITHUB_TOKEN': 'private-fixture-token', 'ACTIONS_RUNTIME_TOKEN': 'private-runtime',
            'GITHUB_OUTPUT': str(self.root / 'not-for-worker'), 'UNREVIEWED_VARIABLE': 'private-other'}
        with patch.dict(os.environ, values):
            env = controller.worker_environment(self.root)
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA'):
            self.assertEqual(env[key], values[key])
        for key in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'GITHUB_OUTPUT', 'UNREVIEWED_VARIABLE'):
            self.assertNotIn(key, env)

    def test_38_runtime_qualification_failure_never_launches_worker(self):
        with patch.object(controller, 'snapshot', side_effect=self.snapshot), \
             patch.object(controller, 'qualify_runtime', side_effect=ValueError('synthetic qualification failure')):
            self.assertEqual(controller.run_prerequisites(self.project, self.manifest, self.output, 'linux-x64',
                process_run=self.process), 1)
        self.assertEqual(self.invocations, [])
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_39_duplicate_json_worker_result_cannot_be_accepted(self):
        def duplicate(argv, **kwargs):
            result = self.process(argv, **kwargs)
            output = Path(argv[argv.index('--output') + 1])
            raw = (output / 'RESULT.json').read_text()
            (output / 'RESULT.json').write_text(raw.replace('{', '{"tests_run":0,', 1))
            return result
        self.assertEqual(self.run_fixture(duplicate), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertEqual(self.receipt()['error']['type'], 'ValueError')
        # Diagnostic wording differs between strict parsers; refusal and the
        # duplicate-JSON classification are the contract being tested.
        self.assertIn('Duplicate', self.receipt()['error']['detail'])
        self.assertIn('JSON', self.receipt()['error']['detail'])

    def test_40_strict_json_rejects_duplicate_members_and_nonstandard_constants(self):
        self.assertEqual(contract.strict_json('{"synthetic":1}'), {'synthetic': 1})
        for raw in ('{"synthetic":0,"synthetic":1}', '{"synthetic":NaN}',
                    '{"synthetic":Infinity}', '{"synthetic":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                contract.strict_json(raw)

    def test_41_report_short_write_flush_and_close_failure_cannot_return_success(self):
        for failure in ('short', 'flush', 'close'):
            class BrokenStream:
                def __enter__(stream):
                    return stream
                def write(stream, raw):
                    return 1 if failure == 'short' else len(raw)
                def flush(stream):
                    if failure == 'flush':
                        raise OSError('synthetic report flush failure')
                def __exit__(stream, *args):
                    if failure == 'close':
                        raise OSError('synthetic report close failure')
            class SyntheticPath:
                def open(path, *args, **kwargs):
                    return BrokenStream()
            with self.subTest(failure=failure), \
                 patch.object(controller, 'safe_path', return_value=SyntheticPath()), \
                 self.assertRaises((ValueError, OSError)):
                controller._write_json(self.root / 'SYNTHETIC.json', {'result': 'SYNTHETIC'})

    def test_42_parent_rejects_nonstandard_number_even_in_an_unused_receipt_field(self):
        def nonstandard(argv, **kwargs):
            result = self.process(argv, **kwargs)
            output = Path(argv[argv.index('--output') + 1])
            raw = (output / 'RESULT.json').read_text()
            (output / 'RESULT.json').write_text(raw.replace('{', '{"duration_seconds":NaN,', 1))
            return result
        self.assertEqual(self.run_fixture(nonstandard), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertEqual(self.receipt()['error']['type'], 'ValueError')

    def test_43_wrong_or_missing_actual_run_identity_cannot_keep_green_worker_json(self):
        for change in ('changed', 'missing'):
            self.output = self.root / ('run_identity_' + change)
            def mismatch(argv, **kwargs):
                result = self.process(argv, **kwargs)
                output = Path(argv[argv.index('--output') + 1])
                value = json.loads((output / 'RESULT.json').read_text())
                if change == 'changed':
                    value['GitHub_run']['GITHUB_RUN_ID'] = 'synthetic-wrong-run'
                else:
                    value.pop('GitHub_run')
                (output / 'RESULT.json').write_text(json.dumps(value) + '\n')
                return result
            with self.subTest(change=change):
                self.assertEqual(self.run_fixture(mismatch), 1)
                self.assertTrue(self.receipt()['frozen_source_unchanged'])


    def test_44_parent_rejects_valid_probe_stdout_rows_that_differ_from_receipt(self):
        def mismatch(argv, **kwargs):
            result = self.process(argv, **kwargs)
            rows = synthetic_probe_rows()
            rows[3]['observations']['flags']['O_CLOEXEC'] = True
            kwargs['stdout'].seek(0)
            kwargs['stdout'].truncate()
            kwargs['stdout'].write(synthetic_probe_stdout(rows))
            return result
        self.assertEqual(self.run_fixture(mismatch), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertEqual(self.receipt()['error']['detail'],
            'Raw native probe rows differ from worker receipt')


class DiscoveryGuards(unittest.TestCase):
    def test_45_worker_rejects_unlisted_id_or_loader_error_before_any_test_execution(self):
        expected = contract.expected_ids('linux-x64')
        trace = 'Traceback (most recent call last):\nImportError: SYNTHETIC_ONLY loader error'
        variants = (([*expected[:-1], 'tests.test_synthetic_only.Fixture.test_unlisted'], []),
            (expected, [trace]))
        for ids, errors in variants:
            attempted = []
            class SyntheticCase(unittest.TestCase):
                def __init__(case, test_id):
                    super().__init__('runTest')
                    case.test_id = test_id
                def id(case):
                    return case.test_id
                def runTest(case):
                    attempted.append(case.test_id)
            suite = unittest.TestSuite(SyntheticCase(test_id) for test_id in ids)
            loader = types.SimpleNamespace(errors=errors, loadTestsFromNames=lambda names: suite)
            fake_probes = types.SimpleNamespace(__file__=str(worker.PROBES_PATH),
                run_probes=lambda root, target: synthetic_probe_rows(target))
            old_cwd, old_path = os.getcwd(), sys.path[:]
            old_tests = sys.modules.get('tests')
            with self.subTest(errors=bool(errors)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(strict=True)
                project = root / 'synthetic_project'
                project.mkdir()
                manifest = root / 'SYNTHETIC_MANIFEST.json'
                manifest.write_text('{}\n')
                output = root / 'worker'
                captured = io.StringIO()
                try:
                    with patch.dict(os.environ), patch.dict(sys.modules), \
                         patch.object(worker, 'qualify_runtime', return_value=synthetic_runtime()), \
                         patch.object(worker, 'snapshot', return_value=([], synthetic_source())) as snapshots, \
                         patch.object(worker.importlib, 'import_module', return_value=fake_probes), \
                         patch.object(worker.unittest, 'TestLoader', return_value=loader), \
                         patch.object(worker.unittest, 'TextTestRunner') as runner, \
                         redirect_stdout(captured):
                        # The guard imports the real stdlib-only probe module;
                        # this fake child must begin with its own clean namespace.
                        sys.modules.pop('platform_prerequisites_probes', None)
                        self.assertEqual(worker.run_worker(project, manifest, output, 'linux-x64'), 1)
                        runner.assert_not_called()
                        self.assertEqual(snapshots.call_count, 2)
                    receipt = json.loads((output / 'RESULT.json').read_text())
                    raw_log = (output / 'FULL_TESTS.log').read_text()
                finally:
                    os.chdir(old_cwd)
                    sys.path[:] = old_path
                    if old_tests is None:
                        sys.modules.pop('tests', None)
                    else:
                        sys.modules['tests'] = old_tests
                self.assertEqual(attempted, [])
                self.assertEqual(receipt['tests_run'], 0)
                self.assertEqual(receipt['result'], 'FAIL_PLATFORM_PREREQUISITES')
                self.assertTrue(receipt['source_files_unchanged'])
                self.assertEqual(receipt['discovery_errors'], errors)
                self.assertIn('Exact prerequisite discovery must succeed before executing any test', raw_log)
                self.assertEqual(len(captured.getvalue().splitlines()), 5)
                if errors:
                    self.assertIn(trace, raw_log)


class ProbeGuards(unittest.TestCase):
    def test_46_only_explicit_operation_target_and_error_pairs_are_observations(self):
        import errno
        supported = OSError(errno.EINVAL, 'SYNTHETIC_UNSUPPORTED')
        self.assertEqual(probes._os_error('fsync_file', supported, 'linux-x64'),
            {'operation': 'fsync_file', 'exception': 'OSError', 'errno': errno.EINVAL,
             'winerror': None, 'expected': True})
        native_windows_refusal = PermissionError(errno.EACCES, 'SYNTHETIC_DIRECTORY_REFUSAL')
        self.assertEqual(probes._os_error('open_directory', native_windows_refusal,
            'windows-x64')['exception'], 'PermissionError')
        boolean_errno = OSError(errno.EINVAL, 'SYNTHETIC_INVALID_BOOLEAN_ERRNO')
        boolean_errno.errno = True
        boolean_winerror = OSError(errno.EINVAL, 'SYNTHETIC_INVALID_BOOLEAN_WINERROR')
        boolean_winerror.winerror = True
        for operation, error, target in (
            ('fsync_file', OSError(errno.EIO, 'SYNTHETIC_IO_FAILURE'), 'linux-x64'),
            ('fsync_file', FileNotFoundError(errno.ENOENT, 'SYNTHETIC_BAD_PATH'), 'linux-x64'),
            ('open_directory', native_windows_refusal, 'linux-x64'),
            ('fsync_file', boolean_errno, 'linux-x64'),
            ('fsync_file', boolean_winerror, 'windows-x64'),
            ('unknown', supported, 'linux-x64')):
            with self.subTest(operation=operation, target=target), self.assertRaises(OSError) as caught:
                probes._os_error(operation, error, target)
            self.assertIs(caught.exception, error)

    def test_47_fsync_protocol_retains_supported_error_and_propagates_unexpected_error(self):
        """Synthetic descriptors exercise error handling; no native durability claim."""
        import errno
        import stat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            def observed_descriptor(descriptor):
                return types.SimpleNamespace(st_mode=stat.S_IFREG if descriptor == 11 else stat.S_IFDIR)
            with patch.object(probes.os, 'open', side_effect=[11, 12]), \
                 patch.object(probes.os, 'fstat', side_effect=observed_descriptor), \
                 patch.object(probes.os, 'close') as close, \
                 patch.object(probes.os, 'fsync', side_effect=[OSError(errno.EINVAL,
                     'SYNTHETIC_UNSUPPORTED_FILE_FSYNC'), None]):
                observed, errors = probes._fsync_probe(root, 'linux-x64')
            self.assertEqual(observed['file_result'], 'OS_ERROR')
            self.assertEqual(observed['directory_fsync_result'], 'RETURNED')
            self.assertEqual([args.args[0] for args in close.call_args_list], [11, 12])
            rows = synthetic_probe_rows()
            observed['integrity'] = rows[2]['observations']['integrity']
            rows[2].update(observations=observed, os_errors=errors)
            contract.validate_probe_rows(rows, 'linux-x64')
            unexpected = OSError(errno.EIO, 'SYNTHETIC_UNEXPECTED_FILE_FSYNC')
            with patch.object(probes.os, 'open', return_value=11), \
                 patch.object(probes.os, 'fstat', side_effect=observed_descriptor), \
                 patch.object(probes.os, 'close') as close, \
                 patch.object(probes.os, 'fsync', side_effect=unexpected), \
                 self.assertRaises(OSError) as caught:
                probes._fsync_probe(root, 'linux-x64')
            self.assertIs(caught.exception, unexpected)
            close.assert_called_once_with(11)

    def test_48_probe_root_must_be_fresh_canonical_before_product_imports(self):
        target = {'linux': 'linux-x64', 'win32': 'windows-x64', 'darwin': 'macos-arm64'}[sys.platform]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            existing = root / 'already_exists'
            existing.mkdir()
            for path in (existing, Path('SYNTHETIC_RELATIVE_PATH')):
                with self.subTest(path=str(path)), self.assertRaisesRegex(ValueError,
                        '^A fresh canonical owned probe leaf is required$'):
                    probes.run_probes(path, target=target)
            self.assertEqual(list(existing.iterdir()), [])


    def test_49_constructor_refusal_is_an_observation_but_later_source_failure_is_not(self):
        """Synthetic product objects distinguish constructor and later failures."""
        class SyntheticSourceChanged(Exception):
            pass
        class SyntheticIdentity:
            @staticmethod
            def from_stat(value):
                observed = probes._stat(value)
                return types.SimpleNamespace(**{key: observed[key] for key in probes.IDENTITY_FIELDS})
        def refused(*args, **kwargs):
            raise SyntheticSourceChanged('SYNTHETIC_CONSTRUCTOR_REFUSAL')
        filesystem = types.SimpleNamespace(FileIdentity=SyntheticIdentity,
            SourceChangedError=SyntheticSourceChanged, VerifiedFileSource=refused)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            probes._create(root / 'payload.bin', probes.PAYLOAD)
            observed, errors = probes._identity_probe(root, filesystem)
            self.assertEqual(observed['verified_source_outcome'], 'CONSTRUCTOR_IDENTITY_REFUSAL')
            self.assertEqual(observed['evidence_scope'], 'INDEPENDENT_CALL_NOT_INTERNAL_STAT_TRACE')
            rows = synthetic_probe_rows()
            observed['integrity'] = rows[0]['observations']['integrity']
            rows[0].update(observations=observed, os_errors=errors)
            contract.validate_probe_rows(rows, 'linux-x64')
            class SyntheticLaterFailure:
                closed = False
                def __init__(source):
                    source.chunks = iter((probes.PAYLOAD, b''))
                def read(source, size):
                    return next(source.chunks)
                def verify_and_close(source):
                    raise SyntheticSourceChanged('SYNTHETIC_LATE_VERIFY_FAILURE')
                def close(source):
                    source.closed = True
            later = SyntheticLaterFailure()
            filesystem.VerifiedFileSource = lambda *args, **kwargs: later
            with self.assertRaisesRegex(ValueError,
                    '^Product source changed after its constructor returned$'):
                probes._identity_probe(root, filesystem)
            self.assertTrue(later.closed)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == EXPECTED_GUARD_TESTS
        and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses) else 1)
