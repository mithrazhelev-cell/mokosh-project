"""Portable CI protocol guards using explicit synthetic records, not native acceptance.

The positive receipt fixtures below do not execute the 248 product cases. The
real cohort is a separate bounded worker invocation with its own raw evidence.
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
import functional_cohort_contract as contract
import run_functional_cohort as controller
import run_functional_cohort_worker as worker
import stage_report_artifacts as artifacts
import validate_functional_cohort_workflow as workflow

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_GUARD_TESTS = 49


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


def synthetic_runtime():
    return {'python': '3.12.3', 'sys_platform': 'linux', 'os_name': 'posix',
        'machine': 'x86_64', 'dependencies': dict(contract.load_contract()['dependency_pins']),
        'isolated': True, 'dont_write_bytecode': True, 'target': 'linux-x64',
        'qualification': 'CI_EXACT_PY3123', 'CI_runtime_qualified': True,
        'python_ssl_openssl': 'synthetic stdlib runtime observation',
        'cryptography_openssl': 'synthetic crypto runtime observation'}


def synthetic_log(cohort=None):
    cohort = contract.load_contract() if cohort is None else cohort
    lines = [testid.rsplit('.', 1)[-1] + ' (' + testid + ') ... ok'
        for testid in cohort['expected_successful_test_ids']]
    return '\n'.join([*lines, '', '-' * 70, 'Ran 248 tests in 0.001s', '', 'OK', ''])


def synthetic_record(*, runtime=None, source=None, worker_sha='a' * 64):
    cohort = contract.load_contract()
    runtime = synthetic_runtime() if runtime is None else runtime
    source = synthetic_source() if source is None else source
    bindings = {}
    for module in cohort['test_modules']:
        path = module.replace('.', '/') + '.py'
        bindings[module] = {'path': path, 'sha256': source['per_file_sha256'][path]}
    return {'schema': 1, 'scope': cohort['scope'],
        'result': 'PASS_FUNCTIONAL_COHORT_248' if runtime['CI_runtime_qualified']
            else 'PASS_LOCAL_LAB_FUNCTIONAL_COHORT_248',
        'contract_sha256': contract.CONTRACT_SHA256, 'worker_sha256': worker_sha,
        'runtime': copy.deepcopy(runtime), 'target': runtime['target'],
        'local_lab': not runtime['CI_runtime_qualified'], 'test_modules': 12,
        'test_module_names': list(cohort['test_modules']), 'discovered': 248,
        'tests_run': 248, 'discovered_test_ids': list(cohort['expected_successful_test_ids']),
        'successful_test_ids': list(cohort['expected_successful_test_ids']),
        'successful_test_count': 248, 'unique_successful_test_count': 248,
        'mandatory_real_mlkem_success_ids': list(cohort['mandatory_real_mlkem_test_ids']),
        'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
        'unexpected_successes': [], 'discovery_errors': [], 'source_before': copy.deepcopy(source),
        'source_after': copy.deepcopy(source), 'source_files_unchanged': True,
        'source_overlay_applied': False, 'R3_candidate_tested': False, 'live_apply': False,
        'native_GUI_acceptance': 'NOT_TESTED', 'physical_GUI': 'NOT_TESTED',
        'product_storage_acceptance': 'NOT_TESTED', 'full2509': 'NOT_EXECUTED_BY_COHORT',
        'loaded_test_module_bindings': copy.deepcopy(bindings),
        'loaded_product_module_bindings': copy.deepcopy(bindings)}


class ContractGuards(unittest.TestCase):
    def setUp(self):
        self.cohort = contract.load_contract()
        self.runtime = synthetic_runtime()
        self.source = synthetic_source()
        self.record = synthetic_record(runtime=self.runtime, source=self.source)
        self.raw_log = synthetic_log(self.cohort)

    def validate(self, record=None, raw_log=None):
        return contract.validate_worker_result(self.record if record is None else record,
            self.raw_log if raw_log is None else raw_log, self.cohort,
            expected_runtime=self.runtime, expected_source=self.source,
            expected_worker_sha256='a' * 64)

    def test_01_pinned_contract_and_synthetic_complete_receipt_positive(self):
        self.assertEqual(len(set(self.cohort['expected_successful_test_ids'])), 248)
        self.assertEqual(len(self.cohort['mandatory_real_mlkem_test_ids']), 6)
        self.validate()

    def test_02_modified_cohort_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'changed.json'
            path.write_bytes(contract.CONTRACT_PATH.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                contract.load_contract(path)

    def test_03_missing_or_duplicate_success_id_is_rejected(self):
        for mutate in (lambda ids: ids.pop(), lambda ids: ids.__setitem__(0, ids[1])):
            value = copy.deepcopy(self.record)
            mutate(value['successful_test_ids'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate(value)

    def test_04_unlisted_success_id_is_rejected_even_with_correct_count(self):
        self.record['successful_test_ids'][0] = 'tests.unlisted.Fixture.test_injected'
        with self.assertRaises(ValueError):
            self.validate()

    def test_05_missing_or_wrong_discovery_inventory_is_rejected(self):
        for field in ('discovered', 'tests_run', 'successful_test_count', 'unique_successful_test_count'):
            for wrong in (247, 249, False, '248'):
                value = copy.deepcopy(self.record)
                value[field] = wrong
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError):
                    self.validate(value)

    def test_06_failure_error_skip_xfail_xpass_never_pass(self):
        for field in ('failures', 'errors', 'skipped', 'expected_failures',
                      'unexpected_successes', 'discovery_errors'):
            value = copy.deepcopy(self.record)
            value[field] = ['synthetic fault']
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_07_real_mlkem_inventory_missing_or_substituted_is_rejected(self):
        for mutate in (lambda ids: ids.pop(),
                       lambda ids: ids.__setitem__(0, self.cohort['expected_successful_test_ids'][0])):
            value = copy.deepcopy(self.record)
            mutate(value['mandatory_real_mlkem_success_ids'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate(value)

    def test_08_changed_source_metadata_pair_is_rejected(self):
        self.record['source_after']['non_atime_metadata']['.']['fixture'] = 'changed'
        with self.assertRaises(ValueError):
            self.validate()

    def test_09_changed_source_hash_or_missing_manifest_member_is_rejected(self):
        for action in ('hash', 'missing'):
            value = copy.deepcopy(self.record)
            name = next(iter(value['source_before']['per_file_sha256']))
            if action == 'hash':
                value['source_before']['per_file_sha256'][name] = '0' * 64
            else:
                value['source_before']['per_file_sha256'].pop(name)
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.validate(value)

    def test_10_worker_contract_and_source_bindings_must_be_exact(self):
        for field in ('worker_sha256', 'contract_sha256'):
            value = copy.deepcopy(self.record)
            value[field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_11_execution_scope_and_no_overlay_claims_are_enforced(self):
        for field in ('source_overlay_applied', 'R3_candidate_tested', 'live_apply'):
            value = copy.deepcopy(self.record)
            value[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_12_gui_storage_or_full_suite_overclaim_is_rejected(self):
        for field in ('native_GUI_acceptance', 'physical_GUI', 'product_storage_acceptance', 'full2509'):
            value = copy.deepcopy(self.record)
            value[field] = 'PASS'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_13_loaded_test_binding_missing_or_changed_is_rejected(self):
        for change in ('missing', 'hash', 'path'):
            value = copy.deepcopy(self.record)
            name = self.cohort['test_modules'][0]
            if change == 'missing':
                value['loaded_test_module_bindings'].pop(name)
            else:
                value['loaded_test_module_bindings'][name][change if change == 'path' else 'sha256'] = (
                    '../outside.py' if change == 'path' else '0' * 64)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_14_loaded_product_binding_must_stay_inside_frozen_source(self):
        self.record['loaded_product_module_bindings']['unapproved'] = {
            'path': '../outside.py', 'sha256': '0' * 64}
        with self.assertRaises(ValueError):
            self.validate()

    def test_15_runtime_record_change_cannot_keep_success(self):
        for field, value in (('python', '3.12.14'), ('target', 'windows-x64'),
                             ('CI_runtime_qualified', False)):
            changed = copy.deepcopy(self.record)
            changed['runtime'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(changed)

    def test_16_raw_log_requires_exact_unique_successes(self):
        lines = self.raw_log.splitlines()
        for changed in ('\n'.join(lines[1:]) + '\n',
                        self.raw_log.replace(lines[0], lines[1], 1)):
            with self.subTest(changed=changed[:80]), self.assertRaises(ValueError):
                self.validate(raw_log=changed)

    def test_17_raw_log_rejects_failure_skip_and_spurious_pass_text(self):
        first = self.raw_log.splitlines()[0]
        for changed in (self.raw_log.replace(first, first.replace('... ok', '... FAIL'), 1),
                        self.raw_log.replace(first, first.replace('... ok', "... skipped 'synthetic'"), 1),
                        self.raw_log + 'injected spurious successful narrative\n'):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                self.validate(raw_log=changed)

    def test_18_raw_log_requires_complete_matching_summary_and_newline(self):
        for changed in (self.raw_log.replace('Ran 248 tests', 'Ran 247 tests'),
                        self.raw_log.replace('\nOK\n', '\nOK (skipped=1)\n'),
                        self.raw_log[:-1], self.raw_log + 'OK\n'):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                self.validate(raw_log=changed)

    def test_19_crlf_raw_log_is_equivalent_not_a_platform_failure(self):
        self.validate(raw_log=self.raw_log.replace('\n', '\r\n'))

    def test_20_lab_result_cannot_masquerade_as_ci_result(self):
        self.record['result'] = 'PASS_LOCAL_LAB_FUNCTIONAL_COHORT_248'
        self.record['local_lab'] = True
        with self.assertRaises(ValueError):
            self.validate()


class RuntimeGuards(unittest.TestCase):
    def qualify_synthetic(self, *, version='3.12.3', target='linux-x64', os_name='posix',
            sys_platform='linux', machine='x86_64', local_lab=False, environment=None,
            dependencies=None):
        pinned = contract.load_contract()
        dependencies = (pinned['dependency_pins'] if dependencies is None else dependencies)
        with patch.object(contract.platform, 'python_version', return_value=version), \
             patch.object(contract.sys, 'version_info', tuple(map(int, version.split('.'))) + ('final', 0)), \
             patch.object(contract.sys, 'platform', sys_platform), \
             patch.object(contract.os, 'name', os_name), \
             patch.object(contract.platform, 'machine', return_value=machine), \
             patch.object(contract, '_pinned_contract', return_value=pinned), \
             patch.object(contract, 'dependency_versions', return_value=dependencies), \
             patch.object(contract, 'crypto_openssl_version', return_value='SYNTHETIC_BACKEND_NOT_NATIVE'), \
             patch.dict(os.environ, {} if environment is None else environment, clear=True):
            return contract.qualify_runtime(target, local_lab=local_lab)

    def test_21_three_synthetic_runtime_targets_bind_exact_python_and_machine(self):
        for values in ({}, {'target': 'windows-x64', 'os_name': 'nt', 'sys_platform': 'win32', 'machine': 'AMD64'},
                       {'target': 'macos-arm64', 'sys_platform': 'darwin', 'machine': 'arm64'}):
            with self.subTest(values=values):
                result = self.qualify_synthetic(**values)
                self.assertTrue(result['CI_runtime_qualified'])
                self.assertEqual(result['qualification'], 'CI_EXACT_PY3123')

    def test_22_wrong_python_is_rejected_without_local_lab(self):
        with self.assertRaises(ValueError):
            self.qualify_synthetic(version='3.12.14')

    def test_23_lab_is_explicit_linux_only_and_not_ci_qualified(self):
        value = self.qualify_synthetic(version='3.12.14', local_lab=True)
        self.assertFalse(value['CI_runtime_qualified'])
        self.assertEqual(value['qualification'], 'LOCAL_LAB_NOT_CI_QUALIFIED')
        with self.assertRaises(ValueError):
            self.qualify_synthetic(version='3.12.14', local_lab=True,
                target='windows-x64', os_name='nt', sys_platform='win32', machine='AMD64')

    def test_24_any_runner_identity_blocks_local_lab(self):
        for name in ('CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.qualify_synthetic(version='3.12.14', local_lab=True, environment={name: '0'})

    def test_25_wrong_platform_or_machine_is_rejected(self):
        for values in ({'target': 'macos-arm64'}, {'machine': 'arm64'},
                       {'target': 'windows-x64', 'os_name': 'nt', 'sys_platform': 'win32', 'machine': 'arm64'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.qualify_synthetic(**values)

    def test_26_missing_or_wrong_dependency_pin_is_rejected(self):
        original = contract.load_contract()['dependency_pins']
        for change in ('missing', 'wrong'):
            pins = dict(original)
            if change == 'missing':
                pins.pop('cryptography')
            else:
                pins['cryptography'] = '50.0.0'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.qualify_synthetic(dependencies=pins)


class WorkflowGuards(unittest.TestCase):
    def test_27_exact_reviewed_workflow_positive_and_protected_scope(self):
        path = ROOT / '.github/workflows/functional-cohort-248.yml'
        self.assertEqual(workflow.check(path)['sha256'], workflow.EXPECTED_SHA256)

    def test_28_changed_policy_pin_command_target_or_lab_flag_is_rejected(self):
        raw = (ROOT / '.github/workflows/functional-cohort-248.yml').read_bytes()
        changes = ((b'workflow_dispatch:', b'push:'), (b'contents: read', b'contents: write'),
            (b"python-version: '3.12.3'", b"python-version: '3.12'"),
            (b'architecture: arm64', b'architecture: x64'),
            (b'fail-fast: false', b'fail-fast: true'), (b'--target', b'--local-lab --target'),
            (b'checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', b'checkout@main'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'changed.yml'
            for before, after in changes:
                self.assertIn(before, raw)
                path.write_bytes(raw.replace(before, after))
                with self.subTest(before=before), self.assertRaises(ValueError):
                    workflow.check(path)

    def test_29_workflow_review_cannot_write_inside_product(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / 'project'
            project.mkdir()
            with self.assertRaises(ValueError):
                workflow.main(['--workflow', str(ROOT / '.github/workflows/functional-cohort-248.yml'),
                    '--project', str(project), '--output', str(project / 'injected.json')])
            self.assertEqual(list(project.iterdir()), [])

    def test_30_existing_allowlist_keeps_cohort_failure_reports_and_no_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'artifacts'
            (root / 'report/worker').mkdir(parents=True)
            (root / 'report/AUDIT_RESULT.json').write_text('{"result":"FAIL_COHORT"}\n')
            (root / 'report/worker/RESULT.json').write_text('{"result":"FAIL_WORKER"}\n')
            (root / 'report/worker/FULL_TESTS.log').write_text('synthetic failed product test detail\n')
            result = artifacts.stage(root, Path(directory) / 'sealed')
            self.assertEqual(result['result'], 'PASS_EXPLICIT_REPORT_ARTIFACT_ALLOWLIST')
            self.assertEqual(set(result['files']), {'report/AUDIT_RESULT.json',
                'report/worker/RESULT.json', 'report/worker/FULL_TESTS.log'})


class ControllerGuards(unittest.TestCase):
    """Synthetic process/snapshot seams prove refusal and final-check control flow."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
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
            worker_sha=hashlib.sha256(controller.WORKER_PATH.read_bytes()).hexdigest())
        value['GitHub_run'] = {key: os.environ.get(key) for key in ('GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}
        (output / 'RESULT.json').write_text(json.dumps(value) + '\n')
        (output / 'FULL_TESTS.log').write_text(synthetic_log(), encoding='ascii')
        kwargs['stdout'].write('SYNTHETIC CHILD STDOUT: not actual 248 test execution\n')
        kwargs['stderr'].write('SYNTHETIC CHILD STDERR\n')
        return types.SimpleNamespace(returncode=0)

    def run_fixture(self, process=None, snapshot=None):
        with patch.object(controller, 'snapshot', side_effect=snapshot or self.snapshot), \
             patch.object(controller, 'qualify_runtime', return_value=self.runtime):
            return controller.run_cohort(self.project, self.manifest, self.output, 'linux-x64',
                process_run=process or self.process)

    def receipt(self):
        return json.loads((self.output / 'AUDIT_RESULT.json').read_text())

    def test_31_synthetic_parent_positive_checks_final_source_copy_and_cleanup(self):
        self.assertEqual(self.run_fixture(), 0)
        value = self.receipt()
        self.assertEqual(value['result'], controller.PASS_CI)
        self.assertTrue(value['frozen_source_unchanged'] and value['temporary_copy_unchanged'])
        self.assertTrue(value['owned_temporary_removed'] and value['tool_files_unchanged'])
        self.assertFalse(value['temporary_copy_retained'])
        self.assertEqual(value['native_GUI_acceptance'], 'NOT_TESTED')
        self.assertEqual([phase for path, phase in self.snapshots],
            ['FROZEN_BEFORE', 'COPY_BEFORE', 'COPY_FINAL', 'FROZEN_FINAL'])

    def test_32_actual_typed_worker_exit_is_required_even_with_complete_record(self):
        for code in (1, 2, False, None, '0'):
            self.output = self.root / ('exit_' + str(code))
            def changed(argv, **kwargs):
                self.process(argv, **kwargs)
                return types.SimpleNamespace(returncode=code)
            with self.subTest(code=code):
                self.assertEqual(self.run_fixture(changed), 1)
                self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_33_missing_receipt_cannot_pass_and_partial_raw_log_is_retained(self):
        def missing(argv, **kwargs):
            kwargs['stderr'].write('synthetic partial child detail before missing receipt\n')
            return types.SimpleNamespace(returncode=0)
        self.assertEqual(self.run_fixture(missing), 1)
        self.assertIn('partial child detail', (self.output / 'worker_stderr.log').read_text())
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_34_timeout_is_failure_with_source_and_copy_final_checks(self):
        def timeout(argv, **kwargs):
            kwargs['stderr'].write('synthetic timeout partial child evidence\n')
            raise subprocess.TimeoutExpired(argv, 300)
        self.assertEqual(self.run_fixture(timeout), 1)
        value = self.receipt()
        self.assertTrue(value['frozen_source_unchanged'] and value['temporary_copy_unchanged'])
        self.assertTrue(value['owned_temporary_removed'])
        self.assertIn('timeout partial', (self.output / 'worker_stderr.log').read_text())

    def test_35_invalid_raw_log_cannot_be_rescued_by_green_worker_json(self):
        def badlog(argv, **kwargs):
            result = self.process(argv, **kwargs)
            output = Path(argv[argv.index('--output') + 1])
            (output / 'FULL_TESTS.log').write_text('OK\n')
            return result
        self.assertEqual(self.run_fixture(badlog), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_36_final_frozen_metadata_change_overrides_worker_success(self):
        def changed(project, manifest, *, phase, **kwargs):
            files, value = self.snapshot(project, manifest, phase=phase)
            if phase == 'FROZEN_FINAL':
                value['non_atime_metadata']['.']['fixture'] = 'mutated'
            return files, value
        self.assertEqual(self.run_fixture(snapshot=changed), 1)
        self.assertFalse(self.receipt()['frozen_source_unchanged'])
        self.assertIn('final_source_error', self.receipt())

    def test_37_final_copy_metadata_change_overrides_worker_success(self):
        def changed(project, manifest, *, phase, **kwargs):
            files, value = self.snapshot(project, manifest, phase=phase)
            if phase == 'COPY_FINAL':
                value['non_atime_metadata']['.']['fixture'] = 'mutated'
            return files, value
        self.assertEqual(self.run_fixture(snapshot=changed), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertFalse(self.receipt()['temporary_copy_unchanged'])

    def test_38_cleanup_exception_after_valid_child_cannot_leave_success(self):
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
        self.assertEqual(self.receipt()['result'], 'FAIL_FUNCTIONAL_COHORT_ANALYSIS')

    def test_39_ci_tool_binding_change_overrides_worker_success(self):
        original = controller.tool_bindings
        calls = []
        def changed(path):
            value = original(path)
            calls.append(True)
            if len(calls) > 1:
                value['ci/run_functional_cohort_worker.py'] = '0' * 64
            return value
        with patch.object(controller, 'tool_bindings', side_effect=changed):
            self.assertEqual(self.run_fixture(), 1)
        self.assertFalse(self.receipt()['tool_files_unchanged'])

    def test_40_output_inside_frozen_project_is_rejected_before_process(self):
        self.output = self.project / 'reports'
        with self.assertRaises(ValueError):
            self.run_fixture()
        self.assertEqual(self.invocations, [])
        self.assertFalse(self.output.exists())

    def test_41_worker_environment_keeps_identity_but_omits_tokens_and_outputs(self):
        values = {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40,
            'GITHUB_TOKEN': 'private-fixture-token', 'ACTIONS_RUNTIME_TOKEN': 'private-runtime',
            'GITHUB_OUTPUT': str(self.root / 'not-for-worker'), 'UNREVIEWED_VARIABLE': 'private-other'}
        with patch.dict(os.environ, values):
            env = controller.worker_environment(self.root)
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA'):
            self.assertEqual(env[key], values[key])
        for key in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'GITHUB_OUTPUT', 'UNREVIEWED_VARIABLE'):
            self.assertNotIn(key, env)

    def test_42_runtime_qualification_failure_never_launches_worker(self):
        with patch.object(controller, 'snapshot', side_effect=self.snapshot), \
             patch.object(controller, 'qualify_runtime', side_effect=ValueError('synthetic qualification failure')):
            self.assertEqual(controller.run_cohort(self.project, self.manifest, self.output, 'linux-x64',
                process_run=self.process), 1)
        self.assertEqual(self.invocations, [])
        self.assertTrue(self.receipt()['frozen_source_unchanged'])

    def test_43_duplicate_json_worker_result_cannot_be_accepted(self):
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

    def test_44_strict_json_rejects_duplicate_members_and_nonstandard_constants(self):
        self.assertEqual(contract.strict_json('{"synthetic":1}'), {'synthetic': 1})
        for raw in ('{"synthetic":0,"synthetic":1}', '{"synthetic":NaN}',
                    '{"synthetic":Infinity}', '{"synthetic":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                contract.strict_json(raw)

    def test_45_report_short_write_flush_and_close_failure_cannot_return_success(self):
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

    def test_46_parent_rejects_nonstandard_number_even_in_an_unused_receipt_field(self):
        def nonstandard(argv, **kwargs):
            result = self.process(argv, **kwargs)
            output = Path(argv[argv.index('--output') + 1])
            raw = (output / 'RESULT.json').read_text()
            (output / 'RESULT.json').write_text(raw.replace('{', '{"duration_seconds":NaN,', 1))
            return result
        self.assertEqual(self.run_fixture(nonstandard), 1)
        self.assertTrue(self.receipt()['frozen_source_unchanged'])
        self.assertEqual(self.receipt()['error']['type'], 'ValueError')

    def test_47_wrong_or_missing_actual_run_identity_cannot_keep_green_worker_json(self):
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


class DiscoveryGuards(unittest.TestCase):
    """Exercise actual worker control flow with synthetic discovery, never product tests."""

    def rejected_discovery(self, ids, errors):
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
        loader = types.SimpleNamespace(errors=errors,
            loadTestsFromNames=lambda modules: suite)
        source = synthetic_source()
        old_cwd, old_path = os.getcwd(), sys.path[:]
        old_tests = sys.modules.get('tests')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / 'synthetic_project'
            project.mkdir()
            manifest = root / 'SYNTHETIC_MANIFEST.json'
            manifest.write_text('{}\n')
            output = root / 'worker'
            try:
                with patch.dict(os.environ), \
                     patch.object(worker, 'qualify_runtime', return_value=synthetic_runtime()), \
                     patch.object(worker, 'snapshot', return_value=([], source)) as snapshots, \
                     patch.object(worker.unittest, 'TestLoader', return_value=loader), \
                     patch.object(worker.unittest, 'TextTestRunner') as runner, \
                     redirect_stdout(io.StringIO()):
                    status = worker.run_worker(project, manifest, output, 'linux-x64')
                    self.assertEqual(status, 1)
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
        self.assertEqual(receipt['result'], 'FAIL_FUNCTIONAL_COHORT_248')
        self.assertEqual(receipt['tests_run'], 0)
        self.assertTrue(receipt['source_files_unchanged'])
        self.assertEqual(receipt['source_before'], receipt['source_after'])
        self.assertEqual(receipt['discovery_errors'], errors)
        self.assertIn('Exact cohort discovery must succeed before executing any test', raw_log)
        return receipt, raw_log

    def test_48_unexpected_discovered_id_is_rejected_before_running_any_suite(self):
        expected = contract.load_contract()['expected_successful_test_ids']
        injected = 'tests.synthetic_only_fixture.NotAProductCase.test_unlisted'
        for ids in ([*expected, injected], [*expected[:-1], injected]):
            with self.subTest(count=len(ids)):
                receipt, _ = self.rejected_discovery(ids, [])
                self.assertEqual(receipt['discovered'], len(ids))
                self.assertIn(injected, receipt['discovered_test_ids'])

    def test_49_discovery_import_trace_is_preserved_without_executing_placeholders(self):
        trace = ('Traceback (most recent call last):\n'
            'ImportError: SYNTHETIC_ONLY discovery import failure; not a product failure')
        receipt, raw_log = self.rejected_discovery(
            contract.load_contract()['expected_successful_test_ids'], [trace])
        self.assertEqual(receipt['discovered'], 248)
        self.assertIn('WORKER_DISCOVERY_ERRORS\n' + trace, raw_log)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == EXPECTED_GUARD_TESTS
        and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses) else 1)
