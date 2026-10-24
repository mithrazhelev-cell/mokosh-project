"""Run fixed platform observations and selected unchanged cases on an owned copy."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import sys
import time
import traceback
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from platform_prerequisites_contract import (CI_PASS, LAB_PASS, CONTRACT_SHA256,
    SCOPE, PROBE_PREFIX, load_contract, expected_ids, qualify_runtime, strict_json,
    same_typed, validate_probe_rows, validate_worker_result)
from run_functional_cohort_worker import case_ids, known_module_paths, module_bindings, checked_write_json
from run_preliminary import read_file, require, safe_path, snapshot

PROBES_PATH = Path(__file__).with_name('platform_prerequisites_probes.py')


def _hash(path):
    return hashlib.sha256(read_file(path)).hexdigest()


def run_worker(project, manifest_path, output, target, *, local_lab=False):
    project, manifest_path, output = map(safe_path, (project, manifest_path, output))
    require(output != project and project not in output.parents,
        'Prerequisite worker output must be outside disposable source copy')
    require(project.is_dir(), 'Existing disposable prerequisite source copy required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 1, 'result': 'INCOMPLETE_PLATFORM_PREREQUISITES', 'scope': SCOPE,
        'contract_sha256': CONTRACT_SHA256, 'target': target, 'local_lab': local_lab,
        'test_modules': 0, 'test_module_names': [], 'discovered': 0,
        'discovered_test_ids': [], 'tests_run': 0, 'successful_test_ids': [],
        'successful_test_count': 0, 'unique_successful_test_count': 0,
        'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [],
        'unexpected_successes': [], 'discovery_errors': [], 'probe_rows': [], 'probe_count': 0,
        'source_files_unchanged': False, 'tool_files_unchanged': False,
        'source_overlay_applied': False, 'R3_candidate_tested': False, 'live_apply': False,
        'product_support': 'NOT_ACCEPTED', 'native_GUI_acceptance': 'NOT_TESTED',
        'physical_GUI': 'NOT_TESTED', 'product_storage_acceptance': 'NOT_TESTED',
        'full2509': 'NOT_EXECUTED_BY_THIS_SUITE', 'prior248': 'NOT_EXECUTED_BY_THIS_SUITE',
        'known_open_findings': ['D005_OPEN', 'Stage2.48_NOT_ACCEPTED', 'NORMAL_V2_LINUX_GATE_RETAINED',
            'CRYPTOGRAPHY_ADVISORY_NOT_FIXED', 'ACL_AND_CRASH_DURABILITY_NOT_ACCEPTED'],
        'python_executable': sys.executable,
        'GitHub_run': {key: os.environ.get(key) for key in ('GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}}
    before = manifest = contract = runtime = None
    ids, modules, probe_stdout = [], [], []
    started = time.monotonic()
    success = False
    log_path = output / 'FULL_TESTS.log'
    with log_path.open('x', encoding='utf-8', newline='\n') as stream:
        try:
            report['worker_sha256'] = _hash(Path(__file__))
            report['probes_sha256'] = _hash(PROBES_PATH)
            contract = load_contract()
            ids = expected_ids(target, contract)
            modules = sorted({'.'.join(name.split('.')[:2]) for name in ids})
            report['test_module_names'], report['test_modules'] = modules[:], len(modules)
            runtime = qualify_runtime(target, local_lab=local_lab)
            report['runtime'] = runtime
            manifest = strict_json(read_file(manifest_path))
            _, before = snapshot(project, manifest)
            report['source_before'] = before
            require(not any(name in sys.modules for name in known_module_paths(project)),
                'Frozen product module namespace populated before prerequisite discovery')
            require(not any(name == 'tests' or name.startswith('tests.') for name in sys.modules),
                'Test namespace populated before prerequisite discovery')
            require('platform_prerequisites_probes' not in sys.modules,
                'Prerequisite probes namespace populated before fixed import')
            os.chdir(project)
            data_root = output / 'isolated_test_data'
            data_root.mkdir(mode=0o700)
            os.environ['MOKOSH_DATA_DIR'] = str(data_root)
            sys.path.insert(0, str(project))
            package = types.ModuleType('tests')
            package.__path__ = [str(project / 'tests')]
            package.__spec__ = importlib.machinery.ModuleSpec('tests', loader=None, is_package=True)
            sys.modules['tests'] = package
            probes = importlib.import_module('platform_prerequisites_probes')
            require(type(getattr(probes, '__file__', None)) is str
                and os.path.normcase(os.path.abspath(probes.__file__)) == os.path.normcase(str(PROBES_PATH)),
                'Prerequisite probes imported from unexpected origin')
            rows = probes.run_probes(data_root / 'probes', target=target)
            validate_probe_rows(rows, target)
            report['probe_rows'], report['probe_count'] = rows, len(rows)
            for row in rows:
                raw = PROBE_PREFIX + json.dumps(row, sort_keys=True, ensure_ascii=True,
                    allow_nan=False, separators=(',', ':')) + '\n'
                require(sys.stdout.write(raw) == len(raw), 'Incomplete native probe stdout write')
                sys.stdout.flush()
                probe_stdout.append(raw)
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(ids)
            discovered = case_ids(suite)
            report['discovered_test_ids'], report['discovered'] = discovered[:], suite.countTestCases()
            report['discovery_errors'] = loader.errors[:]
            if loader.errors:
                stream.write('\nWORKER_DISCOVERY_ERRORS\n' + '\n'.join(loader.errors) + '\n')
            require(not loader.errors and type(report['discovered']) is int
                and report['discovered'] == len(ids) and len(discovered) == len(ids)
                and all(type(item) is str for item in discovered)
                and len(set(discovered)) == len(ids) and set(discovered) == set(ids),
                'Exact prerequisite discovery must succeed before executing any test')

            class Result(unittest.TextTestResult):
                def addSuccess(self, test):
                    report['successful_test_ids'].append(test.id())
                    super().addSuccess(test)

            result = unittest.TextTestRunner(stream=stream, verbosity=2, descriptions=False,
                resultclass=Result).run(suite)
            report.update(tests_run=result.testsRun,
                failures=[{'test': test.id(), 'traceback': detail} for test, detail in result.failures],
                errors=[{'test': test.id(), 'traceback': detail} for test, detail in result.errors],
                skipped=[{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
                expected_failures=[{'test': test.id(), 'traceback': detail} for test, detail in result.expectedFailures],
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        except BaseException as error:
            report['runner_error'] = {'type': type(error).__name__, 'detail': str(error),
                'traceback': traceback.format_exc()}
            stream.write('\nWORKER_RUNNER_ERROR\n' + traceback.format_exc())
        finally:
            if before is not None:
                try:
                    selected_loaded = [name for name in modules if name in sys.modules]
                    report['loaded_test_module_bindings'], report['loaded_product_module_bindings'] = module_bindings(
                        project, {'test_modules': selected_loaded})
                except BaseException as error:
                    report['module_binding_error'] = {'type': type(error).__name__, 'detail': str(error),
                        'traceback': traceback.format_exc()}
                    stream.write('\nWORKER_MODULE_BINDING_ERROR\n' + traceback.format_exc())
            try:
                if manifest is not None:
                    _, after = snapshot(project, manifest)
                    report['source_after'] = after
                    report['source_files_unchanged'] = before is not None and same_typed(after, before)
                    require(report['source_files_unchanged'], 'Disposable source copy changed during prerequisites')
            except BaseException as error:
                report['final_source_error'] = {'type': type(error).__name__, 'detail': str(error),
                    'traceback': traceback.format_exc()}
                stream.write('\nWORKER_FINAL_SOURCE_ERROR\n' + traceback.format_exc())
            try:
                report['tool_files_unchanged'] = (_hash(Path(__file__)) == report.get('worker_sha256')
                    and _hash(PROBES_PATH) == report.get('probes_sha256'))
                require(report['tool_files_unchanged'], 'Prerequisite worker or probe bytes changed')
            except BaseException as error:
                report['final_tool_error'] = {'type': type(error).__name__, 'detail': str(error),
                    'traceback': traceback.format_exc()}
                stream.write('\nWORKER_FINAL_TOOL_ERROR\n' + traceback.format_exc())
            report['successful_test_count'] = len(report['successful_test_ids'])
            report['unique_successful_test_count'] = len(set(report['successful_test_ids']))
            report['duration_seconds'] = round(time.monotonic() - started, 3)
            stream.flush()
    try:
        require(contract is not None and runtime is not None and before is not None,
            'Prerequisite worker preconditions incomplete')
        report['result'] = LAB_PASS if local_lab else CI_PASS
        validate_worker_result(report, read_file(log_path), contract,
            expected_runtime=runtime, expected_source=before,
            expected_worker_sha256=_hash(Path(__file__)), expected_probes_sha256=_hash(PROBES_PATH),
            raw_probe_stdout=''.join(probe_stdout).encode('ascii'))
        success = True
    except BaseException as error:
        report['result'] = 'FAIL_PLATFORM_PREREQUISITES'
        report['acceptance_error'] = {'type': type(error).__name__, 'detail': str(error)}
    checked_write_json(output / 'RESULT.json', report)
    return 0 if success else 1


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('project', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--target', choices=tuple(('linux-x64', 'windows-x64', 'macos-arm64')), required=True)
    parser.add_argument('--local-lab', action='store_true')
    args = parser.parse_args(argv)
    return run_worker(args.project, args.manifest, args.output, args.target, local_lab=args.local_lab)


if __name__ == '__main__':
    raise SystemExit(main())
