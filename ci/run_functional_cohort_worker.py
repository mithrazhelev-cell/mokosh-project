"""Execute exactly the pinned 248 existing tests on an owned frozen source copy.

This child is launched only by the report controller with a private environment.
It has no application overlay or filesystem/profile/GUI acceptance authority.
"""
from __future__ import annotations

import argparse
import hashlib
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
from functional_cohort_contract import (CI_PASS, LAB_PASS, CONTRACT_SHA256, SCOPE,
    load_contract, qualify_runtime, strict_json, validate_worker_result)
from run_preliminary import read_file, require, safe_path, snapshot


def case_ids(suite):
    """Flatten the discovered suite before unittest consumes its test objects."""
    result = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.extend(case_ids(item))
        else:
            result.append(item.id())
    return result


def known_module_paths(project):
    return {path.relative_to(project).with_suffix('').as_posix().replace('/', '.'):
        path.relative_to(project).as_posix() for path in project.rglob('*.py')}


def module_bindings(project, contract):
    """Bind actual loaded product/test origins to bytes in the frozen copy."""
    product = {}
    known = known_module_paths(project)
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, '__file__', None)
        if name in known:
            require(type(origin) is str and os.path.normcase(os.path.abspath(origin))
                == os.path.normcase(str(project / known[name])),
                'Loaded frozen product module has an unexpected origin')
        if not isinstance(origin, str):
            continue
        path = Path(os.path.abspath(origin))
        if not path.is_relative_to(project):
            continue
        relative = path.relative_to(project).as_posix()
        require(name in known and relative == known[name],
            'Unexpected module alias loaded from the frozen source copy')
        raw = read_file(path)
        product[name] = {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest()}
    tests = {name: product[name] for name in contract['test_modules']}
    return tests, product


def checked_write_json(path, value):
    raw = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        require(stream.write(raw) == len(raw), 'Incomplete worker receipt write')
        stream.flush()


def run_worker(project, manifest_path, output, target, *, local_lab=False):
    project, manifest_path, output = map(safe_path, (project, manifest_path, output))
    require(output != project and project not in output.parents,
        'Worker output must be outside the disposable source copy')
    require(project.is_dir(), 'Existing disposable source copy required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 1, 'result': 'INCOMPLETE_FUNCTIONAL_COHORT_248', 'scope': SCOPE,
        'contract_sha256': CONTRACT_SHA256, 'target': target, 'local_lab': local_lab,
        'test_modules': 0, 'test_module_names': [], 'discovered': 0,
        'discovered_test_ids': [], 'tests_run': 0, 'successful_test_ids': [],
        'successful_test_count': 0, 'unique_successful_test_count': 0,
        'mandatory_real_mlkem_success_ids': [], 'failures': [], 'errors': [],
        'skipped': [], 'expected_failures': [], 'unexpected_successes': [], 'discovery_errors': [],
        'source_files_unchanged': False, 'source_overlay_applied': False,
        'R3_candidate_tested': False, 'live_apply': False,
        'native_GUI_acceptance': 'NOT_TESTED', 'physical_GUI': 'NOT_TESTED',
        'product_storage_acceptance': 'NOT_TESTED', 'full2509': 'NOT_EXECUTED_BY_COHORT',
        'known_open_finding': 'D005 OPEN; Stage2.48 NOT_ACCEPTED; native/physical and product storage gates remain',
        'python_executable': sys.executable,
        'GitHub_run': {key: os.environ.get(key) for key in ('GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}}
    before = manifest = contract = None
    runtime = None
    started = time.monotonic()
    success = False
    log_path = output / 'FULL_TESTS.log'
    # Exclusive creation preserves even early qualification/import failure evidence.
    with log_path.open('x', encoding='utf-8', newline='\n') as stream:
        try:
            report['worker_sha256'] = hashlib.sha256(read_file(Path(__file__))).hexdigest()
            contract = load_contract()
            runtime = qualify_runtime(target, local_lab=local_lab, contract=contract)
            report['runtime'] = runtime
            manifest = strict_json(read_file(manifest_path))
            _, before = snapshot(project, manifest)
            report['source_before'] = before
            require(not any(name in sys.modules for name in known_module_paths(project)),
                'Frozen product module namespace populated before controlled discovery')
            os.chdir(project)
            data_dir = output / 'isolated_test_data'
            data_dir.mkdir(mode=0o700)
            os.environ['MOKOSH_DATA_DIR'] = str(data_dir)
            sys.path.insert(0, str(project))
            # Do not let an unrelated installed `tests` package shadow this exact
            # project, whose frozen tests/ directory intentionally has no __init__.
            require(not any(name == 'tests' or name.startswith('tests.') for name in sys.modules),
                'Test namespace was already populated before controlled discovery')
            package = types.ModuleType('tests')
            package.__path__ = [str(project / 'tests')]
            package.__spec__ = importlib.machinery.ModuleSpec('tests', loader=None, is_package=True)
            sys.modules['tests'] = package
            modules = contract['test_modules']
            report['test_module_names'] = modules[:]
            report['test_modules'] = len(modules)
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(modules)
            discovered = case_ids(suite)
            report['discovered_test_ids'] = discovered[:]
            report['discovered'] = suite.countTestCases()
            report['discovery_errors'] = loader.errors[:]
            if loader.errors:
                # Keep the actual loader/import tracebacks without executing a
                # placeholder or any unexpected test outside the accepted set.
                stream.write('\nWORKER_DISCOVERY_ERRORS\n' + '\n'.join(loader.errors) + '\n')
            require(not loader.errors and type(report['discovered']) is int
                and report['discovered'] == 248
                and len(discovered) == 248 and all(type(item) is str for item in discovered)
                and len(set(discovered)) == 248
                and set(discovered) == set(contract['expected_successful_test_ids']),
                'Exact cohort discovery must succeed before executing any test')

            class Result(unittest.TextTestResult):
                def addSuccess(self, test):
                    report['successful_test_ids'].append(test.id())
                    super().addSuccess(test)

            result = unittest.TextTestRunner(stream=stream, verbosity=2,
                descriptions=False, resultclass=Result).run(suite)
            report.update(tests_run=result.testsRun,
                failures=[{'test': test.id(), 'traceback': detail} for test, detail in result.failures],
                errors=[{'test': test.id(), 'traceback': detail} for test, detail in result.errors],
                skipped=[{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
                expected_failures=[{'test': test.id(), 'traceback': detail}
                    for test, detail in result.expectedFailures],
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
            report['loaded_test_module_bindings'], report['loaded_product_module_bindings'] = module_bindings(
                project, contract)
        except BaseException as error:
            report['runner_error'] = {'type': type(error).__name__, 'detail': str(error),
                'traceback': traceback.format_exc()}
            stream.write('\nWORKER_RUNNER_ERROR\n' + traceback.format_exc())
        finally:
            try:
                if manifest is not None:
                    _, after = snapshot(project, manifest)
                    report['source_after'] = after
                    report['source_files_unchanged'] = before is not None and after == before
                    require(report['source_files_unchanged'], 'Disposable source copy changed during cohort')
            except BaseException as error:
                report['final_source_error'] = {'type': type(error).__name__, 'detail': str(error),
                    'traceback': traceback.format_exc()}
                stream.write('\nWORKER_FINAL_SOURCE_ERROR\n' + traceback.format_exc())
            report['successful_test_count'] = len(report['successful_test_ids'])
            report['unique_successful_test_count'] = len(set(report['successful_test_ids']))
            if contract is not None:
                report['mandatory_real_mlkem_success_ids'] = sorted(set(report['successful_test_ids'])
                    & set(contract['mandatory_real_mlkem_test_ids']))
            report['duration_seconds'] = round(time.monotonic() - started, 3)
            stream.flush()
    # Reading the closed log and comparing its complete ID set guards against a
    # successful-looking JSON count that contradicts the preserved raw results.
    try:
        require(contract is not None and runtime is not None and before is not None,
            'Worker preconditions were not completed')
        report['result'] = LAB_PASS if local_lab else CI_PASS
        validate_worker_result(report, read_file(log_path), contract,
            expected_runtime=runtime, expected_source=before,
            expected_worker_sha256=hashlib.sha256(read_file(Path(__file__))).hexdigest())
        success = True
    except BaseException as error:
        report['result'] = 'FAIL_FUNCTIONAL_COHORT_248'
        report['acceptance_error'] = {'type': type(error).__name__, 'detail': str(error)}
    checked_write_json(output / 'RESULT.json', report)
    print(json.dumps({key: report[key] for key in ('result', 'target', 'local_lab',
        'test_modules', 'discovered', 'tests_run', 'successful_test_count',
        'unique_successful_test_count', 'source_files_unchanged', 'duration_seconds',
        'native_GUI_acceptance')}, sort_keys=True), flush=True)
    return 0 if success else 1


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('project', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--target', choices=('linux-x64', 'windows-x64', 'macos-arm64'), required=True)
    parser.add_argument('--local-lab', action='store_true')
    args = parser.parse_args(argv)
    return run_worker(args.project, args.manifest, args.output, args.target, local_lab=args.local_lab)


if __name__ == '__main__':
    raise SystemExit(main())
