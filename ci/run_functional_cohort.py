"""Run the exact 248-test cohort on an owned copy, preserving all source guards.

This is an analysis controller, not product platform, storage or GUI acceptance.
Existing product files, dependencies and the three earlier workflows are inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import (child_environment, private_temp_base, read_file,
    require, run_owned, safe_path, snapshot)
from functional_cohort_contract import (CONTRACT_PATH, CONTRACT_SHA256,
    load_contract, qualify_runtime, strict_json, validate_worker_result)

CI_DIRECTORY = Path(__file__).resolve().parent
WORKER_PATH = CI_DIRECTORY / 'run_functional_cohort_worker.py'
RUN_METADATA = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA',
    'RUNNER_OS', 'ImageOS', 'ImageVersion', 'CI', 'GITHUB_ACTIONS')
PASS_CI = 'PASS_FUNCTIONAL_COHORT_248_ON_RECORDED_RUNTIME_ONLY'
PASS_LAB = 'PASS_LOCAL_LAB_FUNCTIONAL_COHORT_248_PREPARATION_ONLY'


def _read_json(path):
    raw = read_file(path)
    require(len(raw) <= 20 * 1024 * 1024, 'Cohort JSON report exceeds bound')
    return strict_json(raw)


def _write_json(path, record):
    """New owned reports only; a partial write, flush or close cannot return PASS."""
    raw = json.dumps(record, ensure_ascii=False, indent=2) + '\n'
    path = safe_path(path)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        require(stream.write(raw) == len(raw), 'Incomplete cohort report write')
        stream.flush()


def tool_bindings(manifest_path):
    """Bind the executed CI closure and input manifests before and after the child."""
    paths = {
        'ci/run_functional_cohort.py': Path(__file__),
        'ci/run_functional_cohort_worker.py': WORKER_PATH,
        'ci/functional_cohort_contract.py': CI_DIRECTORY / 'functional_cohort_contract.py',
        'ci/functional_cohort_248.json': CONTRACT_PATH,
        'ci/run_preliminary.py': CI_DIRECTORY / 'run_preliminary.py',
        'SOURCE_MANIFEST.json': Path(manifest_path),
    }
    return {name: hashlib.sha256(read_file(path)).hexdigest()
        for name, path in paths.items()}


def worker_environment(directory):
    environment = child_environment(directory)
    # Only public runner bookkeeping and CI/lab qualification signals survive.
    # GITHUB_OUTPUT and credentials are unnecessary in this worker process.
    environment.update({key: os.environ[key] for key in RUN_METADATA if key in os.environ})
    return environment


def run_cohort(project, manifest_path, output, target, *, local_lab=False,
        process_run=run_owned):
    project, manifest_path, output = map(safe_path, (project, manifest_path, output))
    require(output != project and project not in output.parents,
        'Reports must be outside frozen project')
    require(type(local_lab) is bool, 'Local-lab mode must be explicit boolean')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        'schema': 1,
        'result': 'INCOMPLETE_FUNCTIONAL_COHORT_ANALYSIS',
        'scope': 'FUNCTIONAL_COHORT_248_PRELIMINARY_ONLY_NO_PRODUCT_PLATFORM_ACCEPTANCE',
        'target': target,
        'local_lab': local_lab,
        'contract_sha256': CONTRACT_SHA256,
        'expected_test_count': 248,
        'product_mutation_allowed': False,
        'source_overlay_applied': False,
        'R3_candidate_executed': False,
        'live_apply': False,
        'native_GUI_acceptance': 'NOT_TESTED',
        'physical_GUI': 'NOT_TESTED',
        'product_storage_acceptance': 'NOT_TESTED',
        'full2509': 'NOT_EXECUTED_BY_COHORT',
        'callback_reporting_acceptance': 'NOT_TESTED_BY_THIS_UNIT_SUITE',
        'known_open_findings': ['D005_OPEN', 'Stage2.48_NOT_ACCEPTED',
            'CRYPTOGRAPHY_ADVISORY_NOT_FIXED', 'NORMAL_V2_LINUX_GATE_RETAINED'],
        'GitHub_run': {key: os.environ.get(key) for key in RUN_METADATA
            if key not in ('CI', 'GITHUB_ACTIONS')},
        'GitHub_execution': 'REQUIRES_EXTERNAL_RUN_JOB_ATTEMPT_COMMIT_REVIEW',
        'worker_exit_status': None,
        'frozen_source_unchanged': False,
        'temporary_copy_unchanged': False,
        'temporary_copy_retained': False,
        'process_cleanup_scope': 'EXISTING_RUN_OWNED; POSIX_OWNED_SESSION; '
            'WINDOWS_TASKKILL_ON_TIMEOUT_WHILE_ROOT_ALIVE; '
            'NO_UNIVERSAL_NORMAL_DESCENDANT_CLEANUP_CLAIM',
    }
    contract = source_manifest = before = tools_before = None
    temporary_root = copy_root = copy_before = None
    candidate_success = False
    try:
        require(sys.flags.isolated and sys.dont_write_bytecode,
            'Explicit -I and -B required')
        contract = load_contract()
        tools_before = tool_bindings(manifest_path)
        report['tool_bindings_before'] = tools_before
        require(tools_before['ci/functional_cohort_248.json'] == CONTRACT_SHA256,
            'Cohort contract changed before execution')
        source_manifest = _read_json(manifest_path)
        files, before = snapshot(project, source_manifest, phase='FROZEN_BEFORE')
        report['source_before'] = before
        _write_json(output / 'SOURCE_BEFORE.json', before)
        runtime = qualify_runtime(target, local_lab=local_lab, contract=contract)
        report['runtime'] = runtime
        _write_json(output / 'RUNTIME.json', runtime)
        # Syntax checking does not import or activate any product module.
        for name, raw in files.items():
            if name.endswith('.py'):
                compile(raw, name, 'exec', dont_inherit=True)
        report['compiled_python_files'] = sum(name.endswith('.py') for name in files)
        with tempfile.TemporaryDirectory(prefix='mokosh-ci-cohort-',
                dir=private_temp_base(project)) as temporary:
            temporary_root = Path(temporary)
            copy_root = temporary_root / 'project'
            copy_root.mkdir(mode=0o700)
            for name, raw in files.items():
                destination = copy_root.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination.write_bytes(raw)
                destination.chmod(before['observed_file_modes'][name])
            _, copy_before = snapshot(copy_root, source_manifest, phase='COPY_BEFORE')
            report['copy_before'] = copy_before
            try:
                command = [sys.executable, '-I', '-B', str(WORKER_PATH),
                    '--project', str(copy_root), '--manifest', str(manifest_path),
                    '--output', str(output / 'worker'), '--target', target]
                if local_lab:
                    command.append('--local-lab')
                with (output / 'worker_stdout.log').open('x', encoding='utf-8') as stdout, \
                        (output / 'worker_stderr.log').open('x', encoding='utf-8') as stderr:
                    process = process_run(command, cwd=temporary,
                        env=worker_environment(temporary_root), stdin=subprocess.DEVNULL,
                        stdout=stdout, stderr=stderr, timeout=300, check=False)
                report['worker_exit_status'] = process.returncode
                record = _read_json(output / 'worker/RESULT.json')
                raw_test_log = read_file(output / 'worker/FULL_TESTS.log')
                report['worker_result'] = record.get('result')
                report['worker_sha256'] = tools_before['ci/run_functional_cohort_worker.py']
                require(type(process.returncode) is int and process.returncode == 0,
                    'Functional cohort worker process failed')
                require(record.get('GitHub_run') == report['GitHub_run'],
                    'Worker run identity differs from controller context')
                validate_worker_result(record, raw_test_log, contract,
                    expected_runtime=runtime, expected_source=copy_before,
                    expected_worker_sha256=report['worker_sha256'])
                report['validated_test_count'] = record['tests_run']
                report['successful_test_ids'] = record['successful_test_ids']
                report['mandatory_real_mlkem_success_ids'] = record['mandatory_real_mlkem_success_ids']
                report['worker_raw_test_log_sha256'] = hashlib.sha256(raw_test_log).hexdigest()
                candidate_success = True
            finally:
                _, copy_after = snapshot(copy_root, source_manifest, phase='COPY_FINAL')
                report['copy_after'] = copy_after
                report['temporary_copy_unchanged'] = copy_before is not None and copy_after == copy_before
                require(report['temporary_copy_unchanged'], 'Temporary project copy changed')
        # The context manager must finish before any success is eligible.
        report['result'] = (PASS_LAB if local_lab else PASS_CI) if candidate_success \
            else 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
    except BaseException as error:
        report['result'] = 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
        report['error'] = {'type': type(error).__name__, 'detail': str(error),
            'traceback': traceback.format_exc()}
    finally:
        try:
            if source_manifest is not None:
                _, after = snapshot(project, source_manifest, phase='FROZEN_FINAL')
                report['source_after'] = after
                report['frozen_source_unchanged'] = before is not None and after == before
                _write_json(output / 'SOURCE_AFTER.json', after)
                require(report['frozen_source_unchanged'], 'Frozen source changed')
        except BaseException as error:
            report['result'] = 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
            report['final_source_error'] = {'type': type(error).__name__, 'detail': str(error)}
        try:
            report['temporary_copy_retained'] = copy_root.exists() if copy_root is not None else False
            report['owned_temporary_removed'] = not temporary_root.exists() \
                if temporary_root is not None else True
            require(not report['temporary_copy_retained'] and report['owned_temporary_removed'],
                'Owned temporary cohort directory still exists')
        except BaseException as error:
            report['result'] = 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
            report['temporary_cleanup_error'] = {'type': type(error).__name__, 'detail': str(error)}
        try:
            tools_after = tool_bindings(manifest_path)
            report['tool_bindings_after'] = tools_after
            report['tool_files_unchanged'] = tools_before is not None and tools_after == tools_before
            require(report['tool_files_unchanged'], 'CI tool or manifest changed during cohort analysis')
        except BaseException as error:
            report['result'] = 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
            report['final_tool_error'] = {'type': type(error).__name__, 'detail': str(error)}
        if report['result'] in (PASS_CI, PASS_LAB) and not (
                candidate_success and report['frozen_source_unchanged']
                and report['temporary_copy_unchanged']
                and not report['temporary_copy_retained']
                and report.get('owned_temporary_removed') is True
                and report.get('tool_files_unchanged') is True):
            report['result'] = 'FAIL_FUNCTIONAL_COHORT_ANALYSIS'
        _write_json(output / 'AUDIT_RESULT.json', report)
    return 0 if report['result'] in (PASS_CI, PASS_LAB) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('project', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--target', choices=('linux-x64', 'windows-x64', 'macos-arm64'), required=True)
    parser.add_argument('--local-lab', action='store_true')
    arguments = parser.parse_args(argv)
    return run_cohort(arguments.project, arguments.manifest, arguments.output,
        arguments.target, local_lab=arguments.local_lab)


if __name__ == '__main__':
    raise SystemExit(main())
