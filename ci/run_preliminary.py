"""Report-only immutable-source CI controller; no product writes or GUI acceptance."""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback

SOURCE_SHA = '92e159ed818bc6fbf858549452ad78fd0b238f9d8193ac9842147555afb3dcca'
SOURCE_FILES, SOURCE_BYTES, TESTS = 263, 5223645, 2509
CORE_INDEX_SHA = 'fd448cd2a0e85df1a65846af2f308e5d718fd05b0cd826b1d40346283797f1fd'
METADATA_CONTRACT = 'GIT_USER_EXECUTABLE_SEMANTICS_V1'
EXECUTABLE_PATHS = ('run_main_gui_recovery_chain_layout_audit.py', 'run_main_gui_recovery_entry_transition_visual_harness.py', 'run_main_gui_recovery_source_inspection_preparation_request_visual_harness.py', 'run_main_gui_recovery_source_inspection_request_visual_harness.py', 'run_main_gui_recovery_source_inspection_review_visual_harness.py', 'run_main_gui_recovery_source_selection_visual_harness.py', 'run_mokosh_gui.sh', 'run_mokosh_profile_main_gui_visual_harness.py', 'run_mokosh_profile_recovery_visual_harness.py', 'run_mokosh_v2_local_visual_harness.py', 'run_recovery_review_visual_harness.py', 'run_recovery_source_inspection_review_visual_harness.py')

DEPENDENCIES = {'cryptography': '49.0.0', 'argon2-cffi': '25.1.0',
    'argon2-cffi-bindings': '25.1.0', 'cffi': '2.1.0', 'pycparser': '3.0'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink path component rejected')
    return path


def _diagnostic_call(diagnostic, method, *args):
    """Observer faults cannot replace an existing guard or change returned bytes."""
    if diagnostic is None:
        return None
    try:
        return getattr(diagnostic, method)(*args)
    except BaseException:
        try:
            diagnostic.mark_incomplete('COLLECTOR_ERROR')
        except BaseException:
            pass
        return None


def read_file(path, *, diagnostic=None, context=None):
    before = opened = after = raw = None
    try:
        path = safe_path(path)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 32 * 1024 * 1024,
            'Non-regular, linked or oversized source file')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'Source replaced while opening')
            raw = stream.read(32 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(fields(before) == fields(after) and len(raw) == before.st_size, 'Source changed while reading')
        return raw
    except BaseException as error:
        _diagnostic_call(diagnostic, 'read_failure', context, path, error, before, opened, after, raw)
        raise


def validate_manifest(manifest):
    require(type(manifest.get('schema')) is int and manifest['schema'] == 2
        and manifest.get('product_mutation_allowed') is False, 'Manifest scope differs')
    require((manifest.get('file_count'), manifest.get('total_bytes'), manifest.get('verified_canonical_sha256'))
        == (SOURCE_FILES, SOURCE_BYTES, SOURCE_SHA), 'Exact baseline manifest identity differs')
    metadata = manifest.get('metadata_contract')
    require(type(metadata) is dict and metadata.get('name') == METADATA_CONTRACT
        and metadata.get('trusted_core_index_sha256') == CORE_INDEX_SHA
        and metadata.get('required_executable_paths') == list(EXECUTABLE_PATHS)
        and metadata.get('full_posix_modes_preserved_by_git') is False,
        'Executable metadata contract or trusted binding differs')
    rows = manifest.get('records')
    require(type(rows) is list and len(rows) == SOURCE_FILES, 'Manifest source count differs')
    names = []
    for row in rows:
        name = row['path']
        require(isinstance(name, str) and name and not PurePosixPath(name).is_absolute()
            and '\\' not in name and all(p not in ('', '.', '..', '__pycache__', '.git') for p in name.split('/'))
            and not name.endswith('.pyc'), 'Unsafe source member')
        require(type(row['bytes']) is int and row['bytes'] >= 0 and isinstance(row['sha256'], str)
            and len(row['sha256']) == 64, 'Invalid source record')
        require(type(row.get('user_executable')) is bool, 'Executable metadata must be a boolean: ' + name)
        names.append(name)
    require(len(names) == len(set(names)) and sum(r['bytes'] for r in rows) == SOURCE_BYTES,
        'Duplicate source path or byte count differs')
    require(tuple(sorted(row['path'] for row in rows if row['user_executable'])) == EXECUTABLE_PATHS,
        'Declared executable path set differs from trusted baseline')
    return {row['path']: row for row in rows}


def metadata_platform():
    return os.name


def snapshot(project, manifest, *, diagnostic=None, phase='FROZEN_BEFORE'):
    project = safe_path(project)
    wanted = validate_manifest(manifest)
    _diagnostic_call(diagnostic, 'register_sources', wanted)
    family = metadata_platform()
    require(family in ('posix', 'nt'), 'Unqualified filesystem metadata platform')
    allowed_dirs = {p.as_posix() for name in wanted for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    files, directories, modes, metadata = {}, set(), {}, {}
    fields = lambda s: {key: getattr(s, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
    metadata['.'] = fields(project.stat())
    for path in project.rglob('*'):
        require(not path.is_symlink(), 'Source symlink rejected')
        name = path.relative_to(project).as_posix()
        metadata[name] = fields(path.stat())
        if path.is_dir():
            directories.add(name)
        else:
            require(name in wanted, 'Unexpected source member: ' + name)
            raw = read_file(path, diagnostic=diagnostic, context=('SOURCE', phase, name,
                wanted[name]['bytes'], wanted[name]['sha256']))
            require(len(raw) == wanted[name]['bytes'] and digest(raw) == wanted[name]['sha256'],
                'Source bytes differ: ' + name)
            files[name] = raw
            modes[name] = stat.S_IMODE(path.stat().st_mode)
            if family == 'posix':
                require(bool(modes[name] & stat.S_IXUSR) is wanted[name]['user_executable'],
                    'Source user-executable metadata differs: ' + name)
    require(set(files) == set(wanted) and directories == allowed_dirs, 'Missing/extra source path or directory')
    canonical = hashlib.sha256()
    for name, raw in sorted(files.items()):
        encoded = name.encode('utf-8')
        canonical.update(len(encoded).to_bytes(4, 'big') + encoded + len(raw).to_bytes(8, 'big') + raw)
    require(canonical.hexdigest() == SOURCE_SHA, 'Canonical source SHA differs')
    summary = {'files': len(files), 'bytes': sum(map(len, files.values())),
        'canonical_sha256': canonical.hexdigest(), 'per_file_sha256': {n: digest(b) for n, b in sorted(files.items())},
        'observed_file_modes': modes, 'non_atime_metadata': metadata,
        'executable_metadata': {
            'contract': METADATA_CONTRACT,
            'trusted_core_index_sha256': CORE_INDEX_SHA,
            'declared_executable_paths': list(EXECUTABLE_PATHS),
            'status': 'VERIFIED_POSIX_USER_EXECUTABLE_BITS' if family == 'posix'
                else 'NOT_VERIFIED_POSIX_BITS_ON_WINDOWS_FILESYSTEM',
            'full_posix_permissions_or_ownership_reproduction': 'NOT_CLAIMED'}}
    return files, summary


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def child_environment(directory):
    # No CI token, arbitrary env dump, user credential or pip config is passed.
    keep = {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'DISPLAY', 'XAUTHORITY',
        'TCL_LIBRARY', 'TK_LIBRARY', 'LD_LIBRARY_PATH',
        'PROGRAMFILES', 'COMSPEC', 'PATHEXT', 'LANG', 'LC_ALL', 'TZ'}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    directory = safe_path(directory)
    profile = directory / 'private_profile'
    locations = {'HOME': profile, 'USERPROFILE': profile, 'APPDATA': profile / 'AppData/Roaming',
        'LOCALAPPDATA': profile / 'AppData/Local', 'XDG_CONFIG_HOME': profile / '.config',
        'XDG_CACHE_HOME': profile / '.cache', 'XDG_DATA_HOME': profile / '.local/share',
        'TEMP': directory / 'private_tmp', 'TMP': directory / 'private_tmp', 'TMPDIR': directory / 'private_tmp'}
    for key, path in locations.items():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        env[key] = str(path)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1', MOKOSH_DATA_DIR=str(Path(directory) / 'synthetic_data'))
    return env


def private_temp_base(project=None):
    """Resolve known OS temporary-directory aliases before creating owned copies."""
    base = Path(os.environ.get('RUNNER_TEMP') or tempfile.gettempdir()).resolve(strict=True)
    base = safe_path(base)
    require(base.is_dir(), 'Private temporary base must be an existing directory')
    if project is not None:
        require(base != project and project not in base.parents, 'Temporary base must be outside frozen project')
    return base


def run_owned(argv, *, timeout, check=False, **options):
    """Bound the owned child process tree; Linux full-suite work uses a new session."""
    if os.name == 'nt':
        options['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options['start_new_session'] = True
    process = subprocess.Popen(argv, **options)

    def stop_tree():
        if os.name == 'nt':
            if process.poll() is None:
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10, check=False)
        else:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    break
                if sig == signal.SIGTERM:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)

    try:
        returncode = process.wait(timeout=timeout)
    except BaseException as error:
        stop_tree()
        if isinstance(error, subprocess.TimeoutExpired):
            error.owned_pid = process.pid
        raise
    finally:
        # Retire any remaining ordinary descendants before inspecting source.
        if os.name != 'nt':
            stop_tree()
    result = subprocess.CompletedProcess(argv, returncode)
    if check and returncode:
        raise subprocess.CalledProcessError(returncode, argv)
    return result


def runtime_probe(directory):
    report = {'python': platform.python_version(), 'python_executable': sys.executable,
        'platform': platform.platform(), 'machine': platform.machine(), 'dependencies': {}, 'probe_errors': []}
    for name in DEPENDENCIES:
        try:
            report['dependencies'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            report['dependencies'][name] = None
            report['probe_errors'].append({'component': name, 'error': 'PACKAGE_NOT_INSTALLED'})
    code = '''import json,ssl
r={'python_ssl_openssl':ssl.OPENSSL_VERSION}
try:
 from cryptography.hazmat.backends.openssl.backend import backend
 r['cryptography_openssl']=backend.openssl_version_text()
except Exception as e:r['crypto_probe_error']=type(e).__name__+': '+str(e)
try:
 import tkinter as tk, _tkinter
 r['compiled_Tk']=_tkinter.TK_VERSION;r['compiled_Tcl']=_tkinter.TCL_VERSION
 t=tk.Tcl();r['Tcl']=str(t.call('info','patchlevel'))
 r.update(Tk=None,backend=None,Tk_display_probe='NOT_EXECUTED_HEADLESS')
except Exception as e:r['Tk_probe_error']=type(e).__name__+': '+str(e)
print(json.dumps(r))'''
    try:
        with tempfile.TemporaryDirectory(prefix='mokosh-ci-runtime-', dir=private_temp_base()) as temporary:
            process = subprocess.run([sys.executable, '-I', '-B', '-c', code], stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=15, env=child_environment(temporary), check=False)
        (Path(directory) / 'runtime_stdout.log').write_text(process.stdout)
        (Path(directory) / 'runtime_stderr.log').write_text(process.stderr)
        require(type(process.returncode) is int and process.returncode == 0, 'Runtime probe child failed')
        report.update(json.loads(process.stdout))
    except Exception as error:
        report['probe_errors'].append({'component': 'runtime_child', 'error': type(error).__name__ + ': ' + str(error)})
    report['matches_Dell'] = {'Python': report['python'] == '3.12.3',
        'dependencies': report['dependencies'] == DEPENDENCIES, 'Tk': report.get('Tk') == '8.6.14',
        'backend': report.get('backend') == 'x11',
        'cryptography_OpenSSL': report.get('cryptography_openssl') == 'OpenSSL 4.0.1 9 Jun 2026'}
    report['exact_Dell_environment'] = False
    report['Tk_probe_scope'] = 'COMPILED_TK_AND_ACTUAL_TCL_ONLY; ACTUAL_TK_PATCH_UNKNOWN; NO_PRODUCT_GUI'
    return report


def validate_worker(record):
    require(record.get('result') == 'PASS_FROZEN_BASELINE_2509', 'Worker did not pass baseline')
    require(type(record.get('test_modules')) is int and record['test_modules'] == 92
        and type(record.get('discovered')) is int and record['discovered'] == TESTS
        and type(record.get('tests_run')) is int and record['tests_run'] == TESTS, 'Incomplete test inventory')
    ids = record.get('successful_test_ids')
    require(type(ids) is list and all(isinstance(i, str) for i in ids) and len(ids) == len(set(ids)) == TESTS,
        'Missing/duplicate successful test IDs')
    require(all(record.get(k) == [] for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')),
        'Unresolved test result')
    require(record.get('source_files_unchanged') is True
        and record.get('R3_candidate_tested') is False and record.get('source_overlay_applied') is False
        and record.get('live_apply') is False, 'Worker source/scope invariant failed')
    for key in ('source_before', 'source_after'):
        value = record.get(key, {})
        require((value.get('files'), value.get('bytes'), value.get('canonical_sha256'))
            == (SOURCE_FILES, SOURCE_BYTES, SOURCE_SHA), 'Worker source binding differs')
    require(record.get('source_before') == record.get('source_after'), 'Worker source identity changed')
    require(record.get('native_GUI_acceptance') == 'NOT_TESTED'
        and record.get('physical_GUI') == 'NOT_TESTED'
        and record.get('callback_reporting_acceptance') == 'NOT_TESTED_BY_THIS_UNIT_SUITE', 'Worker overclaims GUI acceptance')


def run_audit(project, manifest_path, output, mode, worker, *, probe=runtime_probe, process_run=run_owned,
        diagnostic=None, diagnostic_only=False):
    project, manifest_path, output = safe_path(project), safe_path(manifest_path), safe_path(output)
    require(output != project and project not in output.parents, 'Reports must be outside frozen project')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'result': 'INCOMPLETE', 'mode': mode, 'source_sha256': SOURCE_SHA,
        'product_mutation_allowed': False, 'R3_candidate_executed': False,
        'native_GUI_acceptance': 'NOT_EXECUTED', 'physical_GUI': 'NOT_EXECUTED',
        'callback_cleanliness': 'NOT_ESTABLISHED_BY_UNITTEST_OR_CHILD_EXIT_ZERO',
        'known_open_finding': 'D005 parent restoration OPEN; native callback lifecycle acceptance remains separate',
        'GitHub_run': {key: os.environ.get(key) for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}}
    before, manifest, copy_root = None, None, None
    try:
        require(not diagnostic_only or (diagnostic is not None and mode == 'portability-probe'),
            'Diagnostic mode requires an observer and portability scope')
        require(mode in ('linux-baseline', 'portability-probe'), 'Unsupported audit mode')
        require(mode != 'linux-baseline' or sys.platform == 'linux', 'Full baseline CI mode is Linux-only until other suites are validated')
        manifest = json.loads(read_file(manifest_path, diagnostic=diagnostic,
            context=('FIXED', 'AUDIT_MANIFEST', 'SOURCE_MANIFEST.json', None, None)))
        files, before = snapshot(project, manifest, diagnostic=diagnostic, phase='FROZEN_BEFORE')
        report['source_before'] = before
        write_json(output / 'SOURCE_BEFORE.json', before)
        with tempfile.TemporaryDirectory(prefix='mokosh-ci-source-', dir=private_temp_base(project)) as temporary:
            copy_root = Path(temporary) / 'project'
            copy_root.mkdir(mode=0o700)
            for name, raw in files.items():
                target = copy_root.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(before['observed_file_modes'][name])
            _, copy_before = snapshot(copy_root, manifest, diagnostic=diagnostic, phase='COPY_BEFORE')
            if diagnostic_only:
                _diagnostic_call(diagnostic, 'event', 'COPY_SNAPSHOT_COMPLETE')
                report['result'] = 'DIAGNOSTIC_NON_REPRODUCED'
                report['diagnostic_stop'] = 'BEFORE_COMPILE_RUNTIME_PROBE_WORKER'
                return 1
            for name, raw in files.items():
                if name.endswith('.py'):
                    compile(raw, name, 'exec', dont_inherit=True)
            report['compiled_python_files'] = sum(n.endswith('.py') for n in files)
            report['runtime'] = probe(output)
            write_json(output / 'RUNTIME.json', report['runtime'])
            try:
                if mode == 'linux-baseline':
                    worker = safe_path(worker)
                    report['worker_sha256'] = digest(read_file(worker))
                    with (output / 'worker_stdout.log').open('x', encoding='utf-8') as stdout, \
                         (output / 'worker_stderr.log').open('x', encoding='utf-8') as stderr:
                        process = process_run([sys.executable, '-I', '-B', str(worker), '--project', str(copy_root),
                            '--output', str(output / 'worker')], cwd=temporary, env=child_environment(temporary),
                            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=300, check=False)
                    report['worker_exit_status'] = process.returncode
                    record = json.loads(read_file(output / 'worker/RESULT.json'))
                    report['worker_result'] = record['result']
                    require(type(process.returncode) is int and process.returncode == 0, 'Worker process failed')
                    validate_worker(record)
                    report['result'] = 'PASS_COMPATIBILITY_ON_RECORDED_CI_RUNTIME'
                else:
                    require(not report['runtime'].get('probe_errors') and not report['runtime'].get('Tk_probe_error')
                        and not report['runtime'].get('crypto_probe_error'), 'Portability capability probe unresolved')
                    report['result'] = 'PASS_PORTABILITY_PROBE_ONLY'
                    report['full_2509'] = 'NOT_EXECUTED_ON_THIS_PLATFORM'
            finally:
                _, copy_after = snapshot(copy_root, manifest, diagnostic=diagnostic, phase='COPY_FINAL')
                report['temporary_copy_unchanged'] = copy_after == copy_before
                require(report['temporary_copy_unchanged'], 'Temporary project copy changed')
    except BaseException as error:
        report['result'] = 'FAIL_PRELIMINARY_ANALYSIS'
        report['error'] = {'type': type(error).__name__, 'detail': str(error), 'traceback': traceback.format_exc()}
    finally:
        try:
            if manifest is not None:
                _, after = snapshot(project, manifest, diagnostic=diagnostic, phase='FROZEN_FINAL')
                report['source_after'] = after
                report['frozen_source_unchanged'] = before is not None and after == before
                write_json(output / 'SOURCE_AFTER.json', after)
                require(report['frozen_source_unchanged'], 'Frozen source changed')
        except BaseException as error:
            report['result'] = 'FAIL_PRELIMINARY_ANALYSIS'
            report['final_source_error'] = {'type': type(error).__name__, 'detail': str(error)}
        try:
            report['temporary_copy_retained'] = copy_root.exists() if copy_root is not None else False
            if report['temporary_copy_retained']:
                report['result'] = 'FAIL_PRELIMINARY_ANALYSIS'
                report['temporary_cleanup_error'] = 'Owned temporary source copy still exists'
        except OSError as error:
            report['temporary_copy_retained'] = 'UNKNOWN'
            report['temporary_cleanup_error'] = type(error).__name__ + ': ' + str(error)
            report['result'] = 'FAIL_PRELIMINARY_ANALYSIS'
        if diagnostic is not None:
            report['diagnostic'] = _diagnostic_call(diagnostic, 'summary') or {'collection': 'DIAGNOSTIC_INCOMPLETE'}
            if report['diagnostic']['collection'] != 'DIAGNOSTIC_INCOMPLETE':
                report['diagnostic']['collection'] = 'PENDING_FINAL_RECEIPT'
            report['diagnostic']['finalization_scope'] = 'PRE_ENTRY_FINAL_RECEIPT; FINAL_JOB_LOG_RECEIPT_REQUIRED'
        write_json(output / 'AUDIT_RESULT.json', report)
    return 0 if report['result'].startswith('PASS_') else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--mode', choices=('linux-baseline', 'portability-probe'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', type=Path, default=Path(__file__).with_name('run_baseline_tests.py'))
    args = parser.parse_args()
    require(sys.flags.isolated and sys.dont_write_bytecode, 'Explicit -I and -B required')
    raise SystemExit(run_audit(args.project, args.manifest, args.output, args.mode, args.worker))
