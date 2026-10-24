"""Report-only Python source/dependency analysis; never import application code.

Run with the pinned analysis-tool interpreter. Exit0: complete/no findings;
exit1: complete/findings; exit2: incomplete tool/report; exit3: source drift.
No finding suppression, dependency resolution, package fixes, or product edits.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SOURCE_SHA = '92e159ed818bc6fbf858549452ad78fd0b238f9d8193ac9842147555afb3dcca'
TOOLS = {'bandit': '1.9.4', 'pip-audit': '2.10.1'}
RUNTIME = {'cryptography': '49.0.0', 'argon2-cffi': '25.1.0',
           'argon2-cffi-bindings': '25.1.0', 'cffi': '2.1.0', 'pycparser': '3.0'}
CANDIDATE = {
    'd005_action_captions.py': 'b62813adb60a6d786f331c3d45252a077c1c236acabe0fa2932c6b413c97becb',
    'd005_callback_guard.py': 'b9ca07d14f1079b712d2326cb81262bb1e148b3ecacbf73e26e76d433e00d48e',
    'd005_max_parent_return.py': 'be9759c43434bfa59d14b1e9eab97ff9c67631e477d78fc2ed3f9bde69a9a415',
    'd005_state_labels.py': '2687db6ef3f6500e649ea1f5e73f6a2f160bb34d56d87b5e212161047c286452',
    'd005_x11_restore.py': 'b33904277ef339c62adbe6773abc307c9313b3dc89519bbec89c7fe8d2dbc1f1',
    'run_mokosh_v2_local_visual_harness.py': '9adcedeb13bf68cd43e85eb1b3a9f16d1848d021e67f0e7b3cc814b4057b8fe8',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def non_atime_metadata(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def snapshot(root):
    root = root.resolve(strict=True)
    found = {}
    metadata = {'.': non_atime_metadata(root.lstat())}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'Source symlink rejected')
        name = path.relative_to(root).as_posix()
        metadata[name] = non_atime_metadata(info)
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), 'Nonregular source member rejected')
        require(path.suffix != '.pyc' and not any(p in ('.git', '__pycache__', 'venv') for p in path.relative_to(root).parts), 'Unexpected source cache/repository member')
        raw = path.read_bytes()
        require(non_atime_metadata(path.lstat()) == metadata[name], 'Source changed while read')
        found[name] = {'bytes': len(raw), 'sha256': digest(raw)}
    aggregate = hashlib.sha256()
    for name in found:
        raw = (root / name).read_bytes()
        encoded = name.encode('utf-8', 'surrogateescape')
        aggregate.update(len(encoded).to_bytes(4, 'big'))
        aggregate.update(encoded)
        aggregate.update(len(raw).to_bytes(8, 'big'))
        aggregate.update(raw)
    return {'files': len(found), 'bytes': sum(r['bytes'] for r in found.values()),
            'sha256': aggregate.hexdigest(), 'members': found,
            'non_atime_metadata': metadata,
            'guard_scope': 'CONTENT_PATHS_AND_RECORDED_NON_ATIME_METADATA'}


def validate_runtime_lock(path):
    text = path.read_text()
    lines = [line.strip() for line in text.replace('\\\n', ' ').splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    found = {}
    for line in lines:
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)', line)
        require(match is not None, 'Only exact names/versions with SHA256 hashes allowed in runtime lock')
        name = re.sub('[-_.]+', '-', match[1]).lower()
        require(name not in found, 'Duplicate runtime requirement')
        found[name] = match[2]
    require(found == RUNTIME, 'Runtime lock differs from exact recorded five-package closure')
    return {'packages': found, 'lock_sha256': digest(text.encode())}


def safe_paths(source, output, candidate=None):
    source = source.resolve(strict=True)
    candidate = candidate.resolve(strict=True) if candidate is not None else None
    # Resolve ancestor links before any output mkdir, report, or tool launch.
    output = output.resolve(strict=False)
    require(not output.is_relative_to(source), 'Reports must be outside frozen product')
    require(candidate is None or not output.is_relative_to(candidate),
            'Reports must be outside candidate inputs')
    return source, output, candidate


def child_environment(output):
    home = output / 'private-home'
    for path in (home, home / 'cache', home / 'config', home / 'tmp', home / 'local'):
        path.mkdir(mode=0o700, exist_ok=True)
    keep = {'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in keep}
    environment.update(HOME=str(home), USERPROFILE=str(home),
        XDG_CACHE_HOME=str(home / 'cache'), XDG_CONFIG_HOME=str(home / 'config'),
        LOCALAPPDATA=str(home / 'local'), APPDATA=str(home / 'config'),
        TMPDIR=str(home / 'tmp'), TEMP=str(home / 'tmp'), TMP=str(home / 'tmp'),
        PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    return environment


def execute(name, argv, output, timeout):
    started = time.monotonic()
    with (output / (name + '.stdout.log')).open('xb') as stdout, (output / (name + '.stderr.log')).open('xb') as stderr:
        try:
            process = subprocess.run(argv, cwd=output, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, timeout=timeout, check=False,
                env=child_environment(output))
            exit_code, error = process.returncode, None
        except subprocess.TimeoutExpired:
            exit_code, error = None, 'TIMEOUT'
    return {'argv': argv, 'exit': exit_code, 'error': error,
            'timeout_cleanup_scope': 'DIRECT_CHILD; OUTER_CI_CONTROLLER_OWNS_PROCESS_GROUP',
            'duration_seconds': round(time.monotonic() - started, 3),
            'stdout_sha256': digest((output / (name + '.stdout.log')).read_bytes()),
            'stderr_sha256': digest((output / (name + '.stderr.log')).read_bytes())}


def bandit_summary(output, source, before, process, *, prefix='bandit', candidate=False):
    value = json.loads((output / (prefix + '.report.json')).read_text())
    findings = value.get('results')
    require(type(findings) is list and value.get('errors') == [], 'Bandit parse/tool errors or incomplete report')
    scopes = Counter()
    severities = Counter()
    confidences = Counter()
    rules = Counter()
    inventory = []
    for item in findings:
        path = Path(item['filename']).resolve(strict=True)
        require(path.is_relative_to(source), 'Bandit reported a file outside frozen source')
        name = path.relative_to(source).as_posix()
        scope = ('R3_LAB_CANDIDATE_NOT_APPLIED' if candidate else
                 'tests' if 'tests' in path.relative_to(source).parts else 'application_or_harness')
        scopes[scope] += 1
        severities[item['issue_severity']] += 1
        confidences[item['issue_confidence']] += 1
        rules[item['test_id']] += 1
        inventory.append({'path': name, 'line': item['line_number'], 'rule': item['test_id'],
            'severity': item['issue_severity'], 'confidence': item['issue_confidence'],
            'scope': scope, 'review_status': 'UNTRIAGED_STATIC_FINDING_NOT_CONFIRMED_DEFECT'})
    expected = {name for name in before['members'] if name.endswith('.py')}
    measured = {Path(name).resolve().relative_to(source).as_posix()
                for name in value['metrics'] if name != '_totals'}
    require(measured == expected and value.get('skipped', []) == [], 'Bandit Python-file coverage differs')
    require(process['exit'] == (1 if findings else 0), 'Bandit exit contradicts report')
    index = 'R3_BANDIT_FINDING_INDEX.json' if candidate else 'BANDIT_FINDING_INDEX.json'
    (output / index).write_text(json.dumps(inventory, indent=2) + '\n')
    return {'status': 'COMPLETE_FINDINGS_PRESENT' if findings else 'COMPLETE_NO_FINDINGS',
        'findings': len(findings), 'python_files_scanned': len(measured),
        'by_scope': dict(scopes), 'by_severity': dict(severities),
        'by_confidence': dict(confidences), 'by_rule': dict(rules),
        'nosec_handling': 'IGNORE_EXISTING_NOSEC_AND_REPORT_ALL_ENABLED_RULES',
        'automatic_fixes': False, 'raw_report': prefix + '.report.json'}


def run_bandit(source, before, output, *, prefix='bandit', candidate=False):
    # Bandit1.9.4 emits progress on stdout. Its documented output-file interface
    # keeps machine JSON separate while preserving the complete stdout/stderr.
    argv = [sys.executable, '-I', '-B', '-m', 'bandit', '-r', str(source), '-f', 'json',
            '-o', str(output / (prefix + '.report.json')), '--ignore-nosec']
    process = execute(prefix, argv, output, 180)
    summary = bandit_summary(output, source, before, process, prefix=prefix, candidate=candidate)
    return process, summary


def dependency_summary(output, process):
    value = json.loads((output / 'pip-audit.stdout.log').read_text())
    dependencies = value.get('dependencies')
    require(type(dependencies) is list, 'Dependency report missing')
    actual = {re.sub('[-_.]+', '-', r['name']).lower(): r['version'] for r in dependencies}
    require(actual == RUNTIME and len(dependencies) == len(RUNTIME), 'Dependency audit coverage differs')
    require(not any(r.get('skip_reason') for r in dependencies), 'Dependency advisory lookup skipped')
    findings = [{'name': r['name'], 'version': r['version'], 'vulnerability': v['id'],
                 'aliases': v.get('aliases', []), 'fix_versions': v.get('fix_versions', [])}
                for r in dependencies for v in r['vulns']]
    # Keep the full raw feed evidence; count repeated IDs once in advice.
    groups = []
    for finding in findings:
        identities = {finding['vulnerability'], *finding['aliases']}
        separate = []
        for group in groups:
            if group & identities:
                identities.update(group)
            else:
                separate.append(group)
        groups = [*separate, identities]
    require(process['exit'] == (1 if findings else 0), 'Dependency audit exit contradicts report')
    return {'status': 'COMPLETE_FINDINGS_PRESENT' if findings else 'COMPLETE_NO_KNOWN_VULNERABILITIES',
            'packages': len(dependencies), 'findings': findings,
            'raw_advisory_records': len(findings), 'distinct_alias_group_advisories': len(groups),
            'advisory_alias_groups': [sorted(group) for group in groups],
            'raw_vulnerability_records': len(findings), 'distinct_vulnerabilities': len(groups),
            'duplicate_vulnerability_records': len(findings) - len(groups), 'dependency_resolution': False,
            'application_packages_installed_or_upgraded': False, 'automatic_fixes': False,
            'raw_report': 'pip-audit.stdout.log'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime-requirements', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, help='Exact six R3 overlays; static-only and not applied')
    args = parser.parse_args()
    source, output, candidate = safe_paths(args.source, args.output, args.candidate)
    output.mkdir(mode=0o700, parents=True)
    report = {'result': 'INCOMPLETE', 'scope': 'PRELIMINARY_REPORTS_ONLY_NO_PRODUCT_FIX',
              'source': str(source), 'python': sys.version, 'tools': {}, 'product_changes_allowed': False,
              'GitHub_upload_performed': False, 'crypto_security_acceptance': 'NOT_ESTABLISHED',
              'native_or_physical_GUI_acceptance': 'NOT_ESTABLISHED'}
    code = 2
    before = None
    candidate_before = None
    try:
        require(sys.version_info[:2] == (3, 12) and sys.flags.isolated and sys.dont_write_bytecode,
                'Use explicit Python3.12 -I -B analysis interpreter')
        versions = {name: importlib.metadata.version(name) for name in TOOLS}
        require(versions == TOOLS, 'Analysis tool versions differ from reviewed pins')
        report['tools'] = versions
        before = snapshot(source)
        require(before['files'] == 263 and before['sha256'] == SOURCE_SHA, 'Frozen263 source identity differs; no scan started')
        report['source_before'] = before
        report['runtime_lock'] = validate_runtime_lock(args.runtime_requirements.resolve(strict=True))
        if candidate is not None:
            candidate_before = snapshot(candidate)
            require({n: r['sha256'] for n, r in candidate_before['members'].items()} == CANDIDATE,
                    'Static-only R3 candidate source identity differs')
            report['candidate_before'] = candidate_before
            report['candidate_scope'] = 'SIX_R3_LAB_RUNTIME_OVERLAYS_STATIC_ONLY_NOT_APPLIED'
        report['bandit_process'], report['bandit'] = run_bandit(source, before, output)
        if candidate is not None:
            report['candidate_bandit_process'], report['candidate_bandit'] = run_bandit(
                candidate, candidate_before, output, prefix='candidate-bandit', candidate=True)
        audit = [sys.executable, '-I', '-B', '-m', 'pip_audit', '--strict', '--disable-pip', '--no-deps',
            '--require-hashes', '-r', str(args.runtime_requirements.resolve()), '-f', 'json',
            '--progress-spinner', 'off', '--cache-dir', str(output / 'advisory-cache'), '--timeout', '30']
        report['dependency_process'] = execute('pip-audit', audit, output, 180)
        report['dependencies'] = dependency_summary(output, report['dependency_process'])
        finding_count = (report['bandit']['findings'] + len(report['dependencies']['findings'])
                         + report.get('candidate_bandit', {}).get('findings', 0))
        report['result'] = 'REPORTS_COMPLETE_FINDINGS_PRESENT' if finding_count else 'REPORTS_COMPLETE_NO_FINDINGS'
        code = 1 if finding_count else 0
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'detail': str(error)}
    finally:
        if before is not None:
            try:
                after = snapshot(source)
                report['source_after'] = after
                require(after == before, 'STOP: product source changed during analysis')
                report['source_no_mutation'] = 'PASS'
            except Exception as error:
                report['source_no_mutation'] = 'FAIL_STOP'
                report['source_guard_error'] = {'type': type(error).__name__, 'detail': str(error)}
                report['result'], code = 'STOP_SOURCE_MUTATION_OR_UNVERIFIABLE', 3
        if candidate_before is not None:
            try:
                candidate_after = snapshot(candidate)
                report['candidate_after'] = candidate_after
                require(candidate_after == candidate_before, 'STOP: static-only candidate changed during analysis')
                report['candidate_no_mutation'] = 'PASS'
            except Exception as error:
                report['candidate_no_mutation'] = 'FAIL_STOP'
                report['candidate_guard_error'] = {'type': type(error).__name__, 'detail': str(error)}
                report['result'], code = 'STOP_SOURCE_MUTATION_OR_UNVERIFIABLE', 3
        report['runner_exit'] = code
        report['runner_source_sha256'] = digest(Path(__file__).read_bytes())
        (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report.get(k) for k in ('result', 'source_no_mutation', 'runner_exit', 'error')}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
