"""Fail-closed report-only artifact allowlist; excludes synthetic data/cache."""
from pathlib import Path
import argparse
import json
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import safe_path, read_file, write_json, require, digest

REPORT_NAMES = {'AUDIT_RESULT.json', 'RUNTIME.json', 'SOURCE_BEFORE.json', 'SOURCE_AFTER.json',
    'runtime_stdout.log', 'runtime_stderr.log', 'worker_stdout.log', 'worker_stderr.log',
    'worker/RESULT.json', 'worker/FULL_TESTS.log'}
SECURITY_NAMES = {'RESULT.json', 'bandit.stdout.log', 'bandit.stderr.log', 'bandit.report.json',
    'BANDIT_FINDING_INDEX.json', 'candidate-bandit.stdout.log', 'candidate-bandit.stderr.log',
    'candidate-bandit.report.json', 'R3_BANDIT_FINDING_INDEX.json',
    'pip-audit.stdout.log', 'pip-audit.stderr.log'}
ALLOWED = {'JOB_STATUS.json', 'controls/CI_GUARDS.log', 'controls/WORKFLOW_REVIEW.json'} | {'report/' + n for n in REPORT_NAMES} | {'security/' + n for n in SECURITY_NAMES}
ALLOWED |= {group + '/' + name for group in ('bootstrap-runtime', 'bootstrap-tools') for name in ('RESULT.json', 'pip_install.log')}
EXCLUDED = ('report/worker/isolated_test_data/', 'security/advisory-cache/', 'security/private-home/')
MAX_APPROVED_BYTES = 99 * 1024 * 1024  # Reserve bounded room for failure/manifest receipts.


def stage(root, output):
    root, output = safe_path(root), safe_path(output)
    require(root != output and root not in output.parents and output not in root.parents,
        'Artifact staging must be a separate new directory')
    require(root.is_dir() and not output.exists(), 'Existing report root and new artifact directory required')
    files, excluded, issues = {}, [], []
    for path in root.rglob('*'):
        if path.is_symlink():
            issues.append('SYMLINK_REJECTED')
            continue
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name.startswith(EXCLUDED):
            excluded.append(name)
            continue
        if name not in ALLOWED:
            issues.append('UNAPPROVED_ARTIFACT_FILE_REJECTED')
            continue
        try:
            raw = read_file(path)
            require(len(raw) <= 20 * 1024 * 1024, 'Artifact file exceeds bound')
            require(sum(map(len, files.values())) + len(raw) <= MAX_APPROVED_BYTES, 'Approved report budget exceeded')
            files[name] = raw
        except Exception:
            issues.append('UNSAFE_APPROVED_REPORT_REJECTED')
    approved_count = len(files)
    if not files:
        issues.append('NO_APPROVED_RAW_REPORT_AVAILABLE')
    if issues:
        # No unapproved name/content enters the upload. Preserve an explicit
        # failure receipt and only independently validated approved raw logs.
        files['ARTIFACT_SCOPE_FAILURE.json'] = (json.dumps({'result': 'FAIL_ARTIFACT_SCOPE',
            'issue_counts': {kind: issues.count(kind) for kind in sorted(set(issues))},
            'unapproved_content_included': False, 'approved_failure_logs_preserved': bool(approved_count),
            'approved_raw_file_count': approved_count}) + '\n').encode()
    output.mkdir(mode=0o700)
    for name, raw in sorted(files.items()):
        path = output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
    report = {'result': 'FAIL_SCOPE_WITH_ONLY_APPROVED_FAILURE_EVIDENCE_SEALED' if issues
        else 'PASS_EXPLICIT_REPORT_ARTIFACT_ALLOWLIST', 'safe_subset_sealed': True, 'files':
        {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in sorted(files.items())},
        'known_excluded_synthetic_data_or_cache_files': len(excluded),
        'complete_product_source_tree_or_private_copy_included': False,
        'source_excerpts_may_appear_in_approved_analysis_reports': True,
        'content_secret_scan': 'NOT_PERFORMED_BY_THIS_PATH_ALLOWLIST'}
    write_json(output / 'ARTIFACT_MANIFEST.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = stage(args.root, args.output)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            stream.write('sealed=true\n')
    print(json.dumps(value, indent=2))
    raise SystemExit(0 if value['result'].startswith('PASS_') else 1)
