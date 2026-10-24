"""Stdlib exact reviewed manual verification template, not a general YAML parser."""
from pathlib import Path
import argparse
import hashlib
import json

EXPECTED_SHA256 = '8a4eaeb1b08c3ee6f4d946c710e0832758054e19774cb253908109a5dc6bb3aa'


def check(path):
    observed = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if observed != EXPECTED_SHA256:
        raise ValueError('Reader verification workflow differs from exact reviewed template')
    return {'result': 'PASS_EXACT_REVIEWED_READER_VERIFICATION_TEMPLATE',
        'sha256': observed, 'GitHub_execution': 'NOT_ASSESSED_BY_THIS_TEMPLATE_CHECKER',
        'scope': 'MANUAL_WINDOWS2022_X64_PYTHON3123_PINNED_ACTIONS_READ_ONLY_FIXED_COMMANDS; NOT_GENERAL_YAML_AUDIT'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--workflow', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    status = 1
    try:
        result = check(args.workflow)
        status = 0
    except Exception:
        result = {'result': 'FAIL_READER_VERIFICATION_WORKFLOW_TEMPLATE'}
    raw = json.dumps(result, sort_keys=True) + '\n'
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('Incomplete workflow review receipt')
        stream.flush()
    print(raw, end='', flush=True)
    raise SystemExit(status)
