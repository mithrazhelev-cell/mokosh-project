"""Stdlib-only exact reviewed diagnostic workflow template, not general YAML lint."""
from pathlib import Path
import argparse
import hashlib
import json

EXPECTED_SHA256 = 'da42dabc8430822bdec48a2849ad1d57087a14484360fe9a1fad7d2f72a46f85'


def check(path):
    raw = Path(path).read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != EXPECTED_SHA256:
        raise ValueError('Diagnostic workflow differs from exact reviewed template')
    return {'result': 'PASS_EXACT_REVIEWED_DIAGNOSTIC_WORKFLOW_TEMPLATE',
        'sha256': observed, 'GitHub_execution': 'NOT_ASSESSED_BY_THIS_TEMPLATE_CHECKER',
        'scope': 'MANUAL_WINDOWS2022_X64_PYTHON3123_PINNED_ACTIONS_READ_ONLY_FIXED_COMMANDS; NOT_GENERAL_YAML_AUDIT'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--workflow', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.workflow)
        status = 0
    except Exception:
        result = {'result': 'FAIL_DIAGNOSTIC_WORKFLOW_TEMPLATE'}
        status = 1
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(status)
