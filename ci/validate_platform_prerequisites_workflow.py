"""Exact reviewed prerequisite workflow bytes; not a general YAML/action audit."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import safe_path, require

EXPECTED_SHA256 = '14eda4245276b502289e3f878a7b818da0522c57f117d11b0f1b7ad39e2cb65c'


def check(path):
    path = safe_path(path)
    raw = path.read_bytes()
    require(len(raw) <= 32768, 'Prerequisite workflow exceeds reviewed bound')
    observed = hashlib.sha256(raw).hexdigest()
    require(observed == EXPECTED_SHA256,
        'Platform prerequisite workflow differs from the exact reviewed template')
    return {'result': 'PASS_EXACT_REVIEWED_PLATFORM_PREREQUISITES_WORKFLOW',
        'sha256': observed, 'GitHub_execution': 'NOT_ASSESSED_BY_THIS_TEMPLATE_CHECKER',
        'scope': 'MANUAL_SELECTED35_POSIX_OR21_WINDOWS_PLUS5_OBSERVATIONS_THREE_OS_PYTHON3123_PINNED_ACTIONS_READ_ONLY; NOT_GENERAL_YAML_OR_ACTION_AUDIT',
        'product_platform_GUI_storage_acceptance': 'NOT_ASSESSED'}


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--workflow', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    project, output = map(safe_path, (args.project, args.output))
    require(output != project and project not in output.parents,
        'Workflow review output must be outside frozen project')
    status = 1
    try:
        record = check(args.workflow)
        status = 0
    except Exception:
        record = {'result': 'FAIL_PLATFORM_PREREQUISITES_WORKFLOW_TEMPLATE',
            'GitHub_execution': 'NOT_ASSESSED_BY_THIS_TEMPLATE_CHECKER'}
    raw = json.dumps(record, sort_keys=True, ensure_ascii=True) + '\n'
    require(len(raw.encode('ascii')) <= 4096, 'Workflow review receipt exceeds bound')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = safe_path(output)
    with output.open('x', encoding='ascii') as stream:
        require(stream.write(raw) == len(raw), 'Incomplete workflow review receipt write')
        stream.flush()
    print(raw, end='', flush=True)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
