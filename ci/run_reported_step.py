"""Bound a fixed CI child and explicitly report its actual completed exit code.

The marker is evidence of child completion only. Its write AND flush must succeed.
No command arguments, environment values, file contents or exception bodies enter it.
"""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import child_environment, private_temp_base, require, run_owned

PREFIX = 'MOKOSH_STEP_EXIT='
STEPS = ('BOOTSTRAP', 'NATIVE_READER', 'PORTABILITY_PROBE', 'STAGE', 'CONTROL')
CI_METADATA = ('GITHUB_OUTPUT', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA',
    'RUNNER_OS', 'RUNNER_TEMP', 'ImageOS', 'ImageVersion')


def emit(stream, record):
    line = PREFIX + json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    require(len(line.encode('ascii')) <= 512, 'Step receipt exceeds bound')
    require(stream.write(line) == len(line), 'Incomplete step receipt write')
    stream.flush()


def run_step(command, *, step, timeout, stream=None, process_run=run_owned):
    require(step in STEPS and command and type(timeout) is int and 1 <= timeout <= 600,
        'A fixed step and bounded explicit command are required')
    stream = sys.stdout if stream is None else stream
    record = {'step': step, 'completion': 'INCOMPLETE', 'actual_child_exit': None,
        'scope': 'CHILD_EXIT_ONLY_NOT_PRODUCT_ACCEPTANCE'}
    status = 125
    try:
        with tempfile.TemporaryDirectory(prefix='mokosh-reported-step-', dir=private_temp_base()) as directory:
            environment = child_environment(directory)
            # Only runner bookkeeping required by the existing report/output contracts.
            # Tokens, credential variables and arbitrary caller environment are omitted.
            environment.update({key: os.environ[key] for key in CI_METADATA if key in os.environ})
            child = process_run(command, timeout=timeout, cwd=os.getcwd(), env=environment,
                stdin=subprocess.DEVNULL, check=False)
            require(type(child.returncode) is int, 'Completed child exit must be an integer')
            record.update(completion='CHILD_COMPLETED', actual_child_exit=child.returncode)
            # Preserve representable nonnegative codes exactly. POSIX signals
            # retain their raw negative value, with the usual 128+signal status.
            # Reject projections that could wrap to zero in a portable shell.
            projected = child.returncode if child.returncode >= 0 else 128 - child.returncode
            if 0 <= projected <= 255:
                status = projected
            else:
                record['reason'] = 'CHILD_EXIT_NOT_REPRESENTABLE_IN_PORTABLE_SHELL_STATUS'
                status = 125
    except subprocess.TimeoutExpired:
        record['completion'] = 'INCOMPLETE'
        record['reason'] = 'CHILD_TIMEOUT'
        status = 124
    except Exception:
        record['completion'] = 'INCOMPLETE'
        record['reason'] = 'CHILD_LAUNCH_OR_COLLECTION_FAILED'
        status = 125
    try:
        emit(stream, record)
    except Exception:
        return 125  # Even a written COMPLETE line cannot pass if its flush failed.
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--step', choices=STEPS, required=True)
    parser.add_argument('--timeout', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    return run_step(command, step=args.step, timeout=args.timeout)


if __name__ == '__main__':
    raise SystemExit(main())
