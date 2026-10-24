"""Bound analysis-tool process descendants in a private environment."""
from pathlib import Path
import argparse
import os
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import run_owned, child_environment, private_temp_base, require


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--timeout', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    require(command and 1 <= args.timeout <= 600, 'A bounded explicit analysis command is required')
    with tempfile.TemporaryDirectory(prefix='mokosh-ci-tools-', dir=private_temp_base()) as temporary:
        process = run_owned(command, timeout=args.timeout, cwd=os.getcwd(),
            env=child_environment(temporary))
    raise SystemExit(process.returncode)
