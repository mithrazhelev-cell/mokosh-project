"""Private hashed binary-wheel environment bootstrap; reports failure unchanged."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import traceback
import venv

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_preliminary import safe_path, read_file, snapshot, write_json, require, digest, run_owned, child_environment


def bootstrap(project, manifest_path, destination, requirements, output):
    project, destination, output = map(safe_path, (project, destination, output))
    require(project not in destination.parents and destination != project
        and project not in output.parents and output != project, 'Environment/reports must be outside frozen project')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'result': 'INCOMPLETE', 'product_mutation_allowed': False, 'autofix': False}
    before, manifest = None, None
    try:
        manifest = json.loads(read_file(manifest_path))
        _, before = snapshot(project, manifest)
        require(not destination.exists(), 'Bootstrap destination must be new')
        lock = read_file(requirements)
        require(b'--hash=sha256:' in lock and b'==' in lock, 'Hash-pinned requirements required')
        report['requirements_sha256'] = digest(lock)
        venv.EnvBuilder(with_pip=True).create(destination)
        python = destination / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        with (output / 'pip_install.log').open('x', encoding='utf-8') as log:
            process = run_owned([str(python), '-I', '-B', '-m', 'pip', '--isolated', 'install',
                '--disable-pip-version-check', '--no-input', '--no-cache-dir', '--only-binary=:all:',
                '--require-hashes', '-r', str(Path(requirements).resolve())], stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, timeout=300, check=False,
                env=child_environment(destination / 'bootstrap_environment'))
        report['pip_exit_status'] = process.returncode
        require(type(process.returncode) is int and process.returncode == 0, 'Hashed wheel bootstrap failed')
        report['python_path'] = str(python)
        report['result'] = 'PASS_HASHED_BINARY_ENVIRONMENT_BOOTSTRAP_ONLY'
    except BaseException as error:
        report['result'] = 'FAIL_ENVIRONMENT_BOOTSTRAP'
        report['error'] = {'type': type(error).__name__, 'detail': str(error), 'traceback': traceback.format_exc()}
    finally:
        try:
            require(manifest is not None, 'Manifest unavailable for final source verification')
            _, after = snapshot(project, manifest)
            report['frozen_source_unchanged'] = before is not None and after == before
            require(report['frozen_source_unchanged'], 'Frozen source changed during bootstrap')
        except BaseException as error:
            report['result'] = 'FAIL_ENVIRONMENT_BOOTSTRAP'
            report['final_source_error'] = {'type': type(error).__name__, 'detail': str(error)}
        write_json(output / 'RESULT.json', report)
    if report['result'].startswith('PASS_') and os.environ.get('GITHUB_OUTPUT'):
        require('\n' not in report['python_path'] and '\r' not in report['python_path'], 'Unsafe output path')
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            stream.write('python-path=' + report['python_path'] + '\n')
    return 0 if report['result'].startswith('PASS_') else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('project', 'manifest', 'destination', 'requirements', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(bootstrap(args.project, args.manifest, args.destination, args.requirements, args.output))
