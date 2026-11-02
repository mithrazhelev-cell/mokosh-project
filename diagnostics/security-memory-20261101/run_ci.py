"""Verify this diagnostic's fixed inputs; preserve bounded synthetic evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def verify(root):
    manifest = json.loads((root / 'INPUTS.json').read_text(encoding='utf-8'))
    expected = {'probe.py', 'test_probe.py', 'SCOPE.txt'}
    if set(manifest) != expected:
        raise ValueError('unexpected diagnostic manifest')
    for name, digest in manifest.items():
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('non-regular diagnostic input: ' + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('diagnostic input mismatch: ' + name)
    return manifest


def main(output):
    root = Path(__file__).resolve().parent
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=False)
    summary = {'status': 'STOP', 'product_accepted': False, 'physical_GUI_tested': False,
               'product_code_imported': False, 'child_process_tree_containment_tested': False}
    try:
        summary['verified_inputs'] = verify(root)
        tests = subprocess.run([sys.executable, '-I', '-B', str(root / 'test_probe.py')],
                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)
        (destination / 'ORACLE_TESTS.log').write_text(tests.stdout + tests.stderr, encoding='utf-8')
        summary['oracle_tests_exit'] = tests.returncode
        if tests.returncode:
            raise RuntimeError('oracle tests failed; native probes not started')
        spec = importlib.util.spec_from_file_location('diagnostic_probe', root / 'probe.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        summary['native_exit'] = module.run(destination / 'native')
        if summary['native_exit']:
            summary['status'] = 'FAIL_OR_STOP_NATIVE_REVIEW_REQUIRED'
        else:
            summary['status'] = 'SCOPED_API_PASS_PRODUCT_NOT_ACCEPTED'
    except Exception as exc:
        summary['error'] = {'type': type(exc).__name__, 'message': str(exc)[:500]}
    (destination / 'SUMMARY.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(summary))
    return 0 if summary['status'] == 'SCOPED_API_PASS_PRODUCT_NOT_ACCEPTED' else 1


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    raise SystemExit(main(parser.parse_args().output))
