"""Unreleased isolated own-file preparation; not a MOKOSH app launcher."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
ORACLE_HASH = "c0f4d7e84a4feacbdbea2d9ee967a06abf00db75b11b91bd22940b4d9bae81aa"


def load_oracle():
    data = (ROOT / "ORACLE.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != ORACLE_HASH:
        raise RuntimeError("frozen oracle differs")
    return json.loads(data)


def validate_manifest():
    data = json.loads((ROOT / "PREPARATION_MANIFEST.json").read_text())
    expected = {"ORACLE.json", "WORK_SCOPE.json", "run_windows_probe.py",
        "src/windows_file_api.py", "src/collect_own_files.py", "src/evaluate_records.py",
        "tests/pure_cases.py", "tests/binding_checks.py", "src/__init__.py", "tests/__init__.py"}
    if type(data) is not dict or set(data) != expected:
        raise RuntimeError("preparation manifest file-set differs")
    for name, digest in data.items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("preparation member is not a regular file")
        if type(digest) is not str or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("preparation member bytes differ: " + name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--native-run", action="store_true")
    args = parser.parse_args(argv)
    if not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize:
        raise RuntimeError("requires -I -B and optimize0")
    validate_manifest()
    oracle = load_oracle()
    sys.path.insert(0, str(ROOT))
    if args.self_test:
        from tests.pure_cases import run_pure_checks
        from tests.binding_checks import run_binding_checks
        result = {"scope": "PURE_PREPARATION_CHECKS_ONLY", "native_cases": 0,
            "evaluator": run_pure_checks(oracle), "binding": run_binding_checks(),
            "application_accepted": False, "stage_accepted": False,
            "physical_accepted": False}
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    from src.collect_own_files import collect
    from src.evaluate_records import evaluate_records
    from src.windows_file_api import runtime_metadata, runtime_rejection_reasons
    reasons = runtime_rejection_reasons(runtime_metadata())
    if reasons:
        print(json.dumps({"native_collection": "REFUSED_INCOMPATIBLE_HOST", "reasons": reasons,
                          "native_cases": 0, "application_accepted": False}))
        return 2
    directory, observations = collect(oracle)
    assessment = evaluate_records(observations, oracle)
    with (directory / "ASSESSMENT.json").open("x", encoding="utf-8") as stream:
        json.dump(assessment, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"native_evidence_directory": str(directory), "assessment": assessment,
                      "application_accepted": False, "stage_accepted": False,
                      "physical_accepted": False}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
