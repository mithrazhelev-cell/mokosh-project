"""Isolated macOS own-file diagnostic preparation; not a MOKOSH launcher."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parent
ORACLE_HASH = "50ce179c3c9e8c369d000ec45f9caa1ca30f63f719eecb0ba266c9b845e5c412"
CONTRACT_HASH = "a747385b7753710338299b815bdcc4639023a463f02b58535ec634da6f96e858"
MANIFEST_FILES = {
    "ORACLE.json", "RECORD_CONTRACT.json", "WORK_SCOPE.json", "run_macos_probe.py",
    "src/__init__.py", "src/darwin_file_api.py", "src/collect_own_files.py",
    "src/evaluate_records.py", "tests/__init__.py", "tests/pure_cases.py",
    "tests/binding_checks.py",
}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load_json_bytes(data: bytes):
    return json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique_pairs)


def validate_manifest() -> dict:
    manifest = load_json_bytes((ROOT / "PREPARATION_MANIFEST.json").read_bytes())
    if type(manifest) is not dict or set(manifest) != MANIFEST_FILES:
        raise RuntimeError("preparation manifest file-set differs")
    for name, digest in manifest.items():
        path = ROOT / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("preparation member is not a regular singly linked file")
        if type(digest) is not str or len(digest) != 64 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("preparation member bytes differ: " + name)
    return manifest


def load_frozen() -> tuple[dict, dict]:
    oracle_bytes = (ROOT / "ORACLE.json").read_bytes()
    contract_bytes = (ROOT / "RECORD_CONTRACT.json").read_bytes()
    if hashlib.sha256(oracle_bytes).hexdigest() != ORACLE_HASH:
        raise RuntimeError("frozen oracle differs")
    if hashlib.sha256(contract_bytes).hexdigest() != CONTRACT_HASH:
        raise RuntimeError("frozen record contract differs")
    return load_json_bytes(oracle_bytes), load_json_bytes(contract_bytes)


def _write_result(directory: Path, result: dict) -> None:
    with (directory / "RESULT.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--native-run", action="store_true")
    args = parser.parse_args(argv)
    if not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize != 0:
        raise RuntimeError("requires -I -B and optimize0")
    validate_manifest()
    oracle, contract = load_frozen()
    sys.path.insert(0, str(ROOT))
    if args.self_test:
        from tests.pure_cases import run_self_tests
        from tests.binding_checks import run_binding_checks
        result = {"schema": 1, "scope": "PURE_PREPARATION_CHECKS_ONLY_NOT_MAC_NATIVE",
                  "evaluator": run_self_tests(ROOT), "binding": run_binding_checks(),
                  "native_cases": 0, "application_fix": False, "FS15_accepted": False,
                  "physical_acceptance": False}
        print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
        return 0
    from src.darwin_file_api import runtime_metadata, runtime_rejection_reasons
    runtime = runtime_metadata()
    reasons = runtime_rejection_reasons(runtime)
    if reasons:
        print(json.dumps({"schema": 1, "native_collection": "REFUSED_INCOMPATIBLE_HOST",
                          "reasons": reasons, "runtime": runtime, "native_cases": 0,
                          "application_fix": False, "FS15_accepted": False,
                          "physical_acceptance": False}, ensure_ascii=True), flush=True)
        return 2
    from src.collect_own_files import collect_native
    from src.evaluate_records import RecordRejected, evaluate_records
    directory, observations, collector_error = collect_native(oracle, contract, ORACLE_HASH, CONTRACT_HASH)
    result = {"schema": 1, "status": "INCOMPLETE_OR_UNEXPECTED",
              "application_fix": False, "FS15_accepted": False, "physical_acceptance": False,
              "collector_error_present": collector_error is not None, "assessment": None}
    try:
        assessment = evaluate_records(observations, oracle, contract)
        if collector_error is not None:
            raise RuntimeError("collector error cannot report native match")
        result.update(status=assessment["status"], assessment=assessment)
    except RecordRejected as exc:
        result["rejection"] = {"reason": exc.reason, "detail": str(exc)[:2500]}
        unavailable = {getattr(errno, "ENOTSUP", 45), getattr(errno, "ENOSYS", 78)}
        if any(event["op"] == "rename_excl" and event["return"] == -1 and event["errno"] in unavailable
               for case in observations["case_records"] for event in case["events"]):
            result["status"] = "NOT_EXERCISED_UNSUPPORTED"
    _write_result(directory, result)
    print(json.dumps({"native_evidence_directory": str(directory), "result": result}, ensure_ascii=True), flush=True)
    return 0 if result["assessment"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
