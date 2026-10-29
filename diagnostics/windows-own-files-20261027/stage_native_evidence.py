"""Stage a bounded own-file pilot result; no native API, subprocess or deletion.

This helper copies only reviewed capture names and known synthetic evidence.
A missing/rejected native folder yields sealed logs with an explicit limitation.
The seal checks bytes; it does not authenticate native execution or accept MOKOSH.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ORACLE_SHA256 = "c0f4d7e84a4feacbdbea2d9ee967a06abf00db75b11b91bd22940b4d9bae81aa"
SCOPE = "SEVEN_OWN_FILE_WIN32_API_GROUPS_NOT_APPLICATION_FIX_OR_PROCESS_SECURITY"
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_FILES = 45
CAPTURE_FILES = {"stdout.txt", "stderr.txt", "CAPTURE.json"}
ROOT_JSON = {"OBSERVATIONS.json", "ASSESSMENT.json", "COLLECTOR_ERROR.json"}
CASE_IDS = tuple("W%02d" % x for x in range(1, 8))
FIXTURES = {"stage.bin", "control.bin", "moved.bin", "published-Δ-Ж.bin"}
SYNTHETIC_HASHES = {
    hashlib.sha256(bytes(range(256)) * 16).hexdigest(),
    hashlib.sha256(b"B" * 4096).hexdigest(),
    hashlib.sha256(b"C" * 4096).hexdigest(),
}


class StagingError(ValueError):
    pass


def _directory(path: Path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise StagingError("directory is not an ordinary nonreparse directory")
    return info


def _regular_bytes(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & 0x400
        or before.st_nlink != 1
        or not 0 <= before.st_size <= maximum
    ):
        raise StagingError("source is nonregular, linked, reparse or oversized")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        actual = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if actual != expected or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise StagingError("source changed between lstat and open")
        chunks = []
        total = 0
        while True:
            part = os.read(descriptor, min(65536, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            if total > maximum:
                raise StagingError("source grew beyond byte bound")
            chunks.append(part)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected:
            raise StagingError("source changed while copied")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise StagingError("source byte count differs")
        return data
    finally:
        os.close(descriptor)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StagingError("duplicate JSON key")
        result[key] = value
    return result


def _json(data: bytes):
    if len(data) > MAX_JSON_BYTES:
        raise StagingError("JSON byte bound")
    return json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)


def _capture(capture: Path, expected_run_id, expected_attempt, expected_commit):
    _directory(capture)
    if {p.name for p in capture.iterdir()} != CAPTURE_FILES:
        raise StagingError("capture file set differs")
    if not re.fullmatch(r"MOKOSH_WIN_CAPTURE_[0-9]+_[0-9]+", capture.name):
        raise StagingError("capture basename differs")
    files = {
        "capture/stdout.txt": _regular_bytes(capture / "stdout.txt", 512 * 1024),
        "capture/stderr.txt": _regular_bytes(capture / "stderr.txt", 256 * 1024),
        "capture/CAPTURE.json": _regular_bytes(capture / "CAPTURE.json", 16384),
    }
    record = _json(files["capture/CAPTURE.json"])
    expected_keys = {"schema", "run_id", "run_attempt", "github_sha", "started_ns", "ended_ns",
                     "native_exit_code", "launcher_status", "launcher_error",
                     "application_accepted", "stage_accepted", "physical_accepted"}
    if type(record) is not dict or set(record) != expected_keys:
        raise StagingError("capture schema differs")
    if type(record["schema"]) is not int or record["schema"] != 1:
        raise StagingError("capture schema version differs")
    for key in ("run_id", "run_attempt"):
        if type(record[key]) is not str or not re.fullmatch(r"[0-9]+", record[key]):
            raise StagingError("invalid capture run identifier")
    if capture.name != "MOKOSH_WIN_CAPTURE_" + record["run_id"] + "_" + record["run_attempt"]:
        raise StagingError("capture name/run mismatch")
    if expected_run_id is not None and record["run_id"] != expected_run_id:
        raise StagingError("capture belongs to another run")
    if expected_attempt is not None and record["run_attempt"] != expected_attempt:
        raise StagingError("capture belongs to another attempt")
    if type(record["github_sha"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", record["github_sha"]):
        raise StagingError("invalid capture commit identifier")
    if expected_commit is not None and record["github_sha"] != expected_commit:
        raise StagingError("capture belongs to another commit")
    if any(type(record[k]) is not int or record[k] <= 0 for k in ("started_ns", "ended_ns")):
        raise StagingError("invalid capture time")
    if not 0 <= record["ended_ns"] - record["started_ns"] <= 15 * 60 * 10**9:
        raise StagingError("capture time interval differs")
    code = record["native_exit_code"]
    if code is not None and (type(code) is not int or not -(2**31) <= code <= 2**32 - 1):
        raise StagingError("invalid native exit type/value")
    if type(record["launcher_status"]) is not str or record["launcher_status"] not in {"RETURNED", "LAUNCH_ERROR"}:
        raise StagingError("invalid launcher status")
    if record["launcher_status"] == "RETURNED" and code is None:
        raise StagingError("returned process lacks exit code")
    if record["launcher_error"] is not None and (type(record["launcher_error"]) is not str or len(record["launcher_error"]) > 4000):
        raise StagingError("invalid launcher error")
    if record["launcher_status"] == "RETURNED" and record["launcher_error"] is not None:
        raise StagingError("returned process has a contradictory launcher error")
    if record["launcher_status"] == "LAUNCH_ERROR" and (code is not None or type(record["launcher_error"]) is not str):
        raise StagingError("launch error has contradictory exit/error fields")
    if any(type(record[k]) is not bool or record[k] for k in ("application_accepted", "stage_accepted", "physical_accepted")):
        raise StagingError("capture scope escalation")
    return record, files


def _native_files(source: Path, capture_record: dict, temp_roots: tuple[Path, ...]):
    if not source.is_absolute() or not re.fullmatch(r"MOKOSH_WIN_OWN_FILES_[A-Za-z0-9_-]{6,32}", source.name):
        raise StagingError("native directory path or basename differs")
    parent = source.parent.resolve(strict=True)
    if parent not in {p.resolve(strict=True) for p in temp_roots}:
        raise StagingError("native directory is not an immediate child of approved TEMP")
    info = _directory(source)
    created_ns = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
    tolerance = 2 * 10**9  # Finite creation-time check; not directory-origin authentication.
    if not capture_record["started_ns"] - tolerance <= created_ns <= capture_record["ended_ns"] + tolerance:
        raise StagingError("native directory creation is outside this capture")
    files = {}
    for entry in sorted(source.iterdir(), key=lambda p: p.name):
        if entry.name in ROOT_JSON:
            data = _regular_bytes(entry, MAX_JSON_BYTES)
            value = _json(data)
            if type(value) is not dict:
                raise StagingError("native root JSON is not an object")
            if entry.name == "OBSERVATIONS.json":
                if value.get("oracle_sha256") != ORACLE_SHA256 or value.get("scope") != SCOPE:
                    raise StagingError("observations binding differs")
                if any(type(value.get(k)) is not bool or value[k] for k in ("application_accepted", "stage_accepted", "physical_accepted")):
                    raise StagingError("observations scope escalation")
            if entry.name == "ASSESSMENT.json":
                if any(type(value.get(k)) is not bool or value[k] for k in ("application_accepted", "stage_accepted", "physical_accepted")):
                    raise StagingError("assessment scope escalation")
            if entry.name == "COLLECTOR_ERROR.json":
                if set(value) != {"type", "detail"} or type(value["type"]) is not str or type(value["detail"]) is not str or len(value["type"]) > 128 or len(value["detail"]) > 4000:
                    raise StagingError("collector error schema differs")
            files["native/" + entry.name] = data
        elif entry.name in CASE_IDS:
            _directory(entry)
            for leaf in sorted(entry.iterdir(), key=lambda p: p.name):
                if leaf.name == "CASE_OBSERVATION.json":
                    data = _regular_bytes(leaf, 128 * 1024)
                    value = _json(data)
                    if type(value) is not dict or set(value) != {"id", "events", "facts"} or value["id"] != entry.name:
                        raise StagingError("case observation identity/schema differs")
                elif leaf.name in FIXTURES:
                    data = _regular_bytes(leaf, 4096)
                    if len(data) != 4096 or hashlib.sha256(data).hexdigest() not in SYNTHETIC_HASHES:
                        raise StagingError("fixture is not an exact known synthetic payload")
                else:
                    raise StagingError("unknown native case member")
                files["native/" + entry.name + "/" + leaf.name] = data
        else:
            raise StagingError("unknown native root member")
    if not any(name in {"native/OBSERVATIONS.json", "native/COLLECTOR_ERROR.json"} or name.endswith("/CASE_OBSERVATION.json") for name in files):
        raise StagingError("native directory contains no observation or error record")
    return files


def stage_evidence(capture_dir: Path, destination: Path, *, temp_roots=None,
                   expected_run_id=None, expected_attempt=None, expected_commit=None) -> dict:
    """Copy own bounded fixtures. Optional roots/IDs are for reviewed pure tests."""
    capture_dir, destination = Path(capture_dir), Path(destination)
    record, files = _capture(capture_dir, expected_run_id, expected_attempt, expected_commit)
    if temp_roots is None:
        temp_roots = [Path(tempfile.gettempdir())]
        if os.environ.get("RUNNER_TEMP"):
            temp_roots.append(Path(os.environ["RUNNER_TEMP"]))
    roots = tuple(Path(p) for p in temp_roots)
    status = "SEALED_LOGS_ONLY_NO_NATIVE_DIRECTORY"
    problem = None
    source = None
    try:
        lines = files["capture/stdout.txt"].decode("utf-8", errors="strict").splitlines()
        first = next((line for line in lines if line.strip()), None)
        startup = _json(first.encode("utf-8")) if first is not None else None
        if type(startup) is dict and "native_evidence_directory" in startup:
            if set(startup) != {"native_evidence_directory", "collection_status"} or startup["collection_status"] != "STARTING_NOT_ACCEPTED":
                raise StagingError("first startup record differs")
            if type(startup["native_evidence_directory"]) is not str:
                raise StagingError("native directory is not an exact string")
            source = Path(startup["native_evidence_directory"])
            native = _native_files(source, record, roots)
            files.update(native)
            status = "SEALED_ALLOWLISTED_OBSERVATIONS_NOT_ACCEPTANCE"
    except (StagingError, OSError, ValueError, UnicodeError, StopIteration, RecursionError) as exc:
        status = "SEALED_LOGS_ONLY_NATIVE_DIRECTORY_REJECTED"
        problem = type(exc).__name__ + ": " + str(exc)[:500]
    if len(files) > MAX_FILES or sum(len(b) for b in files.values()) > MAX_TOTAL_BYTES:
        raise StagingError("total staged size/file bound")
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise StagingError("staging destination must be new")
    if destination.parent.resolve(strict=True) in roots or destination == capture_dir.absolute():
        raise StagingError("staging destination must be distinct from TEMP capture")
    resolved_destination = destination.resolve(strict=False)
    for original in (capture_dir, source):
        if original is not None:
            resolved_original = original.resolve(strict=False)
            if resolved_destination == resolved_original or resolved_original in resolved_destination.parents or resolved_destination in resolved_original.parents:
                raise StagingError("staging path overlaps captured source")
    _directory(destination.parent)
    status_record = {
        "schema": 1, "status": status, "problem": problem,
        "native_directory": str(source) if source is not None else None,
        "native_exit_code": record["native_exit_code"],
        "application_accepted": False, "stage_accepted": False, "physical_accepted": False,
        "limits": "Manifest byte integrity only; no native origin or app acceptance. Forced job timeout/cancellation can prevent this staging step entirely.",
    }
    files["STAGING_STATUS.json"] = (json.dumps(status_record, ensure_ascii=True, indent=2) + "\n").encode()
    if len(files) + 1 > MAX_FILES or sum(len(b) for b in files.values()) + 16384 > MAX_TOTAL_BYTES:
        raise StagingError("sealed status/manifest exceed final byte/file budget")
    destination.mkdir(mode=0o700, exist_ok=False)
    manifest = {}
    for name, data in sorted(files.items()):
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        manifest[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, indent=2) + "\n").encode()
    with (destination / "MANIFEST.json").open("xb") as stream:
        stream.write(manifest_bytes)
    return {"sealed": True, "status": status, "files": len(manifest),
            "bytes": sum(x["bytes"] for x in manifest.values()),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "destination": str(destination)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args(argv)
    result = stage_evidence(Path(args.capture_dir), Path(args.destination),
        expected_run_id=os.environ.get("GITHUB_RUN_ID"),
        expected_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
        expected_commit=os.environ.get("GITHUB_SHA"))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
            stream.write("sealed=true\n")
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["status"] == "SEALED_ALLOWLISTED_OBSERVATIONS_NOT_ACCEPTANCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
