"""Run the frozen own-file component bench; never modify project source.

This is a Linux GitHub-hosted confirmation wrapper, not a product launcher.
The runner is invoked in this process; there are no worker/helper processes.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import runpy
import stat
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
MAX_RAW = 16 * 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
MAX_CAPTURE = 512 * 1024
MAX_INPUT = 1024 * 1024
MANIFEST_NAME = "INPUT_MANIFEST.json"


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit):
    """Bound and compare the opened exact regular file and its current name."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "input is not regular")
        require(0 <= before.st_size <= limit, "input exceeds bound")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(data) == before.st_size and len(data) <= limit, "input size changed")
        require(all(getattr(before, k) == getattr(after, k) == getattr(current, k) for k in fields), "input changed while read")
        return data
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
    finally:
        os.close(fd)


def record(path, value):
    write_new(path, (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def expected_file(path, binding, limit=MAX_INPUT):
    data = read_regular(path, limit)
    require(len(data) == binding["bytes"] and sha256(data) == binding["sha256"], "frozen file hash/size differs: " + path.name)
    return data


def manifest():
    expected = os.environ.get("MOKOSH_SYNC_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "workflow manifest pin absent")
    data = read_regular(HERE / MANIFEST_NAME, MAX_INPUT)
    require(sha256(data) == expected, "portable input manifest differs")
    value = json.loads(data)
    require(value["scope"] == "ACTUAL_SINK_SOURCE_COPY_AND_PURE_LIFECYCLE_WARNING_COMPONENT_ONLY", "scope differs")
    require(value["case_count"] == 14 and value["variants"] == ["baseline", "candidate"], "case matrix differs")
    require(set(value["diagnostic_files"]) == {
        "run_github_confirmation.py", "run_actual_sink_sync.py", "SYNC_ACTUAL_COMPONENT_SCOPE_V2.json",
        "SYNC_ACTUAL_COMPONENT_ORACLE_V2.json", "candidate_sync_replacement.json", "README.txt"
    }, "diagnostic allowlist differs")
    for name, binding in value["diagnostic_files"].items():
        require(Path(name).name == name, "non-leaf input")
        expected_file(HERE / name, binding)
    return value, {"bytes": len(data), "sha256": sha256(data)}


def source_snapshot(source_dir, value):
    require(source_dir.is_dir() and not source_dir.is_symlink(), "project source directory unsafe")
    result = {}
    for name, binding in value["source_files"].items():
        require(Path(name).name == name, "non-leaf source")
        data = expected_file(source_dir / name, binding)
        info = (source_dir / name).stat(follow_symlinks=False)
        result[name] = {"bytes": len(data), "sha256": sha256(data),
                        "identity": {k: getattr(info, "st_" + k) for k in ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")}}
    require(len(result) == 6, "source closure differs")
    return result


class BoundedLog(io.TextIOBase):
    def __init__(self, path):
        self.stream = path.open("xb")
        self.count = 0
        self.limit_hit = False

    @property
    def encoding(self):
        return "utf-8"

    def writable(self):
        return True

    def write(self, text):
        require(isinstance(text, str), "log expects text")
        data = text.encode("utf-8", errors="backslashreplace")
        room = MAX_LOG - self.count
        self.stream.write(data[:room])
        self.count += min(len(data), room)
        if len(data) > room:
            self.limit_hit = True
            raise RuntimeError("component log bound exceeded")
        return len(text)

    def flush(self):
        if not self.stream.closed:
            self.stream.flush()

    def close(self):
        if not self.closed:
            self.flush()
            self.stream.close()
        super().close()


def mount_context(path):
    """Record only the longest containing mount entry, never full mountinfo."""
    try:
        data = read_regular(Path("/proc/self/mountinfo"), MAX_INPUT)
    except BaseException:
        # procfs virtual file size commonly differs from read bytes; use a
        # bounded read for this public system metadata only, never fixtures.
        try:
            with open("/proc/self/mountinfo", "rb") as stream:
                data = stream.read(MAX_INPUT + 1)
            require(len(data) <= MAX_INPUT, "mountinfo bound")
        except BaseException as exc:
            return {"status": "NOT_COLLECTED", "error_type": type(exc).__name__}
    matches = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields, tail = left.split(), right.split()
        if len(fields) < 6 or len(tail) < 3:
            continue
        point = fields[4]
        for octal, char in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
            point = point.replace(octal, char)
        if str(path) == point or str(path).startswith(point.rstrip("/") + "/"):
            matches.append((len(point), {"status": "OBSERVED", "mount_id": fields[0], "mount_point": point,
                "filesystem_type": tail[0], "mount_options": fields[5], "super_options": tail[2]}))
    return max(matches, key=lambda pair: pair[0])[1] if matches else {"status": "NOT_COLLECTED"}


def run_confirmation():
    require(sys.version_info[:3] == (3, 12, 3), "GitHub confirmation requires Python3.12.3")
    require(sys.flags.isolated and sys.dont_write_bytecode and not sys.flags.optimize, "requires -I -B without optimize")
    require(sys.platform == "linux" and platform.machine() == "x86_64", "Linux x64 only")
    require(os.getuid() == os.geteuid(), "unexpected unequal identity")
    os.umask(0o077)
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    commit = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9]+", run_id) is not None and re.fullmatch(r"[0-9]+", attempt) is not None, "GitHub run binding absent")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "GitHub commit absent")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(HERE.is_relative_to(workspace), "diagnostic outside checkout")
    capture = Path(tempfile.mkdtemp(prefix="MOKOSH_SINK_SYNC_" + run_id + "_" + attempt + "_", dir=runner_temp))
    require(stat.S_IMODE(capture.stat().st_mode) == 0o700, "capture directory mode differs")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
        stream.write("capture_dir=" + str(capture) + "\n")
    source_dir = workspace / "project"
    started = time.time_ns()
    result = {"schema": 1, "scope": "ACTUAL_SINK_SOURCE_COPY_AND_PURE_LIFECYCLE_WARNING_COMPONENT_ONLY",
        "github_commit": commit, "github_run_id": run_id, "github_run_attempt": attempt, "started_ns": started,
        "runner_status": "LAUNCH_ERROR", "component_exit_code": None, "errors": [],
        "application_changes": 0, "application_accepted": False, "FS15_accepted": False, "physical_accepted": False,
        "runtime": {"python": list(sys.version_info[:3]), "implementation": platform.python_implementation(),
            "executable": sys.executable, "prefix": sys.prefix, "system": platform.system(), "machine": platform.machine(),
            "kernel": platform.release(), "uid": os.getuid(), "euid": os.geteuid(), "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"), "filesystem": mount_context(capture)},
        "network_scope": "This component runner performs no network operations. GitHub checkout/setup-Python/artifact services use network and write to the ephemeral runner environment; the whole job is not offline.",
        "process_scope": "Same-process runpy invocation; no helper/concurrent worker processes; not OS isolation or attacker prevention proof."}
    before = None
    inputs = None
    log_out, log_err = BoundedLog(capture / "STDOUT.txt"), BoundedLog(capture / "STDERR.txt")
    try:
        value, manifest_binding = manifest()
        result["input_manifest"] = manifest_binding
        result["diagnostic_files"] = value["diagnostic_files"]
        before = source_snapshot(source_dir, value)
        result["source_before"] = before
        replacement = json.loads(expected_file(HERE / "candidate_sync_replacement.json", value["diagnostic_files"]["candidate_sync_replacement.json"]))
        old = replacement["old_text"].encode("utf-8")
        new = replacement["new_text"].encode("utf-8")
        original = expected_file(source_dir / "mokosh_v2_filesystem.py", value["source_files"]["mokosh_v2_filesystem.py"])
        require(original.count(old) == 1, "candidate old byte segment not unique")
        candidate = original.replace(old, new, 1)
        require(len(candidate) == value["candidate"]["bytes"] and sha256(candidate) == value["candidate"]["sha256"], "constructed candidate differs")
        inputs = capture / "inputs"
        inputs.mkdir(mode=0o700)
        candidate_path = inputs / "mokosh_v2_filesystem.py"
        write_new(candidate_path, candidate)
        result["candidate"] = {"bytes": len(candidate), "sha256": sha256(candidate), "source": "exact frozen one-function byte replacement in own temporary copy"}
        argv_before = sys.argv[:]
        token_names = ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        removed_tokens = {name: os.environ.pop(name) for name in token_names if name in os.environ}
        result["credential_environment_names_removed_for_component"] = sorted(removed_tokens)
        try:
            sys.argv = [str(HERE / "run_actual_sink_sync.py"), "--source-dir", str(source_dir), "--candidate-file", str(candidate_path),
                "--work-root", str(capture / "component"), "--oracle-file", str(HERE / "SYNC_ACTUAL_COMPONENT_ORACLE_V2.json")]
            with contextlib.redirect_stdout(log_out), contextlib.redirect_stderr(log_err):
                try:
                    runpy.run_path(str(HERE / "run_actual_sink_sync.py"), run_name="__main__")
                    code = 0
                except SystemExit as exc:
                    code = 0 if exc.code is None else exc.code
                    require(type(code) is int, "non-integer component exit")
            result["component_exit_code"] = code
            result["runner_status"] = "RETURNED"
        finally:
            sys.argv = argv_before
            os.environ.update(removed_tokens)
    except BaseException as exc:
        result["errors"].append({"phase": "run", "type": type(exc).__name__, "message": str(exc)[:2500], "traceback": traceback.format_exc(limit=12)[-8000:]})
    finally:
        try:
            value_after, manifest_after = manifest()
            require(result.get("input_manifest") == manifest_after, "manifest pre/post differs")
            after = source_snapshot(source_dir, value_after)
            require(before is not None and after == before, "source pre/post differs or initial guard absent")
            result["source_after"] = after
            result["source_guards"] = "PASS_SIX_INPUT_BYTES_AND_METADATA_ONLY"
            if inputs is not None:
                expected_file(inputs / "mokosh_v2_filesystem.py", value_after["candidate"])
            result["diagnostic_guards"] = "PASS_FROZEN_INPUTS"
        except BaseException as exc:
            result["errors"].append({"phase": "final_guards", "type": type(exc).__name__, "message": str(exc)[:2500]})
        log_out.close()
        log_err.close()
        result["log_bound_hit"] = log_out.limit_hit or log_err.limit_hit
        result["ended_ns"] = time.time_ns()
        for label, path, bound in (("stdout", capture / "STDOUT.txt", MAX_LOG), ("stderr", capture / "STDERR.txt", MAX_LOG), ("raw", capture / "component/RAW.json", MAX_RAW)):
            try:
                data = read_regular(path, bound)
                result[label] = {"bytes": len(data), "sha256": sha256(data)}
            except FileNotFoundError:
                result[label] = None
            except BaseException as exc:
                result[label] = None
                result["errors"].append({"phase": "capture_" + label, "type": type(exc).__name__, "message": str(exc)[:2500]})
        result["capture_status"] = "COMPONENT_RETURNED_WITH_EXACT_CAPTURE" if result["runner_status"] == "RETURNED" and result["component_exit_code"] == 0 and not result["errors"] and not result["log_bound_hit"] and result["raw"] is not None else "ERROR_OR_COMPONENT_FAILURE"
        record(capture / "CAPTURE.json", result)
    print(json.dumps({"capture_directory": str(capture), "capture_status": result["capture_status"], "component_exit_code": result["component_exit_code"], "application_accepted": False}))
    return 0 if result["capture_status"] == "COMPONENT_RETURNED_WITH_EXACT_CAPTURE" else 1


def stage(capture, destination):
    value, binding = manifest()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    capture = capture.absolute()
    require(capture.parent == temp and capture.name.startswith("MOKOSH_SINK_SYNC_"), "capture path outside own root")
    require(capture.is_dir() and not capture.is_symlink(), "capture root unsafe")
    require(capture.stat().st_uid == os.getuid() and stat.S_IMODE(capture.stat().st_mode) == 0o700, "capture identity/mode differs")
    capture_data = read_regular(capture / "CAPTURE.json", MAX_CAPTURE)
    capture_record = json.loads(capture_data)
    require(capture_record.get("input_manifest") == binding, "capture frozen manifest binding differs")
    require(capture_record["github_commit"] == os.environ["GITHUB_SHA"] and capture_record["github_run_id"] == os.environ["GITHUB_RUN_ID"] and capture_record["github_run_attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "capture belongs to another run")
    payload = {"CAPTURE.json": capture_data}
    for key, source, target, bound in (("stdout", capture / "STDOUT.txt", "STDOUT.txt", MAX_LOG), ("stderr", capture / "STDERR.txt", "STDERR.txt", MAX_LOG), ("raw", capture / "component/RAW.json", "RAW.json", MAX_RAW)):
        observed = capture_record.get(key)
        if observed is None:
            require(key == "raw", "missing required log")
            continue
        data = read_regular(source, bound)
        require({"bytes": len(data), "sha256": sha256(data)} == observed, "captured payload changed")
        payload[target] = data
    require(destination.name == "artifact_upload" and destination.parent.resolve(strict=True) == Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True), "artifact destination differs")
    destination.mkdir(mode=0o700, exist_ok=False)
    for name, data in payload.items():
        write_new(destination / name, data)
    evidence = {"schema": 1, "scope": value["scope"], "input_manifest": binding,
        "github_commit": capture_record["github_commit"], "github_run_id": capture_record["github_run_id"],
        "github_run_attempt": capture_record["github_run_attempt"], "files": {name: {"bytes": len(data), "sha256": sha256(data)} for name, data in sorted(payload.items())},
        "application_accepted": False, "stage_accepted": False, "physical_accepted": False}
    record(destination / "EVIDENCE_MANIFEST.json", evidence)
    payload["EVIDENCE_MANIFEST.json"] = read_regular(destination / "EVIDENCE_MANIFEST.json", MAX_CAPTURE)
    sums = "".join(sha256(data) + "  " + name + "\n" for name, data in sorted(payload.items())).encode("ascii")
    write_new(destination / "SHA256SUMS", sums)
    require({p.name for p in destination.iterdir()} == set(payload) | {"SHA256SUMS"}, "staged extra/missing member")
    for name, data in payload.items():
        require(read_regular(destination / name, MAX_RAW) == data, "staged bytes differ")
    require(read_regular(destination / "SHA256SUMS", MAX_CAPTURE) == sums, "staged checksum bytes differ")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
        stream.write("sealed=true\n")
    print(json.dumps({"sealed": True, "payload_files": len(payload), "raw_present": "RAW.json" in payload, "application_accepted": False}))
    return 0


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--run", action="store_true")
    modes.add_argument("--stage", action="store_true")
    parser.add_argument("--capture-dir", type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    if args.run:
        require(args.capture_dir is None and args.destination is None, "unexpected run paths")
        return run_confirmation()
    require(args.capture_dir is not None and args.destination is not None, "stage paths required")
    return stage(args.capture_dir, args.destination)


if __name__ == "__main__":
    raise SystemExit(main())
