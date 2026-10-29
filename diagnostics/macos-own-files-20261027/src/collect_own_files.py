"""Finite collector of the frozen own-file operations; never an app backend.

The operation intents are frozen before implementation. Observed return values,
errno, descriptor metadata and read bytes are produced only by the actual calls.
The collector does not turn the contract's expected values into observations.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .darwin_file_api import (
    DarwinFileApi, MAX_IO, checked_leaf, open_flags, runtime_metadata,
    runtime_rejection_reasons, stat_identity,
)


PAYLOADS = {"A": bytes(range(256)) * 16, "B": b"B" * 4096, "C": b"C" * 4096}
SCOPE = "MACOS_OWN_FILES_DIAGNOSTIC_SEVEN_GROUPS_NOT_APPLICATION_FIX"


def _write_json(path: Path, value: dict) -> None:
    # An exclusive evidence create does not overwrite an existing artifact.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def _error(exc: BaseException) -> dict:
    number = getattr(exc, "errno", None)
    return {"type": type(exc).__name__, "message": str(exc)[:2000],
            "errno": number if type(number) is int else None}


class _CaseCollector:
    def __init__(self, api: DarwinFileApi, directory: Path, definition: dict, category: str):
        self.api = api
        self.directory = directory
        self.definition = definition
        self.record = {"id": definition["id"], "category": category,
                       "events": [], "reads": [], "snapshots": [], "complete": False}
        self.owned: dict[str, int] = {}
        self.close_uncertainty = []
        self.emergency_closes = []

    def _register(self, role: str, descriptor: int) -> None:
        if role in self.owned or type(descriptor) is not int or descriptor < 0:
            raise RuntimeError("invalid logical descriptor registration")
        self.owned[role] = descriptor

    def _fd(self, role: str) -> int:
        if role not in self.owned:
            raise RuntimeError("logical descriptor is not owned: " + role)
        return self.owned[role]

    def _close(self, role: str) -> None:
        descriptor = self.owned.pop(role)
        # Retire numeric descriptor BEFORE close. An error is uncertain and must
        # never cause retry against a possibly reused descriptor number.
        try:
            os.close(descriptor)
        except BaseException:
            self.close_uncertainty.append(role)
            raise

    def _open(self, step: dict, event: dict) -> int:
        operation, role, leaf = step["op"], step["role"], step["leaf"]
        flags = open_flags(operation)
        mode = 0o600 if operation == "create" else 0
        event.update(actual_flags=flags, actual_mode=mode, actual_inheritable=None)
        if operation == "open_dir":
            descriptor = os.open(self.directory, flags)
        else:
            checked_leaf(leaf)
            descriptor = os.open(leaf, flags, mode, dir_fd=self._fd("dir"))
        self._register(role, descriptor)
        event["actual_inheritable"] = os.get_inheritable(descriptor)
        if event["actual_inheritable"] is not False:
            raise RuntimeError("own descriptor unexpectedly inheritable")
        info = os.fstat(descriptor)
        if operation == "open_dir":
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("own case directory identity/type rejected")
        elif not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("own file identity/type rejected")
        return descriptor

    def _step(self, step: dict, index: int) -> None:
        event = {key: copy.deepcopy(step[key]) for key in ("op", "role", "leaf", "phase", "args")}
        event.update(index=index, **{"return": -1, "errno": 0, "success": False})
        operation, role, args = step["op"], step["role"], step["args"]
        self.record["events"].append(event)
        try:
            if operation in ("open_dir", "create", "open_read", "open_write"):
                returned = self._open(step, event)
            elif operation == "pwrite":
                payload = PAYLOADS[args["payload"]]
                if args["count"] != MAX_IO or args["offset"] != 0:
                    raise ValueError("write exceeds frozen own payload bound")
                returned = os.pwrite(self._fd(role), payload, 0)
            elif operation == "fsync":
                os.fsync(self._fd(role))
                returned = 0
            elif operation == "pread":
                if args != {"offset": 0, "count": MAX_IO}:
                    raise ValueError("read exceeds frozen own payload bound")
                descriptor = self._fd(role)
                identity = stat_identity(os.fstat(descriptor))
                data = os.pread(descriptor, MAX_IO, 0)
                returned = len(data)
                self.record["reads"].append({
                    "event_index": index, "role": role, "phase": step["phase"],
                    "count": returned, "offset": 0, "hex": data.hex(),
                    "sha256": hashlib.sha256(data).hexdigest(), "identity": identity,
                })
            elif operation == "rename_excl":
                if args["flags"] != 4 or args["to_dir_role"] != "dir":
                    raise ValueError("rename intent differs from frozen own operation")
                returned = self.api.rename_excl(self._fd(role), step["leaf"], args["to_leaf"])
            elif operation == "path_stat":
                checked_leaf(step["leaf"])
                snapshot = {"event_index": index, "role": role, "phase": step["phase"],
                            "leaf": step["leaf"], "exists": False, "errno": 0}
                self.record["snapshots"].append(snapshot)
                try:
                    info = os.stat(step["leaf"], dir_fd=self._fd("dir"), follow_symlinks=False)
                except OSError as exc:
                    if type(exc.errno) is not int or exc.errno <= 0:
                        raise RuntimeError("path stat failure without exact positive errno") from exc
                    snapshot["errno"] = exc.errno
                    raise
                snapshot.update(exists=True, **{k: v for k, v in stat_identity(info).items() if k != "observed_by"})
                returned = 0
            elif operation == "unlink":
                checked_leaf(step["leaf"])
                os.unlink(step["leaf"], dir_fd=self._fd(role))
                returned = 0
            elif operation == "close":
                self._close(role)
                returned = 0
            else:
                raise ValueError("unknown frozen operation")
            if type(returned) is not int or returned < 0:
                raise RuntimeError("operation did not return an exact nonnegative integer")
            event.update(**{"return": returned, "errno": 0, "success": True})
        except OSError as exc:
            number = exc.errno
            if type(number) is not int or number <= 0:
                raise RuntimeError("operation failed without exact positive errno") from exc
            event.update(**{"return": -1, "errno": number, "success": False})
            # These operations have meaningful refusal observations. They are
            # recorded, not accepted here. Only the independent evaluator can
            # decide whether a particular refusal matches its frozen criterion.
            if operation not in ("rename_excl", "path_stat"):
                raise
        if operation in ("pread", "pwrite") and event["return"] != MAX_IO:
            raise RuntimeError("short own-file I/O retained as incomplete observation")

    def collect(self) -> dict:
        for index, step in enumerate(self.definition["steps"]):
            self._step(step, index)
        if self.owned or self.close_uncertainty:
            raise RuntimeError("own descriptor lifetime is incomplete")
        self.record["complete"] = True
        return self.record

    def close_remaining_once(self) -> None:
        # Error-only shutdown is retained separately from the planned event
        # stream; a partial record cannot become a complete seven-case PASS.
        for role in list(reversed(self.owned)):
            item = {"role": role, "return": None, "error": None}
            try:
                self._close(role)
                item["return"] = 0
            except BaseException as exc:
                item["error"] = _error(exc)
            self.emergency_closes.append(item)


def collect_native(oracle: dict, contract: dict, oracle_sha256: str, contract_sha256: str) -> tuple[Path, dict, dict | None]:
    """Collect exactly one new own-file run, preserving errors/partial records."""
    runtime = runtime_metadata()
    reasons = runtime_rejection_reasons(runtime)
    if reasons:
        raise RuntimeError("Darwin native probe refused: " + "; ".join(reasons))
    api = DarwinFileApi()
    root = Path(tempfile.mkdtemp(prefix="MOKOSH_MAC_OWN_FILES_"))
    os.chmod(root, 0o700)
    print(json.dumps({"native_evidence_directory": str(root),
                      "collection_status": "STARTING_NOT_ACCEPTED"}), flush=True)
    volume = os.statvfs(root)
    runtime["volume_metadata"] = {
        "filesystem_type": "NOT_COLLECTED",
        "statvfs": {name: getattr(volume, name) for name in (
            "f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail", "f_files",
            "f_ffree", "f_favail", "f_flag", "f_namemax")},
    }
    observations = {"schema": 1, "origin": "NATIVE_DARWIN_OWN_FILES", "scope": SCOPE,
                    "oracle_sha256": oracle_sha256, "record_contract_sha256": contract_sha256,
                    "runtime": runtime, "case_records": [], "case_count": 0,
                    "application_fix": False, "FS15_accepted": False, "physical_acceptance": False}
    error_record = None
    category = {item["id"]: item["category"] for item in oracle["cases"]}
    for definition in contract["cases"]:
        case_directory = root / definition["id"]
        case_directory.mkdir(mode=0o700, exist_ok=False)
        collector = _CaseCollector(api, case_directory, definition, category[definition["id"]])
        try:
            collector.collect()
        except BaseException as exc:
            collector.close_remaining_once()
            error_record = {"schema": 1, "case_id": definition["id"], "error": _error(exc),
                            "emergency_closes": collector.emergency_closes,
                            "close_uncertainty": collector.close_uncertainty,
                            "application_fix": False, "FS15_accepted": False, "physical_acceptance": False}
        observations["case_records"].append(collector.record)
        observations["case_count"] = len(observations["case_records"])
        _write_json(case_directory / "CASE_OBSERVATION.json", collector.record)
        if error_record is not None:
            break
    _write_json(root / "OBSERVATIONS.json", observations)
    if error_record is not None:
        _write_json(root / "COLLECTOR_ERROR.json", error_record)
    return root, observations, error_record
