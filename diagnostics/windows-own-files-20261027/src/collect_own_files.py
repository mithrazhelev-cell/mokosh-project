"""Finite own-file Win32 observations. No application or foreign-process code."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

from .windows_file_api import WindowsFileApi, WinApiError

OWNER_ACCESS = 0xC0010000
READ = 0x80000000
WRITE = 0x40000000
DELETE = 0x10000
ORACLE_HASH = "c0f4d7e84a4feacbdbea2d9ee967a06abf00db75b11b91bd22940b4d9bae81aa"
SCOPE = "SEVEN_OWN_FILE_WIN32_API_GROUPS_NOT_APPLICATION_FIX_OR_PROCESS_SECURITY"
A = bytes(range(256)) * 16
B = b"B" * 4096
C = b"C" * 4096
PUBLISHED = "published-Δ-Ж.bin"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Case:
    def __init__(self, api, directory, case_id):
        self.api = api
        self.directory = directory
        self.id = case_id
        self.events = []
        self.facts = {"snapshots": {}}
        self.handles = []
        self.names = {}
        self.close_attempts = set()

    def path(self, leaf):
        if leaf not in {"stage.bin", "control.bin", "moved.bin", PUBLISHED}:
            raise ValueError("unlisted fixed leaf")
        return self.directory / leaf

    def call(self, role, operation, request, function, handle=None):
        if len(self.events) >= 256 or any(e["role"] == role for e in self.events):
            raise RuntimeError("event bound or duplicate role")
        event = {"role": role, "operation": operation, "request": request,
                 "handle_id": self.names.get(id(handle)), "success": False,
                 "winerror": 0}
        try:
            value = function()
        except WinApiError as exc:
            event["winerror"] = exc.code
            self.events.append(event)
            return None, exc.code
        except BaseException as exc:
            # No invented Win32 code for a Python/binding observation failure.
            event["winerror"] = None
            event["instrument_error"] = {"type": type(exc).__name__, "detail": str(exc)[:1000]}
            self.events.append(event)
            raise
        event["success"] = True
        if value is None:
            event["result"] = {}
        elif type(value) in (dict, int, str, bool):
            event["result"] = value
        elif type(value) is bytes:
            event["result"] = {"transferred_bytes": len(value),
                               "data_hex": value.hex(), "sha256": digest(value)}
        self.events.append(event)
        return value, 0

    def require(self, result):
        value, error = result
        if error:
            raise RuntimeError(f"unexpected native refusal {error}")
        return value

    def open(self, role, path, access=OWNER_ACCESS, share=0, creation=1):
        result = self.call(role, "CreateFileW", {
            "path": str(path), "desired_access": access, "share_mode": share,
            "creation_disposition": creation,
        }, lambda: self.api.open(str(path), access, share, creation))
        handle, error = result
        if not error:
            logical = f"H{len(self.handles) + 1:03d}"
            self.names[id(handle)] = logical
            self.handles.append(handle)
            self.events[-1]["handle_id"] = logical
        return result

    def close(self, handle, role):
        if id(handle) in self.close_attempts:
            raise RuntimeError("second close attempt refused")
        self.close_attempts.add(id(handle))
        self.require(self.call(role, "CloseHandle", {}, handle.close, handle))

    def write(self, handle, data, prefix):
        offset = 0
        for count in range(16):
            if offset == len(data):
                return offset
            chunk = data[offset:]
            transferred = self.require(self.call(
                f"{prefix}_{count:02d}", "WriteFile",
                {"requested_bytes": len(chunk), "sha256": digest(chunk),
                 "data_hex": chunk.hex()}, lambda: handle.write(chunk), handle))
            self.events[-1]["result"] = {"transferred_bytes": transferred}
            if type(transferred) is not int or not 1 <= transferred <= len(chunk):
                raise RuntimeError("invalid write progress")
            offset += transferred
        raise RuntimeError("bounded write progress exhausted")

    def flush(self, handle, role):
        self.require(self.call(role, "FlushFileBuffers", {}, handle.flush, handle))

    def snapshot_held(self, handle, name):
        info = self.require(self.call(name + "_info", "GetFileInformationByHandle",
                                     {}, handle.identity, handle))
        if type(info["size"]) is not int or not 0 <= info["size"] <= 4096:
            raise RuntimeError("snapshot size bound")
        self.require(self.call(name + "_seek", "SetFilePointerEx", {"offset": 0, "move_method": 0},
                               lambda: handle.seek(0), handle))
        data = bytearray()
        roles = []
        for n in range(16):
            remaining = info["size"] - len(data)
            if not remaining:
                break
            role = f"{name}_read_{n:02d}"
            part = self.require(self.call(role, "ReadFile",
                {"requested_bytes": remaining, "group": name},
                lambda: handle.read(remaining), handle))
            roles.append(role)
            if type(part) is not bytes or not 1 <= len(part) <= remaining:
                raise RuntimeError("invalid read progress")
            data.extend(part)
        if len(data) != info["size"]:
            raise RuntimeError("bounded read progress exhausted")
        after_role = name + "_info_after"
        after = self.require(self.call(after_role, "GetFileInformationByHandle",
                                      {}, handle.identity, handle))
        if any(info[k] != after[k] for k in ("volume_serial", "file_index", "size")):
            raise RuntimeError("object changed during snapshot")
        snapshot = {"exists": True, "bytes": len(data), "sha256": digest(data),
                    "identity": {k: after[k] for k in ("volume_serial", "file_index")},
                    "read_events": roles, "identity_event": after_role}
        self.facts["snapshots"][name] = snapshot
        return snapshot

    def snapshot_path(self, path, name):
        handle = self.require(self.open(name + "_open", path, READ, 7, 3))
        result = self.snapshot_held(handle, name)
        self.close(handle, name + "_close")
        return result

    def absence(self, path, name):
        role = name + "_absence"
        try:
            path.lstat()
        except FileNotFoundError as exc:
            error = exc.winerror
            if type(error) is not int or error not in (2, 3):
                raise RuntimeError("absence not an exact missing-path observation")
            self.events.append({"role": role, "operation": "Path.lstat",
                "request": {"path": str(path)}, "handle_id": None,
                "success": False, "winerror": error, "result": {"exists": False}})
            result = {"exists": False, "bytes": 0, "sha256": None,
                      "identity": None, "absence_event": role}
            self.facts["snapshots"][name] = result
            return result
        raise RuntimeError("expected own absent path is present")

    def rename(self, handle, role, target, kind):
        request = {"information_class": 3, "replace_if_exists": False,
            "root_directory_null": True, "target_kind": kind,
            "target_leaf": target.name, "target_path": str(target),
            "filename_length_unit": "utf16le_bytes",
            "filename_length": len(str(target).encode("utf-16-le")),
            "filename_utf16_hex": str(target).encode("utf-16-le").hex()}
        return self.call(role, "SetFileInformationByHandle", request,
                         lambda: handle.rename(str(target)), handle)

    def finish(self):
        # Close only explicitly owned handles; never delete a guessed name.
        for handle in self.handles:
            if id(handle) not in self.close_attempts:
                self.close(handle, f"final_close_{self.names[id(handle)]}")
        before = self.facts["snapshots"]["control_c_before"]
        after = self.snapshot_path(self.path("control.bin"), "control_c_after")
        self.facts.update({
            "handles_closed": all(h.closed for h in self.handles),
            "close_uncertainty": any(h.close_uncertain for h in self.handles),
            "control_c_bytes_before": before["bytes"],
            "control_c_bytes_after": after["bytes"],
            "control_c_sha256_before": before["sha256"],
            "control_c_sha256_after": after["sha256"],
            "control_c_identity_unchanged": before["identity"] == after["identity"],
        })
        return {"id": self.id, "events": self.events, "facts": self.facts}


def perform_case(api, directory, case_id):
    case = Case(api, directory, case_id)
    try:
        c = case.require(case.open("control_create", case.path("control.bin")))
        case.write(c, C, "control_write")
        case.flush(c, "control_flush")
        case.snapshot_held(c, "control_c_before")
        case.close(c, "control_close")
        stage = case.path("stage.bin")
        target = case.path(PUBLISHED)
        if case_id == "W04":
            owner = case.require(case.open("preexisting_writer_create", stage, READ | WRITE, 7))
        else:
            owner = case.require(case.open("owner_create", stage))
        written = case.write(owner, A, "owner_write")
        if case_id == "W01":
            case.flush(owner, "owner_flush")
        initial = case.snapshot_held(owner, "source_before")
        facts = case.facts
        if case_id == "W01":
            case.close(owner, "owner_close")
            after = case.snapshot_path(stage, "source_after")
            case.absence(target, "output_after")
            facts.update(owner_write_bytes=written, owner_read_bytes=initial["bytes"],
                owner_read_sha256=initial["sha256"], after_close_sha256=after["sha256"],
                same_file_identity_after_close=initial["identity"] == after["identity"],
                stage_present_after_close=after["exists"], output_present=False)
        elif case_id == "W02":
            value, error = case.open("blocked_write_open", stage, WRITE, 7, 3)
            before = case.snapshot_held(owner, "before_release")
            case.close(owner, "owner_close")
            released = case.require(case.open("released_write_open", stage, WRITE, 7, 3))
            b_written = case.write(released, B, "released_write")
            case.close(released, "released_writer_close")
            after = case.snapshot_path(stage, "source_after")
            facts.update(blocked_write_open_success=value is not None,
                blocked_write_open_winerror=error, before_release_sha256=before["sha256"],
                release_close_success=True, after_release_write_open_success=True,
                after_release_write_bytes=b_written, after_release_sha256=after["sha256"],
                same_file_identity_after_release=initial["identity"] == after["identity"])
        elif case_id == "W03":
            value, error = case.open("blocked_delete_open", stage, DELETE, 7, 3)
            _, delete_error = case.call("blocked_deletefile", "DeleteFileW", {"path": str(stage)},
                                       lambda: api.delete_file(str(stage)))
            moved = case.path("moved.bin")
            move_request = {"source_path": str(stage), "target_path": str(moved), "flags": 0}
            _, move_error = case.call("blocked_move", "MoveFileExW", move_request,
                                     lambda: api.move_file(str(stage), str(moved)))
            held = case.snapshot_held(owner, "owner_after_refusals")
            case.absence(moved, "moved_while_held")
            case.close(owner, "owner_close")
            case.require(case.call("released_move", "MoveFileExW", move_request,
                                   lambda: api.move_file(str(stage), str(moved))))
            moved_snapshot = case.snapshot_path(moved, "moved_before_delete")
            case.require(case.call("released_deletefile", "DeleteFileW", {"path": str(moved)},
                                   lambda: api.delete_file(str(moved))))
            case.absence(stage, "source_after")
            case.absence(moved, "moved_after")
            facts.update(blocked_delete_open_success=value is not None,
                blocked_delete_open_winerror=error, blocked_deletefile_success=not delete_error,
                blocked_deletefile_error_nonzero=delete_error > 0, blocked_move_success=not move_error,
                blocked_move_error_nonzero=move_error > 0, source_sha256_after_refusals=held["sha256"],
                source_identity_after_refusals_unchanged=initial["identity"] == held["identity"],
                rename_destination_absent_while_held=True, after_release_move_success=True,
                after_release_moved_sha256=moved_snapshot["sha256"], after_release_delete_success=True,
                both_source_and_moved_absent_at_end=True)
        elif case_id == "W04":
            value, error = case.open("exclusive_conflict_open", stage, OWNER_ACCESS, 0, 3)
            case.close(owner, "preexisting_writer_close")
            exclusive = case.require(case.open("exclusive_after_release_open", stage, OWNER_ACCESS, 0, 3))
            held = case.snapshot_held(exclusive, "exclusive_owner_after_release")
            case.close(exclusive, "exclusive_owner_close")
            after = case.snapshot_path(stage, "source_after")
            facts.update(preexisting_share_mode=7, exclusive_open_with_existing_writer_success=value is not None,
                exclusive_open_with_existing_writer_winerror=error,
                preexisting_owner_sha256_unchanged=initial["sha256"],
                exclusive_open_after_writer_close_success=True, exclusive_owner_read_sha256=held["sha256"],
                same_file_identity_preserved=initial["identity"] == held["identity"] == after["identity"])
        elif case_id == "W05":
            case.require(case.rename(owner, "owner_rename", target, "absolute_own_fresh_case_leaf"))
            _, write_error = case.open("blocked_target_write_open", target, WRITE, 7, 3)
            _, delete_error = case.open("blocked_target_delete_open", target, DELETE, 7, 3)
            held = case.snapshot_held(owner, "owner_after_rename")
            case.absence(stage, "source_after")
            case.close(owner, "owner_close")
            after = case.snapshot_path(target, "target_after")
            facts.update(rename_while_owner_held_success=True, old_source_name_absent_after_rename=True,
                unicode_destination_name=target.name, owner_read_after_rename_sha256=held["sha256"],
                blocked_target_write_success=not write_error, blocked_target_write_winerror=write_error,
                blocked_target_delete_open_success=not delete_error,
                blocked_target_delete_open_winerror=delete_error, target_after_close_sha256=after["sha256"],
                same_file_identity_after_rename_and_close=initial["identity"] == held["identity"] == after["identity"])
        elif case_id == "W06":
            _, error = case.rename(owner, "owner_rename_collision", case.path("control.bin"),
                                   "absolute_own_preexisting_control_c")
            held = case.snapshot_held(owner, "owner_after_refusal")
            case.close(owner, "owner_close")
            after = case.snapshot_path(stage, "source_after")
            control = facts["snapshots"]["control_c_before"]
            target_after = case.snapshot_path(case.path("control.bin"), "target_after")
            facts.update(rename_collision_success=not error, rename_collision_error_nonzero=error > 0,
                source_present_after_refusal=after["exists"], source_sha256_after_refusal=after["sha256"],
                source_identity_after_refusal_unchanged=initial["identity"] == held["identity"] == after["identity"],
                collision_target_sha256_before=control["sha256"],
                collision_target_sha256_after=target_after["sha256"],
                collision_target_identity_unchanged=control["identity"] == target_after["identity"],
                copy_or_replace_fallback_used=False)
        elif case_id == "W07":
            case.require(case.call("owner_disposition", "SetFileInformationByHandle",
                {"information_class": 4, "delete_file": True}, owner.mark_delete, owner))
            held = case.snapshot_held(owner, "owner_after_disposition")
            case.close(owner, "owner_close")
            case.absence(stage, "source_after")
            case.absence(target, "output_after")
            facts.update(disposition_mark_success=True, owner_read_after_mark_sha256=held["sha256"],
                stage_absent_after_close=True, output_present=False, name_based_cleanup_used=False)
        else:
            raise ValueError("unlisted case")
        return case.finish()
    finally:
        # On any unexpected error only retire/close owned resources once.
        # Leave all names, bytes and the fresh directory available for review.
        for handle in case.handles:
            if id(handle) not in case.close_attempts:
                try:
                    case.close(handle, f"error_close_{case.names[id(handle)]}")
                except BaseException:
                    pass
        case.facts["handles_closed"] = all(h.closed for h in case.handles)
        case.facts["close_uncertainty"] = any(h.close_uncertain for h in case.handles)
        with (directory / "CASE_OBSERVATION.json").open("x", encoding="utf-8") as stream:
            json.dump({"id": case.id, "events": case.events, "facts": case.facts},
                      stream, ensure_ascii=False, indent=2)


def collect(oracle):
    api = WindowsFileApi()  # Refuses incompatible runtime before creating a run.
    parent = Path(tempfile.gettempdir())
    volume = api.volume_info(str(parent))
    if volume["fs_name"].upper() != "NTFS" or volume["drive_type"] != 3:
        raise RuntimeError("requires an ordinary local fixed NTFS volume")
    root = Path(tempfile.mkdtemp(prefix="MOKOSH_WIN_OWN_FILES_", dir=parent))
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or getattr(root_info, "st_file_attributes", 0) & 0x400:
        raise RuntimeError("unexpected run directory or reparse point")
    print(json.dumps({"native_evidence_directory": str(root),
                      "collection_status": "STARTING_NOT_ACCEPTED"}, ensure_ascii=True), flush=True)
    record = {"schema": 1, "scope": SCOPE, "provenance": "NATIVE_OBSERVATION",
        "oracle_sha256": ORACLE_HASH, "application_accepted": False,
        "stage_accepted": False, "physical_accepted": False, "cases": [],
        "runtime": api.runtime, "volume": volume, "run_id": uuid.uuid4().hex,
        "collection_status": "INCOMPLETE"}
    try:
        for case_id in oracle["case_order"]:
            directory = root / case_id
            directory.mkdir(exist_ok=False)
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise RuntimeError("unexpected case directory or reparse point")
            record["cases"].append(perform_case(api, directory, case_id))
        record["collection_status"] = "COMPLETE"
    except BaseException as exc:
        with (root / "COLLECTOR_ERROR.json").open("x", encoding="utf-8") as stream:
            json.dump({"type": type(exc).__name__, "detail": str(exc)[:4000]}, stream)
        raise
    finally:
        with (root / "OBSERVATIONS.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
    return root, record
