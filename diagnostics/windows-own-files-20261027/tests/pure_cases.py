"""Synthetic evaluator fixtures, not Windows observations or an API simulator."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import PureWindowsPath

from src.evaluate_records import EvaluationError, ORACLE_SHA256, SCOPE, PAYLOADS, evaluate_records


OWNER = 0xC0010000
READ = 0x80000000
WRITE = 0x40000000
DELETE = 0x10000


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FixtureCase:
    """Serialize a declared synthetic consistent record; call no native API."""

    def __init__(self, expected, index):
        self.id = expected["id"]
        self.directory = PureWindowsPath("C:/MOKOSH_SYNTHETIC_FIXTURE") / self.id
        self.events = []
        self.facts = deepcopy(expected["expected_facts"])
        self.facts["snapshots"] = {}
        self.next_handle = 0
        self.identities = {"A": {"volume_serial": 17, "file_index": index * 10 + 1},
                           "C": {"volume_serial": 17, "file_index": index * 10 + 2}}

    def path(self, leaf):
        return str(self.directory / leaf)

    def event(self, role, operation, request, handle=None, success=True, winerror=0, result=None):
        event = {"role": role, "operation": operation, "request": request,
                 "handle_id": handle, "success": success, "winerror": winerror}
        if result is not None:
            event["result"] = result
        self.events.append(event)
        return event

    def open(self, role, leaf, access=OWNER, share=0, creation=1, *, refusal=False):
        handle = None
        if not refusal:
            self.next_handle += 1
            handle = f"H{self.next_handle:03d}"
        self.event(role, "CreateFileW", {"path": self.path(leaf), "desired_access": access,
            "share_mode": share, "creation_disposition": creation}, handle,
            not refusal, 32 if refusal else 0)
        return handle

    def close(self, handle, role):
        self.event(role, "CloseHandle", {}, handle)

    def write(self, handle, payload, role):
        data = PAYLOADS[payload]
        self.event(role, "WriteFile", {"requested_bytes": len(data), "sha256": digest(data),
            "data_hex": data.hex()}, handle, result={"transferred_bytes": len(data)})

    def held_snapshot(self, handle, payload, name):
        data = PAYLOADS[payload]
        identity = self.identities["C" if payload == "C" else "A"]
        info = dict(identity, links=1, size=len(data), attributes=0x80)
        self.event(name + "_info", "GetFileInformationByHandle", {}, handle, result=info)
        self.event(name + "_seek", "SetFilePointerEx", {"offset": 0, "move_method": 0}, handle)
        read_role = name + "_read_00"
        self.event(read_role, "ReadFile", {"requested_bytes": len(data), "group": name}, handle,
            result={"transferred_bytes": len(data), "data_hex": data.hex(), "sha256": digest(data)})
        info_role = name + "_info_after"
        self.event(info_role, "GetFileInformationByHandle", {}, handle, result=dict(info))
        snapshot = {"exists": True, "bytes": len(data), "sha256": digest(data),
            "identity": dict(identity), "read_events": [read_role], "identity_event": info_role}
        self.facts["snapshots"][name] = snapshot
        return snapshot

    def path_snapshot(self, leaf, payload, name):
        handle = self.open(name + "_open", leaf, READ, 7, 3)
        snapshot = self.held_snapshot(handle, payload, name)
        self.close(handle, name + "_close")
        return snapshot

    def absent(self, leaf, name):
        role = name + "_absence"
        self.event(role, "Path.lstat", {"path": self.path(leaf)}, success=False,
            winerror=2, result={"exists": False})
        self.facts["snapshots"][name] = {"exists": False, "bytes": 0, "sha256": None,
            "identity": None, "absence_event": role}

    def rename(self, owner, role, target, kind, *, refusal=False):
        path = self.path(target)
        encoded = path.encode("utf-16-le")
        self.event(role, "SetFileInformationByHandle", {"information_class": 3,
            "replace_if_exists": False, "root_directory_null": True, "target_kind": kind,
            "target_leaf": target, "target_path": path, "filename_length_unit": "utf16le_bytes",
            "filename_length": len(encoded), "filename_utf16_hex": encoded.hex()}, owner,
            not refusal, 183 if refusal else 0)

    def build(self):
        c = self.open("control_create", "control.bin")
        self.write(c, "C", "control_write_00")
        self.event("control_flush", "FlushFileBuffers", {}, c)
        self.held_snapshot(c, "C", "control_c_before")
        self.close(c, "control_close")
        if self.id == "W04":
            owner = self.open("preexisting_writer_create", "stage.bin", READ | WRITE, 7)
        else:
            owner = self.open("owner_create", "stage.bin")
        self.write(owner, "A", "owner_write_00")
        if self.id == "W01":
            self.event("owner_flush", "FlushFileBuffers", {}, owner)
        self.held_snapshot(owner, "A", "source_before")
        if self.id == "W01":
            self.close(owner, "owner_close")
            self.path_snapshot("stage.bin", "A", "source_after")
            self.absent("published-Δ-Ж.bin", "output_after")
        elif self.id == "W02":
            self.open("blocked_write_open", "stage.bin", WRITE, 7, 3, refusal=True)
            self.held_snapshot(owner, "A", "before_release")
            self.close(owner, "owner_close")
            writer = self.open("released_write_open", "stage.bin", WRITE, 7, 3)
            self.write(writer, "B", "released_write_00")
            self.close(writer, "released_writer_close")
            self.path_snapshot("stage.bin", "B", "source_after")
        elif self.id == "W03":
            self.open("blocked_delete_open", "stage.bin", DELETE, 7, 3, refusal=True)
            self.event("blocked_deletefile", "DeleteFileW", {"path": self.path("stage.bin")},
                success=False, winerror=32)
            move = {"source_path": self.path("stage.bin"), "target_path": self.path("moved.bin"), "flags": 0}
            self.event("blocked_move", "MoveFileExW", dict(move), success=False, winerror=32)
            self.held_snapshot(owner, "A", "owner_after_refusals")
            self.absent("moved.bin", "moved_while_held")
            self.close(owner, "owner_close")
            self.event("released_move", "MoveFileExW", dict(move))
            self.path_snapshot("moved.bin", "A", "moved_before_delete")
            self.event("released_deletefile", "DeleteFileW", {"path": self.path("moved.bin")})
            self.absent("stage.bin", "source_after")
            self.absent("moved.bin", "moved_after")
        elif self.id == "W04":
            self.open("exclusive_conflict_open", "stage.bin", OWNER, 0, 3, refusal=True)
            self.close(owner, "preexisting_writer_close")
            acquired = self.open("exclusive_after_release_open", "stage.bin", OWNER, 0, 3)
            self.held_snapshot(acquired, "A", "exclusive_owner_after_release")
            self.close(acquired, "exclusive_owner_close")
            self.path_snapshot("stage.bin", "A", "source_after")
        elif self.id == "W05":
            self.rename(owner, "owner_rename", "published-Δ-Ж.bin", "absolute_own_fresh_case_leaf")
            self.open("blocked_target_write_open", "published-Δ-Ж.bin", WRITE, 7, 3, refusal=True)
            self.open("blocked_target_delete_open", "published-Δ-Ж.bin", DELETE, 7, 3, refusal=True)
            self.held_snapshot(owner, "A", "owner_after_rename")
            self.absent("stage.bin", "source_after")
            self.close(owner, "owner_close")
            self.path_snapshot("published-Δ-Ж.bin", "A", "target_after")
        elif self.id == "W06":
            #183 is synthetic example data only; oracle requires nonzero, not183.
            self.rename(owner, "owner_rename_collision", "control.bin", "absolute_own_preexisting_control_c", refusal=True)
            self.held_snapshot(owner, "A", "owner_after_refusal")
            self.close(owner, "owner_close")
            self.path_snapshot("stage.bin", "A", "source_after")
            self.path_snapshot("control.bin", "C", "target_after")
        elif self.id == "W07":
            self.event("owner_disposition", "SetFileInformationByHandle", {"information_class": 4,
                "delete_file": True}, owner)
            self.held_snapshot(owner, "A", "owner_after_disposition")
            self.close(owner, "owner_close")
            self.absent("stage.bin", "source_after")
            self.absent("published-Δ-Ж.bin", "output_after")
        self.path_snapshot("control.bin", "C", "control_c_after")
        return {"id": self.id, "events": self.events, "facts": self.facts}


def make_synthetic_fixture(oracle):
    return {"schema": 1, "scope": SCOPE, "provenance": "SYNTHETIC_NOT_NATIVE",
        "oracle_sha256": ORACLE_SHA256, "application_accepted": False,
        "stage_accepted": False, "physical_accepted": False,
        "collection_status": "COMPLETE",
        "runtime": {"fixture_only": True},
        "cases": [FixtureCase(case, index).build() for index, case in enumerate(oracle["cases"], 1)]}


def _event(record, case_id, role):
    case = next(case for case in record["cases"] if case["id"] == case_id)
    return next(event for event in case["events"] if event["role"] == role)


def _case(record, case_id):
    return next(case for case in record["cases"] if case["id"] == case_id)


def _remove_event(record, case_id, role):
    case = _case(record, case_id)
    case["events"] = [event for event in case["events"] if event["role"] != role]


def _replace_read(record, case_id, role, payload):
    result = _event(record, case_id, role)["result"]
    data = PAYLOADS[payload]
    result.update(transferred_bytes=len(data), data_hex=data.hex(), sha256=digest(data))


def run_pure_checks(oracle):
    """Root invokes once after review. Every test is synthetic record checking."""
    fixture = make_synthetic_fixture(oracle)
    positive = evaluate_records(fixture, oracle)
    assert positive["accepted"] is True and positive["native_execution_authenticated"] is False
    mutations = []

    def add(identifier, description, mutate, *, mutate_oracle=None):
        changed, changed_oracle = deepcopy(fixture), deepcopy(oracle)
        mutate(changed)
        if mutate_oracle is not None:
            mutate_oracle(changed_oracle)
        raw_hash = digest(json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        try:
            evaluate_records(changed, changed_oracle)
        except EvaluationError as exc:
            mutations.append({"id": identifier, "description": description, "rejected": True,
                "reason": str(exc), "record_sha256": raw_hash})
        else:
            raise AssertionError(identifier + " unexpectedly accepted")

    add("M01", "Missing W05", lambda r: r["cases"].pop(4))
    add("M02", "Duplicate case", lambda r: r["cases"].append(deepcopy(r["cases"][0])))
    def reorder(r):
        r["cases"][0], r["cases"][1] = r["cases"][1], r["cases"][0]
    add("M03", "Reordered cases", reorder)
    add("M04", "Boolean error is not integer zero", lambda r: _event(r, "W01", "owner_create").update(winerror=False))
    add("M05", "Missing path is not sharing refusal", lambda r: _event(r, "W02", "blocked_write_open").update(winerror=2))
    add("M06", "Denial fact without attempted operation", lambda r: _remove_event(r, "W03", "blocked_delete_open"))
    add("M07", "Exclusive sharing weakened", lambda r: _event(r, "W01", "owner_create")["request"].update(share_mode=7))
    add("M08", "Missing actual allowed postrelease write", lambda r: _remove_event(r, "W02", "released_write_00"))
    def changed_collision_target(r):
        _replace_read(r, "W06", "target_after_read_00", "B")
        _case(r, "W06")["facts"]["snapshots"]["target_after"]["sha256"] = digest(PAYLOADS["B"])
    add("M09", "Actual collision-target snapshot/read changed to B, C facts retained", changed_collision_target)
    add("M10", "Raw A owner read changed to B, facts retained", lambda r: _replace_read(r, "W01", "source_before_read_00", "B"))
    add("M11", "Rename replacement enabled", lambda r: _event(r, "W05", "owner_rename")["request"].update(replace_if_exists=True))
    add("M12", "Failed close hidden by closed facts", lambda r: _event(r, "W01", "owner_close").update(success=False, winerror=6))
    add("M13", "Unicode filename length counts codepoints", lambda r: _event(r, "W05", "owner_rename")["request"].update(filename_length=len(_event(r, "W05", "owner_rename")["request"]["target_path"])))
    add("M14", "Application acceptance escalated", lambda r: r.update(application_accepted=True))
    add("M15", "Absence evidence uses the wrong leaf", lambda r: _event(r, "W07", "source_after_absence")["request"].update(path=_event(r, "W07", "output_after_absence")["request"]["path"]))
    add("M16", "Preclose snapshot reused as afterclose evidence", lambda r: _case(r, "W01")["facts"]["snapshots"].update(source_after=deepcopy(_case(r, "W01")["facts"]["snapshots"]["source_before"])))
    add("M17", "Snapshot identity unsupported by raw info", lambda r: _case(r, "W01")["facts"]["snapshots"]["control_c_after"]["identity"].update(file_index=999999))
    add("M18", "Own successful handle close omitted", lambda r: _remove_event(r, "W01", "control_close"))
    add("M19", "Frozen oracle semantics altered", lambda r: None,
        mutate_oracle=lambda o: o["cases"][1]["expected_facts"].update(blocked_write_open_winerror=2))
    def false_native(r):
        r["provenance"] = "NATIVE_OBSERVATION"
        r["runtime"] = {"os_name": "posix", "sys_platform": "linux", "system": "Linux",
            "machine": "x86_64", "python_implementation": "CPython", "python_major_minor": [3, 12],
            "pointer_bytes": 8, "wchar_bytes": 4, "isolated": True, "dont_write_bytecode": True, "optimize": 0}
        r["volume"] = {"fs_name": "NTFS", "drive_type": 3, "serial": 17}
    add("M20", "Native provenance with wrong actual platform", false_native)
    assert len(mutations) == 20
    return {"status": "PASS_PURE_EVALUATOR_CONTROLS_ONLY", "positive_count": 1,
        "mutation_count": 20, "mutations": mutations, "positive_assessment": positive,
        "synthetic_fixture": fixture, "native_cases_executed": 0,
        "application_accepted": False, "stage_accepted": False, "physical_accepted": False}
