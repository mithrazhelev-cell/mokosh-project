"""Bounded serialized-record checks; this module never proves native origin.

The oracle was frozen independently before implementation. Synthetic fixtures
exercise this evaluator only. No Win32 library, application, or process API is
imported here.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PureWindowsPath


ORACLE_SHA256 = "c0f4d7e84a4feacbdbea2d9ee967a06abf00db75b11b91bd22940b4d9bae81aa"
ORACLE_CANONICAL_SHA256 = "ebbc96aae747a62107f6e1f825e3190e4caf0c8b1a92f19d2f3f86ee0dc8f3ad"
SCOPE = "SEVEN_OWN_FILE_WIN32_API_GROUPS_NOT_APPLICATION_FIX_OR_PROCESS_SECURITY"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 256
PAYLOADS = {"A": bytes(range(256)) * 16, "B": b"B" * 4096, "C": b"C" * 4096}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HANDLE_ID = re.compile(r"H[0-9]{3,6}\Z")
LEAVES = {"stage.bin", "control.bin", "moved.bin", "published-Δ-Ж.bin"}
OPERATIONS = {
    "CreateFileW", "ReadFile", "WriteFile", "SetFilePointerEx",
    "FlushFileBuffers", "GetFileInformationByHandle", "GetHandleInformation",
    "SetFileInformationByHandle", "CloseHandle", "DeleteFileW", "MoveFileExW",
    "Path.lstat",
}


class EvaluationError(ValueError):
    """A missing, inconsistent, malformed, or scope-escalating record."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise EvaluationError(reason)


def _int(value: object, minimum: int = 0, maximum: int = 2**64 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _bounded(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    _need(depth <= 20 and count[0] <= 60000, "record nesting/item bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        _need(-(2**64) <= value <= 2**64 - 1, "integer bound")
        return
    if type(value) is str:
        _need(len(value) <= 16384, "string bound")
        return
    if type(value) is list:
        _need(len(value) <= 512, "list bound")
        for item in value:
            _bounded(item, depth + 1, count)
        return
    _need(type(value) is dict and len(value) <= 128, "non-JSON value/dict bound")
    for key, item in value.items():
        _need(type(key) is str and len(key) <= 160, "dictionary key")
        _bounded(item, depth + 1, count)


def _exact(actual: object, expected: object, reason: str) -> None:
    _need(type(actual) is type(expected) and actual == expected, reason)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_oracle(path: str | Path) -> dict:
    raw = Path(path).read_bytes()
    _need(len(raw) <= 256 * 1024, "oracle byte bound")
    _need(_digest(raw) == ORACLE_SHA256, "oracle raw binding")
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise EvaluationError("oracle JSON") from exc
    _validate_oracle(value)
    return value


def _validate_oracle(oracle: object) -> None:
    _need(type(oracle) is dict, "oracle type")
    _bounded(oracle)
    canonical = json.dumps(oracle, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    _need(_digest(canonical) == ORACLE_CANONICAL_SHA256, "frozen oracle semantics")


def _win_path(value: object, parent: PureWindowsPath | None = None) -> PureWindowsPath:
    _need(type(value) is str and 1 <= len(value) <= 512 and "\x00" not in value, "bounded path")
    path = PureWindowsPath(value)
    _need(path.is_absolute() and len(path.drive) == 2 and path.drive[1] == ":", "absolute local-drive path")
    _need(".." not in path.parts and path.name in LEAVES, "fixed own leaf path")
    if parent is not None:
        _need(path.parent == parent, "path escaped own case directory")
    return path


def _raw_bytes(value: object, maximum: int = 4096) -> bytes:
    _need(type(value) is str and len(value) <= maximum * 2 and len(value) % 2 == 0, "bounded hex payload")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise EvaluationError("payload hex") from exc
    _need(result.hex() == value, "canonical payload hex")
    return result


def _snapshot(snapshot: object, events: dict[str, dict], positions: dict[str, int], read_positions: dict[str, int]) -> dict:
    _need(type(snapshot) is dict, "snapshot type")
    for key in ("exists", "bytes", "sha256", "identity"):
        _need(key in snapshot, "snapshot missing " + key)
    _need(type(snapshot["exists"]) is bool and _int(snapshot["bytes"], 0, 4096), "snapshot existence/size types")
    if not snapshot["exists"]:
        _need(snapshot["bytes"] == 0 and snapshot["sha256"] is None and snapshot["identity"] is None, "absent snapshot fields")
        role = snapshot.get("absence_event")
        _need(type(role) is str and role in events, "absent snapshot support")
        event = events[role]
        _need(event["operation"] == "Path.lstat" and event["success"] is False, "absent snapshot operation")
        _need(event["winerror"] in (2, 3) and type(event["winerror"]) is int, "absence requires exact missing-path error")
        _need(event.get("result", {}).get("exists") is False, "absent snapshot result")
        return snapshot
    _need(snapshot["bytes"] == 4096 and type(snapshot["sha256"]) is str and HEX64.fullmatch(snapshot["sha256"]) is not None, "present snapshot digest/size")
    identity = snapshot["identity"]
    _need(type(identity) is dict and set(identity) == {"volume_serial", "file_index"}, "snapshot identity shape")
    _need(_int(identity["volume_serial"], 0, 2**32 - 1) and _int(identity["file_index"], 0), "snapshot identity types")
    roles = snapshot.get("read_events")
    _need(type(roles) is list and 1 <= len(roles) <= 64 and len(set(roles)) == len(roles), "snapshot read roles")
    _need(all(type(role) is str and role in events for role in roles), "snapshot missing read event")
    _need([positions[role] for role in roles] == sorted(positions[role] for role in roles), "snapshot read order")
    read_events = [events[role] for role in roles]
    _need(all(event["operation"] == "ReadFile" and event["success"] is True for event in read_events), "snapshot support is not successful reads")
    _need(len({event["handle_id"] for event in read_events}) == 1, "snapshot reads use different handles")
    _need(len({event["request"].get("group") for event in read_events}) == 1, "snapshot reads use different groups")
    _need(read_positions[roles[0]] == 0, "snapshot read did not start at file offset zero")
    cumulative = 0
    for role in roles:
        _need(read_positions[role] == cumulative, "snapshot read offsets are not contiguous")
        cumulative += events[role]["result"]["transferred_bytes"]
    data = b"".join(_raw_bytes(event["result"]["data_hex"]) for event in read_events)
    _need(len(data) == snapshot["bytes"] and _digest(data) == snapshot["sha256"], "snapshot bytes not supported by actual read records")
    role = snapshot.get("identity_event")
    _need(type(role) is str and role in events, "snapshot identity event")
    event = events[role]
    _need(event["operation"] == "GetFileInformationByHandle" and event["success"] is True, "snapshot identity operation")
    _need(event["handle_id"] == read_events[0]["handle_id"], "snapshot identity different handle")
    result = event.get("result", {})
    _need({k: result.get(k) for k in identity} == identity and result.get("size") == snapshot["bytes"], "snapshot identity/size unsupported")
    return snapshot


def _case(record: dict, expected: dict, oracle: dict) -> None:
    _need(type(record) is dict and set(record) == {"id", "events", "facts"}, "case shape")
    case_id = expected["id"]
    _exact(record["id"], case_id, "case identifier/order")
    facts, raw_events = record["facts"], record["events"]
    _need(type(facts) is dict and type(raw_events) is list and 1 <= len(raw_events) <= MAX_EVENTS, "case facts/events")
    for name, wanted in expected["expected_facts"].items():
        _need(name in facts, case_id + " missing fact " + name)
        _exact(facts[name], wanted, case_id + " fact " + name)
    events: dict[str, dict] = {}
    positions: dict[str, int] = {}
    handles: dict[str, dict] = {}
    writes: dict[str, bytes] = {}
    read_positions: dict[str, int] = {}
    event_paths: dict[str, PureWindowsPath] = {}
    critical = {item["role"]: item for item in expected["critical_event_contracts"]}
    opener_role = "preexisting_writer_create" if case_id == "W04" else "owner_create"
    opener_candidates = [event for event in raw_events if type(event) is dict and event.get("role") == opener_role]
    _need(len(opener_candidates) == 1, case_id + " source opener missing/duplicate")
    parent = _win_path(opener_candidates[0].get("request", {}).get("path")).parent
    _need(parent.name == case_id, "case directory name")
    _need(_win_path(opener_candidates[0]["request"]["path"]).name == "stage.bin", "source opener wrong leaf")
    for number, event in enumerate(raw_events):
        _need(type(event) is dict and {"role", "operation", "request", "handle_id", "success", "winerror"} <= set(event), "event shape")
        _need(set(event) <= {"role", "operation", "request", "handle_id", "success", "winerror", "result"}, "unrecognized event field")
        role, operation, request = event["role"], event["operation"], event["request"]
        _need(type(role) is str and 1 <= len(role) <= 120 and role not in events, "event role missing/duplicate")
        _need(type(operation) is str and operation in OPERATIONS and type(request) is dict, "event operation/request")
        _need(type(event["success"]) is bool and _int(event["winerror"], 0, 2**32 - 1), "event exact success/error types")
        _need((event["success"] and event["winerror"] == 0) or (not event["success"] and event["winerror"] > 0), "event return/error mismatch")
        result = event.get("result")
        if result is None:
            result = {}
        _need(type(result) is dict or (operation == "GetHandleInformation" and _int(result, 0, 2**32 - 1)), "event result shape")
        handle = event["handle_id"]
        _need(handle is None or (type(handle) is str and HANDLE_ID.fullmatch(handle) is not None), "logical handle ID")
        if operation in ("CreateFileW", "DeleteFileW", "Path.lstat"):
            _win_path(request.get("path"), parent)
        if operation == "MoveFileExW":
            _win_path(request.get("source_path"), parent)
            _win_path(request.get("target_path"), parent)
            _exact(request.get("flags"), 0, "move flags")
        if operation == "CreateFileW":
            _need(all(_int(request.get(k), 0, 2**32 - 1) for k in ("desired_access", "share_mode", "creation_disposition")), "create argument types")
            _need(request["share_mode"] in (0, 7) and request["creation_disposition"] in (1, 3), "create argument values")
            if event["success"]:
                _need(handle is not None and handle not in handles, "successful open handle reuse")
                handles[handle] = {"open": True, "event": event, "position": 0, "path": _win_path(request["path"], parent), "open_position": number}
            else:
                _need(handle is None, "failed open has authority")
        elif operation in ("DeleteFileW", "MoveFileExW", "Path.lstat"):
            _need(handle is None, "path operation has raw authority")
            if operation in ("DeleteFileW", "MoveFileExW"):
                _need(role in critical and case_id == "W03", "unlisted named move/delete or cleanup fallback")
        else:
            _need(handle in handles and handles[handle]["open"] is True, "use of missing/closed handle")
        if handle is not None and handle in handles:
            event_paths[role] = handles[handle]["path"]
        elif operation in ("DeleteFileW", "Path.lstat"):
            event_paths[role] = _win_path(request["path"], parent)
        if operation == "CloseHandle":
            _need(event["success"] is True, "close failure/uncertain resource")
            handles[handle]["open"] = False
            handles[handle]["close_position"] = number
        if operation == "SetFilePointerEx":
            _exact(request.get("offset"), 0, "seek offset")
            _exact(request.get("move_method"), 0, "seek move method")
            handles[handle]["position"] = 0
        if operation == "SetFileInformationByHandle":
            _need(role in critical and role in ("owner_rename", "owner_rename_collision", "owner_disposition"), "unlisted rename/disposition")
            _need(handle == opener_candidates[0]["handle_id"], "rename/disposition not original owner handle")
            info_class = request.get("information_class")
            _need(_int(info_class, 3, 4), "information class exact type")
            if info_class == 3:
                target = _win_path(request.get("target_path"), parent)
                encoded = request["target_path"].encode("utf-16-le")
                _exact(request.get("replace_if_exists"), False, "rename replacement enabled")
                _exact(request.get("root_directory_null"), True, "rename RootDirectory not NULL")
                _exact(request.get("filename_length"), len(encoded), "rename UTF16 byte length")
                _exact(request.get("filename_utf16_hex"), encoded.hex(), "rename UTF16 data")
                _exact(request.get("target_leaf"), target.name, "rename target leaf")
                if event["success"]:
                    handles[handle]["path"] = target
            else:
                _exact(request.get("delete_file"), True, "disposition delete flag")
        if operation in ("ReadFile", "WriteFile"):
            requested = request.get("requested_bytes")
            transferred = result.get("transferred_bytes")
            _need(_int(requested, 1, 4096) and _int(transferred, 0, requested), "I/O progress types/bounds")
            if operation == "ReadFile":
                data = _raw_bytes(result.get("data_hex"))
                _need(type(request.get("group")) is str, "read group")
                _need(len(data) == transferred and _digest(data) == result.get("sha256"), "read bytes/count/digest")
                read_positions[role] = handles[handle]["position"]
            else:
                data = _raw_bytes(request.get("data_hex"))
                _need(len(data) == requested and _digest(data) == request.get("sha256"), "write request bytes/count/digest")
                _need(transferred > 0, "write made no progress")
                writes[handle] = writes.get(handle, b"") + data[:transferred]
                _need(len(writes[handle]) <= 4096, "aggregate write bound")
            handles[handle]["position"] += transferred
            _need(handles[handle]["position"] <= 4096, "I/O file offset bound")
        if operation == "GetFileInformationByHandle" and event["success"]:
            for name, maximum in (("volume_serial", 2**32 - 1), ("file_index", 2**64 - 1), ("links", 2**32 - 1), ("size", 4096), ("attributes", 2**32 - 1)):
                _need(_int(result.get(name), 0, maximum), "file info integer " + name)
            _need(not result["attributes"] & (0x10 | 0x400), "regular own file info")
        if not event["success"] and role not in critical:
            _need(operation == "Path.lstat" and event["winerror"] in (2, 3) and result.get("exists") is False, "unlisted failed native operation")
        events[role], positions[role] = event, number
    _need(handles and all(state["open"] is False for state in handles.values()), "unclosed own handle")
    critical_positions = []
    for wanted in expected["critical_event_contracts"]:
        _need(wanted["role"] in events, "missing attempted critical operation")
        event = events[wanted["role"]]
        critical_positions.append(positions[wanted["role"]])
        for name in ("operation", "success", "winerror"):
            if name in wanted:
                _exact(event.get(name), wanted[name], case_id + " critical " + name)
        if wanted.get("winerror_constraint") == "exact_int_gt_0":
            _need(_int(event["winerror"], 1, 2**32 - 1), "expected positive native error")
        for name, value in wanted.get("request", {}).items():
            _exact(event["request"].get(name), value, case_id + " critical request " + name)
        role = wanted["role"]
        if event["operation"] == "CreateFileW":
            leaf = "published-Δ-Ж.bin" if role in ("blocked_target_write_open", "blocked_target_delete_open") else "stage.bin"
            _need(_win_path(event["request"].get("path"), parent).name == leaf, "critical open wrong named object")
        if role in ("blocked_deletefile", "released_deletefile"):
            leaf = "stage.bin" if role == "blocked_deletefile" else "moved.bin"
            _need(_win_path(event["request"].get("path"), parent).name == leaf, "critical delete wrong named object")
        if event["operation"] == "MoveFileExW":
            _need(_win_path(event["request"].get("source_path"), parent).name == "stage.bin" and _win_path(event["request"].get("target_path"), parent).name == "moved.bin", "critical move wrong named object")
    _need(critical_positions == sorted(critical_positions), "critical operation order")
    for handle, data in writes.items():
        event = handles[handle]["event"]
        path = _win_path(event["request"]["path"], parent)
        payload = "C" if path.name == "control.bin" else "B" if case_id == "W02" and event["role"] == "released_write_open" else "A"
        _need(data == PAYLOADS[payload], "actual write stream differs from declared fixture")
    source_handle = opener_candidates[0]["handle_id"]
    _need(writes.get(source_handle) == PAYLOADS["A"], "source fixture write missing")
    snapshots = facts.get("snapshots")
    _need(type(snapshots) is dict, "supporting snapshots missing")
    common_snapshots = {"control_c_before", "control_c_after", "source_before", "source_after"}
    specific_snapshots = {
        "W01": {"output_after"},
        "W02": {"before_release"},
        "W03": {"owner_after_refusals", "moved_while_held", "moved_before_delete", "moved_after"},
        "W04": {"exclusive_owner_after_release"},
        "W05": {"owner_after_rename", "target_after"},
        "W06": {"owner_after_refusal", "target_after"},
        "W07": {"owner_after_disposition", "output_after"},
    }
    _need(set(snapshots) == common_snapshots | specific_snapshots[case_id], "supporting snapshot names/count")
    snapshot_leaves = {
        "control_c_before": "control.bin", "control_c_after": "control.bin",
        "source_before": "stage.bin", "source_after": "stage.bin",
        "before_release": "stage.bin", "owner_after_refusals": "stage.bin",
        "exclusive_owner_after_release": "stage.bin", "owner_after_rename": "published-Δ-Ж.bin",
        "owner_after_refusal": "stage.bin", "owner_after_disposition": "stage.bin",
        "moved_while_held": "moved.bin", "moved_before_delete": "moved.bin", "moved_after": "moved.bin",
        "target_after": "published-Δ-Ж.bin" if case_id == "W05" else "control.bin",
        "output_after": "published-Δ-Ж.bin",
    }
    for name, snap in snapshots.items():
        _snapshot(snap, events, positions, read_positions)
        expected_path = parent / snapshot_leaves[name]
        support_roles = snap["read_events"] + [snap["identity_event"]] if snap["exists"] else [snap["absence_event"]]
        _need(all(event_paths[role] == expected_path for role in support_roles), "snapshot support wrong named leaf or handle-name phase")
    for name in ("control_c_before", "control_c_after", "source_before", "source_after"):
        _need(name in snapshots, "missing supporting snapshot " + name)
    before_c, after_c = snapshots["control_c_before"], snapshots["control_c_after"]
    before, after = snapshots["source_before"], snapshots["source_after"]
    for snap in (before_c, after_c):
        _need(snap["exists"] is True and snap["sha256"] == oracle["payloads"]["C"]["sha256"], "control C raw bytes changed")
    _need(before_c["identity"] == after_c["identity"], "control C identity changed")
    _need(before["exists"] is True and before["sha256"] == oracle["payloads"]["A"]["sha256"], "source initial raw bytes")
    _need(before["identity"] != before_c["identity"], "source aliases control")
    _need(events[before["read_events"][0]]["handle_id"] == source_handle, "source initial snapshot not original owner")
    _need(positions[before_c["read_events"][-1]] < positions[opener_role], "control before snapshot timing")
    after_c_first = positions[after_c["read_events"][0]]
    noncontrol_positions = [positions[role] for role, path in event_paths.items() if path.name != "control.bin"]
    _need(noncontrol_positions and after_c_first > max(noncontrol_positions), "control after snapshot precedes final source operation")
    if case_id in ("W03", "W05", "W07"):
        _need(after["exists"] is False, "source must be absent at end")
    else:
        wanted_payload = "B" if case_id == "W02" else "A"
        _need(after["exists"] is True and after["sha256"] == oracle["payloads"][wanted_payload]["sha256"] and after["identity"] == before["identity"], "final source bytes/identity")
    for phase in ("before", "after"):
        snap = snapshots["control_c_" + phase]
        _exact(facts["control_c_bytes_" + phase], snap["bytes"], "C size fact unsupported")
        _exact(facts["control_c_sha256_" + phase], snap["sha256"], "C digest fact unsupported")
    read_fact_sources = {
        "W01": {"owner_read_sha256": "source_before", "after_close_sha256": "source_after"},
        "W02": {"before_release_sha256": "before_release", "after_release_sha256": "source_after"},
        "W03": {"source_sha256_after_refusals": "owner_after_refusals", "after_release_moved_sha256": "moved_before_delete"},
        "W04": {"preexisting_owner_sha256_unchanged": "source_before", "exclusive_owner_read_sha256": "exclusive_owner_after_release"},
        "W05": {"owner_read_after_rename_sha256": "owner_after_rename", "target_after_close_sha256": "target_after"},
        "W06": {"source_sha256_after_refusal": "source_after", "collision_target_sha256_before": "control_c_before", "collision_target_sha256_after": "target_after"},
        "W07": {"owner_read_after_mark_sha256": "owner_after_disposition"},
    }
    for fact_name, snapshot_name in read_fact_sources[case_id].items():
        _need(snapshot_name in snapshots, "missing read fact support " + snapshot_name)
        snap = snapshots[snapshot_name]
        _need(snap["exists"] is True and snap["sha256"] == facts[fact_name], "read fact not supported")
        if snapshot_name not in ("control_c_before", "control_c_after") and not (case_id == "W06" and snapshot_name == "target_after"):
            _need(snap["identity"] == before["identity"], "read phase object identity differs")
    if case_id == "W06":
        _need(snapshots["target_after"]["identity"] == before_c["identity"], "collision target identity differs from preexisting C")
        _need(positions[snapshots["target_after"]["read_events"][0]] > positions["owner_close"], "collision target snapshot precedes owner close")
    phase_roles = {
        "W02": [("before_release", "blocked_write_open", "owner_close")],
        "W03": [("owner_after_refusals", "blocked_move", "owner_close"), ("moved_before_delete", "released_move", "released_deletefile")],
        "W04": [("exclusive_owner_after_release", "exclusive_after_release_open", None)],
        "W05": [("owner_after_rename", "owner_rename", "owner_close"), ("target_after", "owner_close", None)],
        "W06": [("owner_after_refusal", "owner_rename_collision", "owner_close")],
        "W07": [("owner_after_disposition", "owner_disposition", "owner_close")],
    }
    for snapshot_name, after_role, before_role in phase_roles.get(case_id, []):
        snap = snapshots[snapshot_name]
        _need(snap["identity"] == before["identity"], "phase snapshot changed source object identity")
        first = positions[snap["read_events"][0]]
        last = positions[snap["read_events"][-1]]
        _need(first > positions[after_role], "phase snapshot precedes tested action")
        if before_role is not None:
            _need(last < positions[before_role], "phase snapshot follows release/deletion")
        if snapshot_name.startswith("owner_after") or snapshot_name == "before_release":
            _need(events[snap["read_events"][0]]["handle_id"] == source_handle, "held phase snapshot reopened source")
    release_role = {"W01": "owner_close", "W02": "released_writer_close", "W04": "exclusive_owner_close", "W06": "owner_close"}.get(case_id)
    if release_role is not None:
        _need(release_role in positions, "missing release close for final snapshot")
        final_handle = events[after["read_events"][0]]["handle_id"]
        _need(handles[final_handle]["open_position"] > positions[release_role], "after-close snapshot did not use a new postrelease open")
    if case_id == "W05":
        final_handle = events[snapshots["target_after"]["read_events"][0]]["handle_id"]
        _need(handles[final_handle]["open_position"] > positions["owner_close"], "renamed after-close snapshot reopened too early")
    if case_id == "W04":
        _need(events[snapshots["exclusive_owner_after_release"]["read_events"][0]]["handle_id"] == events["exclusive_after_release_open"]["handle_id"], "exclusive read wrong acquired handle")
    if case_id == "W01":
        _need("output_after" in snapshots and snapshots["output_after"]["exists"] is False, "W01 output absence unsupported")
        _need(facts["owner_write_bytes"] == len(writes[source_handle]) and facts["owner_read_bytes"] == before["bytes"], "W01 I/O facts unsupported")
    if case_id == "W02":
        handle = events["released_write_open"]["handle_id"]
        _need(writes.get(handle) == PAYLOADS["B"] and facts["after_release_write_bytes"] == len(writes[handle]), "postrelease B write not attempted")
    if case_id == "W03":
        _need("moved_after" in snapshots and snapshots["moved_after"]["exists"] is False, "moved name final absence unsupported")
        _need("moved_while_held" in snapshots and snapshots["moved_while_held"]["exists"] is False, "held move-target absence unsupported")
        _need(positions["blocked_move"] < positions[snapshots["moved_while_held"]["absence_event"]] < positions["owner_close"], "held move-target absence timing")
        _need(all(positions[snapshots[name]["absence_event"]] > positions["released_deletefile"] for name in ("source_after", "moved_after")), "final source/moved absence precedes tested deletion")
    if case_id == "W05":
        _need(positions["owner_rename"] < positions[after["absence_event"]] < positions["owner_close"], "old source absence timing")
    if case_id in ("W01", "W07"):
        _need(positions[snapshots["output_after"]["absence_event"]] > positions["owner_close"], "final output absence precedes owner close")
    if case_id == "W07":
        _need("output_after" in snapshots and snapshots["output_after"]["exists"] is False, "W07 output absence unsupported")
        _need(positions[after["absence_event"]] > positions["owner_close"], "stage absence precedes disposition close")


def _evaluate_records(record: object, oracle: object) -> dict:
    """Return consistency assessment or raise EvaluationError; never certify origin."""
    _validate_oracle(oracle)
    _bounded(record)
    _need(type(record) is dict, "record type")
    _need(len(json.dumps(record, ensure_ascii=True).encode()) <= MAX_JSON_BYTES, "record byte bound")
    required = {"schema", "scope", "provenance", "oracle_sha256", "application_accepted", "stage_accepted", "physical_accepted", "cases"}
    _need(required <= set(record) <= required | {"runtime", "volume", "run_id", "collection_status"}, "top-level record fields")
    _exact(record["schema"], 1, "schema")
    _exact(record["scope"], SCOPE, "scope")
    _exact(record["oracle_sha256"], ORACLE_SHA256, "record oracle binding")
    _need(type(record["provenance"]) is str and record["provenance"] in ("NATIVE_OBSERVATION", "SYNTHETIC_NOT_NATIVE"), "provenance")
    for key in ("application_accepted", "stage_accepted", "physical_accepted"):
        _exact(record[key], False, "forbidden scope escalation " + key)
    if "collection_status" in record:
        _exact(record["collection_status"], "COMPLETE", "incomplete collection")
    if record["provenance"] == "NATIVE_OBSERVATION":
        runtime, volume = record.get("runtime"), record.get("volume")
        _need(type(runtime) is dict and type(volume) is dict, "native runtime/volume metadata missing")
        expected_runtime = {"os_name": "nt", "sys_platform": "win32", "system": "Windows", "python_implementation": "CPython", "python_major_minor": [3, 12], "pointer_bytes": 8, "wchar_bytes": 2, "isolated": True, "dont_write_bytecode": True, "optimize": 0}
        for key, value in expected_runtime.items():
            _exact(runtime.get(key), value, "native runtime " + key)
        _need(type(runtime.get("machine")) is str and runtime["machine"].upper() in ("AMD64", "X86_64"), "native architecture")
        _need(type(volume.get("fs_name")) is str and volume["fs_name"].upper() == "NTFS", "native filesystem")
        _exact(volume.get("drive_type"), 3, "native fixed drive")
        _need(_int(volume.get("serial"), 0, 2**32 - 1), "native volume serial")
    _need(type(record["cases"]) is list and len(record["cases"]) == 7, "case count")
    for case, expected in zip(record["cases"], oracle["cases"]):
        _case(case, expected, oracle)
        if record["provenance"] == "NATIVE_OBSERVATION":
            for snap in case["facts"]["snapshots"].values():
                if snap["exists"]:
                    _exact(snap["identity"]["volume_serial"], record["volume"]["serial"], "snapshot differs from selected native volume")
    return {
        "accepted": True,
        "scope": "SERIALIZED_RECORD_CONSISTENCY_ONLY_NOT_NATIVE_ORIGIN_PROOF",
        "provenance": record["provenance"],
        "serialized_groups_matched": 7,
        "native_execution_authenticated": False,
        "native_cases_executed_by_evaluator": 0,
        "application_accepted": False,
        "stage_accepted": False,
        "physical_accepted": False,
    }


def evaluate_records(record: object, oracle: object) -> dict:
    """Reject malformed data predictably without masking EvaluationError details."""
    try:
        return _evaluate_records(record, oracle)
    except EvaluationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise EvaluationError("malformed record or oracle structure: " + type(exc).__name__) from exc
