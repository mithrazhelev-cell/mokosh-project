#!/usr/bin/env python3
"""Frozen own-file sink diagnostics; never an application acceptance test.

This runner imports six byte-pinned module COPIES and runs the fourteen cases
specified by the immutable V2 oracle. No crypto pipeline or GUI is imported.
The baseline's eight desired-contract failures are expected and remain FAIL.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import sys
import traceback
from dataclasses import asdict
from types import SimpleNamespace


ORACLE_SHA256 = "f2135342c80e7b49f5c21e1926b3bf7f6d3f95800c577b6d0746ccfd5450ba58"
CANDIDATE_PIN = (31040, "1851a2ad5be8a95b277098e4665957717c6652a62e3dd225478cab351c2e0f90")
SOURCE_PINS = {
    "mokosh_v2_filesystem.py": (31279, "1b997352cb45935ad8b49303de6188fec39d90dd747747981ec0541df6ea88bc"),
    "mokosh_v2_format.py": (17901, "9a08d0041f817e344e67881fa9e5664dc2b5e9ecb48cdfad769b18af49a1f63f"),
    "mokosh_v2_key_slots.py": (11535, "bf0c6a16f764afe9c5b39ad7c44c6ca9804defae82065b9e8c84b6500ff4ad55"),
    "mokosh_v2_operation_journal.py": (7644, "6353d0afec260ddad8fb135f99fae43ea7e326ead3fc2e2f6cc899ead70e95cd"),
    "mokosh_v2_operation_lease.py": (8247, "5b28544ef2db4b4d7df4301878de5ca2a09200ff1d854b58c1ee2ac192e9d857"),
    "mokosh_v2_operation_lifecycle.py": (14298, "79aa7a035dc4aae9ef07d4a16dcb900e5999181edb96d04482105f29a7e99e2b"),
}
IMPORT_ORDER = (
    "mokosh_v2_key_slots", "mokosh_v2_format", "mokosh_v2_operation_journal",
    "mokosh_v2_operation_lease", "mokosh_v2_filesystem", "mokosh_v2_operation_lifecycle",
)
EXPECTED_ALIASES = tuple(f"ASC{i:02d}" for i in range(1, 15))
ANNOTATION_KEYS = {"interpretation", "rollback_claim", "teardown", "narrow_contract_match_expected"}
META_FIELDS = ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")


class DiagnosticGuardError(RuntimeError):
    pass


class SyntheticInitialFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DiagnosticGuardError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(value):
    return {field: getattr(value, "st_" + field) for field in META_FIELDS}


def pinned_read(path, expected=None):
    """Read regular, non-symlink input without importing it; verify stable bytes."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "input is not one regular file: " + str(path))
    require(0 < before.st_size <= 2 * 1024 * 1024, "input size out of bounds")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require(metadata(before) == metadata(opened), "input changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        require(metadata(opened) == metadata(os.fstat(descriptor)) == metadata(path.lstat()), "input changed while reading")
    finally:
        os.close(descriptor)
    require(len(data) == before.st_size, "input read length mismatch")
    if expected is not None:
        require((len(data), digest(data)) == expected, "pinned input mismatch: " + str(path))
    return data


def write_new(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(descriptor)


def exception_graph(exc, initial=None):
    """Bounded identity graph: explicit causes and implicit initial context."""
    if exc is None:
        return {"root": None, "nodes": [], "initial_reachable": False}
    todo, ids, nodes = [exc], {id(exc): 0}, []
    while todo:
        current = todo.pop(0)
        require(len(nodes) < 24, "exception graph exceeds bound")
        item = {
            "id": ids[id(current)], "type": type(current).__name__,
            "message": str(current)[:500], "errno": getattr(current, "errno", None),
            "is_initial": current is initial, "suppress_context": current.__suppress_context__,
        }
        for label in ("__cause__", "__context__"):
            child = getattr(current, label)
            if child is None:
                item[label] = None
            else:
                if id(child) not in ids:
                    ids[id(child)] = len(ids)
                    todo.append(child)
                item[label] = ids[id(child)]
        nodes.append(item)
    return {"root": 0, "nodes": nodes, "initial_reachable": any(n["is_initial"] for n in nodes)}


def cause_chain(exc):
    values, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        values.append(exc)
        exc = exc.__cause__
    return values


def fixture_snapshot(folder):
    result = {}
    for path in sorted(folder.iterdir()):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 8192, "unexpected fixture object")
        data = path.read_bytes()
        result[path.name] = {"metadata": metadata(info), "sha256": digest(data), "hex": data.hex()}
    return result


def loaded_application_names():
    return sorted(n for n in sys.modules if n.startswith("mokosh_"))


def load_copies(folder, variant):
    require(not loaded_application_names(), "application modules already loaded")
    modules, receipts = {}, {}
    for name in IMPORT_ORDER:
        path = folder / (name + ".py")
        expected = CANDIDATE_PIN if variant == "candidate" and name == "mokosh_v2_filesystem" else SOURCE_PINS[path.name]
        data = pinned_read(path, expected)
        spec = importlib.util.spec_from_file_location(name, path)
        require(spec is not None and spec.loader is not None, "copy module spec unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        require(Path(module.__file__).resolve() == path.resolve(), "module loaded from wrong source")
        require(pinned_read(path, expected) == data, "loaded copy changed")
        modules[name] = module
        receipts[name] = {"path": str(path), "bytes": len(data), "sha256": digest(data)}
    require(loaded_application_names() == sorted(IMPORT_ORDER), "application import allowlist mismatch")
    return modules, receipts


class ComponentOS:
    """Delegate ordinary own-file calls; inject fsync only at exact boundary."""

    def __init__(self, original, module_path, folder, injection):
        self.original = original
        self.module_path = str(module_path)
        self.parent_identity = (folder.stat().st_dev, folder.stat().st_ino)
        self.folder = folder
        self.injection = injection
        self.injected = 0
        self.ordinals = {}
        self.opens, self.events = [], []
        self.operation = "construct"

    def __getattr__(self, name):
        return getattr(self.original, name)

    def open(self, *args, **kwargs):
        descriptor = self.original.open(*args, **kwargs)
        self.opens.append({"fd": descriptor, "path": os.fspath(args[0]), "metadata": metadata(self.original.fstat(descriptor))})
        self.events.append({"event": "open", **self.opens[-1]})
        return descriptor

    def fsync(self, descriptor):
        caller = sys._getframe(1)
        parent = caller.f_back
        info = self.original.fstat(descriptor)
        own_directory = stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.parent_identity
        event = {"event": "fsync", "fd": descriptor, "metadata": metadata(info),
                 "function": caller.f_code.co_name, "caller": None if parent is None else parent.f_code.co_name,
                 "function_file": caller.f_code.co_filename, "operation": self.operation,
                 "own_directory": own_directory, "boundary": None, "injected": False,
                 "real_fsync_called": False}
        self.events.append(event)
        require(caller.f_code.co_filename == self.module_path, "fsync did not originate in copied filesystem")
        if caller.f_code.co_name == "_sync_directory":
            require(parent is not None and parent.f_code.co_filename == self.module_path and own_directory,
                    "directory sync caller or owned descriptor differs")
            direct = parent.f_code.co_name
            ordinal = self.ordinals.get(direct, 0) + 1
            self.ordinals[direct] = ordinal
            if direct == "_create_private_temp" and self.operation == "construct" and ordinal == 1:
                boundary = "constructor_directory"
            elif direct == "commit" and self.operation == "commit" and ordinal in (1, 2):
                boundary = "commit_directory_" + str(ordinal)
            elif direct == "abort" and self.operation == "abort" and ordinal == 1:
                boundary = "abort_directory"
            else:
                raise DiagnosticGuardError("unexpected directory-sync boundary")
            event["boundary"] = boundary
            if self.injection is not None and boundary == self.injection["boundary"] and self.injected == 0:
                self.injected += 1
                number = getattr(errno, self.injection["errno"])
                event.update(injected=True, errno=number, errno_alias=self.injection["errno"])
                event["fixture_at_injection"] = fixture_snapshot(self.folder)
                raise OSError(number, "synthetic injected fsync error")
        else:
            require(caller.f_code.co_name in {"_create_private_journal", "seal_for_verification"}
                    and stat.S_ISREG(info.st_mode), "unexpected regular-file fsync boundary")
        event["real_fsync_called"] = True
        try:
            return self.original.fsync(descriptor)
        except BaseException as exc:
            event["unexpected_real_error"] = exception_graph(exc)
            raise

    def link(self, *args, **kwargs):
        event = {"event": "link", "source": os.fspath(args[0]), "target": os.fspath(args[1]), "returned": False}
        self.events.append(event)
        try:
            value = self.original.link(*args, **kwargs)
        except BaseException as exc:
            event["exception"] = exception_graph(exc)
            raise
        event["returned"] = True
        return value

    def unlink(self, *args, **kwargs):
        event = {"event": "unlink", "name": os.fspath(args[0]), "returned": False}
        self.events.append(event)
        try:
            value = self.original.unlink(*args, **kwargs)
        except BaseException as exc:
            event["exception"] = exception_graph(exc)
            raise
        event["returned"] = True
        return value

    def close(self, descriptor):
        event = {"event": "close", "fd": descriptor, "returned": False}
        self.events.append(event)
        value = self.original.close(descriptor)
        event["returned"] = True
        return value


def captured_descriptors_closed(proxy):
    details = []
    for item in proxy.opens:
        try:
            info = os.fstat(item["fd"])
        except OSError as exc:
            details.append({"fd": item["fd"], "closed": exc.errno == errno.EBADF, "errno": exc.errno})
        else:
            details.append({"fd": item["fd"], "closed": False, "metadata": metadata(info)})
    return all(item["closed"] for item in details), details


def sink_state(sink, folder, fixtures, payloads):
    final = folder / fixtures["FINAL_NAME"]
    exists = final.exists()
    result = {"final_present": exists, "publish_result_present": sink is not None and sink.publish_result is not None}
    if exists:
        data = final.read_bytes()
        result["final_payload"] = next((name for name, value in payloads.items() if data == value), "UNEXPECTED_BYTES")
        result["final_nlink"] = final.stat().st_nlink
    if sink is not None:
        result.update(committed=sink.committed, aborted=sink.aborted, active=sink._active,
                      temp_present=(folder / sink._temp_name).exists(), journal_present=(folder / sink._journal_name).exists())
    else:
        generated = [p.name for p in folder.iterdir() if p.name not in {
            fixtures["FINAL_NAME"], fixtures["RETAINED_INPUT_NAME"], fixtures["UNRELATED_SENTINEL_NAME"]}]
        # No generated name may be silently missed because of an assumed suffix.
        result.update(temp_present=bool(generated), journal_present=bool(generated))
        result["new_sink_names"] = len(generated)
    return result


def publish_fields(sink, lifecycle):
    value = sink.publish_result
    require(value is not None, "actual sink did not supply publish result")
    carrier = SimpleNamespace(publish=value)
    warning = lifecycle._safe_publish_warning(carrier)
    outcome = lifecycle.OperationOutcome(ok=True, result=carrier, warning=warning)
    result = {name: getattr(value, name) for name in (
        "output_verified", "publication_sync_complete", "temporary_removed", "journal_removed",
        "cleanup_sync_complete", "resources_closed", "warning_required", "residue_requires_review")}
    result.update(operation_outcome_ok=outcome.ok, operation_outcome_failure=outcome.failure,
                  lifecycle_warning=None if outcome.warning is None else outcome.warning.code.value,
                  output_identity=None if value.output_identity is None else asdict(value.output_identity))
    return result


def verify_effect_order(case, variant, proxy, sink, record, fixtures, payloads):
    """Frozen extra assertions are effects, not forecast agreement alone."""
    events = proxy.events
    dirs = [e["boundary"] for e in events if e["event"] == "fsync" and e["own_directory"]]
    regular = [e for e in events if e["event"] == "fsync" and not e["own_directory"]]
    unlinks = [e for e in events if e["event"] == "unlink"]
    links = [e for e in events if e["event"] == "link"]
    if case["alias"] == "ASC02":
        require(not proxy.opens and not regular and not dirs and not links and not unlinks, "collision constructor had side effects")
        return
    require(regular and regular[0]["function"] == "_create_private_journal" and regular[0]["real_fsync_called"],
            "constructor journal fsync did not succeed before directory sync")
    first_directory = next(i for i, e in enumerate(events) if e["event"] == "fsync" and e["own_directory"])
    require(events.index(regular[0]) < first_directory, "journal fsync order differs")
    require(len(proxy.opens) == 3, "constructor did not capture exactly parent/temp/journal descriptors")
    require(all(e["name"] != fixtures["FINAL_NAME"] for e in unlinks), "sink attempted to unlink final target")
    if case["alias"] == "ASC01":
        require(dirs == ["constructor_directory", "commit_directory_1", "commit_directory_2"], "normal directory sync sequence differs")
    if sink is not None and sink.publish_result is not None:
        require(len(links) == 1 and links[0]["returned"], "published case did not link exactly once")
    if case["injection"] is None:
        return
    injected = [e for e in events if e["event"] == "fsync" and e["injected"]]
    require(len(injected) == 1, "exact injection event missing")
    event = injected[0]
    snapshot = event["fixture_at_injection"]
    boundary = case["injection"]["boundary"]
    if boundary == "constructor_directory":
        require(fixtures["FINAL_NAME"] not in snapshot, "constructor created final output")
        require(len(snapshot) == 4, "constructor failure boundary lacks exact temp/journal fixture names")
        if variant == "candidate":
            require(set(record["snapshots"]["after_terminal_action"]) == {
                fixtures["RETAINED_INPUT_NAME"], fixtures["UNRELATED_SENTINEL_NAME"]}, "constructor rollback left any generated name")
    elif boundary == "commit_directory_1":
        require(sink is not None and len(snapshot) == 5, "first post-link boundary did not retain five fixture names")
        require(snapshot[fixtures["FINAL_NAME"]]["hex"] == payloads["OUTPUT_PAYLOAD"].hex(), "output missing at first sync failure")
        require(snapshot[sink._temp_name]["hex"] == payloads["OUTPUT_PAYLOAD"].hex(), "temporary bytes differ at first sync failure")
        if variant == "candidate" or case["injection"]["errno"] == "EIO":
            require(not unlinks and dirs == ["constructor_directory", "commit_directory_1"], "first-sync failure still attempted cleanup or second sync")
    elif boundary == "commit_directory_2":
        require(set(snapshot) == {fixtures["RETAINED_INPUT_NAME"], fixtures["UNRELATED_SENTINEL_NAME"], fixtures["FINAL_NAME"]}, "second-sync boundary still had residue")
        require(len(unlinks) == 2 and all(e["returned"] for e in unlinks), "second-sync cleanup did not remove both names exactly once")
        require(all(events.index(e) < events.index(event) for e in unlinks), "cleanup happened after second sync")
    elif boundary == "abort_directory":
        require(set(snapshot) == {fixtures["RETAINED_INPUT_NAME"], fixtures["UNRELATED_SENTINEL_NAME"]}, "abort sync boundary retains unexpected names")
        require(len(unlinks) == 2 and all(e["returned"] for e in unlinks), "abort did not remove both own names once")
        require(all(events.index(e) < events.index(event) for e in unlinks), "abort cleanup happened after sync")


def environment_limitation(action_error, events):
    graph = exception_graph(action_error)
    if any(node["type"] in {"OperationLeaseUnsupported", "AtomicPublishUnsupportedError"} for node in graph["nodes"]):
        return "Required real no-clobber link or cooperative lease capability unavailable."
    unsupported = {errno.EINVAL, errno.ENOSYS, getattr(errno, "ENOTSUP", errno.EINVAL)}
    if any(any(node["errno"] in unsupported for node in event.get("unexpected_real_error", {}).get("nodes", [])) for event in events):
        return "Required real normal fsync capability unavailable."
    return None


def compare_expected(expected, actual, prefix=""):
    differences = []
    for name, wanted in expected.items():
        if name in ANNOTATION_KEYS:
            continue
        label = prefix + name
        if name not in actual:
            differences.append({"field": label, "expected": wanted, "missing": True})
        elif isinstance(wanted, dict):
            if not isinstance(actual[name], dict):
                differences.append({"field": label, "expected": wanted, "actual": actual[name]})
            else:
                differences.extend(compare_expected(wanted, actual[name], label + "."))
        elif type(wanted) is not type(actual[name]) or wanted != actual[name]:
            differences.append({"field": label, "expected": wanted, "actual": actual[name]})
    return differences


def execute_case(case, variant, modules, copy_folder, folder, fixtures, payloads):
    folder.mkdir(mode=0o700)
    for field, data_name in (("RETAINED_INPUT_NAME", "RETAINED_PAYLOAD"), ("UNRELATED_SENTINEL_NAME", "UNRELATED_PAYLOAD")):
        write_new(folder / fixtures[field], payloads[data_name])
    if case["alias"] == "ASC02":
        write_new(folder / fixtures["FINAL_NAME"], payloads["COLLISION_PAYLOAD"])
    initial_files = fixture_snapshot(folder)
    fs, lifecycle = modules["mokosh_v2_filesystem"], modules["mokosh_v2_operation_lifecycle"]
    original_os = fs.os
    proxy = ComponentOS(original_os, str(copy_folder / "mokosh_v2_filesystem.py"), folder, case["injection"])
    fs.os = proxy
    record = {"alias": case["alias"], "variant": variant, "status": "STARTED", "snapshots": {"initial": initial_files}}
    observed, sink, initial, action_error = {}, None, None, None
    closure_details = []
    try:
        try:
            sink = fs.ExclusiveFileQuarantineSink(str(folder / fixtures["FINAL_NAME"]))
        except BaseException as exc:
            action_error = exc
        observed["constructor_returns"] = sink is not None
        if sink is None:
            closed, closure_details = captured_descriptors_closed(proxy)
            observed.update(sink_state(None, folder, fixtures, payloads),
                            captured_constructor_descriptors_closed=closed,
                            sink_opens=len(proxy.opens),
                            directory_sync_calls=sum(e.get("own_directory", False) for e in proxy.events if e["event"] == "fsync"))
            if case["alias"] == "ASC02":
                observed["existing_final_identity_and_bytes_unchanged"] = fixture_snapshot(folder)[fixtures["FINAL_NAME"]] == initial_files[fixtures["FINAL_NAME"]]
        elif case["alias"] in {"ASC04", "ASC05", "ASC06"}:
            observed["snapshot_before_teardown"] = sink_state(sink, folder, fixtures, payloads)
            proxy.injection = None
            proxy.operation = "abort"
            sink.abort()
            closed, closure_details = captured_descriptors_closed(proxy)
            record["baseline_teardown_state"] = sink_state(sink, folder, fixtures, payloads)
            require(closed and not sink._active and not Path(sink.temp_path).exists()
                    and not Path(sink.journal_path).exists(), "constructor control teardown incomplete")
        else:
            remaining = payloads["OUTPUT_PAYLOAD"]
            while remaining:
                remaining = remaining[sink.write(remaining):]
            if case["alias"] in {"ASC12", "ASC13", "ASC14"}:
                proxy.operation = "abort"
                if case["alias"] == "ASC12":
                    try:
                        sink.abort()
                    except BaseException as exc:
                        action_error = exc
                    event_count = len(proxy.events)
                    sink.abort()
                    require(len(proxy.events) == event_count, "inactive abort performed an additional operation")
                else:
                    initial = (lifecycle.OperationCancelled("synthetic initial cancellation")
                               if case["alias"] == "ASC13" else SyntheticInitialFailure("synthetic initial failure"))
                    try:
                        with sink:
                            raise initial
                    except BaseException as exc:
                        action_error = exc
                closed, closure_details = captured_descriptors_closed(proxy)
                observed.update(sink_state(sink, folder, fixtures, payloads), captured_sink_descriptors_closed=closed)
            else:
                sink.seal_for_verification()
                record["snapshots"]["before_commit"] = fixture_snapshot(folder)
                if case["alias"] == "ASC03":
                    write_new(folder / fixtures["FINAL_NAME"], payloads["COLLISION_PAYLOAD"])
                    collision = fixture_snapshot(folder)[fixtures["FINAL_NAME"]]
                proxy.operation = "commit"
                try:
                    sink.commit()
                except BaseException as exc:
                    action_error = exc
                if case["alias"] == "ASC03":
                    state = sink_state(sink, folder, fixtures, payloads)
                    observed.update(committed_before_abort=sink.committed,
                                    publish_result_present_before_abort=sink.publish_result is not None,
                                    temp_present_before_abort=state["temp_present"], journal_present_before_abort=state["journal_present"])
                    proxy.operation = "abort"
                    sink.abort()
                    closed, closure_details = captured_descriptors_closed(proxy)
                    observed["abort_after_collision"] = {**sink_state(sink, folder, fixtures, payloads),
                        "exception": None, "captured_sink_descriptors_closed": closed,
                        "final_identity_and_bytes_unchanged": fixture_snapshot(folder)[fixtures["FINAL_NAME"]] == collision}
                    observed["late_final_identity_and_bytes_unchanged"] = observed["abort_after_collision"]["final_identity_and_bytes_unchanged"]
                else:
                    closed, closure_details = captured_descriptors_closed(proxy)
                    observed.update(sink_state(sink, folder, fixtures, payloads))
                    observed.update(publish_fields(sink, lifecycle))
                    require(closed, "publish descriptor remains open")
        observed["exception"] = None if action_error is None else type(action_error).__name__
        if action_error is not None:
            chain = cause_chain(action_error)
            observed.update(exception_message=str(action_error), cause_chain=[type(e).__name__ for e in chain],
                            cause=None if action_error.__cause__ is None else type(action_error.__cause__).__name__)
            if len(chain) > 1:
                observed["inner_message"] = str(chain[1])
            if isinstance(chain[-1], OSError) and chain[-1].errno is not None:
                wanted_name = case["injection"]["errno"] if case["injection"] else None
                observed["cause_errno"] = wanted_name if wanted_name and chain[-1].errno == getattr(errno, wanted_name) else chain[-1].errno
        if case["injection"] is not None:
            observed["injected_errno"] = case["injection"]["errno"]
        graph = exception_graph(action_error, initial)
        if initial is not None:
            observed.update(initial_reason=type(initial).__name__, initial_reason_in_exception_graph=graph["initial_reachable"],
                            initial_reason_is_final_exception=action_error is initial,
                            primary_reason_typed_field=hasattr(action_error, "primary_reason"))
        record.update(observed=observed, action_exception=graph, descriptor_closure=closure_details,
                      descriptor_opens=proxy.opens, events=proxy.events, injection_count=proxy.injected)
        record["snapshots"]["after_terminal_action"] = fixture_snapshot(folder)
        for field in ("RETAINED_INPUT_NAME", "UNRELATED_SENTINEL_NAME"):
            name = fixtures[field]
            require(record["snapshots"]["after_terminal_action"][name] == initial_files[name], "retained fixture changed: " + name)
        require(proxy.injected == (0 if case["injection"] is None else 1), "injection count differs")
        require(not any("unexpected_real_error" in event for event in proxy.events), "underlying normal fsync failed")
        verify_effect_order(case, variant, proxy, sink, record, fixtures, payloads)
        require(loaded_application_names() == sorted(IMPORT_ORDER), "case imported unexpected application code")
        if sink is not None and sink.publish_result is not None:
            require(action_error is None and sink.committed, "publication reclassified as failure")
            if observed["temp_present"]:
                before, after = record["snapshots"]["before_commit"], record["snapshots"]["after_terminal_action"]
                require(after[sink._temp_name]["hex"] == before[sink._temp_name]["hex"], "retained temporary bytes changed")
                require(after[sink._journal_name] == before[sink._journal_name], "retained journal changed")
                require(after[sink._temp_name]["metadata"]["ino"] == after[fixtures["FINAL_NAME"]]["metadata"]["ino"], "retained temp/final object differs")
        forecast = compare_expected(case["expected_" + variant], observed)
        desired = compare_expected(case["expected_candidate"], observed)
        record.update(status="COMPLETE", forecast={"matches": not forecast, "differences": forecast},
                      desired_contract={"grade": "PASS" if not desired else "FAIL", "differences": desired})
    except BaseException as exc:
        limitation = environment_limitation(action_error, proxy.events)
        record.update(status="ENVIRONMENT_UNSUPPORTED" if limitation else "ERROR", unexpected_error=exception_graph(exc), traceback=traceback.format_exc(limit=8),
                      observed=observed, action_exception=exception_graph(action_error, initial),
                      descriptor_opens=proxy.opens, events=proxy.events, injection_count=proxy.injected,
                      forecast={"matches": False}, desired_contract={"grade": "NOT_RUN" if limitation else "ERROR"},
                      environment_limitation=limitation)
        # Capture closure before opening any file; do not guess cleanup targets.
        record["descriptor_closure_after_error"] = captured_descriptors_closed(proxy)[1]
    finally:
        fs.os = original_os
        require(fs.os is original_os and os.fsync is original_os.fsync, "OS binding restoration failed")
    return record


def execute(args):
    require(sys.flags.isolated and sys.dont_write_bytecode and not sys.flags.optimize, "run with -I -B without optimize")
    require(sys.platform == "linux" and os.getuid() == os.geteuid(), "this diagnostic requires Linux equal uid/euid")
    require(not loaded_application_names(), "existing application import refused")
    oracle_data = pinned_read(args.oracle_file)
    require(digest(oracle_data) == ORACLE_SHA256, "immutable oracle digest mismatch")
    oracle = json.loads(oracle_data)
    require(tuple(c["alias"] for c in oracle["cases"]) == EXPECTED_ALIASES, "oracle aliases differ")
    require(args.source_dir.is_dir() and not args.source_dir.is_symlink(), "source directory invalid")
    source_bytes = {name: pinned_read(args.source_dir / name, pin) for name, pin in SOURCE_PINS.items()}
    candidate = pinned_read(args.candidate_file, CANDIDATE_PIN)
    require(not args.work_root.exists() and not args.work_root.is_symlink(), "work-root must be a new path")
    args.work_root.mkdir(mode=0o700)
    raw = {"schema": 1, "status": "STARTED", "scope": "ACTUAL_SINK_SOURCE_COPY_AND_PURE_LIFECYCLE_WARNING_COMPONENT_ONLY",
           "oracle_sha256": ORACLE_SHA256, "runtime": {"python": list(sys.version_info[:3]), "system": platform.system(),
           "machine": platform.machine(), "uid": os.getuid(), "euid": os.geteuid(), "root_identity": os.getuid() == 0,
           "isolated": bool(sys.flags.isolated), "no_bytecode": sys.dont_write_bytecode},
           "limitations": ["Own synthetic files only; configured fsync errors are injected.",
           "UID0 observations are not unprivileged prevention or isolation proof.",
           "Not pinned Dell3.12.3, full pipeline, cryptography, GUI, physical, power-loss or cross-platform acceptance.",
           "FS15/BM03/BM04/cleanup/FS16 and mandatory physical/product gates remain open."],
           "source_inputs": {name: {"bytes": len(data), "sha256": digest(data)} for name, data in source_bytes.items()},
           "candidate_input": {"bytes": len(candidate), "sha256": digest(candidate)}, "variants": {}, "errors": [],
           "original_apply": False, "runtime_update": False, "application_pass_allowed": False,
           "physical_acceptance": False, "stage_pass_allowed": False, "commit_tag_allowed": False,
           "D005": "OPEN", "FS15": "OPEN_NOT_FIXED"}
    old_umask = os.umask(0o077)
    try:
        cases_root = args.work_root / "cases"
        cases_root.mkdir(mode=0o700)
        fixtures = oracle["fixtures"]
        payloads = {name: bytes.fromhex(fixtures[name]) for name in (
            "OUTPUT_PAYLOAD", "RETAINED_PAYLOAD", "UNRELATED_PAYLOAD", "COLLISION_PAYLOAD")}
        for variant in ("baseline", "candidate"):
            copy_folder = args.work_root / ("source_" + variant)
            copy_folder.mkdir(mode=0o700)
            for name, data in source_bytes.items():
                write_new(copy_folder / name, candidate if variant == "candidate" and name == "mokosh_v2_filesystem.py" else data)
            variant_root = cases_root / variant
            variant_root.mkdir(mode=0o700)
            try:
                modules, receipts = load_copies(copy_folder, variant)
                records = [execute_case(case, variant, modules, copy_folder, variant_root / case["alias"], fixtures, payloads)
                           for case in oracle["cases"]]
                raw["variants"][variant] = {"loaded_copies": receipts, "cases": records,
                    "forecast_matches": sum(c["forecast"]["matches"] for c in records),
                    "desired_contract_passes": sum(c["desired_contract"]["grade"] == "PASS" for c in records),
                    "desired_contract_failures": sum(c["desired_contract"]["grade"] == "FAIL" for c in records),
                    "errors": sum(c["status"] == "ERROR" for c in records),
                    "environment_not_run": sum(c["status"] == "ENVIRONMENT_UNSUPPORTED" for c in records)}
                for name, data in source_bytes.items():
                    wanted = candidate if variant == "candidate" and name == "mokosh_v2_filesystem.py" else data
                    require(pinned_read(copy_folder / name) == wanted, "source copy changed after cases")
            finally:
                for name in IMPORT_ORDER:
                    sys.modules.pop(name, None)
                require(not loaded_application_names(), "unexpected application modules remain")
        counts = raw["variants"]
        require(counts["baseline"]["forecast_matches"] == counts["candidate"]["forecast_matches"] == 14, "forecast mismatch")
        require(counts["baseline"]["desired_contract_passes"] == 6 and counts["baseline"]["desired_contract_failures"] == 8,
                "baseline desired-contract counts differ")
        require(counts["candidate"]["desired_contract_passes"] == 14 and counts["candidate"]["desired_contract_failures"] == 0,
                "candidate desired-contract counts differ")
        raw["status"] = "EXPECTED_SOURCE_COPY_BEHAVIOR_MATCHES_NOT_APPLICATION_ACCEPTANCE"
    except BaseException as exc:
        raw["status"] = "MISMATCH_OR_ERROR"
        raw["errors"].append({"phase": "execution", "exception": exception_graph(exc), "traceback": traceback.format_exc(limit=8)})
    finally:
        try:
            for name, data in source_bytes.items():
                require(pinned_read(args.source_dir / name, SOURCE_PINS[name]) == data, "original selected input changed")
            require(pinned_read(args.candidate_file, CANDIDATE_PIN) == candidate, "candidate input changed")
            require(pinned_read(args.oracle_file) == oracle_data, "frozen oracle changed")
            raw["selected_input_postguards"] = "PASS"
        except BaseException as exc:
            raw["selected_input_postguards"] = "FAIL"
            raw["status"] = "MISMATCH_OR_ERROR"
            raw["errors"].append({"phase": "postguards", "exception": exception_graph(exc)})
        raw_path = args.work_root / "RAW.json"
        write_new(raw_path, (json.dumps(raw, ensure_ascii=False, indent=2) + "\n").encode())
        os.umask(old_umask)
    summary = {"status": raw["status"], "raw_path": str(raw_path), "raw_sha256": digest(raw_path.read_bytes()),
               "runtime": raw["runtime"], "counts": {name: {k: value[k] for k in (
                   "forecast_matches", "desired_contract_passes", "desired_contract_failures", "errors")}
                   for name, value in raw["variants"].items()},
               "selected_input_postguards": raw["selected_input_postguards"], "application_pass_allowed": False,
               "physical_acceptance": False, "original_apply": False, "D005": "OPEN", "FS15": "OPEN_NOT_FIXED"}
    print("ACTUAL_SINK_SYNC_DIAGNOSTIC=" + json.dumps(summary, sort_keys=True), flush=True)
    return 0 if raw["status"] == "EXPECTED_SOURCE_COPY_BEHAVIOR_MATCHES_NOT_APPLICATION_ACCEPTANCE" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--candidate-file", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--oracle-file", type=Path,
                        default=Path(__file__).resolve().parent.parent / "analysis" / "SYNC_ACTUAL_COMPONENT_ORACLE_V2.json")
    args = parser.parse_args()
    for name in ("source_dir", "candidate_file", "work_root", "oracle_file"):
        setattr(args, name, getattr(args, name).absolute())
    try:
        return execute(args)
    except BaseException as exc:
        print("ACTUAL_SINK_SYNC_DIAGNOSTIC_REFUSED=" + json.dumps(exception_graph(exc), sort_keys=True), file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
