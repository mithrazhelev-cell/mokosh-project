"""Portable prerequisite checks. Fake own calls never count as native proof."""
import copy
import struct

from src.windows_file_api import (
    OwnedHandle, WinApiError, WindowsFileApi, layout_metadata,
    pack_rename_info, runtime_metadata, runtime_rejection_reasons,
)


def run_binding_checks():
    records = []
    eligible = {"os_name": "nt", "sys_platform": "win32", "system": "Windows",
        "machine": "AMD64", "python_implementation": "CPython",
        "python_major_minor": [3, 12], "pointer_bytes": 8, "wchar_bytes": 2,
        "isolated": True, "dont_write_bytecode": True, "optimize": 0}
    assert runtime_rejection_reasons(eligible) == []
    records.append({"name": "eligible_runtime_data_only", "matched": True})
    changes = [("os_name", "posix"), ("sys_platform", "linux"),
        ("system", "Linux"), ("machine", "ARM64"),
        ("python_implementation", "PyPy"), ("python_major_minor", [3, 13]),
        ("python_major_minor", [True, 12]), ("pointer_bytes", 4),
        ("wchar_bytes", 4), ("isolated", False),
        ("dont_write_bytecode", False), ("optimize", 1), ("optimize", False)]
    for i, (key, value) in enumerate(changes):
        bad = copy.deepcopy(eligible)
        bad[key] = value
        assert runtime_rejection_reasons(bad), key
        records.append({"name": f"runtime_reject_{i:02d}_{key}", "matched": True})
    wanted = {"pointer_bytes": 8, "DWORD_bytes": 4, "BOOL_bytes": 4,
        "rename_size": 24, "rename_root_offset": 8, "rename_length_offset": 16,
        "rename_filename_offset": 20, "identity_size": 52,
        "identity_volume_offset": 28, "identity_index_high_offset": 44,
        "identity_index_low_offset": 48}
    assert layout_metadata() == wanted
    records.append({"name": "host_ctypes_fixed_width_layout_not_Windows_execution", "matched": True})
    target = "C:\\MOKOSH_OWN\\W05\\published-Δ-Ж-😀.bin"
    payload = target.encode("utf-16-le")
    packed = pack_rename_info(target)
    assert packed[:16] == b"\0" * 16
    assert struct.unpack_from("<I", packed, 16)[0] == len(payload)
    assert packed[20:20 + len(payload)] == payload
    assert packed[20 + len(payload):] == b"\0\0"
    assert len(payload) != len(target)
    records.append({"name": "UTF16_byte_length_and_offset20_not_character_count", "matched": True})
    for i, path in enumerate(["relative.bin", "C:\\x\\..\\b.bin", "\\\\server\\share\\a",
        "C:\\x\\a:ads", "C:\\x\\NUL.txt", "C:\\x\\a.bin\0other", "C:\\" + "a" * 241]):
        try:
            pack_rename_info(path)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe path accepted")
        records.append({"name": f"rename_path_rejection_{i:02d}", "matched": True})

    class FakeOwnApi:
        def __init__(self, fail=False):
            self.calls = []
            self.fail = fail

        def _bool(self, op, value):
            self.calls.append((op, value))
            if self.fail:
                raise WinApiError(op, 6)
            return 1

    fake = FakeOwnApi()
    handle = OwnedHandle(fake, 123, "C:\\MOKOSH_OWN\\stage.bin")
    handle.close()
    handle.close()
    assert fake.calls == [("CloseHandle", 123)]
    assert handle.closed is True and handle.close_uncertain is False
    records.append({"name": "own_close_single_mock_call_idempotent_no_native_credit", "matched": True})
    fake = FakeOwnApi(fail=True)
    handle = OwnedHandle(fake, 456, "C:\\MOKOSH_OWN\\stage.bin")
    try:
        handle.close()
    except WinApiError as exc:
        assert exc.code == 6
    else:
        raise AssertionError("mock close failure accepted")
    assert handle.closed and handle.close_uncertain and handle._value is None
    try:
        handle.close()
    except RuntimeError:
        pass
    else:
        raise AssertionError("uncertain close was accepted again")
    assert fake.calls == [("CloseHandle", 456)]
    records.append({"name": "mock_failed_own_close_retires_authority_without_retry", "matched": True})
    for code in [0, False, True, -1]:
        try:
            WinApiError("MockCall", code)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("invalid native error code accepted")
    records.append({"name": "zero_boolean_negative_native_error_rejected", "matched": True})
    actual = runtime_metadata()
    if runtime_rejection_reasons(actual):
        try:
            WindowsFileApi()
        except RuntimeError:
            pass
        else:
            raise AssertionError("actual incompatible host entered native backend")
        records.append({"name": "actual_incompatible_host_refused_before_DLL_load", "matched": True})
    return {"scope": "PORTABLE_GUARDS_AND_MOCK_OWN_LIFETIME_NOT_NATIVE",
        "count": len(records), "records": records, "native_cases": 0,
        "Windows_acceptance": False, "actual_host": actual}
