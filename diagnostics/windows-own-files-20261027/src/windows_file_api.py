"""Limited own-file Win32 bindings for the frozen seven-case laboratory probe.

Importing this module performs no Win32 load or file operation.  It is not a
MOKOSH backend and does not assert native execution or application acceptance.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import platform
import struct
import sys


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
OWNER_ACCESS = GENERIC_READ | GENERIC_WRITE | DELETE
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_RENAME_INFO_CLASS = 3
FILE_DISPOSITION_INFO_CLASS = 4
DRIVE_FIXED = 3
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800
MAX_IO = 4096
MAX_PATH_UTF16_UNITS = 240
RENAME_FILENAME_OFFSET = 20

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_LPDWORD = ctypes.POINTER(_DWORD)
_LPWSTR = ctypes.POINTER(ctypes.c_wchar)


class _FileTime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _ByHandleInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", _DWORD),
        ("creation", _FileTime),
        ("access", _FileTime),
        ("write", _FileTime),
        ("volume_serial", _DWORD),
        ("size_high", _DWORD),
        ("size_low", _DWORD),
        ("links", _DWORD),
        ("index_high", _DWORD),
        ("index_low", _DWORD),
    ]


class _RenameLayout(ctypes.Structure):
    # SDK modern union occupies one DWORD, followed by natural x64 padding.
    _fields_ = [
        ("flags", _DWORD),
        ("root_directory", _HANDLE),
        ("filename_length", _DWORD),
        ("filename", ctypes.c_uint16 * 1),
    ]


def layout_metadata() -> dict:
    """Pure layout facts; these do not execute a Windows API."""
    return {
        "pointer_bytes": ctypes.sizeof(_HANDLE),
        "DWORD_bytes": ctypes.sizeof(_DWORD),
        "BOOL_bytes": ctypes.sizeof(_BOOL),
        "rename_size": ctypes.sizeof(_RenameLayout),
        "rename_root_offset": _RenameLayout.root_directory.offset,
        "rename_length_offset": _RenameLayout.filename_length.offset,
        "rename_filename_offset": _RenameLayout.filename.offset,
        "identity_size": ctypes.sizeof(_ByHandleInformation),
        "identity_volume_offset": _ByHandleInformation.volume_serial.offset,
        "identity_index_high_offset": _ByHandleInformation.index_high.offset,
        "identity_index_low_offset": _ByHandleInformation.index_low.offset,
    }


def runtime_metadata() -> dict:
    """Describe the actual interpreter; no file/process-security operation."""
    return {
        "os_name": os.name,
        "sys_platform": sys.platform,
        "system": platform.system(),
        "windows_release": platform.release(),
        "windows_version": platform.version(),
        "machine": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_major_minor": list(sys.version_info[:2]),
        "python_version": sys.version,
        "pointer_bytes": ctypes.sizeof(ctypes.c_void_p),
        "wchar_bytes": ctypes.sizeof(ctypes.c_wchar),
        "isolated": bool(sys.flags.isolated),
        "dont_write_bytecode": bool(sys.dont_write_bytecode),
        "optimize": sys.flags.optimize,
        "rights": "NOT_COLLECTED",
    }


def runtime_rejection_reasons(metadata: dict) -> list[str]:
    """Pure eligibility evaluation.  Supplying data never enables DLL loading."""
    if type(metadata) is not dict:
        return ["runtime metadata is not a dict"]
    expected = {
        "os_name": "nt",
        "sys_platform": "win32",
        "system": "Windows",
        "python_implementation": "CPython",
        "python_major_minor": [3, 12],
        "pointer_bytes": 8,
        "wchar_bytes": 2,
        "isolated": True,
        "dont_write_bytecode": True,
        "optimize": 0,
    }
    reasons = []
    for name, wanted in expected.items():
        value = metadata.get(name)
        if type(value) is not type(wanted) or value != wanted:
            reasons.append("unexpected runtime " + name)
    version = metadata.get("python_major_minor")
    if type(version) is list and any(type(x) is not int for x in version):
        reasons.append("noninteger Python version component")
    machine = metadata.get("machine")
    if type(machine) is not str or machine.upper() not in {"AMD64", "X86_64"}:
        reasons.append("unexpected runtime machine")
    return reasons


def _absolute_path(path: str) -> str:
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("expected a nonempty plain path string")
    encoded = path.encode("utf-16-le", errors="strict")
    if len(encoded) // 2 > MAX_PATH_UTF16_UNITS:
        raise ValueError("own-file path exceeds the probe bound")
    drive, tail = ntpath.splitdrive(path)
    if (
        len(drive) != 2
        or drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        or drive[1] != ":"
        or not tail.startswith("\\")
        or "/" in tail
        or ":" in tail
        or any(ord(ch) < 32 for ch in path)
    ):
        raise ValueError("expected an absolute local-drive Win32 path")
    parts = tail.split("\\")[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update("COM" + str(i) for i in range(1, 10))
    reserved.update("LPT" + str(i) for i in range(1, 10))
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or part.endswith((".", " "))
            or any(ch in '<>"|?*' for ch in part)
            or part.split(".", 1)[0].upper() in reserved
        ):
            raise ValueError("unsupported Win32 path component")
    return path


def pack_rename_info(absolute_target: str) -> bytes:
    """Pure x64 FILE_RENAME_INFO buffer, no replace and RootDirectory=NULL."""
    target = _absolute_path(absolute_target)
    name = target.encode("utf-16-le", errors="strict")
    buffer = bytearray(max(24, RENAME_FILENAME_OFFSET + len(name) + 2))
    # Union slot, HANDLE and every padding byte remain zero.
    struct.pack_into("<I", buffer, 16, len(name))
    buffer[RENAME_FILENAME_OFFSET : RENAME_FILENAME_OFFSET + len(name)] = name
    return bytes(buffer)


class WinApiError(OSError):
    """Immediate native failure, retaining the operation and exact error."""

    def __init__(self, operation: str, code: int):
        if type(operation) is not str or type(code) is not int:
            raise TypeError("native error fields require exact str/int")
        if not 1 <= code <= 0xFFFFFFFF:
            raise ValueError("native failure requires an exact nonzero uint32 error")
        self.op = operation
        self.code = code
        super().__init__(code, operation + " failed")


class WindowsFileApi:
    """Guarded Windows x64 API instance; never offers a mock native backend."""

    def __init__(self) -> None:
        self.runtime = runtime_metadata()
        reasons = runtime_rejection_reasons(self.runtime)
        if reasons:
            raise RuntimeError("Windows native probe refused: " + "; ".join(reasons))
        layout = layout_metadata()
        wanted = {
            "pointer_bytes": 8,
            "DWORD_bytes": 4,
            "BOOL_bytes": 4,
            "rename_size": 24,
            "rename_root_offset": 8,
            "rename_length_offset": 16,
            "rename_filename_offset": 20,
            "identity_size": 52,
            "identity_volume_offset": 28,
            "identity_index_high_offset": 44,
            "identity_index_low_offset": 48,
        }
        if layout != wanted:
            raise RuntimeError("Windows native probe refused: ABI layout differs")
        self._dll = ctypes.WinDLL(
            "kernel32.dll", use_last_error=True, winmode=LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        prototypes = {
            "CreateFileW": ([ctypes.c_wchar_p, _DWORD, _DWORD, ctypes.c_void_p, _DWORD, _DWORD, _HANDLE], _HANDLE),
            "ReadFile": ([_HANDLE, ctypes.c_void_p, _DWORD, _LPDWORD, ctypes.c_void_p], _BOOL),
            "WriteFile": ([_HANDLE, ctypes.c_void_p, _DWORD, _LPDWORD, ctypes.c_void_p], _BOOL),
            "SetFilePointerEx": ([_HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), _DWORD], _BOOL),
            "FlushFileBuffers": ([_HANDLE], _BOOL),
            "GetFileInformationByHandle": ([_HANDLE, ctypes.POINTER(_ByHandleInformation)], _BOOL),
            "SetFileInformationByHandle": ([_HANDLE, ctypes.c_int32, ctypes.c_void_p, _DWORD], _BOOL),
            "CloseHandle": ([_HANDLE], _BOOL),
            "DeleteFileW": ([ctypes.c_wchar_p], _BOOL),
            "MoveFileExW": ([ctypes.c_wchar_p, ctypes.c_wchar_p, _DWORD], _BOOL),
            "GetVolumePathNameW": ([ctypes.c_wchar_p, _LPWSTR, _DWORD], _BOOL),
            "GetDriveTypeW": ([ctypes.c_wchar_p], _DWORD),
            "GetVolumeInformationW": ([ctypes.c_wchar_p, _LPWSTR, _DWORD, _LPDWORD, _LPDWORD, _LPDWORD, _LPWSTR, _DWORD], _BOOL),
        }
        for name, (argtypes, restype) in prototypes.items():
            fn = getattr(self._dll, name)
            fn.argtypes = argtypes
            fn.restype = restype

    def _bool(self, operation: str, *args) -> int:
        ctypes.set_last_error(0)
        result = int(getattr(self._dll, operation)(*args))
        if result == 0:
            error = int(ctypes.get_last_error())
            raise WinApiError(operation, error)
        return result

    def open(self, path: str, access: int, share: int, creation: int) -> OwnedHandle:
        path = _absolute_path(path)
        if type(access) is not int or not 0 <= access <= 0xFFFFFFFF:
            raise ValueError("invalid exact uint32 access")
        if type(share) is not int or share not in {0, SHARE_ALL}:
            raise ValueError("unsupported exact sharing mode")
        if type(creation) is not int or creation not in {CREATE_NEW, OPEN_EXISTING}:
            raise ValueError("unsupported exact creation mode")
        ctypes.set_last_error(0)
        value = self._dll.CreateFileW(
            path, access, share, None, creation, FILE_ATTRIBUTE_NORMAL, None
        )
        if value == ctypes.c_void_p(-1).value:
            error = int(ctypes.get_last_error())
            raise WinApiError("CreateFileW", error)
        if value is None or value == 0:
            error = int(ctypes.get_last_error())
            raise WinApiError("CreateFileW_unexpected_null_handle", error)
        return OwnedHandle(self, value, path)

    def delete_file(self, path: str) -> None:
        self._bool("DeleteFileW", _absolute_path(path))

    def move_file(self, source: str, target: str) -> None:
        source = _absolute_path(source)
        target = _absolute_path(target)
        if ntpath.dirname(source).casefold() != ntpath.dirname(target).casefold():
            raise ValueError("the probe permits only same-directory moves")
        self._bool("MoveFileExW", source, target, 0)

    def volume_info(self, path: str) -> dict:
        """Three prerequisite queries; each successful subcall is explicit."""
        path = _absolute_path(path)
        root = ctypes.create_unicode_buffer(261)
        self._bool("GetVolumePathNameW", path, root, len(root))
        root_path = root.value
        _absolute_path(root_path)
        if not root_path.endswith("\\"):
            raise RuntimeError("volume root lacks required trailing backslash")
        ctypes.set_last_error(0)
        drive_type = int(self._dll.GetDriveTypeW(root_path))
        # This return is a category, not BOOL; do not invent a GetLastError.
        fs_name = ctypes.create_unicode_buffer(261)
        serial = _DWORD()
        maximum_component = _DWORD()
        flags = _DWORD()
        self._bool(
            "GetVolumeInformationW", root_path, None, 0,
            ctypes.byref(serial), ctypes.byref(maximum_component),
            ctypes.byref(flags), fs_name, len(fs_name),
        )
        return {
            "root": root_path,
            "drive_type": drive_type,
            "fs_name": fs_name.value,
            "serial": int(serial.value),
            "maximum_component_length": int(maximum_component.value),
            "filesystem_flags": int(flags.value),
            "prerequisite_calls": [
                {"operation": "GetVolumePathNameW", "success": True, "winerror": 0},
                {"operation": "GetDriveTypeW", "return_category": drive_type},
                {"operation": "GetVolumeInformationW", "success": True, "winerror": 0},
            ],
            "result_form": "CHECKED_NORMALIZED_SUCCESS_NOT_RAW_BOOL_ONE",
        }


class OwnedHandle:
    """One newly acquired own file handle; no destructor or close retry."""

    def __init__(self, api: WindowsFileApi, value: int, path: str) -> None:
        self._api = api
        self._value = value
        self.path = path
        self.closed = False
        self.close_uncertain = False
        self._renamed = False
        self._delete_marked = False

    def _handle(self) -> int:
        if self.closed or self._value is None:
            raise RuntimeError("owned numeric handle authority is retired")
        return self._value

    def read(self, limit: int) -> bytes:
        if type(limit) is not int or not 1 <= limit <= MAX_IO:
            raise ValueError("read limit must be an exact bounded positive int")
        handle = self._handle()
        buffer = ctypes.create_string_buffer(limit)
        count = _DWORD()
        self._api._bool("ReadFile", handle, buffer, limit, ctypes.byref(count), None)
        if count.value > limit:
            raise RuntimeError("ReadFile reported an oversized transfer")
        return bytes(buffer.raw[: count.value])

    def write(self, data: bytes) -> int:
        if type(data) is not bytes or not 1 <= len(data) <= MAX_IO:
            raise ValueError("write requires exact bounded nonempty bytes")
        handle = self._handle()
        buffer = ctypes.create_string_buffer(data, len(data))
        count = _DWORD()
        self._api._bool(
            "WriteFile", handle, buffer, len(data), ctypes.byref(count), None
        )
        if not 1 <= count.value <= len(data):
            raise RuntimeError("WriteFile reported invalid progress")
        return int(count.value)

    def seek(self, offset: int) -> None:
        if type(offset) is not int or not 0 <= offset <= MAX_IO:
            raise ValueError("seek requires an exact bounded nonnegative int")
        result = ctypes.c_int64()
        self._api._bool(
            "SetFilePointerEx", self._handle(), offset, ctypes.byref(result), 0
        )
        if result.value != offset:
            raise RuntimeError("SetFilePointerEx returned an unexpected position")

    def flush(self) -> None:
        self._api._bool("FlushFileBuffers", self._handle())

    def identity(self) -> dict:
        info = _ByHandleInformation()
        self._api._bool(
            "GetFileInformationByHandle", self._handle(), ctypes.byref(info)
        )
        attributes = int(info.attributes)
        if attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            raise RuntimeError("owned fixture is a directory or reparse object")
        return {
            "volume_serial": int(info.volume_serial),
            "file_index": (int(info.index_high) << 32) | int(info.index_low),
            "links": int(info.links),
            "size": (int(info.size_high) << 32) | int(info.size_low),
            "attributes": attributes,
        }

    def rename(self, absolute_target: str) -> None:
        handle = self._handle()
        target = _absolute_path(absolute_target)
        if self._renamed or self._delete_marked:
            raise RuntimeError("probe fixture already renamed or marked for deletion")
        if ntpath.dirname(self.path).casefold() != ntpath.dirname(target).casefold():
            raise ValueError("the probe permits only same-directory rename")
        packed = pack_rename_info(target)
        buffer = ctypes.create_string_buffer(packed, len(packed))
        self._api._bool(
            "SetFileInformationByHandle", handle,
            FILE_RENAME_INFO_CLASS, buffer, len(packed),
        )
        self.path = target
        self._renamed = True

    def mark_delete(self) -> None:
        handle = self._handle()
        if self._renamed or self._delete_marked:
            raise RuntimeError("only an unpublished unmarked probe stage may be discarded")
        marker = ctypes.c_uint8(1)
        self._api._bool(
            "SetFileInformationByHandle", handle,
            FILE_DISPOSITION_INFO_CLASS, ctypes.byref(marker), 1,
        )
        self._delete_marked = True

    def close(self) -> None:
        if self.closed:
            if self.close_uncertain:
                raise RuntimeError("previous close was uncertain; numeric handle will not be retried")
            return
        value = self._handle()
        self._value = None
        self.closed = True
        self.close_uncertain = True
        self._api._bool("CloseHandle", value)
        self.close_uncertain = False
