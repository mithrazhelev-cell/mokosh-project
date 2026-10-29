"""Small guarded Darwin binding; importing does not load libSystem.

RENAME_EXCL is a no-clobber name operation, not a source-file-descriptor
publication API.  The class is only used on the collector's fresh own files.
"""

from __future__ import annotations

import ctypes
import os
import platform
import stat
import sys


RENAME_EXCL = 4
MAX_IO = 4096
LIBSYSTEM_PATH = "/usr/lib/libSystem.B.dylib"
LEAVES = frozenset({
    "stage.bin", "published.bin", "published-Δ-Ж.bin", "original.bin", "control.bin"
})
FLAG_NAMES = (
    "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_NOFOLLOW",
    "O_CLOEXEC", "O_DIRECTORY",
)
DARWIN_FLAG_VALUES = {
    "O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2, "O_NOFOLLOW": 0x100,
    "O_CREAT": 0x200, "O_EXCL": 0x800, "O_DIRECTORY": 0x100000,
    "O_CLOEXEC": 0x1000000,
}
OPEN_FLAG_NAMES = {
    "open_dir": ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"),
    "create": ("O_RDWR", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC"),
    "open_read": ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC"),
    "open_write": ("O_WRONLY", "O_NOFOLLOW", "O_CLOEXEC"),
}


def runtime_metadata() -> dict:
    """Actual interpreter metadata, without loading a foreign native library."""
    return {
        "system": platform.system(),
        "sys_platform": sys.platform,
        "os_name": os.name,
        "implementation": platform.python_implementation(),
        "python_minor": list(sys.version_info[:2]),
        "python_version": list(sys.version_info[:3]),
        "python_version_text": sys.version,
        "macos_version": platform.mac_ver()[0],
        "kernel_release": platform.release(),
        "kernel_version": platform.version(),
        "machine": platform.machine(),
        "pointer_bytes": ctypes.sizeof(ctypes.c_void_p),
        "int_bytes": ctypes.sizeof(ctypes.c_int),
        "uint_bytes": ctypes.sizeof(ctypes.c_uint),
        "isolated": bool(sys.flags.isolated),
        "dont_write_bytecode": bool(sys.dont_write_bytecode),
        "optimize": sys.flags.optimize,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "flag_values": {name: getattr(os, name, None) for name in FLAG_NAMES},
        "dir_fd_support": {
            name: getattr(os, name) in os.supports_dir_fd
            for name in ("open", "stat", "unlink")
        },
        "filesystem_type": "NOT_COLLECTED",
        "volume_metadata": {"filesystem_type": "NOT_COLLECTED", "statvfs": "NOT_COLLECTED"},
        "other_process_rights": "NOT_COLLECTED",
    }


def runtime_rejection_reasons(metadata: dict) -> list[str]:
    """Pure guard. Supplying eligible data does not load a native library."""
    if type(metadata) is not dict:
        return ["runtime is not a dict"]
    expected = {
        "system": "Darwin", "sys_platform": "darwin", "os_name": "posix",
        "implementation": "CPython", "python_minor": [3, 12],
        "pointer_bytes": 8, "int_bytes": 4, "uint_bytes": 4,
        "isolated": True, "dont_write_bytecode": True, "optimize": 0,
    }
    reasons = []
    for key, wanted in expected.items():
        actual = metadata.get(key)
        if type(actual) is not type(wanted) or actual != wanted:
            reasons.append("unexpected runtime " + key)
    minor = metadata.get("python_minor")
    if type(minor) is list and any(type(x) is not int for x in minor):
        reasons.append("noninteger Python version component")
    if metadata.get("machine") not in ("arm64", "x86_64"):
        reasons.append("unexpected runtime machine")
    uid, euid = metadata.get("uid"), metadata.get("euid")
    if type(uid) is not int or type(euid) is not int or uid <= 0 or uid != euid:
        reasons.append("ordinary equal nonzero uid/euid required")
    flags = metadata.get("flag_values")
    if type(flags) is not dict or any(
        type(flags.get(name)) is not int or flags[name] < 0 for name in FLAG_NAMES
    ):
        reasons.append("required exact integer open flags unavailable")
    elif any(flags.get(name) != value for name, value in DARWIN_FLAG_VALUES.items()):
        reasons.append("runtime open flags differ from verified Darwin ABI")
    support = metadata.get("dir_fd_support")
    if type(support) is not dict or any(support.get(n) is not True for n in ("open", "stat", "unlink")):
        reasons.append("required directory-relative operations unavailable")
    return reasons


def checked_leaf(value: str) -> bytes:
    if type(value) is not str or value not in LEAVES:
        raise ValueError("leaf is outside fixed own-file allowlist")
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > 80 or b"/" in encoded or b"\x00" in encoded:
        raise ValueError("invalid own leaf encoding")
    return encoded


def open_flags(operation: str) -> int:
    if operation not in OPEN_FLAG_NAMES:
        raise ValueError("unknown open operation")
    flags = 0
    for name in OPEN_FLAG_NAMES[operation]:
        value = getattr(os, name, None)
        if type(value) is not int or value < 0:
            raise RuntimeError("required open flag unavailable: " + name)
        flags |= value
    return flags


def stat_identity(info: os.stat_result) -> dict:
    """Raw own-object fields, without claiming immutable contents."""
    return {
        "observed_by": "fstat",
        "st_dev": info.st_dev, "st_ino": info.st_ino, "st_size": info.st_size,
        "st_nlink": info.st_nlink, "st_mode": info.st_mode, "st_uid": info.st_uid,
    }


class NativeApiError(OSError):
    def __init__(self, operation: str, code: int):
        if type(operation) is not str or type(code) is not int or not 1 <= code <= 0x7FFFFFFF:
            raise ValueError("native failure requires exact positive errno")
        self.operation = operation
        super().__init__(code, operation + " failed")


class DarwinFileApi:
    """Lazy binding after actual runtime guard; no mocked native constructor."""

    def __init__(self) -> None:
        self.runtime = runtime_metadata()
        reasons = runtime_rejection_reasons(self.runtime)
        if reasons:
            raise RuntimeError("Darwin native probe refused: " + "; ".join(reasons))
        self._library = ctypes.CDLL(LIBSYSTEM_PATH, use_errno=True)
        self._rename = self._library.renameatx_np
        self._rename.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
        ]
        self._rename.restype = ctypes.c_int

    def rename_excl(self, directory_fd: int, old_leaf: str, new_leaf: str) -> int:
        if type(directory_fd) is not int or directory_fd < 0:
            raise ValueError("expected an owned directory descriptor")
        # Checking the descriptor is a directory does not prove every ancestor
        # namespace safe; the collector itself supplies its new own descriptor.
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise ValueError("descriptor is not a directory")
        source, target = checked_leaf(old_leaf), checked_leaf(new_leaf)
        ctypes.set_errno(0)
        result = self._rename(directory_fd, source, directory_fd, target, RENAME_EXCL)
        if result == -1:
            raise NativeApiError("renameatx_np", ctypes.get_errno())
        if result != 0:
            raise RuntimeError("unexpected renameatx_np return")
        return result
