"""Strict non-secret crash journal codec for MOKOSH v2 quarantine files.

The record binds one random operation identifier to one parent directory and
one temporary inode.  It deliberately contains no source path, output path,
file name, content size, key, credential, contact, or plaintext metadata.

A structurally valid record is evidence for read-only reconciliation only.  It
does not prove that an operation is abandoned and never authorizes deletion,
publication, decryption, or recovery.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from mokosh_v2_format import V2FormatError


JOURNAL_FORMAT = "MOKOSH-OPJ"
JOURNAL_VERSION = 1
OPERATION_ID_BYTES = 16
OPERATION_ID_HEX_LEN = OPERATION_ID_BYTES * 2
TEMP_NAME_PREFIX = ".mokosh-quarantine-"
JOURNAL_NAME_PREFIX = ".mokosh-operation-"
JOURNAL_NAME_SUFFIX = ".json"
MAX_JOURNAL_SIZE = 2048
PRIVATE_FILE_MODE = 0o600
MAX_UINT64 = (1 << 64) - 1
MAX_UINT32 = (1 << 32) - 1

_OPERATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FIELDS = frozenset(
    {
        "format",
        "version",
        "operation_id",
        "temporary_name",
        "parent_device",
        "parent_inode",
        "temp_device",
        "temp_inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "initial_links",
    }
)


class OperationJournalError(V2FormatError):
    """The operation journal is malformed, ambiguous, or unsupported."""


@dataclass(frozen=True, slots=True)
class OperationJournalRecord:
    format: str
    version: int
    operation_id: str
    temporary_name: str
    parent_device: int
    parent_inode: int
    temp_device: int
    temp_inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    initial_links: int


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OperationJournalError("duplicate operation journal field")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise OperationJournalError(f"non-standard JSON constant is forbidden: {value}")


def _require_uint(value: Any, field: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise OperationJournalError(f"{field} must be a bounded unsigned integer")
    return value


def validate_operation_id(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION_ID_RE.fullmatch(value) is None:
        raise OperationJournalError("operation_id must be 32 lowercase hex characters")
    return value


def temporary_name_for(operation_id: str) -> str:
    return TEMP_NAME_PREFIX + validate_operation_id(operation_id)


def journal_name_for(operation_id: str) -> str:
    return (
        JOURNAL_NAME_PREFIX
        + validate_operation_id(operation_id)
        + JOURNAL_NAME_SUFFIX
    )


def operation_id_from_journal_name(name: Any) -> str:
    if not isinstance(name, str):
        raise OperationJournalError("journal name must be text")
    if not name.startswith(JOURNAL_NAME_PREFIX) or not name.endswith(
        JOURNAL_NAME_SUFFIX
    ):
        raise OperationJournalError("journal name has an invalid envelope")
    operation_id = name[
        len(JOURNAL_NAME_PREFIX) : -len(JOURNAL_NAME_SUFFIX)
    ]
    validate_operation_id(operation_id)
    if journal_name_for(operation_id) != name:
        raise OperationJournalError("journal name is not canonical")
    return operation_id


def operation_id_from_temporary_name(name: Any) -> str:
    if not isinstance(name, str) or not name.startswith(TEMP_NAME_PREFIX):
        raise OperationJournalError("temporary name has an invalid prefix")
    operation_id = name[len(TEMP_NAME_PREFIX) :]
    validate_operation_id(operation_id)
    if temporary_name_for(operation_id) != name:
        raise OperationJournalError("temporary name is not canonical")
    return operation_id


def build_operation_journal(
    *,
    operation_id: str,
    parent_device: int,
    parent_inode: int,
    temp_device: int,
    temp_inode: int,
    owner_uid: int,
    owner_gid: int,
) -> OperationJournalRecord:
    exact_id = validate_operation_id(operation_id)
    record = OperationJournalRecord(
        format=JOURNAL_FORMAT,
        version=JOURNAL_VERSION,
        operation_id=exact_id,
        temporary_name=temporary_name_for(exact_id),
        parent_device=parent_device,
        parent_inode=parent_inode,
        temp_device=temp_device,
        temp_inode=temp_inode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=PRIVATE_FILE_MODE,
        initial_links=1,
    )
    validate_operation_journal(record)
    return record


def validate_operation_journal(value: Any) -> OperationJournalRecord:
    if not isinstance(value, OperationJournalRecord):
        raise OperationJournalError("operation journal record type is invalid")
    if value.format != JOURNAL_FORMAT:
        raise OperationJournalError("operation journal format is unsupported")
    if type(value.version) is not int or value.version != JOURNAL_VERSION:
        raise OperationJournalError("operation journal format or version is unsupported")
    operation_id = validate_operation_id(value.operation_id)
    if value.temporary_name != temporary_name_for(operation_id):
        raise OperationJournalError("temporary name is not bound to operation_id")
    _require_uint(value.parent_device, "parent_device", MAX_UINT64)
    _require_uint(value.parent_inode, "parent_inode", MAX_UINT64)
    _require_uint(value.temp_device, "temp_device", MAX_UINT64)
    _require_uint(value.temp_inode, "temp_inode", MAX_UINT64)
    _require_uint(value.owner_uid, "owner_uid", MAX_UINT32)
    _require_uint(value.owner_gid, "owner_gid", MAX_UINT32)
    if type(value.mode) is not int or value.mode != PRIVATE_FILE_MODE:
        raise OperationJournalError("operation journal mode policy is invalid")
    if type(value.initial_links) is not int or value.initial_links != 1:
        raise OperationJournalError("operation journal file policy is invalid")
    return value


def encode_operation_journal(value: OperationJournalRecord) -> bytes:
    record = validate_operation_journal(value)
    encoded = json.dumps(
        asdict(record),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > MAX_JOURNAL_SIZE:
        raise OperationJournalError("operation journal exceeds its size limit")
    return encoded


def decode_operation_journal(data: Any) -> OperationJournalRecord:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise OperationJournalError("operation journal must be bytes")
    exact = bytes(data)
    if not exact or len(exact) > MAX_JOURNAL_SIZE:
        raise OperationJournalError("operation journal size is invalid")
    try:
        decoded = json.loads(
            exact.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationJournalError("operation journal is not strict JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) != _FIELDS:
        raise OperationJournalError("operation journal fields are not exact")
    record = OperationJournalRecord(**decoded)
    validate_operation_journal(record)
    if encode_operation_journal(record) != exact:
        raise OperationJournalError("operation journal encoding is not canonical")
    return record
