"""Strict in-memory MOKOSH Vault wrapping-key lifecycle.

The keyring keeps independently generated 32-byte roots used by the existing
HKDF/AES-GCM Key Vault file slots.  It performs no password KDF, Vault
container encryption, path I/O, network access, logging, key deletion, or
automatic file re-encryption.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from mokosh_v2_key_slots import KeyVaultSlot
from mokosh_v2_vault_slots import create_vault_slot, unwrap_vault_slot


KEYRING_FORMAT_NAME = "MOKOSH_VAULT_KEYRING"
KEYRING_SCHEMA = 1
KEYRING_PURPOSE = "MOKOSH_V2_KEY_VAULT_SLOT"
KEYRING_ALGORITHM = "HKDF-SHA-256+AES-256-GCM"
KEY_STATE_ACTIVE = "active"
KEY_STATE_RETIRED = "retired"

WRAPPING_KEY_LEN = 32
MAX_KEY_VERSION = 0xFFFFFFFF
MAX_KEY_RECORDS = 4096
MAX_ENCODED_KEYRING_LEN = 768 * 1024

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_KEYRING_FIELDS = frozenset(
    {
        "active_key_version",
        "algorithm",
        "format",
        "keys",
        "purpose",
        "version",
    }
)
_KEY_RECORD_FIELDS = frozenset(
    {"created_utc", "key_version", "retired_utc", "state", "wrapping_key"}
)


class VaultKeyringError(ValueError):
    """Base class for strict keyring failures."""


class VaultKeyringFormatError(VaultKeyringError):
    """A keyring record is malformed, ambiguous, or non-canonical."""


class VaultKeyringDuplicateKeyError(VaultKeyringFormatError):
    """Strict keyring JSON contains a duplicate object key."""


class VaultKeyringPolicyError(VaultKeyringError):
    """A lifecycle transition or resource bound is not permitted."""


class VaultKeyVersionNotFoundError(VaultKeyringError):
    """The explicitly requested wrapping-key version does not exist."""


class VaultKeyUsageError(VaultKeyringError):
    """A wrapping key is requested for a purpose its state does not allow."""


@dataclass(frozen=True, slots=True)
class VaultKeyRecord:
    key_version: int
    state: str
    created_utc: str
    retired_utc: str | None
    wrapping_key: bytes = field(repr=False)

    def __copy__(self) -> None:
        raise TypeError("VaultKeyRecord cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultKeyRecord cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultKeyRecord cannot be pickled")


@dataclass(frozen=True, slots=True)
class VaultKeyring:
    active_key_version: int
    keys: tuple[VaultKeyRecord, ...]

    def __copy__(self) -> None:
        raise TypeError("VaultKeyring cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultKeyring cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultKeyring cannot be pickled")


def _plain_uint32(value: Any, field_name: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_KEY_VERSION:
        raise VaultKeyringFormatError(f"{field_name} must be a positive uint32")
    return value


def _exact_key(value: Any, field_name: str = "wrapping_key") -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultKeyringFormatError(f"{field_name} must be bytes")
    result = bytes(value)
    if len(result) != WRAPPING_KEY_LEN:
        raise VaultKeyringFormatError(
            f"{field_name} must contain exactly {WRAPPING_KEY_LEN} bytes"
        )
    return result


def _random_key() -> bytes:
    result = os.urandom(WRAPPING_KEY_LEN)
    if not isinstance(result, bytes) or len(result) != WRAPPING_KEY_LEN:
        raise VaultKeyringPolicyError(
            "secure random source returned an invalid wrapping key"
        )
    return result


def _strict_utc(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise VaultKeyringFormatError(
            f"{field_name} must be strict UTC text ending in Z"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise VaultKeyringFormatError(
            f"{field_name} is not a valid UTC timestamp"
        ) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise VaultKeyringFormatError(f"{field_name} is not canonical UTC")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode_key(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise VaultKeyringFormatError(
            "wrapping_key must be unpadded base64url text"
        )
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        result = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultKeyringFormatError("wrapping_key is invalid base64url") from exc
    if len(result) != WRAPPING_KEY_LEN or _b64encode(result) != value:
        raise VaultKeyringFormatError(
            f"wrapping_key must canonically encode {WRAPPING_KEY_LEN} bytes"
        )
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VaultKeyringDuplicateKeyError(
                f"duplicate keyring JSON key: {key}"
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VaultKeyringFormatError(
        f"non-standard keyring JSON constant is forbidden: {value}"
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VaultKeyringFormatError(
            "keyring cannot be canonically encoded"
        ) from exc


def validate_keyring(keyring: VaultKeyring) -> None:
    if not isinstance(keyring, VaultKeyring):
        raise VaultKeyringFormatError("keyring must be VaultKeyring")
    active_version = _plain_uint32(
        keyring.active_key_version, "active_key_version"
    )
    if type(keyring.keys) is not tuple:
        raise VaultKeyringFormatError("keys must be a tuple")
    if not 1 <= len(keyring.keys) <= MAX_KEY_RECORDS:
        raise VaultKeyringPolicyError(
            f"keyring must contain 1 to {MAX_KEY_RECORDS} records"
        )

    seen_material: set[bytes] = set()
    for index, record in enumerate(keyring.keys, start=1):
        if not isinstance(record, VaultKeyRecord):
            raise VaultKeyringFormatError("keys must contain VaultKeyRecord objects")
        version = _plain_uint32(record.key_version, "key_version")
        if version != index:
            raise VaultKeyringFormatError(
                "key versions must be ordered, contiguous, and start at one"
            )
        if record.state not in {KEY_STATE_ACTIVE, KEY_STATE_RETIRED}:
            raise VaultKeyringFormatError("key state is unsupported")
        created = _strict_utc(record.created_utc, "created_utc")
        material = _exact_key(record.wrapping_key)
        if material in seen_material:
            raise VaultKeyringFormatError(
                "wrapping-key material must be unique across versions"
            )
        seen_material.add(material)

        is_last = index == len(keyring.keys)
        if is_last:
            if record.state != KEY_STATE_ACTIVE or record.retired_utc is not None:
                raise VaultKeyringFormatError(
                    "the highest key version must be the sole active key"
                )
        else:
            if record.state != KEY_STATE_RETIRED:
                raise VaultKeyringFormatError(
                    "every older key version must be retired"
                )
            retired = _strict_utc(record.retired_utc, "retired_utc")
            next_created = _strict_utc(
                keyring.keys[index].created_utc, "next created_utc"
            )
            if retired < created or retired != next_created:
                raise VaultKeyringFormatError(
                    "retirement must exactly match the next key activation"
                )

    if active_version != keyring.keys[-1].key_version:
        raise VaultKeyringFormatError(
            "active_key_version must identify the highest key version"
        )


def _record_to_mapping(record: VaultKeyRecord) -> dict[str, Any]:
    return {
        "created_utc": record.created_utc,
        "key_version": record.key_version,
        "retired_utc": record.retired_utc,
        "state": record.state,
        "wrapping_key": _b64encode(record.wrapping_key),
    }


def keyring_to_mapping(keyring: VaultKeyring) -> dict[str, Any]:
    validate_keyring(keyring)
    return {
        "active_key_version": keyring.active_key_version,
        "algorithm": KEYRING_ALGORITHM,
        "format": KEYRING_FORMAT_NAME,
        "keys": [_record_to_mapping(record) for record in keyring.keys],
        "purpose": KEYRING_PURPOSE,
        "version": KEYRING_SCHEMA,
    }


def encode_keyring(keyring: VaultKeyring) -> bytes:
    encoded = _canonical_json(keyring_to_mapping(keyring))
    if not 1 <= len(encoded) <= MAX_ENCODED_KEYRING_LEN:
        raise VaultKeyringPolicyError("encoded keyring exceeds its bound")
    return encoded


def _record_from_mapping(value: Any) -> VaultKeyRecord:
    if not isinstance(value, dict) or set(value) != _KEY_RECORD_FIELDS:
        raise VaultKeyringFormatError(
            "key record fields are missing or unsupported"
        )
    state = value["state"]
    if not isinstance(state, str):
        raise VaultKeyringFormatError("key state must be text")
    retired = value["retired_utc"]
    if retired is not None and not isinstance(retired, str):
        raise VaultKeyringFormatError("retired_utc must be text or null")
    return VaultKeyRecord(
        key_version=_plain_uint32(value["key_version"], "key_version"),
        state=state,
        created_utc=_strict_utc(value["created_utc"], "created_utc"),
        retired_utc=retired,
        wrapping_key=_b64decode_key(value["wrapping_key"]),
    )


def keyring_from_mapping(value: Any) -> VaultKeyring:
    if not isinstance(value, dict) or set(value) != _KEYRING_FIELDS:
        raise VaultKeyringFormatError(
            "keyring fields are missing or unsupported"
        )
    if value["format"] != KEYRING_FORMAT_NAME:
        raise VaultKeyringFormatError("keyring format is invalid")
    if type(value["version"]) is not int or value["version"] != KEYRING_SCHEMA:
        raise VaultKeyringFormatError("keyring schema is unsupported")
    if value["purpose"] != KEYRING_PURPOSE:
        raise VaultKeyringFormatError("keyring purpose is unsupported")
    if value["algorithm"] != KEYRING_ALGORITHM:
        raise VaultKeyringFormatError("keyring algorithm is unsupported")
    raw_keys = value["keys"]
    if not isinstance(raw_keys, list):
        raise VaultKeyringFormatError("keys must be a JSON array")
    if not 1 <= len(raw_keys) <= MAX_KEY_RECORDS:
        raise VaultKeyringPolicyError(
            f"keyring must contain 1 to {MAX_KEY_RECORDS} records"
        )
    result = VaultKeyring(
        active_key_version=_plain_uint32(
            value["active_key_version"], "active_key_version"
        ),
        keys=tuple(_record_from_mapping(item) for item in raw_keys),
    )
    validate_keyring(result)
    return result


def parse_keyring(data: bytes | bytearray | memoryview) -> VaultKeyring:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise VaultKeyringFormatError("keyring input must be bytes")
    encoded = bytes(data)
    if not 1 <= len(encoded) <= MAX_ENCODED_KEYRING_LEN:
        raise VaultKeyringPolicyError("encoded keyring exceeds its bound")
    try:
        text = encoded.decode("utf-8", errors="strict")
        mapping = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise VaultKeyringFormatError("keyring is not valid UTF-8") from exc
    except VaultKeyringError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VaultKeyringFormatError("keyring is not strict bounded JSON") from exc
    result = keyring_from_mapping(mapping)
    if _canonical_json(mapping) != encoded:
        raise VaultKeyringFormatError("keyring is not canonical JSON")
    return result


def create_keyring(*, created_utc: str | None = None) -> VaultKeyring:
    timestamp = _strict_utc(created_utc or utc_now(), "created_utc")
    result = VaultKeyring(
        active_key_version=1,
        keys=(
            VaultKeyRecord(
                key_version=1,
                state=KEY_STATE_ACTIVE,
                created_utc=timestamp,
                retired_utc=None,
                wrapping_key=_random_key(),
            ),
        ),
    )
    validate_keyring(result)
    return result


def keyring_from_legacy_key(
    legacy_key: bytes | bytearray | memoryview,
    *,
    created_utc: str,
) -> VaultKeyring:
    """Explicitly preserve one legacy root as key version one."""

    timestamp = _strict_utc(created_utc, "created_utc")
    result = VaultKeyring(
        active_key_version=1,
        keys=(
            VaultKeyRecord(
                key_version=1,
                state=KEY_STATE_ACTIVE,
                created_utc=timestamp,
                retired_utc=None,
                wrapping_key=_exact_key(legacy_key, "legacy_key"),
            ),
        ),
    )
    validate_keyring(result)
    return result


def rotate_keyring(
    keyring: VaultKeyring,
    *,
    rotated_utc: str | None = None,
) -> VaultKeyring:
    """Retire the active version and append one independent random key."""

    validate_keyring(keyring)
    if len(keyring.keys) >= MAX_KEY_RECORDS:
        raise VaultKeyringPolicyError("keyring record limit is exhausted")
    if keyring.active_key_version >= MAX_KEY_VERSION:
        raise VaultKeyringPolicyError("key version counter is exhausted")
    timestamp = _strict_utc(rotated_utc or utc_now(), "rotated_utc")
    active = keyring.keys[-1]
    if timestamp < active.created_utc:
        raise VaultKeyringPolicyError("rotation time must not move backwards")

    new_key = _random_key()
    if any(record.wrapping_key == new_key for record in keyring.keys):
        raise VaultKeyringPolicyError(
            "secure random source repeated existing wrapping-key material"
        )
    retired = VaultKeyRecord(
        key_version=active.key_version,
        state=KEY_STATE_RETIRED,
        created_utc=active.created_utc,
        retired_utc=timestamp,
        wrapping_key=active.wrapping_key,
    )
    new_version = active.key_version + 1
    replacement = VaultKeyRecord(
        key_version=new_version,
        state=KEY_STATE_ACTIVE,
        created_utc=timestamp,
        retired_utc=None,
        wrapping_key=new_key,
    )
    result = VaultKeyring(
        active_key_version=new_version,
        keys=keyring.keys[:-1] + (retired, replacement),
    )
    validate_keyring(result)
    return result


def active_key_record(keyring: VaultKeyring) -> VaultKeyRecord:
    validate_keyring(keyring)
    record = keyring.keys[-1]
    if record.state != KEY_STATE_ACTIVE:
        raise VaultKeyUsageError("active wrapping key is unavailable")
    return record


def key_record_for_decryption(
    keyring: VaultKeyring,
    key_version: int,
) -> VaultKeyRecord:
    """Select exactly one version; never search or fall back after failure."""

    validate_keyring(keyring)
    version = _plain_uint32(key_version, "key_version")
    if version > len(keyring.keys):
        raise VaultKeyVersionNotFoundError(
            "requested wrapping-key version is unavailable"
        )
    record = keyring.keys[version - 1]
    if record.key_version != version:
        raise VaultKeyVersionNotFoundError(
            "requested wrapping-key version is unavailable"
        )
    return record


def create_vault_slot_for_keyring(
    keyring: VaultKeyring,
    dek: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
) -> KeyVaultSlot:
    """Create a file slot with only the sole active key version."""

    active = active_key_record(keyring)
    return create_vault_slot(
        active.wrapping_key,
        active.key_version,
        dek,
        file_id,
    )


def unwrap_vault_slot_for_keyring(
    keyring: VaultKeyring,
    slot: KeyVaultSlot,
    file_id: bytes | bytearray | memoryview,
) -> bytes:
    """Unwrap with the slot's exact version and with no automatic fallback."""

    if not isinstance(slot, KeyVaultSlot):
        raise VaultKeyUsageError("slot must be KeyVaultSlot")
    record = key_record_for_decryption(keyring, slot.vault_key_version)
    return unwrap_vault_slot(slot, record.wrapping_key, file_id)
