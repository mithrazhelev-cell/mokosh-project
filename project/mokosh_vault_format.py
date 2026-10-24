"""Strict encrypted MOKOSH Key Vault format and in-memory state machine.

The Vault format is deliberately separate from the MOKOSH v2 file envelope.
This module performs bounded in-memory parsing, Argon2id password derivation,
AES-256-GCM authenticated encryption, legacy/keyring payload dispatch,
password rewrap, and explicit session state transitions.  It performs no path
or network I/O and stores no password.
"""

from __future__ import annotations

import base64
import binascii
import enum
import json
import math
import os
import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from mokosh_vault_keyring import (
    VaultKeyring,
    VaultKeyringError,
    create_keyring,
    encode_keyring,
    keyring_from_legacy_key,
    keyring_from_mapping,
    keyring_to_mapping,
    parse_keyring,
    rotate_keyring,
)


VAULT_MAGIC = b"MOKVLT1\x00"
VAULT_MAJOR_VERSION = 1
VAULT_MINOR_VERSION = 0
VAULT_FLAGS = 0
VAULT_PREAMBLE_STRUCT = struct.Struct(">8sBBHII")
VAULT_PREAMBLE_LEN = VAULT_PREAMBLE_STRUCT.size
VAULT_FORMAT_NAME = "MOKOSH_KEY_VAULT"
VAULT_PAYLOAD_NAME = "MOKOSH_VAULT_PAYLOAD"
VAULT_PAYLOAD_SCHEMA = 1
VAULT_KEYRING_PAYLOAD_SCHEMA = 2
SUPPORTED_VAULT_PAYLOAD_SCHEMAS = frozenset(
    {VAULT_PAYLOAD_SCHEMA, VAULT_KEYRING_PAYLOAD_SCHEMA}
)
VAULT_AAD_DOMAIN = b"MOKOSH\x00KEY-VAULT\x00AES-256-GCM\x00"

VAULT_ID_LEN = 16
VAULT_ROOT_KEY_LEN = 32
VAULT_SALT_LEN = 16
VAULT_NONCE_LEN = 12
VAULT_GCM_TAG_LEN = 16
MAX_VAULT_HEADER_LEN = 4096
MAX_VAULT_CIPHERTEXT_LEN = 1024 * 1024
MAX_PASSWORD_UTF8_LEN = 1024
MAX_VAULT_REVISION = (1 << 63) - 1

MIN_ARGON2_TIME_COST = 1
MAX_ARGON2_TIME_COST = 10
MIN_ARGON2_MEMORY_KIB = 8 * 1024
MAX_ARGON2_MEMORY_KIB = 1024 * 1024
MIN_ARGON2_PARALLELISM = 1
MAX_ARGON2_PARALLELISM = 16

DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_MEMORY_KIB = 64 * 1024
DEFAULT_ARGON2_PARALLELISM = 4
DEFAULT_INACTIVITY_TIMEOUT = 300.0

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEADER_FIELDS = frozenset(
    {
        "format",
        "version",
        "vault_id",
        "revision",
        "created_utc",
        "updated_utc",
        "payload_schema",
        "kdf",
        "aead",
    }
)
_KDF_FIELDS = frozenset(
    {"algorithm", "salt", "time_cost", "memory_kib", "parallelism"}
)
_AEAD_FIELDS = frozenset({"algorithm", "nonce"})
_PAYLOAD_FIELDS = frozenset(
    {"format", "version", "vault_id", "revision", "vault_root_key"}
)
_KEYRING_PAYLOAD_FIELDS = frozenset(
    {"format", "version", "vault_id", "revision", "keyring"}
)


class VaultError(ValueError):
    """Base class for strict Vault failures."""


class VaultFormatError(VaultError):
    """The Vault preamble, header, payload, or bounds are invalid."""


class VaultDuplicateKeyError(VaultFormatError):
    """Strict JSON contains a duplicate object key."""


class VaultUnsupportedVersionError(VaultFormatError):
    """The Vault format or payload version is unsupported."""


class VaultMigrationRequiredError(VaultUnsupportedVersionError):
    """A legacy schema needs an explicit, authenticated migration."""


class VaultPolicyError(VaultError):
    """Resource or rollback policy rejects the Vault before KDF work."""


class VaultAuthenticationError(VaultError):
    """The password or authenticated Vault bytes are invalid."""


class VaultStateError(VaultError):
    """An operation is invalid in the current session state."""


@dataclass(frozen=True, slots=True)
class VaultKDFPolicy:
    max_time_cost: int = 5
    max_memory_kib: int = 256 * 1024
    max_parallelism: int = 8


DEFAULT_VAULT_KDF_POLICY = VaultKDFPolicy()


@dataclass(frozen=True, slots=True)
class VaultHeader:
    vault_id: bytes
    revision: int
    created_utc: str
    updated_utc: str
    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int
    nonce: bytes
    payload_schema: int = VAULT_PAYLOAD_SCHEMA


@dataclass(frozen=True, slots=True)
class ParsedVault:
    header: VaultHeader
    preamble_bytes: bytes
    header_bytes: bytes
    ciphertext: bytes

    @property
    def encoded(self) -> bytes:
        return self.preamble_bytes + self.header_bytes + self.ciphertext


class VaultSessionState(enum.Enum):
    LOCKED = "locked"
    UNLOCKING = "unlocking"
    UNLOCKED = "unlocked"
    LOCKING = "locking"
    FAILED = "failed"


def _plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise VaultFormatError(f"{field} must be an integer")
    return value


def _exact_bytes(value: Any, field: str, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultFormatError(f"{field} must be bytes")
    result = bytes(value)
    if len(result) != length:
        raise VaultFormatError(f"{field} must contain exactly {length} bytes")
    return result


def _random_exact(length: int, field: str) -> bytes:
    result = os.urandom(length)
    if not isinstance(result, bytes) or len(result) != length:
        raise VaultError(f"secure random source returned invalid {field}")
    return result


def _password_bytes(password: Any) -> bytes:
    if not isinstance(password, str):
        raise VaultFormatError("password must be text")
    try:
        result = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise VaultFormatError("password must be valid UTF-8 text") from exc
    if not 1 <= len(result) <= MAX_PASSWORD_UTF8_LEN:
        raise VaultFormatError(
            f"password must contain 1 to {MAX_PASSWORD_UTF8_LEN} UTF-8 bytes"
        )
    return result


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: Any, field: str, length: int) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise VaultFormatError(f"{field} must be unpadded base64url text")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        result = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultFormatError(f"{field} is invalid base64url") from exc
    if len(result) != length or _b64encode(result) != value:
        raise VaultFormatError(f"{field} must canonically encode {length} bytes")
    return result


def _strict_utc(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise VaultFormatError(f"{field} must be strict UTC text ending in Z")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise VaultFormatError(f"{field} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise VaultFormatError(f"{field} is not canonical UTC")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VaultDuplicateKeyError(f"duplicate Vault JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VaultFormatError(f"non-standard JSON constant is forbidden: {value}")


def _decode_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        result = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise VaultFormatError(f"{label} is not valid UTF-8") from exc
    except VaultDuplicateKeyError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VaultFormatError(f"{label} is not strict bounded JSON") from exc
    if not isinstance(result, dict):
        raise VaultFormatError(f"{label} must be a JSON object")
    return result


def _canonical_json(value: Mapping[str, Any], label: str) -> bytes:
    try:
        result = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VaultFormatError(f"{label} cannot be canonically encoded") from exc
    return result


def validate_vault_kdf_policy(policy: VaultKDFPolicy) -> None:
    if not isinstance(policy, VaultKDFPolicy):
        raise VaultPolicyError("policy must be VaultKDFPolicy")
    limits = (
        (policy.max_time_cost, "max_time_cost", MIN_ARGON2_TIME_COST, MAX_ARGON2_TIME_COST),
        (policy.max_memory_kib, "max_memory_kib", MIN_ARGON2_MEMORY_KIB, MAX_ARGON2_MEMORY_KIB),
        (policy.max_parallelism, "max_parallelism", MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM),
    )
    for value, field, minimum, maximum in limits:
        if type(value) is not int or not minimum <= value <= maximum:
            raise VaultPolicyError(f"{field} is outside the supported range")


def _validate_kdf_values(
    time_cost: Any,
    memory_kib: Any,
    parallelism: Any,
    *,
    policy: VaultKDFPolicy,
) -> tuple[int, int, int]:
    validate_vault_kdf_policy(policy)
    values = (
        (_plain_int(time_cost, "time_cost"), "time_cost", MIN_ARGON2_TIME_COST, MAX_ARGON2_TIME_COST, policy.max_time_cost),
        (_plain_int(memory_kib, "memory_kib"), "memory_kib", MIN_ARGON2_MEMORY_KIB, MAX_ARGON2_MEMORY_KIB, policy.max_memory_kib),
        (_plain_int(parallelism, "parallelism"), "parallelism", MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM, policy.max_parallelism),
    )
    checked: list[int] = []
    for value, field, minimum, maximum, local_maximum in values:
        if not minimum <= value <= maximum:
            raise VaultFormatError(f"{field} is outside the Vault format range")
        if value > local_maximum:
            raise VaultPolicyError(f"{field} exceeds local KDF policy")
        checked.append(value)
    return checked[0], checked[1], checked[2]


def _header_mapping(header: VaultHeader) -> dict[str, Any]:
    return {
        "aead": {"algorithm": "AES-256-GCM", "nonce": _b64encode(header.nonce)},
        "created_utc": header.created_utc,
        "format": VAULT_FORMAT_NAME,
        "kdf": {
            "algorithm": "Argon2id",
            "memory_kib": header.memory_kib,
            "parallelism": header.parallelism,
            "salt": _b64encode(header.salt),
            "time_cost": header.time_cost,
        },
        "payload_schema": header.payload_schema,
        "revision": header.revision,
        "updated_utc": header.updated_utc,
        "vault_id": _b64encode(header.vault_id),
        "version": VAULT_MAJOR_VERSION,
    }


def _validate_header_mapping(
    value: Mapping[str, Any], *, policy: VaultKDFPolicy
) -> VaultHeader:
    if set(value) != _HEADER_FIELDS:
        raise VaultFormatError("Vault header fields are missing or unsupported")
    if value["format"] != VAULT_FORMAT_NAME:
        raise VaultFormatError("Vault header format is invalid")
    if type(value["version"]) is not int or value["version"] != VAULT_MAJOR_VERSION:
        raise VaultUnsupportedVersionError("Vault header version is unsupported")
    if (
        type(value["payload_schema"]) is not int
        or value["payload_schema"] not in SUPPORTED_VAULT_PAYLOAD_SCHEMAS
    ):
        raise VaultUnsupportedVersionError("Vault payload schema is unsupported")
    revision = _plain_int(value["revision"], "revision")
    if not 1 <= revision <= MAX_VAULT_REVISION:
        raise VaultFormatError("revision is outside the supported range")
    created = _strict_utc(value["created_utc"], "created_utc")
    updated = _strict_utc(value["updated_utc"], "updated_utc")
    if updated < created:
        raise VaultFormatError("updated_utc must not precede created_utc")

    kdf = value["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != _KDF_FIELDS:
        raise VaultFormatError("Vault KDF fields are missing or unsupported")
    if kdf["algorithm"] != "Argon2id":
        raise VaultUnsupportedVersionError("Vault KDF algorithm is unsupported")
    time_cost, memory_kib, parallelism = _validate_kdf_values(
        kdf["time_cost"], kdf["memory_kib"], kdf["parallelism"], policy=policy
    )

    aead = value["aead"]
    if not isinstance(aead, dict) or set(aead) != _AEAD_FIELDS:
        raise VaultFormatError("Vault AEAD fields are missing or unsupported")
    if aead["algorithm"] != "AES-256-GCM":
        raise VaultUnsupportedVersionError("Vault AEAD algorithm is unsupported")
    return VaultHeader(
        vault_id=_b64decode(value["vault_id"], "vault_id", VAULT_ID_LEN),
        revision=revision,
        created_utc=created,
        updated_utc=updated,
        salt=_b64decode(kdf["salt"], "salt", VAULT_SALT_LEN),
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
        nonce=_b64decode(aead["nonce"], "nonce", VAULT_NONCE_LEN),
        payload_schema=value["payload_schema"],
    )


def encode_vault_header(header: VaultHeader, *, policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY) -> bytes:
    if not isinstance(header, VaultHeader):
        raise VaultFormatError("header must be VaultHeader")
    validated = _validate_header_mapping(_header_mapping(header), policy=policy)
    result = _canonical_json(_header_mapping(validated), "Vault header")
    if not 1 <= len(result) <= MAX_VAULT_HEADER_LEN:
        raise VaultFormatError("Vault header exceeds its encoded bound")
    return result


def _legacy_payload_bytes(header: VaultHeader, root_key: bytes) -> bytes:
    mapping = {
        "format": VAULT_PAYLOAD_NAME,
        "revision": header.revision,
        "vault_id": _b64encode(header.vault_id),
        "vault_root_key": _b64encode(root_key),
        "version": VAULT_PAYLOAD_SCHEMA,
    }
    return _canonical_json(mapping, "Vault payload")


def _parse_legacy_payload(data: bytes, header: VaultHeader) -> bytes:
    value = _decode_json(data, "Vault payload")
    if set(value) != _PAYLOAD_FIELDS:
        raise VaultAuthenticationError("authenticated Vault payload is invalid")
    try:
        if value["format"] != VAULT_PAYLOAD_NAME:
            raise VaultFormatError("payload format mismatch")
        if type(value["version"]) is not int or value["version"] != VAULT_PAYLOAD_SCHEMA:
            raise VaultFormatError("payload version mismatch")
        if type(value["revision"]) is not int or value["revision"] != header.revision:
            raise VaultFormatError("payload revision mismatch")
        vault_id = _b64decode(value["vault_id"], "payload vault_id", VAULT_ID_LEN)
        if vault_id != header.vault_id:
            raise VaultFormatError("payload vault identifier mismatch")
        root_key = _b64decode(
            value["vault_root_key"], "vault_root_key", VAULT_ROOT_KEY_LEN
        )
        if _canonical_json(value, "Vault payload") != data:
            raise VaultFormatError("Vault payload is not canonical JSON")
        return root_key
    except VaultError as exc:
        raise VaultAuthenticationError("authenticated Vault payload is invalid") from exc


def _keyring_payload_bytes(header: VaultHeader, keyring: VaultKeyring) -> bytes:
    mapping = {
        "format": VAULT_PAYLOAD_NAME,
        "keyring": keyring_to_mapping(keyring),
        "revision": header.revision,
        "vault_id": _b64encode(header.vault_id),
        "version": VAULT_KEYRING_PAYLOAD_SCHEMA,
    }
    return _canonical_json(mapping, "Vault keyring payload")


def _parse_keyring_payload(data: bytes, header: VaultHeader) -> VaultKeyring:
    value = _decode_json(data, "Vault keyring payload")
    if set(value) != _KEYRING_PAYLOAD_FIELDS:
        raise VaultAuthenticationError(
            "authenticated Vault keyring payload is invalid"
        )
    try:
        if value["format"] != VAULT_PAYLOAD_NAME:
            raise VaultFormatError("keyring payload format mismatch")
        if (
            type(value["version"]) is not int
            or value["version"] != VAULT_KEYRING_PAYLOAD_SCHEMA
        ):
            raise VaultFormatError("keyring payload version mismatch")
        if type(value["revision"]) is not int or value["revision"] != header.revision:
            raise VaultFormatError("keyring payload revision mismatch")
        vault_id = _b64decode(
            value["vault_id"], "keyring payload vault_id", VAULT_ID_LEN
        )
        if vault_id != header.vault_id:
            raise VaultFormatError("keyring payload vault identifier mismatch")
        keyring = keyring_from_mapping(value["keyring"])
        if _canonical_json(value, "Vault keyring payload") != data:
            raise VaultFormatError("Vault keyring payload is not canonical JSON")
        return keyring
    except (VaultError, VaultKeyringError) as exc:
        raise VaultAuthenticationError(
            "authenticated Vault keyring payload is invalid"
        ) from exc


def _derive_kek(password: Any, header: VaultHeader) -> bytes:
    password_data = _password_bytes(password)
    kdf = Argon2id(
        salt=header.salt,
        length=32,
        iterations=header.time_cost,
        lanes=header.parallelism,
        memory_cost=header.memory_kib,
    )
    return kdf.derive(password_data)


def parse_vault(
    data: bytes | bytearray | memoryview,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> ParsedVault:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise VaultFormatError("Vault input must be bytes")
    encoded = bytes(data)
    if len(encoded) < VAULT_PREAMBLE_LEN:
        raise VaultFormatError("Vault preamble is truncated")
    try:
        magic, major, minor, flags, header_len, ciphertext_len = (
            VAULT_PREAMBLE_STRUCT.unpack(encoded[:VAULT_PREAMBLE_LEN])
        )
    except struct.error as exc:
        raise VaultFormatError("Vault preamble is invalid") from exc
    if magic != VAULT_MAGIC:
        raise VaultFormatError("Vault magic is invalid")
    if major != VAULT_MAJOR_VERSION or minor != VAULT_MINOR_VERSION:
        raise VaultUnsupportedVersionError("Vault preamble version is unsupported")
    if flags != VAULT_FLAGS:
        raise VaultUnsupportedVersionError("Vault preamble flags are unsupported")
    if not 1 <= header_len <= MAX_VAULT_HEADER_LEN:
        raise VaultFormatError("Vault header length is outside its bound")
    if not VAULT_GCM_TAG_LEN + 1 <= ciphertext_len <= MAX_VAULT_CIPHERTEXT_LEN:
        raise VaultFormatError("Vault ciphertext length is outside its bound")
    expected = VAULT_PREAMBLE_LEN + header_len + ciphertext_len
    if len(encoded) != expected:
        raise VaultFormatError("Vault length is truncated or has trailing data")
    header_bytes = encoded[VAULT_PREAMBLE_LEN : VAULT_PREAMBLE_LEN + header_len]
    mapping = _decode_json(header_bytes, "Vault header")
    header = _validate_header_mapping(mapping, policy=policy)
    if _canonical_json(mapping, "Vault header") != header_bytes:
        raise VaultFormatError("Vault header is not canonical JSON")
    if type(minimum_revision) is not int or minimum_revision < 0:
        raise VaultPolicyError("minimum_revision must be a non-negative integer")
    if header.revision < minimum_revision:
        raise VaultPolicyError("Vault revision violates anti-rollback policy")
    return ParsedVault(
        header=header,
        preamble_bytes=encoded[:VAULT_PREAMBLE_LEN],
        header_bytes=header_bytes,
        ciphertext=encoded[VAULT_PREAMBLE_LEN + header_len :],
    )


def _seal_payload(
    header: VaultHeader,
    payload: bytes,
    password: Any,
    *,
    policy: VaultKDFPolicy,
) -> bytes:
    header_bytes = encode_vault_header(header, policy=policy)
    if not isinstance(payload, bytes) or not payload:
        raise VaultFormatError("Vault payload must be non-empty bytes")
    ciphertext_len = len(payload) + VAULT_GCM_TAG_LEN
    if not VAULT_GCM_TAG_LEN + 1 <= ciphertext_len <= MAX_VAULT_CIPHERTEXT_LEN:
        raise VaultFormatError("Vault payload exceeds its ciphertext bound")
    preamble = VAULT_PREAMBLE_STRUCT.pack(
        VAULT_MAGIC,
        VAULT_MAJOR_VERSION,
        VAULT_MINOR_VERSION,
        VAULT_FLAGS,
        len(header_bytes),
        ciphertext_len,
    )
    aad = VAULT_AAD_DOMAIN + preamble + header_bytes
    kek = _derive_kek(password, header)
    try:
        ciphertext = AESGCM(kek).encrypt(header.nonce, payload, aad)
    finally:
        del kek
    if len(ciphertext) != ciphertext_len:
        raise AssertionError("internal Vault ciphertext-length invariant failed")
    return preamble + header_bytes + ciphertext


def _seal_legacy(
    header: VaultHeader,
    root_key: bytes,
    password: Any,
    *,
    policy: VaultKDFPolicy,
) -> bytes:
    if header.payload_schema != VAULT_PAYLOAD_SCHEMA:
        raise VaultFormatError("legacy payload requires schema one")
    return _seal_payload(
        header,
        _legacy_payload_bytes(header, root_key),
        password,
        policy=policy,
    )


def _seal_keyring(
    header: VaultHeader,
    keyring: VaultKeyring,
    password: Any,
    *,
    policy: VaultKDFPolicy,
) -> bytes:
    if header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA:
        raise VaultFormatError("keyring payload requires schema two")
    return _seal_payload(
        header,
        _keyring_payload_bytes(header, keyring),
        password,
        policy=policy,
    )


def create_vault(
    password: str,
    *,
    root_key: bytes | bytearray | memoryview | None = None,
    vault_id: bytes | bytearray | memoryview | None = None,
    created_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> bytes:
    _password_bytes(password)
    exact_root = (
        _random_exact(VAULT_ROOT_KEY_LEN, "vault_root_key")
        if root_key is None
        else _exact_bytes(root_key, "root_key", VAULT_ROOT_KEY_LEN)
    )
    exact_id = (
        _random_exact(VAULT_ID_LEN, "vault_id")
        if vault_id is None
        else _exact_bytes(vault_id, "vault_id", VAULT_ID_LEN)
    )
    timestamp = _strict_utc(created_utc or utc_now(), "created_utc")
    checked = _validate_kdf_values(
        time_cost, memory_kib, parallelism, policy=policy
    )
    header = VaultHeader(
        vault_id=exact_id,
        revision=1,
        created_utc=timestamp,
        updated_utc=timestamp,
        salt=_random_exact(VAULT_SALT_LEN, "salt"),
        time_cost=checked[0],
        memory_kib=checked[1],
        parallelism=checked[2],
        nonce=_random_exact(VAULT_NONCE_LEN, "nonce"),
    )
    return _seal_legacy(header, exact_root, password, policy=policy)


def _unlock_payload(
    data: bytes | bytearray | memoryview,
    password: str,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> tuple[ParsedVault, bytes]:
    parsed = parse_vault(data, policy=policy, minimum_revision=minimum_revision)
    aad = VAULT_AAD_DOMAIN + parsed.preamble_bytes + parsed.header_bytes
    kek = _derive_kek(password, parsed.header)
    try:
        try:
            payload = AESGCM(kek).decrypt(
                parsed.header.nonce, parsed.ciphertext, aad
            )
        except InvalidTag as exc:
            raise VaultAuthenticationError(
                "Vault password or authenticated bytes are invalid"
            ) from exc
    finally:
        del kek
    return parsed, payload


def unlock_vault(
    data: bytes | bytearray | memoryview,
    password: str,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> tuple[ParsedVault, bytes]:
    parsed = parse_vault(data, policy=policy, minimum_revision=minimum_revision)
    if parsed.header.payload_schema != VAULT_PAYLOAD_SCHEMA:
        raise VaultUnsupportedVersionError(
            "legacy Vault API requires payload schema one"
        )
    parsed, payload = _unlock_payload(
        parsed.encoded,
        password,
        policy=policy,
        minimum_revision=minimum_revision,
    )
    return parsed, _parse_legacy_payload(payload, parsed.header)


def unlock_keyring_vault(
    data: bytes | bytearray | memoryview,
    password: str,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> tuple[ParsedVault, VaultKeyring]:
    parsed = parse_vault(data, policy=policy, minimum_revision=minimum_revision)
    if parsed.header.payload_schema == VAULT_PAYLOAD_SCHEMA:
        raise VaultMigrationRequiredError(
            "legacy Vault requires explicit keyring migration"
        )
    if parsed.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA:
        raise VaultUnsupportedVersionError(
            "Vault keyring payload schema is unsupported"
        )
    parsed, payload = _unlock_payload(
        parsed.encoded,
        password,
        policy=policy,
        minimum_revision=minimum_revision,
    )
    return parsed, _parse_keyring_payload(payload, parsed.header)


def rewrap_vault(
    parsed: ParsedVault,
    root_key: bytes | bytearray | memoryview,
    new_password: str,
    *,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> bytes:
    if not isinstance(parsed, ParsedVault):
        raise VaultFormatError("parsed must be ParsedVault")
    if parsed.header.payload_schema != VAULT_PAYLOAD_SCHEMA:
        raise VaultUnsupportedVersionError(
            "legacy rewrap requires payload schema one"
        )
    exact_root = _exact_bytes(root_key, "root_key", VAULT_ROOT_KEY_LEN)
    _password_bytes(new_password)
    if parsed.header.revision >= MAX_VAULT_REVISION:
        raise VaultPolicyError("Vault revision counter is exhausted")
    timestamp = _strict_utc(updated_utc or utc_now(), "updated_utc")
    if timestamp < parsed.header.updated_utc:
        raise VaultPolicyError("updated_utc must not move backwards")
    checked = _validate_kdf_values(
        time_cost, memory_kib, parallelism, policy=policy
    )
    header = VaultHeader(
        vault_id=parsed.header.vault_id,
        revision=parsed.header.revision + 1,
        created_utc=parsed.header.created_utc,
        updated_utc=timestamp,
        salt=_random_exact(VAULT_SALT_LEN, "salt"),
        time_cost=checked[0],
        memory_kib=checked[1],
        parallelism=checked[2],
        nonce=_random_exact(VAULT_NONCE_LEN, "nonce"),
        payload_schema=VAULT_PAYLOAD_SCHEMA,
    )
    return _seal_legacy(header, exact_root, new_password, policy=policy)


def create_keyring_vault(
    password: str,
    *,
    keyring: VaultKeyring | None = None,
    vault_id: bytes | bytearray | memoryview | None = None,
    created_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> bytes:
    """Create a schema-two Vault with one strict versioned keyring."""

    _password_bytes(password)
    timestamp = _strict_utc(created_utc or utc_now(), "created_utc")
    exact_keyring = keyring or create_keyring(created_utc=timestamp)
    encode_keyring(exact_keyring)
    if (
        exact_keyring.active_key_version != 1
        or len(exact_keyring.keys) != 1
        or exact_keyring.keys[0].created_utc != timestamp
    ):
        raise VaultPolicyError(
            "new Vault must begin with exactly key version one"
        )
    exact_id = (
        _random_exact(VAULT_ID_LEN, "vault_id")
        if vault_id is None
        else _exact_bytes(vault_id, "vault_id", VAULT_ID_LEN)
    )
    checked = _validate_kdf_values(
        time_cost, memory_kib, parallelism, policy=policy
    )
    header = VaultHeader(
        vault_id=exact_id,
        revision=1,
        created_utc=timestamp,
        updated_utc=timestamp,
        salt=_random_exact(VAULT_SALT_LEN, "salt"),
        time_cost=checked[0],
        memory_kib=checked[1],
        parallelism=checked[2],
        nonce=_random_exact(VAULT_NONCE_LEN, "nonce"),
        payload_schema=VAULT_KEYRING_PAYLOAD_SCHEMA,
    )
    return _seal_keyring(header, exact_keyring, password, policy=policy)


def _rewrap_keyring_vault(
    parsed: ParsedVault,
    keyring: VaultKeyring,
    new_password: str,
    *,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> bytes:
    """Seal the same keyring as the next immutable Vault revision."""

    if not isinstance(parsed, ParsedVault):
        raise VaultFormatError("parsed must be ParsedVault")
    if parsed.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA:
        raise VaultMigrationRequiredError(
            "keyring rewrap requires payload schema two"
        )
    encode_keyring(keyring)
    _password_bytes(new_password)
    if parsed.header.revision >= MAX_VAULT_REVISION:
        raise VaultPolicyError("Vault revision counter is exhausted")
    timestamp = _strict_utc(updated_utc or utc_now(), "updated_utc")
    if timestamp < parsed.header.updated_utc:
        raise VaultPolicyError("updated_utc must not move backwards")
    if keyring.keys[-1].created_utc > timestamp:
        raise VaultPolicyError("Vault timestamp precedes active key creation")
    checked = _validate_kdf_values(
        time_cost, memory_kib, parallelism, policy=policy
    )
    header = VaultHeader(
        vault_id=parsed.header.vault_id,
        revision=parsed.header.revision + 1,
        created_utc=parsed.header.created_utc,
        updated_utc=timestamp,
        salt=_random_exact(VAULT_SALT_LEN, "salt"),
        time_cost=checked[0],
        memory_kib=checked[1],
        parallelism=checked[2],
        nonce=_random_exact(VAULT_NONCE_LEN, "nonce"),
        payload_schema=VAULT_KEYRING_PAYLOAD_SCHEMA,
    )
    return _seal_keyring(header, keyring, new_password, policy=policy)


def rewrap_keyring_vault(
    data: bytes | bytearray | memoryview,
    current_password: str,
    new_password: str,
    *,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> bytes:
    """Authenticate and rewrap an unchanged schema-two keyring."""

    parsed, keyring = unlock_keyring_vault(
        data,
        current_password,
        policy=policy,
        minimum_revision=minimum_revision,
    )
    return _rewrap_keyring_vault(
        parsed,
        keyring,
        new_password,
        updated_utc=updated_utc,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
        policy=policy,
    )


def migrate_legacy_vault_to_keyring(
    data: bytes | bytearray | memoryview,
    password: str,
    *,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
    minimum_revision: int = 0,
) -> bytes:
    """Explicitly migrate one authenticated schema-one root to version one."""

    parsed = parse_vault(data, policy=policy, minimum_revision=minimum_revision)
    if parsed.header.payload_schema != VAULT_PAYLOAD_SCHEMA:
        raise VaultMigrationRequiredError(
            "migration source must use legacy payload schema one"
        )
    parsed, legacy_key = unlock_vault(
        parsed.encoded,
        password,
        policy=policy,
        minimum_revision=minimum_revision,
    )
    keyring = keyring_from_legacy_key(
        legacy_key,
        created_utc=parsed.header.created_utc,
    )
    if parsed.header.revision >= MAX_VAULT_REVISION:
        raise VaultPolicyError("Vault revision counter is exhausted")
    timestamp = _strict_utc(updated_utc or utc_now(), "updated_utc")
    if timestamp < parsed.header.updated_utc:
        raise VaultPolicyError("updated_utc must not move backwards")
    checked = _validate_kdf_values(
        time_cost, memory_kib, parallelism, policy=policy
    )
    header = VaultHeader(
        vault_id=parsed.header.vault_id,
        revision=parsed.header.revision + 1,
        created_utc=parsed.header.created_utc,
        updated_utc=timestamp,
        salt=_random_exact(VAULT_SALT_LEN, "salt"),
        time_cost=checked[0],
        memory_kib=checked[1],
        parallelism=checked[2],
        nonce=_random_exact(VAULT_NONCE_LEN, "nonce"),
        payload_schema=VAULT_KEYRING_PAYLOAD_SCHEMA,
    )
    return _seal_keyring(header, keyring, password, policy=policy)


def _clock_value(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VaultStateError("monotonic clock must return a finite number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise VaultStateError("monotonic clock must return a finite non-negative number")
    return result


def _zeroize_best_effort(secret: bytearray | None) -> None:
    if secret is not None:
        for index in range(len(secret)):
            secret[index] = 0


class VaultSession:
    """Explicit locked/unlocked state machine for one encrypted Vault image."""

    __slots__ = (
        "_encoded",
        "_state",
        "_root_key",
        "_keyring_data",
        "_parsed",
        "_last_activity",
        "_timeout",
        "_clock",
        "_policy",
        "_minimum_revision",
    )

    def __init__(
        self,
        encoded: bytes | bytearray | memoryview,
        *,
        inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
        policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
        minimum_revision: int = 0,
    ) -> None:
        parsed = parse_vault(
            encoded, policy=policy, minimum_revision=minimum_revision
        )
        if isinstance(inactivity_timeout, bool) or not isinstance(
            inactivity_timeout, (int, float)
        ):
            raise VaultStateError("inactivity_timeout must be a finite number")
        timeout = float(inactivity_timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise VaultStateError("inactivity_timeout must be positive and finite")
        if not callable(clock):
            raise VaultStateError("clock must be callable")
        self._encoded = parsed.encoded
        self._state = VaultSessionState.LOCKED
        self._root_key: bytearray | None = None
        self._keyring_data: bytearray | None = None
        self._parsed: ParsedVault | None = parsed
        self._last_activity: float | None = None
        self._timeout = timeout
        self._clock = clock
        self._policy = policy
        self._minimum_revision = minimum_revision

    def __repr__(self) -> str:
        revision = self._parsed.header.revision if self._parsed is not None else "unknown"
        return f"VaultSession(state={self._state.value!r}, revision={revision!r})"

    def __copy__(self) -> None:
        raise TypeError("VaultSession cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultSession cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultSession cannot be pickled")

    @property
    def state(self) -> VaultSessionState:
        return self._state

    @property
    def revision(self) -> int:
        if self._parsed is None:
            raise VaultStateError("Vault metadata is unavailable")
        return self._parsed.header.revision

    @property
    def encoded(self) -> bytes:
        return self._encoded

    def unlock(self, password: str) -> None:
        if self._state is not VaultSessionState.LOCKED:
            raise VaultStateError("unlock requires the locked state")
        self._state = VaultSessionState.UNLOCKING
        try:
            assert self._parsed is not None
            if self._parsed.header.payload_schema == VAULT_PAYLOAD_SCHEMA:
                parsed, root_key = unlock_vault(
                    self._encoded,
                    password,
                    policy=self._policy,
                    minimum_revision=self._minimum_revision,
                )
                keyring_data = None
            elif (
                self._parsed.header.payload_schema
                == VAULT_KEYRING_PAYLOAD_SCHEMA
            ):
                parsed, keyring = unlock_keyring_vault(
                    self._encoded,
                    password,
                    policy=self._policy,
                    minimum_revision=self._minimum_revision,
                )
                root_key = None
                keyring_data = encode_keyring(keyring)
            else:
                raise VaultUnsupportedVersionError(
                    "Vault payload schema is unsupported"
                )
            now = _clock_value(self._clock())
        except BaseException:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
            self._state = VaultSessionState.FAILED
            raise
        self._parsed = parsed
        self._root_key = bytearray(root_key) if root_key is not None else None
        self._keyring_data = (
            bytearray(keyring_data) if keyring_data is not None else None
        )
        self._last_activity = now
        self._state = VaultSessionState.UNLOCKED

    def reset_failure(self) -> None:
        if self._state is not VaultSessionState.FAILED:
            raise VaultStateError("reset_failure requires the failed state")
        _zeroize_best_effort(self._root_key)
        _zeroize_best_effort(self._keyring_data)
        self._root_key = None
        self._keyring_data = None
        self._last_activity = None
        self._state = VaultSessionState.LOCKED

    def _require_unlocked(self) -> None:
        has_one_secret = (self._root_key is None) != (self._keyring_data is None)
        if self._state is not VaultSessionState.UNLOCKED or not has_one_secret:
            raise VaultStateError("Vault session is not unlocked")

    def check_inactivity(self) -> bool:
        self._require_unlocked()
        try:
            now = _clock_value(self._clock())
        except BaseException:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
            self._state = VaultSessionState.FAILED
            raise
        assert self._last_activity is not None
        if now < self._last_activity:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
            self._state = VaultSessionState.FAILED
            raise VaultStateError("monotonic clock moved backwards")
        if now - self._last_activity >= self._timeout:
            self.lock()
            return True
        return False

    def touch(self) -> None:
        self._require_unlocked()
        try:
            now = _clock_value(self._clock())
        except BaseException:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
            self._state = VaultSessionState.FAILED
            raise
        assert self._last_activity is not None
        if now < self._last_activity:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
            self._state = VaultSessionState.FAILED
            raise VaultStateError("monotonic clock moved backwards")
        self._last_activity = now

    def root_key_copy(self) -> bytes:
        if self.check_inactivity():
            raise VaultStateError("Vault session expired")
        if self._root_key is None:
            raise VaultMigrationRequiredError(
                "schema-two Vault exposes a keyring, not a legacy root key"
            )
        self.touch()
        return bytes(self._root_key)

    def keyring_copy(self) -> VaultKeyring:
        if self.check_inactivity():
            raise VaultStateError("Vault session expired")
        if self._keyring_data is None:
            raise VaultMigrationRequiredError(
                "legacy Vault requires explicit keyring migration"
            )
        result = parse_keyring(bytes(self._keyring_data))
        self.touch()
        return result

    def change_password(
        self,
        new_password: str,
        *,
        updated_utc: str | None = None,
        time_cost: int = DEFAULT_ARGON2_TIME_COST,
        memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
        parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    ) -> bytes:
        if self.check_inactivity():
            raise VaultStateError("Vault session expired")
        assert self._parsed is not None
        if self._root_key is not None:
            result = rewrap_vault(
                self._parsed,
                self._root_key,
                new_password,
                updated_utc=updated_utc,
                time_cost=time_cost,
                memory_kib=memory_kib,
                parallelism=parallelism,
                policy=self._policy,
            )
        elif self._keyring_data is not None:
            keyring = parse_keyring(bytes(self._keyring_data))
            result = _rewrap_keyring_vault(
                self._parsed,
                keyring,
                new_password,
                updated_utc=updated_utc,
                time_cost=time_cost,
                memory_kib=memory_kib,
                parallelism=parallelism,
                policy=self._policy,
            )
        else:
            raise VaultStateError("Vault session secret is unavailable")
        parsed = parse_vault(result, policy=self._policy)
        self._encoded = result
        self._parsed = parsed
        self._minimum_revision = max(self._minimum_revision, parsed.header.revision)
        self.touch()
        return result

    def rotate_keyring(
        self,
        current_password: str,
        *,
        rotated_utc: str | None = None,
        time_cost: int = DEFAULT_ARGON2_TIME_COST,
        memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
        parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    ) -> bytes:
        """Verify the current password and publish an in-memory next keyring revision."""

        if self.check_inactivity():
            raise VaultStateError("Vault session expired")
        if self._keyring_data is None or self._parsed is None:
            raise VaultMigrationRequiredError(
                "key rotation requires payload schema two"
            )
        verified_parsed, verified = unlock_keyring_vault(
            self._encoded,
            current_password,
            policy=self._policy,
            minimum_revision=self._minimum_revision,
        )
        current_data = bytes(self._keyring_data)
        if (
            verified_parsed.header.revision != self._parsed.header.revision
            or encode_keyring(verified) != current_data
        ):
            raise VaultStateError("unlocked keyring no longer matches Vault bytes")
        timestamp = _strict_utc(rotated_utc or utc_now(), "rotated_utc")
        rotated = rotate_keyring(verified, rotated_utc=timestamp)
        result = _rewrap_keyring_vault(
            self._parsed,
            rotated,
            current_password,
            updated_utc=timestamp,
            time_cost=time_cost,
            memory_kib=memory_kib,
            parallelism=parallelism,
            policy=self._policy,
        )
        parsed, confirmed = unlock_keyring_vault(
            result,
            current_password,
            policy=self._policy,
            minimum_revision=self._parsed.header.revision + 1,
        )
        confirmed_data = encode_keyring(confirmed)
        _zeroize_best_effort(self._keyring_data)
        self._keyring_data = bytearray(confirmed_data)
        self._encoded = result
        self._parsed = parsed
        self._minimum_revision = max(
            self._minimum_revision, parsed.header.revision
        )
        self.touch()
        return result

    def lock(self) -> None:
        if self._state is VaultSessionState.LOCKED:
            return
        if self._state is not VaultSessionState.UNLOCKED:
            raise VaultStateError("lock requires the unlocked or locked state")
        self._state = VaultSessionState.LOCKING
        _zeroize_best_effort(self._root_key)
        _zeroize_best_effort(self._keyring_data)
        self._root_key = None
        self._keyring_data = None
        self._last_activity = None
        self._state = VaultSessionState.LOCKED

    def close(self) -> None:
        if self._state is VaultSessionState.UNLOCKED:
            self.lock()
        elif self._state is VaultSessionState.FAILED:
            _zeroize_best_effort(self._root_key)
            _zeroize_best_effort(self._keyring_data)
            self._root_key = None
            self._keyring_data = None
            self._last_activity = None
