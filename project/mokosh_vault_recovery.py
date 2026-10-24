"""Strict in-memory offline recovery contract for a MOKOSH Vault keyring.

The recovery record is an authenticated, bounded copy of one exact schema-two
Vault keyring.  A fresh 32-byte recovery root protects it independently from
normal Vault unlock.  This module performs no path I/O, storage publication,
network access, logging, migration, key rotation, key deletion, or user-file
mutation.  Its public recovery operation is a read-only rehearsal that returns
only non-secret evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mokosh_vault_format import (
    MAX_VAULT_REVISION,
    VAULT_KEYRING_PAYLOAD_SCHEMA,
    VaultError,
    VaultSession,
    VaultSessionState,
    parse_vault,
)
from mokosh_vault_keyring import (
    MAX_ENCODED_KEYRING_LEN,
    VaultKeyring,
    VaultKeyringError,
    encode_keyring,
    keyring_from_mapping,
    keyring_to_mapping,
)


RECOVERY_MAGIC = b"MOKREC1\x00"
RECOVERY_MAJOR_VERSION = 1
RECOVERY_MINOR_VERSION = 0
RECOVERY_FLAGS = 0
RECOVERY_PREAMBLE_STRUCT = struct.Struct(">8sBBHII")
RECOVERY_PREAMBLE_LEN = RECOVERY_PREAMBLE_STRUCT.size

RECOVERY_FORMAT_NAME = "MOKOSH_VAULT_RECOVERY"
RECOVERY_PAYLOAD_NAME = "MOKOSH_VAULT_RECOVERY_PAYLOAD"
RECOVERY_PURPOSE = "OFFLINE_VAULT_KEYRING_RECOVERY"
RECOVERY_KDF_ALGORITHM = "HKDF-SHA-256"
RECOVERY_AEAD_ALGORITHM = "AES-256-GCM"

RECOVERY_ROOT_KEY_LEN = 32
RECOVERY_ID_LEN = 16
RECOVERY_VAULT_ID_LEN = 16
RECOVERY_NONCE_LEN = 12
RECOVERY_SHA256_LEN = 32
RECOVERY_GCM_TAG_LEN = 16
MAX_RECOVERY_HEADER_LEN = 4096
MAX_RECOVERY_CIPHERTEXT_LEN = MAX_ENCODED_KEYRING_LEN + 64 * 1024
MAX_RECOVERY_RECORDS = 32

RECOVERY_KDF_DOMAIN = b"MOKOSH\x00VAULT-RECOVERY\x00HKDF-SHA-256\x00"
RECOVERY_AAD_DOMAIN = b"MOKOSH\x00VAULT-RECOVERY\x00AES-256-GCM\x00"

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEADER_FIELDS = frozenset(
    {
        "aead",
        "created_utc",
        "format",
        "kdf",
        "purpose",
        "recovery_id",
        "source_revision",
        "source_vault_sha256",
        "vault_id",
        "version",
    }
)
_KDF_FIELDS = frozenset({"algorithm"})
_AEAD_FIELDS = frozenset({"algorithm", "nonce"})
_PAYLOAD_FIELDS = frozenset(
    {
        "format",
        "keyring",
        "keyring_sha256",
        "purpose",
        "recovery_id",
        "source_revision",
        "source_vault_sha256",
        "vault_id",
        "version",
    }
)


class VaultRecoveryError(ValueError):
    """Base class for strict Vault recovery failures."""


class VaultRecoveryFormatError(VaultRecoveryError):
    """A recovery preamble, header, payload, or bound is invalid."""


class VaultRecoveryDuplicateKeyError(VaultRecoveryFormatError):
    """Strict recovery JSON contains a duplicate object key."""


class VaultRecoveryUnsupportedVersionError(VaultRecoveryFormatError):
    """A recovery format, algorithm, or Vault schema is unsupported."""


class VaultRecoveryPolicyError(VaultRecoveryError):
    """A recovery resource, state, or freshness policy refuses the input."""


class VaultRecoveryStateError(VaultRecoveryPolicyError):
    """Recovery setup is invalid for the current Vault session state."""


class VaultRecoveryStaleError(VaultRecoveryPolicyError):
    """The recovery record predates the current Vault generation."""


class VaultRecoveryRollbackError(VaultRecoveryPolicyError):
    """The presented current Vault predates the recovery record."""


class VaultRecoveryMixedVaultError(VaultRecoveryPolicyError):
    """Recovery inputs belong to different Vault identifiers."""


class VaultRecoveryConflictError(VaultRecoveryPolicyError):
    """Recovery inputs claim one state but carry conflicting exact bytes."""


class VaultRecoveryDuplicateRecordError(VaultRecoveryPolicyError):
    """A candidate set repeats a record or recovery identifier."""


class VaultRecoveryAuthenticationError(VaultRecoveryError):
    """The recovery root or authenticated record bytes are invalid."""


@dataclass(frozen=True, slots=True)
class ParsedVaultRecoveryRecord:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    source_vault_sha256: bytes
    created_utc: str
    nonce: bytes
    preamble_bytes: bytes = field(repr=False)
    header_bytes: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)

    @property
    def encoded(self) -> bytes:
        return self.preamble_bytes + self.header_bytes + self.ciphertext


@dataclass(frozen=True, slots=True)
class VaultRecoverySetup:
    record: bytes = field(repr=False)
    recovery_key: bytes = field(repr=False)
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    source_vault_sha256: bytes

    def __copy__(self) -> None:
        raise TypeError("VaultRecoverySetup cannot be copied")

    def __deepcopy__(self, memo: Any) -> None:
        raise TypeError("VaultRecoverySetup cannot be deep-copied")

    def __reduce__(self) -> None:
        raise TypeError("VaultRecoverySetup cannot be pickled")


@dataclass(frozen=True, slots=True)
class VaultRecoveryRehearsal:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    source_vault_sha256: bytes
    created_utc: str
    keyring_sha256: bytes
    active_key_version: int
    key_count: int


def _exact_bytes(value: Any, field_name: str, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultRecoveryFormatError(f"{field_name} must be bytes")
    result = bytes(value)
    if len(result) != length:
        raise VaultRecoveryFormatError(
            f"{field_name} must contain exactly {length} bytes"
        )
    return result


def _random_exact(length: int, field_name: str) -> bytes:
    result = os.urandom(length)
    if not isinstance(result, bytes) or len(result) != length:
        raise VaultRecoveryPolicyError(
            f"secure random source returned invalid {field_name}"
        )
    return result


def _plain_revision(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_VAULT_REVISION:
        raise VaultRecoveryFormatError(
            "source_revision must be a positive supported integer"
        )
    return value


def _strict_utc(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise VaultRecoveryFormatError(
            f"{field_name} must be strict UTC text ending in Z"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise VaultRecoveryFormatError(
            f"{field_name} is not a valid UTC timestamp"
        ) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise VaultRecoveryFormatError(f"{field_name} is not canonical UTC")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: Any, field_name: str, length: int) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise VaultRecoveryFormatError(
            f"{field_name} must be unpadded base64url text"
        )
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        result = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise VaultRecoveryFormatError(
            f"{field_name} is invalid base64url"
        ) from exc
    if len(result) != length or _b64encode(result) != value:
        raise VaultRecoveryFormatError(
            f"{field_name} must canonically encode {length} bytes"
        )
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VaultRecoveryDuplicateKeyError(
                f"duplicate recovery JSON key: {key}"
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VaultRecoveryFormatError(
        f"non-standard recovery JSON constant is forbidden: {value}"
    )


def _decode_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        result = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise VaultRecoveryFormatError(f"{label} is not valid UTF-8") from exc
    except VaultRecoveryError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VaultRecoveryFormatError(
            f"{label} is not strict bounded JSON"
        ) from exc
    if not isinstance(result, dict):
        raise VaultRecoveryFormatError(f"{label} must be a JSON object")
    return result


def _canonical_json(value: Mapping[str, Any], label: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VaultRecoveryFormatError(
            f"{label} cannot be canonically encoded"
        ) from exc


def _header_mapping(
    *,
    recovery_id: bytes,
    vault_id: bytes,
    source_revision: int,
    source_vault_sha256: bytes,
    created_utc: str,
    nonce: bytes,
) -> dict[str, Any]:
    return {
        "aead": {
            "algorithm": RECOVERY_AEAD_ALGORITHM,
            "nonce": _b64encode(nonce),
        },
        "created_utc": created_utc,
        "format": RECOVERY_FORMAT_NAME,
        "kdf": {"algorithm": RECOVERY_KDF_ALGORITHM},
        "purpose": RECOVERY_PURPOSE,
        "recovery_id": _b64encode(recovery_id),
        "source_revision": source_revision,
        "source_vault_sha256": _b64encode(source_vault_sha256),
        "vault_id": _b64encode(vault_id),
        "version": RECOVERY_MAJOR_VERSION,
    }


def _validate_header_mapping(
    value: Mapping[str, Any],
) -> tuple[bytes, bytes, int, bytes, str, bytes]:
    if set(value) != _HEADER_FIELDS:
        raise VaultRecoveryFormatError(
            "recovery header fields are missing or unsupported"
        )
    if value["format"] != RECOVERY_FORMAT_NAME:
        raise VaultRecoveryFormatError("recovery header format is invalid")
    if (
        type(value["version"]) is not int
        or value["version"] != RECOVERY_MAJOR_VERSION
    ):
        raise VaultRecoveryUnsupportedVersionError(
            "recovery header version is unsupported"
        )
    if value["purpose"] != RECOVERY_PURPOSE:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery header purpose is unsupported"
        )
    kdf = value["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != _KDF_FIELDS:
        raise VaultRecoveryFormatError(
            "recovery KDF fields are missing or unsupported"
        )
    if kdf["algorithm"] != RECOVERY_KDF_ALGORITHM:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery KDF algorithm is unsupported"
        )
    aead = value["aead"]
    if not isinstance(aead, dict) or set(aead) != _AEAD_FIELDS:
        raise VaultRecoveryFormatError(
            "recovery AEAD fields are missing or unsupported"
        )
    if aead["algorithm"] != RECOVERY_AEAD_ALGORITHM:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery AEAD algorithm is unsupported"
        )
    return (
        _b64decode(value["recovery_id"], "recovery_id", RECOVERY_ID_LEN),
        _b64decode(value["vault_id"], "vault_id", RECOVERY_VAULT_ID_LEN),
        _plain_revision(value["source_revision"]),
        _b64decode(
            value["source_vault_sha256"],
            "source_vault_sha256",
            RECOVERY_SHA256_LEN,
        ),
        _strict_utc(value["created_utc"], "created_utc"),
        _b64decode(aead["nonce"], "nonce", RECOVERY_NONCE_LEN),
    )


def _derive_aead_key(
    recovery_key: bytes | bytearray | memoryview,
    recovery_id: bytes | bytearray | memoryview,
    vault_id: bytes | bytearray | memoryview,
) -> bytes:
    exact_key = _exact_bytes(
        recovery_key, "recovery_key", RECOVERY_ROOT_KEY_LEN
    )
    exact_recovery_id = _exact_bytes(
        recovery_id, "recovery_id", RECOVERY_ID_LEN
    )
    exact_vault_id = _exact_bytes(vault_id, "vault_id", RECOVERY_VAULT_ID_LEN)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=RECOVERY_KDF_DOMAIN + exact_vault_id + exact_recovery_id,
    ).derive(exact_key)


def parse_recovery_record(
    data: bytes | bytearray | memoryview,
) -> ParsedVaultRecoveryRecord:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise VaultRecoveryFormatError("recovery input must be bytes")
    encoded = bytes(data)
    if len(encoded) < RECOVERY_PREAMBLE_LEN:
        raise VaultRecoveryFormatError("recovery preamble is truncated")
    try:
        magic, major, minor, flags, header_len, ciphertext_len = (
            RECOVERY_PREAMBLE_STRUCT.unpack(encoded[:RECOVERY_PREAMBLE_LEN])
        )
    except struct.error as exc:
        raise VaultRecoveryFormatError("recovery preamble is invalid") from exc
    if magic != RECOVERY_MAGIC:
        raise VaultRecoveryFormatError("recovery magic is invalid")
    if major != RECOVERY_MAJOR_VERSION or minor != RECOVERY_MINOR_VERSION:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery preamble version is unsupported"
        )
    if flags != RECOVERY_FLAGS:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery preamble flags are unsupported"
        )
    if not 1 <= header_len <= MAX_RECOVERY_HEADER_LEN:
        raise VaultRecoveryFormatError(
            "recovery header length is outside its bound"
        )
    if not RECOVERY_GCM_TAG_LEN + 1 <= ciphertext_len <= MAX_RECOVERY_CIPHERTEXT_LEN:
        raise VaultRecoveryFormatError(
            "recovery ciphertext length is outside its bound"
        )
    expected = RECOVERY_PREAMBLE_LEN + header_len + ciphertext_len
    if len(encoded) != expected:
        raise VaultRecoveryFormatError(
            "recovery length is truncated or has trailing data"
        )
    start = RECOVERY_PREAMBLE_LEN
    end = start + header_len
    preamble = encoded[:start]
    header_bytes = encoded[start:end]
    mapping = _decode_json(header_bytes, "recovery header")
    values = _validate_header_mapping(mapping)
    if _canonical_json(mapping, "recovery header") != header_bytes:
        raise VaultRecoveryFormatError("recovery header is not canonical JSON")
    return ParsedVaultRecoveryRecord(
        recovery_id=values[0],
        vault_id=values[1],
        source_revision=values[2],
        source_vault_sha256=values[3],
        created_utc=values[4],
        nonce=values[5],
        preamble_bytes=preamble,
        header_bytes=header_bytes,
        ciphertext=encoded[end:],
    )


def _payload_mapping(
    parsed: ParsedVaultRecoveryRecord,
    keyring: VaultKeyring,
) -> dict[str, Any]:
    keyring_data = encode_keyring(keyring)
    return {
        "format": RECOVERY_PAYLOAD_NAME,
        "keyring": keyring_to_mapping(keyring),
        "keyring_sha256": _b64encode(hashlib.sha256(keyring_data).digest()),
        "purpose": RECOVERY_PURPOSE,
        "recovery_id": _b64encode(parsed.recovery_id),
        "source_revision": parsed.source_revision,
        "source_vault_sha256": _b64encode(parsed.source_vault_sha256),
        "vault_id": _b64encode(parsed.vault_id),
        "version": RECOVERY_MAJOR_VERSION,
    }


def _decrypt_keyring(
    parsed: ParsedVaultRecoveryRecord,
    recovery_key: bytes | bytearray | memoryview,
) -> tuple[VaultKeyring, bytes]:
    if not isinstance(parsed, ParsedVaultRecoveryRecord):
        raise VaultRecoveryFormatError(
            "parsed must be ParsedVaultRecoveryRecord"
        )
    aead_key = _derive_aead_key(
        recovery_key, parsed.recovery_id, parsed.vault_id
    )
    aad = RECOVERY_AAD_DOMAIN + parsed.preamble_bytes + parsed.header_bytes
    try:
        try:
            plaintext = AESGCM(aead_key).decrypt(
                parsed.nonce, parsed.ciphertext, aad
            )
        except InvalidTag as exc:
            raise VaultRecoveryAuthenticationError(
                "recovery root or authenticated bytes are invalid"
            ) from exc
    finally:
        del aead_key
    try:
        value = _decode_json(plaintext, "recovery payload")
        if set(value) != _PAYLOAD_FIELDS:
            raise VaultRecoveryFormatError(
                "recovery payload fields are missing or unsupported"
            )
        if value["format"] != RECOVERY_PAYLOAD_NAME:
            raise VaultRecoveryFormatError("recovery payload format is invalid")
        if (
            type(value["version"]) is not int
            or value["version"] != RECOVERY_MAJOR_VERSION
        ):
            raise VaultRecoveryUnsupportedVersionError(
                "recovery payload version is unsupported"
            )
        if value["purpose"] != RECOVERY_PURPOSE:
            raise VaultRecoveryUnsupportedVersionError(
                "recovery payload purpose is unsupported"
            )
        if (
            _b64decode(value["recovery_id"], "recovery_id", RECOVERY_ID_LEN)
            != parsed.recovery_id
            or _b64decode(
                value["vault_id"], "vault_id", RECOVERY_VAULT_ID_LEN
            )
            != parsed.vault_id
            or _plain_revision(value["source_revision"])
            != parsed.source_revision
            or _b64decode(
                value["source_vault_sha256"],
                "source_vault_sha256",
                RECOVERY_SHA256_LEN,
            )
            != parsed.source_vault_sha256
        ):
            raise VaultRecoveryFormatError(
                "recovery payload metadata does not match its header"
            )
        keyring_digest = _b64decode(
            value["keyring_sha256"],
            "keyring_sha256",
            RECOVERY_SHA256_LEN,
        )
        exact_keyring = keyring_from_mapping(value["keyring"])
        exact_keyring_data = encode_keyring(exact_keyring)
        if not hmac.compare_digest(
            hashlib.sha256(exact_keyring_data).digest(), keyring_digest
        ):
            raise VaultRecoveryFormatError(
                "recovery keyring digest does not match its exact state"
            )
        if _canonical_json(value, "recovery payload") != plaintext:
            raise VaultRecoveryFormatError(
                "recovery payload is not canonical JSON"
            )
        return exact_keyring, keyring_digest
    except (VaultRecoveryError, VaultKeyringError) as exc:
        raise VaultRecoveryAuthenticationError(
            "authenticated recovery payload is invalid"
        ) from exc
    finally:
        del plaintext


def create_recovery_record(
    session: VaultSession,
    *,
    created_utc: str | None = None,
) -> VaultRecoverySetup:
    """Create an independent recovery record from one unlocked keyring session."""

    if not isinstance(session, VaultSession):
        raise VaultRecoveryStateError(
            "recovery setup requires a VaultSession"
        )
    if session.state is not VaultSessionState.UNLOCKED:
        raise VaultRecoveryStateError(
            "recovery setup requires an unlocked Vault session"
        )
    try:
        if session.check_inactivity():
            raise VaultRecoveryStateError(
                "Vault session expired before recovery setup"
            )
        source = session.encoded
        parsed_source = parse_vault(source)
    except VaultRecoveryError:
        raise
    except VaultError as exc:
        raise VaultRecoveryStateError(
            "Vault session cannot provide a recovery source"
        ) from exc
    if parsed_source.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery setup requires Vault keyring payload schema two"
        )
    try:
        exact_keyring = session.keyring_copy()
    except VaultError as exc:
        raise VaultRecoveryStateError(
            "Vault keyring is unavailable for recovery setup"
        ) from exc
    if session.encoded != source or session.revision != parsed_source.header.revision:
        raise VaultRecoveryStateError(
            "Vault session changed during recovery setup"
        )
    keyring_data = encode_keyring(exact_keyring)
    timestamp = _strict_utc(created_utc or utc_now(), "created_utc")
    if timestamp < parsed_source.header.updated_utc:
        raise VaultRecoveryPolicyError(
            "recovery creation time precedes the source Vault"
        )

    recovery_key = _random_exact(RECOVERY_ROOT_KEY_LEN, "recovery root")
    if any(
        hmac.compare_digest(record.wrapping_key, recovery_key)
        for record in exact_keyring.keys
    ):
        raise VaultRecoveryPolicyError(
            "recovery root repeated Vault wrapping-key material"
        )
    recovery_id = _random_exact(RECOVERY_ID_LEN, "recovery identifier")
    nonce = _random_exact(RECOVERY_NONCE_LEN, "recovery nonce")
    source_digest = hashlib.sha256(source).digest()
    header_mapping = _header_mapping(
        recovery_id=recovery_id,
        vault_id=parsed_source.header.vault_id,
        source_revision=parsed_source.header.revision,
        source_vault_sha256=source_digest,
        created_utc=timestamp,
        nonce=nonce,
    )
    header_bytes = _canonical_json(header_mapping, "recovery header")
    if not 1 <= len(header_bytes) <= MAX_RECOVERY_HEADER_LEN:
        raise VaultRecoveryPolicyError("recovery header exceeds its bound")

    placeholder = ParsedVaultRecoveryRecord(
        recovery_id=recovery_id,
        vault_id=parsed_source.header.vault_id,
        source_revision=parsed_source.header.revision,
        source_vault_sha256=source_digest,
        created_utc=timestamp,
        nonce=nonce,
        preamble_bytes=b"",
        header_bytes=header_bytes,
        ciphertext=b"",
    )
    payload_bytes = _canonical_json(
        _payload_mapping(placeholder, exact_keyring), "recovery payload"
    )
    ciphertext_len = len(payload_bytes) + RECOVERY_GCM_TAG_LEN
    if not RECOVERY_GCM_TAG_LEN + 1 <= ciphertext_len <= MAX_RECOVERY_CIPHERTEXT_LEN:
        raise VaultRecoveryPolicyError(
            "recovery payload exceeds its ciphertext bound"
        )
    preamble = RECOVERY_PREAMBLE_STRUCT.pack(
        RECOVERY_MAGIC,
        RECOVERY_MAJOR_VERSION,
        RECOVERY_MINOR_VERSION,
        RECOVERY_FLAGS,
        len(header_bytes),
        ciphertext_len,
    )
    aead_key = _derive_aead_key(recovery_key, recovery_id, parsed_source.header.vault_id)
    aad = RECOVERY_AAD_DOMAIN + preamble + header_bytes
    try:
        ciphertext = AESGCM(aead_key).encrypt(nonce, payload_bytes, aad)
    finally:
        del aead_key
        del payload_bytes
        del keyring_data
    if len(ciphertext) != ciphertext_len:
        raise AssertionError(
            "internal recovery ciphertext-length invariant failed"
        )
    encoded = preamble + header_bytes + ciphertext
    confirmed = parse_recovery_record(encoded)
    confirmed_keyring, _ = _decrypt_keyring(confirmed, recovery_key)
    if encode_keyring(confirmed_keyring) != encode_keyring(exact_keyring):
        raise AssertionError("internal recovery keyring invariant failed")
    try:
        if session.check_inactivity():
            raise VaultRecoveryStateError(
                "Vault session expired during recovery setup"
            )
    except VaultRecoveryError:
        raise
    except VaultError as exc:
        raise VaultRecoveryStateError(
            "Vault session failed during recovery setup"
        ) from exc
    if session.encoded != source or session.revision != parsed_source.header.revision:
        raise VaultRecoveryStateError(
            "Vault session changed during recovery setup"
        )
    return VaultRecoverySetup(
        record=encoded,
        recovery_key=recovery_key,
        recovery_id=recovery_id,
        vault_id=parsed_source.header.vault_id,
        source_revision=parsed_source.header.revision,
        source_vault_sha256=source_digest,
    )


def validate_recovery_record_set(
    records: tuple[bytes | bytearray | memoryview, ...],
) -> tuple[ParsedVaultRecoveryRecord, ...]:
    """Strictly parse one bounded, non-duplicated, single-state record set."""

    if type(records) is not tuple or not 1 <= len(records) <= MAX_RECOVERY_RECORDS:
        raise VaultRecoveryPolicyError(
            f"recovery record set must be a tuple of 1 to {MAX_RECOVERY_RECORDS} items"
        )
    parsed_items: list[ParsedVaultRecoveryRecord] = []
    seen_records: set[bytes] = set()
    seen_ids: set[bytes] = set()
    for item in records:
        parsed = parse_recovery_record(item)
        if parsed.encoded in seen_records or parsed.recovery_id in seen_ids:
            raise VaultRecoveryDuplicateRecordError(
                "recovery record set contains a duplicate"
            )
        seen_records.add(parsed.encoded)
        seen_ids.add(parsed.recovery_id)
        parsed_items.append(parsed)
    first = parsed_items[0]
    if any(item.vault_id != first.vault_id for item in parsed_items[1:]):
        raise VaultRecoveryMixedVaultError(
            "recovery record set mixes Vault identifiers"
        )
    if any(
        item.source_revision != first.source_revision
        or item.source_vault_sha256 != first.source_vault_sha256
        for item in parsed_items[1:]
    ):
        raise VaultRecoveryConflictError(
            "recovery record set mixes Vault states"
        )
    return tuple(parsed_items)


def rehearse_recovery(
    record: bytes | bytearray | memoryview,
    recovery_key: bytes | bytearray | memoryview,
    current_vault: bytes | bytearray | memoryview,
) -> VaultRecoveryRehearsal:
    """Verify exact recoverability without returning keys or mutating storage."""

    parsed_record = validate_recovery_record_set((record,))[0]
    try:
        current = parse_vault(current_vault)
    except VaultError as exc:
        raise VaultRecoveryConflictError(
            "current Vault bytes are invalid or unsupported"
        ) from exc
    if current.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA:
        raise VaultRecoveryUnsupportedVersionError(
            "recovery rehearsal requires Vault keyring payload schema two"
        )
    if parsed_record.vault_id != current.header.vault_id:
        raise VaultRecoveryMixedVaultError(
            "recovery record belongs to another Vault"
        )
    if parsed_record.source_revision < current.header.revision:
        raise VaultRecoveryStaleError(
            "recovery record predates the current Vault generation"
        )
    if parsed_record.source_revision > current.header.revision:
        raise VaultRecoveryRollbackError(
            "current Vault predates the recovery record"
        )
    current_digest = hashlib.sha256(current.encoded).digest()
    if not hmac.compare_digest(
        parsed_record.source_vault_sha256, current_digest
    ):
        raise VaultRecoveryConflictError(
            "recovery record does not match the exact current Vault bytes"
        )
    exact_keyring, keyring_digest = _decrypt_keyring(
        parsed_record, recovery_key
    )
    if parsed_record.created_utc < current.header.updated_utc:
        raise VaultRecoveryPolicyError(
            "recovery record creation time precedes the current Vault"
        )
    return VaultRecoveryRehearsal(
        recovery_id=parsed_record.recovery_id,
        vault_id=parsed_record.vault_id,
        source_revision=parsed_record.source_revision,
        source_vault_sha256=parsed_record.source_vault_sha256,
        created_utc=parsed_record.created_utc,
        keyring_sha256=keyring_digest,
        active_key_version=exact_keyring.active_key_version,
        key_count=len(exact_keyring.keys),
    )
