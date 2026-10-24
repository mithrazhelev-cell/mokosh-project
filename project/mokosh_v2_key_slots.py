"""Strict, non-cryptographic MOKOSH v2 key-slot schema codec.

The module validates public JSON metadata only. It does not accept passwords,
derive keys, unwrap DEKs, access a Key Vault, or perform KEM operations.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


MAX_KEY_SLOTS = 64
SLOT_ID_LEN = 16
SALT_LEN = 16
GCM_NONCE_LEN = 12
WRAPPED_DEK_LEN = 48
X25519_PUBLIC_KEY_LEN = 32
MLKEM768_CIPHERTEXT_LEN = 1088

ARGON2_MIN_TIME_COST = 2
ARGON2_MAX_TIME_COST = 10
ARGON2_MIN_MEMORY_KIB = 64 * 1024
ARGON2_MAX_MEMORY_KIB = 1024 * 1024
ARGON2_MIN_PARALLELISM = 1
ARGON2_MAX_PARALLELISM = 16

PASSWORD_SLOT_TYPE = "PASSWORD"
KEY_VAULT_SLOT_TYPE = "KEY_VAULT"
CONTACT_HYBRID_SLOT_TYPE = "CONTACT_HYBRID"

PASSWORD_SUITE = "ARGON2ID-AES-256-GCM"
KEY_VAULT_SUITE = "KEY-VAULT-HKDF-SHA-256-AES-256-GCM"
CONTACT_HYBRID_SUITE = (
    "X25519-ML-KEM-768-HKDF-SHA-256-AES-256-GCM"
)

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_COMMON_FIELDS = frozenset({"type", "suite", "slot_id"})
_PASSWORD_FIELDS = _COMMON_FIELDS | frozenset(
    {
        "salt",
        "time_cost",
        "memory_kib",
        "parallelism",
        "wrap_nonce",
        "wrapped_dek",
    }
)
_KEY_VAULT_FIELDS = _COMMON_FIELDS | frozenset(
    {"vault_key_version", "wrap_nonce", "wrapped_dek"}
)
_CONTACT_HYBRID_FIELDS = _COMMON_FIELDS | frozenset(
    {
        "recipient_key_version",
        "ephemeral_x25519_public_key",
        "mlkem_ciphertext",
        "wrap_nonce",
        "wrapped_dek",
    }
)


class KeySlotError(ValueError):
    """A key slot is malformed, ambiguous, unsupported, or out of bounds."""


class UnknownKeySlotTypeError(KeySlotError):
    """The slot type is not defined by MOKOSH v2."""


class DuplicateKeySlotError(KeySlotError):
    """Two slots use the same public slot identifier."""


@dataclass(frozen=True, slots=True)
class PasswordSlot:
    slot_id: bytes
    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int
    wrap_nonce: bytes
    wrapped_dek: bytes


@dataclass(frozen=True, slots=True)
class KeyVaultSlot:
    slot_id: bytes
    vault_key_version: int
    wrap_nonce: bytes
    wrapped_dek: bytes


@dataclass(frozen=True, slots=True)
class ContactHybridSlot:
    slot_id: bytes
    recipient_key_version: int
    ephemeral_x25519_public_key: bytes
    mlkem_ciphertext: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes


KeySlot = PasswordSlot | KeyVaultSlot | ContactHybridSlot


def _require_plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise KeySlotError(f"{field} must be an integer")
    return value


def _require_int_range(
    value: Any, field: str, minimum: int, maximum: int
) -> int:
    parsed = _require_plain_int(value, field)
    if not minimum <= parsed <= maximum:
        raise KeySlotError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return parsed


def _decode_base64url_exact(value: Any, field: str, expected_len: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise KeySlotError(f"{field} must be unpadded base64url text")
    expected_text_len = len(_encode_base64url(b"\x00" * expected_len))
    if len(value) != expected_text_len:
        raise KeySlotError(
            f"{field} must contain exactly {expected_text_len} base64url characters"
        )
    if _BASE64URL_RE.fullmatch(value) is None:
        raise KeySlotError(f"{field} contains non-base64url characters")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise KeySlotError(f"{field} is not valid base64url") from exc
    if len(decoded) != expected_len:
        raise KeySlotError(
            f"{field} must decode to exactly {expected_len} bytes"
        )
    if _encode_base64url(decoded) != value:
        raise KeySlotError(f"{field} is not canonical base64url")
    return decoded


def _encode_base64url(value: bytes) -> str:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise KeySlotError("binary slot field must be bytes")
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def _require_exact_fields(slot: Mapping[str, Any], expected: frozenset[str]) -> None:
    fields = set(slot)
    missing = sorted(expected - fields)
    unknown = sorted(fields - expected)
    if missing:
        raise KeySlotError(f"slot is missing required fields: {', '.join(missing)}")
    if unknown:
        raise KeySlotError(f"slot contains unknown fields: {', '.join(unknown)}")


def _require_suite(slot: Mapping[str, Any], expected: str) -> None:
    if slot["suite"] != expected:
        raise KeySlotError(f"slot suite must be {expected}")


def parse_key_slot(value: Any) -> KeySlot:
    if not isinstance(value, Mapping):
        raise KeySlotError("key slot must be a JSON object")
    if not all(isinstance(field, str) for field in value):
        raise KeySlotError("key slot field names must be text")
    if "type" not in value:
        raise KeySlotError("slot is missing required field: type")
    slot_type = value["type"]
    if not isinstance(slot_type, str):
        raise KeySlotError("slot type must be text")

    if slot_type == PASSWORD_SLOT_TYPE:
        _require_exact_fields(value, _PASSWORD_FIELDS)
        _require_suite(value, PASSWORD_SUITE)
        return PasswordSlot(
            slot_id=_decode_base64url_exact(value["slot_id"], "slot_id", SLOT_ID_LEN),
            salt=_decode_base64url_exact(value["salt"], "salt", SALT_LEN),
            time_cost=_require_int_range(
                value["time_cost"],
                "time_cost",
                ARGON2_MIN_TIME_COST,
                ARGON2_MAX_TIME_COST,
            ),
            memory_kib=_require_int_range(
                value["memory_kib"],
                "memory_kib",
                ARGON2_MIN_MEMORY_KIB,
                ARGON2_MAX_MEMORY_KIB,
            ),
            parallelism=_require_int_range(
                value["parallelism"],
                "parallelism",
                ARGON2_MIN_PARALLELISM,
                ARGON2_MAX_PARALLELISM,
            ),
            wrap_nonce=_decode_base64url_exact(
                value["wrap_nonce"], "wrap_nonce", GCM_NONCE_LEN
            ),
            wrapped_dek=_decode_base64url_exact(
                value["wrapped_dek"], "wrapped_dek", WRAPPED_DEK_LEN
            ),
        )

    if slot_type == KEY_VAULT_SLOT_TYPE:
        _require_exact_fields(value, _KEY_VAULT_FIELDS)
        _require_suite(value, KEY_VAULT_SUITE)
        return KeyVaultSlot(
            slot_id=_decode_base64url_exact(value["slot_id"], "slot_id", SLOT_ID_LEN),
            vault_key_version=_require_int_range(
                value["vault_key_version"], "vault_key_version", 1, 0xFFFFFFFF
            ),
            wrap_nonce=_decode_base64url_exact(
                value["wrap_nonce"], "wrap_nonce", GCM_NONCE_LEN
            ),
            wrapped_dek=_decode_base64url_exact(
                value["wrapped_dek"], "wrapped_dek", WRAPPED_DEK_LEN
            ),
        )

    if slot_type == CONTACT_HYBRID_SLOT_TYPE:
        _require_exact_fields(value, _CONTACT_HYBRID_FIELDS)
        _require_suite(value, CONTACT_HYBRID_SUITE)
        return ContactHybridSlot(
            slot_id=_decode_base64url_exact(value["slot_id"], "slot_id", SLOT_ID_LEN),
            recipient_key_version=_require_int_range(
                value["recipient_key_version"],
                "recipient_key_version",
                1,
                0xFFFFFFFF,
            ),
            ephemeral_x25519_public_key=_decode_base64url_exact(
                value["ephemeral_x25519_public_key"],
                "ephemeral_x25519_public_key",
                X25519_PUBLIC_KEY_LEN,
            ),
            mlkem_ciphertext=_decode_base64url_exact(
                value["mlkem_ciphertext"],
                "mlkem_ciphertext",
                MLKEM768_CIPHERTEXT_LEN,
            ),
            wrap_nonce=_decode_base64url_exact(
                value["wrap_nonce"], "wrap_nonce", GCM_NONCE_LEN
            ),
            wrapped_dek=_decode_base64url_exact(
                value["wrapped_dek"], "wrapped_dek", WRAPPED_DEK_LEN
            ),
        )

    raise UnknownKeySlotTypeError(f"unsupported key slot type: {slot_type}")


def key_slot_to_mapping(slot: KeySlot) -> dict[str, Any]:
    if isinstance(slot, PasswordSlot):
        result = {
            "type": PASSWORD_SLOT_TYPE,
            "suite": PASSWORD_SUITE,
            "slot_id": _encode_base64url(slot.slot_id),
            "salt": _encode_base64url(slot.salt),
            "time_cost": slot.time_cost,
            "memory_kib": slot.memory_kib,
            "parallelism": slot.parallelism,
            "wrap_nonce": _encode_base64url(slot.wrap_nonce),
            "wrapped_dek": _encode_base64url(slot.wrapped_dek),
        }
    elif isinstance(slot, KeyVaultSlot):
        result = {
            "type": KEY_VAULT_SLOT_TYPE,
            "suite": KEY_VAULT_SUITE,
            "slot_id": _encode_base64url(slot.slot_id),
            "vault_key_version": slot.vault_key_version,
            "wrap_nonce": _encode_base64url(slot.wrap_nonce),
            "wrapped_dek": _encode_base64url(slot.wrapped_dek),
        }
    elif isinstance(slot, ContactHybridSlot):
        result = {
            "type": CONTACT_HYBRID_SLOT_TYPE,
            "suite": CONTACT_HYBRID_SUITE,
            "slot_id": _encode_base64url(slot.slot_id),
            "recipient_key_version": slot.recipient_key_version,
            "ephemeral_x25519_public_key": _encode_base64url(
                slot.ephemeral_x25519_public_key
            ),
            "mlkem_ciphertext": _encode_base64url(slot.mlkem_ciphertext),
            "wrap_nonce": _encode_base64url(slot.wrap_nonce),
            "wrapped_dek": _encode_base64url(slot.wrapped_dek),
        }
    else:
        raise KeySlotError("slot must be a supported key-slot object")

    parse_key_slot(result)
    return result


def parse_key_slots(value: Any) -> tuple[KeySlot, ...]:
    if not isinstance(value, list):
        raise KeySlotError("key_slots must be a JSON array")
    if len(value) > MAX_KEY_SLOTS:
        raise KeySlotError(f"key_slots exceeds the limit of {MAX_KEY_SLOTS}")

    parsed: list[KeySlot] = []
    seen_slot_ids: set[bytes] = set()
    for index, item in enumerate(value):
        try:
            slot = parse_key_slot(item)
        except KeySlotError as exc:
            raise KeySlotError(f"key_slots[{index}]: {exc}") from exc
        if slot.slot_id in seen_slot_ids:
            raise DuplicateKeySlotError(
                f"key_slots[{index}] duplicates an existing slot_id"
            )
        seen_slot_ids.add(slot.slot_id)
        parsed.append(slot)
    return tuple(parsed)


def key_slots_to_list(slots: Sequence[KeySlot]) -> list[dict[str, Any]]:
    if not isinstance(slots, Sequence) or isinstance(
        slots, (str, bytes, bytearray, memoryview)
    ):
        raise KeySlotError("slots must be a sequence of key-slot objects")
    if len(slots) > MAX_KEY_SLOTS:
        raise KeySlotError(f"slots exceeds the limit of {MAX_KEY_SLOTS}")
    encoded = [key_slot_to_mapping(slot) for slot in slots]
    parse_key_slots(encoded)
    return encoded
