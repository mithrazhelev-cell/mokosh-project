"""In-memory HKDF-SHA-256 and AES-GCM Key Vault slot operations.

The 32-byte Vault root key is only input keying material for HKDF. It is never
used directly as an AES-GCM key. This module performs no filesystem, Key Vault,
recovery, network, or GUI operations.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mokosh_v2_key_slots import (
    GCM_NONCE_LEN,
    KEY_VAULT_SUITE,
    SLOT_ID_LEN,
    KeySlotError,
    KeyVaultSlot,
    key_slot_to_mapping,
)


VAULT_ROOT_KEY_LEN = 32
DEK_LEN = 32
KEK_LEN = 32
FILE_ID_LEN = 16
VAULT_SLOT_HKDF_INFO_DOMAIN = b"MOKOSH2\x00KEY-VAULT-SLOT-KEK\x00"
VAULT_SLOT_AAD_DOMAIN = b"MOKOSH2\x00KEY-VAULT-SLOT-WRAP\x00"


class VaultSlotCryptoError(KeySlotError):
    """Base class for Key Vault slot cryptographic failures."""


class VaultSlotInputError(VaultSlotCryptoError):
    """A root key, DEK, file identifier, slot, or random value is invalid."""


class VaultSlotAuthenticationError(VaultSlotCryptoError):
    """The root key or authenticated Key Vault slot data is invalid."""


def _require_exact_bytes(value: Any, field: str, expected_len: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultSlotInputError(f"{field} must be bytes")
    encoded = bytes(value)
    if len(encoded) != expected_len:
        raise VaultSlotInputError(
            f"{field} must contain exactly {expected_len} bytes"
        )
    return encoded


def _require_vault_slot(slot: Any) -> KeyVaultSlot:
    if not isinstance(slot, KeyVaultSlot):
        raise VaultSlotCryptoError("slot must be KeyVaultSlot")
    try:
        key_slot_to_mapping(slot)
    except KeySlotError as exc:
        raise VaultSlotCryptoError("Key Vault slot is invalid") from exc
    return slot


def _random_exact(length: int, field: str) -> bytes:
    value = os.urandom(length)
    if not isinstance(value, bytes) or len(value) != length:
        raise VaultSlotInputError(f"secure random source returned invalid {field}")
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical_json(mapping: dict[str, Any]) -> bytes:
    return json.dumps(
        mapping,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _common_bound_metadata(
    file_id: bytes | bytearray | memoryview,
    slot: KeyVaultSlot,
) -> dict[str, Any]:
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    exact_slot = _require_vault_slot(slot)
    return {
        "file_id": _b64url(exact_file_id),
        "slot_id": _b64url(exact_slot.slot_id),
        "suite": KEY_VAULT_SUITE,
        "type": "KEY_VAULT",
        "vault_key_version": exact_slot.vault_key_version,
    }


def build_vault_slot_hkdf_info(
    file_id: bytes | bytearray | memoryview,
    slot: KeyVaultSlot,
) -> bytes:
    """Return exact domain-separated HKDF info for one file and Vault slot."""

    return VAULT_SLOT_HKDF_INFO_DOMAIN + _canonical_json(
        _common_bound_metadata(file_id, slot)
    )


def build_vault_slot_aad(
    file_id: bytes | bytearray | memoryview,
    slot: KeyVaultSlot,
) -> bytes:
    """Return exact AES-GCM AAD, excluding only the wrapped DEK itself."""

    metadata = _common_bound_metadata(file_id, slot)
    metadata["wrap_nonce"] = _b64url(slot.wrap_nonce)
    return VAULT_SLOT_AAD_DOMAIN + _canonical_json(metadata)


def derive_vault_slot_kek(
    vault_root_key: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
    slot: KeyVaultSlot,
) -> bytes:
    """Derive one 32-byte per-file/per-slot KEK from a Vault root key."""

    exact_root_key = _require_exact_bytes(
        vault_root_key, "vault_root_key", VAULT_ROOT_KEY_LEN
    )
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    info = build_vault_slot_hkdf_info(exact_file_id, slot)
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=KEK_LEN,
        salt=exact_file_id,
        info=info,
    ).derive(exact_root_key)
    if len(kek) != KEK_LEN:
        raise AssertionError("internal HKDF output-length invariant failed")
    return kek


def create_vault_slot(
    vault_root_key: bytes | bytearray | memoryview,
    vault_key_version: int,
    dek: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
) -> KeyVaultSlot:
    """Create an authenticated Key Vault slot entirely in memory."""

    exact_root_key = _require_exact_bytes(
        vault_root_key, "vault_root_key", VAULT_ROOT_KEY_LEN
    )
    exact_dek = _require_exact_bytes(dek, "dek", DEK_LEN)
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    _require_vault_slot(
        KeyVaultSlot(
            slot_id=b"\x00" * SLOT_ID_LEN,
            vault_key_version=vault_key_version,
            wrap_nonce=b"\x00" * GCM_NONCE_LEN,
            wrapped_dek=b"\x00" * (DEK_LEN + 16),
        )
    )
    provisional = KeyVaultSlot(
        slot_id=_random_exact(SLOT_ID_LEN, "slot_id"),
        vault_key_version=vault_key_version,
        wrap_nonce=_random_exact(GCM_NONCE_LEN, "wrap_nonce"),
        wrapped_dek=b"\x00" * (DEK_LEN + 16),
    )
    _require_vault_slot(provisional)
    aad = build_vault_slot_aad(exact_file_id, provisional)
    kek = derive_vault_slot_kek(exact_root_key, exact_file_id, provisional)
    try:
        wrapped_dek = AESGCM(kek).encrypt(
            provisional.wrap_nonce,
            exact_dek,
            aad,
        )
    finally:
        del kek

    result = KeyVaultSlot(
        slot_id=provisional.slot_id,
        vault_key_version=provisional.vault_key_version,
        wrap_nonce=provisional.wrap_nonce,
        wrapped_dek=wrapped_dek,
    )
    _require_vault_slot(result)
    return result


def unwrap_vault_slot(
    slot: KeyVaultSlot,
    vault_root_key: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
) -> bytes:
    """Authenticate and unwrap one DEK without selecting a key version."""

    exact_slot = _require_vault_slot(slot)
    exact_root_key = _require_exact_bytes(
        vault_root_key, "vault_root_key", VAULT_ROOT_KEY_LEN
    )
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    aad = build_vault_slot_aad(exact_file_id, exact_slot)
    kek = derive_vault_slot_kek(exact_root_key, exact_file_id, exact_slot)
    try:
        try:
            dek = AESGCM(kek).decrypt(
                exact_slot.wrap_nonce,
                exact_slot.wrapped_dek,
                aad,
            )
        except InvalidTag as exc:
            raise VaultSlotAuthenticationError(
                "Vault key or authenticated Key Vault slot data is invalid"
            ) from exc
    finally:
        del kek
    if len(dek) != DEK_LEN:
        raise VaultSlotAuthenticationError("unwrapped DEK has invalid length")
    return dek
