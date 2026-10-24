"""In-memory hybrid X25519 + ML-KEM-768 contact-slot operations.

Both shared secrets are mandatory input to HKDF-SHA-256. The module has no
classic-only fallback and performs no contact storage, trust, filesystem,
network, or GUI operations.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mokosh_v2_key_slots import (
    CONTACT_HYBRID_SUITE,
    GCM_NONCE_LEN,
    MLKEM768_CIPHERTEXT_LEN,
    SLOT_ID_LEN,
    X25519_PUBLIC_KEY_LEN,
    ContactHybridSlot,
    KeySlotError,
    key_slot_to_mapping,
)


X25519_PRIVATE_KEY_LEN = 32
X25519_SHARED_SECRET_LEN = 32
MLKEM768_PUBLIC_KEY_LEN = 1184
MLKEM768_PRIVATE_SEED_LEN = 64
MLKEM768_SHARED_SECRET_LEN = 32
FILE_ID_LEN = 16
DEK_LEN = 32
KEK_LEN = 32
CONTACT_SLOT_HKDF_INFO_DOMAIN = b"MOKOSH2\x00CONTACT-HYBRID-SLOT-KEK\x00"
CONTACT_SLOT_AAD_DOMAIN = b"MOKOSH2\x00CONTACT-HYBRID-SLOT-WRAP\x00"


class ContactSlotCryptoError(KeySlotError):
    """Base class for hybrid contact-slot cryptographic failures."""


class ContactSlotInputError(ContactSlotCryptoError):
    """A key, DEK, file identifier, slot, or random value is invalid."""


class ContactSlotAuthenticationError(ContactSlotCryptoError):
    """Recipient keys or authenticated contact-slot data are invalid."""


class ContactSlotEnvironmentError(ContactSlotCryptoError):
    """The required ML-KEM-768 implementation is unavailable."""


def _mlkem_module():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as exc:
        raise ContactSlotEnvironmentError("ML-KEM-768 is unavailable") from exc
    return mlkem


def _require_exact_bytes(value: Any, field: str, expected_len: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ContactSlotInputError(f"{field} must be bytes")
    encoded = bytes(value)
    if len(encoded) != expected_len:
        raise ContactSlotInputError(
            f"{field} must contain exactly {expected_len} bytes"
        )
    return encoded


def _require_contact_slot(slot: Any) -> ContactHybridSlot:
    if not isinstance(slot, ContactHybridSlot):
        raise ContactSlotCryptoError("slot must be ContactHybridSlot")
    try:
        key_slot_to_mapping(slot)
    except KeySlotError as exc:
        raise ContactSlotCryptoError("hybrid contact slot is invalid") from exc
    return slot


def _random_exact(length: int, field: str) -> bytes:
    value = os.urandom(length)
    if not isinstance(value, bytes) or len(value) != length:
        raise ContactSlotInputError(f"secure random source returned invalid {field}")
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
    slot: ContactHybridSlot,
) -> dict[str, Any]:
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    exact_slot = _require_contact_slot(slot)
    return {
        "ephemeral_x25519_public_key": _b64url(
            exact_slot.ephemeral_x25519_public_key
        ),
        "file_id": _b64url(exact_file_id),
        "mlkem_ciphertext": _b64url(exact_slot.mlkem_ciphertext),
        "recipient_key_version": exact_slot.recipient_key_version,
        "slot_id": _b64url(exact_slot.slot_id),
        "suite": CONTACT_HYBRID_SUITE,
        "type": "CONTACT_HYBRID",
    }


def build_contact_slot_hkdf_info(
    file_id: bytes | bytearray | memoryview,
    slot: ContactHybridSlot,
) -> bytes:
    return CONTACT_SLOT_HKDF_INFO_DOMAIN + _canonical_json(
        _common_bound_metadata(file_id, slot)
    )


def build_contact_slot_aad(
    file_id: bytes | bytearray | memoryview,
    slot: ContactHybridSlot,
) -> bytes:
    metadata = _common_bound_metadata(file_id, slot)
    metadata["wrap_nonce"] = _b64url(slot.wrap_nonce)
    return CONTACT_SLOT_AAD_DOMAIN + _canonical_json(metadata)


def derive_contact_slot_kek(
    x25519_shared_secret: bytes | bytearray | memoryview,
    mlkem_shared_secret: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
    slot: ContactHybridSlot,
) -> bytes:
    exact_x25519 = _require_exact_bytes(
        x25519_shared_secret,
        "x25519_shared_secret",
        X25519_SHARED_SECRET_LEN,
    )
    exact_mlkem = _require_exact_bytes(
        mlkem_shared_secret,
        "mlkem_shared_secret",
        MLKEM768_SHARED_SECRET_LEN,
    )
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    info = build_contact_slot_hkdf_info(exact_file_id, slot)
    ikm = (
        len(exact_x25519).to_bytes(2, "big")
        + exact_x25519
        + len(exact_mlkem).to_bytes(2, "big")
        + exact_mlkem
    )
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=KEK_LEN,
        salt=exact_file_id,
        info=info,
    ).derive(ikm)
    if len(kek) != KEK_LEN:
        raise AssertionError("internal hybrid HKDF output-length invariant failed")
    return kek


def _load_x25519_public(raw: bytes):
    try:
        return x25519.X25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ContactSlotInputError("recipient X25519 public key is invalid") from exc


def _load_mlkem_public(raw: bytes):
    mlkem = _mlkem_module()
    try:
        return mlkem.MLKEM768PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ContactSlotInputError("recipient ML-KEM-768 public key is invalid") from exc


def _load_x25519_private(raw: bytes):
    try:
        return x25519.X25519PrivateKey.from_private_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ContactSlotInputError("recipient X25519 private key is invalid") from exc


def _load_mlkem_private(raw: bytes):
    mlkem = _mlkem_module()
    try:
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ContactSlotInputError("recipient ML-KEM-768 private seed is invalid") from exc


def create_contact_slot(
    recipient_x25519_public_key: bytes | bytearray | memoryview,
    recipient_mlkem768_public_key: bytes | bytearray | memoryview,
    recipient_key_version: int,
    dek: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
) -> ContactHybridSlot:
    exact_x_public = _require_exact_bytes(
        recipient_x25519_public_key,
        "recipient_x25519_public_key",
        X25519_PUBLIC_KEY_LEN,
    )
    exact_pq_public = _require_exact_bytes(
        recipient_mlkem768_public_key,
        "recipient_mlkem768_public_key",
        MLKEM768_PUBLIC_KEY_LEN,
    )
    exact_dek = _require_exact_bytes(dek, "dek", DEK_LEN)
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    _require_contact_slot(
        ContactHybridSlot(
            slot_id=b"\x00" * SLOT_ID_LEN,
            recipient_key_version=recipient_key_version,
            ephemeral_x25519_public_key=b"\x00" * X25519_PUBLIC_KEY_LEN,
            mlkem_ciphertext=b"\x00" * MLKEM768_CIPHERTEXT_LEN,
            wrap_nonce=b"\x00" * GCM_NONCE_LEN,
            wrapped_dek=b"\x00" * (DEK_LEN + 16),
        )
    )
    slot_id = _random_exact(SLOT_ID_LEN, "slot_id")
    wrap_nonce = _random_exact(GCM_NONCE_LEN, "wrap_nonce")
    x_public = _load_x25519_public(exact_x_public)
    pq_public = _load_mlkem_public(exact_pq_public)

    ephemeral_private = x25519.X25519PrivateKey.generate()
    try:
        x_shared = ephemeral_private.exchange(x_public)
    except ValueError as exc:
        raise ContactSlotInputError("recipient X25519 public key is invalid") from exc
    ephemeral_public_raw = ephemeral_private.public_key().public_bytes_raw()

    try:
        pq_shared, pq_ciphertext = pq_public.encapsulate()
    except ValueError as exc:
        raise ContactSlotInputError("recipient ML-KEM-768 public key is invalid") from exc
    exact_x_shared = _require_exact_bytes(
        x_shared, "X25519 shared secret", X25519_SHARED_SECRET_LEN
    )
    exact_pq_shared = _require_exact_bytes(
        pq_shared, "ML-KEM-768 shared secret", MLKEM768_SHARED_SECRET_LEN
    )
    exact_pq_ciphertext = _require_exact_bytes(
        pq_ciphertext, "ML-KEM-768 ciphertext", MLKEM768_CIPHERTEXT_LEN
    )

    provisional = ContactHybridSlot(
        slot_id=slot_id,
        recipient_key_version=recipient_key_version,
        ephemeral_x25519_public_key=ephemeral_public_raw,
        mlkem_ciphertext=exact_pq_ciphertext,
        wrap_nonce=wrap_nonce,
        wrapped_dek=b"\x00" * (DEK_LEN + 16),
    )
    _require_contact_slot(provisional)
    aad = build_contact_slot_aad(exact_file_id, provisional)
    kek = derive_contact_slot_kek(
        exact_x_shared, exact_pq_shared, exact_file_id, provisional
    )
    try:
        wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, exact_dek, aad)
    finally:
        del kek

    result = ContactHybridSlot(
        slot_id=provisional.slot_id,
        recipient_key_version=provisional.recipient_key_version,
        ephemeral_x25519_public_key=provisional.ephemeral_x25519_public_key,
        mlkem_ciphertext=provisional.mlkem_ciphertext,
        wrap_nonce=provisional.wrap_nonce,
        wrapped_dek=wrapped_dek,
    )
    _require_contact_slot(result)
    return result


def unwrap_contact_slot(
    slot: ContactHybridSlot,
    recipient_x25519_private_key: bytes | bytearray | memoryview,
    recipient_mlkem768_private_seed: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
) -> bytes:
    exact_slot = _require_contact_slot(slot)
    exact_x_private = _require_exact_bytes(
        recipient_x25519_private_key,
        "recipient_x25519_private_key",
        X25519_PRIVATE_KEY_LEN,
    )
    exact_pq_private = _require_exact_bytes(
        recipient_mlkem768_private_seed,
        "recipient_mlkem768_private_seed",
        MLKEM768_PRIVATE_SEED_LEN,
    )
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    x_private = _load_x25519_private(exact_x_private)
    pq_private = _load_mlkem_private(exact_pq_private)
    try:
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            exact_slot.ephemeral_x25519_public_key
        )
        x_shared = x_private.exchange(ephemeral_public)
        pq_shared = pq_private.decapsulate(exact_slot.mlkem_ciphertext)
    except (TypeError, ValueError) as exc:
        raise ContactSlotAuthenticationError(
            "recipient keys or authenticated hybrid contact-slot data are invalid"
        ) from exc
    try:
        exact_x_shared = _require_exact_bytes(
            x_shared, "X25519 shared secret", X25519_SHARED_SECRET_LEN
        )
        exact_pq_shared = _require_exact_bytes(
            pq_shared, "ML-KEM-768 shared secret", MLKEM768_SHARED_SECRET_LEN
        )
    except ContactSlotInputError as exc:
        raise ContactSlotAuthenticationError(
            "recipient keys or authenticated hybrid contact-slot data are invalid"
        ) from exc
    aad = build_contact_slot_aad(exact_file_id, exact_slot)
    kek = derive_contact_slot_kek(
        exact_x_shared, exact_pq_shared, exact_file_id, exact_slot
    )
    try:
        try:
            dek = AESGCM(kek).decrypt(
                exact_slot.wrap_nonce, exact_slot.wrapped_dek, aad
            )
        except InvalidTag as exc:
            raise ContactSlotAuthenticationError(
                "recipient keys or authenticated hybrid contact-slot data are invalid"
            ) from exc
    finally:
        del kek
    if len(dek) != DEK_LEN:
        raise ContactSlotAuthenticationError("unwrapped DEK has invalid length")
    return dek
