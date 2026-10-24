"""In-memory Argon2id and AES-256-GCM password-slot operations.

This module wraps and unwraps only a 32-byte DEK. It performs no filesystem
I/O, stores no password, does not use a nickname, and does not activate GUI
operations.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from mokosh_v2_key_slots import (
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    GCM_NONCE_LEN,
    SALT_LEN,
    SLOT_ID_LEN,
    KeySlotError,
    PasswordSlot,
    key_slot_to_mapping,
)


DEK_LEN = 32
KEK_LEN = 32
FILE_ID_LEN = 16
MAX_PASSWORD_UTF8_LEN = 1024
PASSWORD_SLOT_AAD_DOMAIN = b"MOKOSH2\x00PASSWORD-SLOT-WRAP\x00"


class PasswordSlotCryptoError(KeySlotError):
    """Base class for password-slot cryptographic failures."""


class PasswordInputError(PasswordSlotCryptoError):
    """A password, DEK, file identifier, or random value is invalid."""


class PasswordSlotPolicyError(PasswordSlotCryptoError):
    """Argon2id parameters exceed the local execution policy."""


class PasswordSlotAuthenticationError(PasswordSlotCryptoError):
    """The password or authenticated password-slot data is invalid."""


@dataclass(frozen=True, slots=True)
class PasswordKDFPolicy:
    max_time_cost: int = 5
    max_memory_kib: int = 256 * 1024
    max_parallelism: int = 8


DEFAULT_PASSWORD_KDF_POLICY = PasswordKDFPolicy()


def _require_plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise PasswordSlotPolicyError(f"{field} must be an integer")
    return value


def validate_password_kdf_policy(policy: PasswordKDFPolicy) -> None:
    if not isinstance(policy, PasswordKDFPolicy):
        raise PasswordSlotPolicyError("policy must be PasswordKDFPolicy")
    values = (
        (
            policy.max_time_cost,
            "max_time_cost",
            ARGON2_MIN_TIME_COST,
            ARGON2_MAX_TIME_COST,
        ),
        (
            policy.max_memory_kib,
            "max_memory_kib",
            ARGON2_MIN_MEMORY_KIB,
            ARGON2_MAX_MEMORY_KIB,
        ),
        (
            policy.max_parallelism,
            "max_parallelism",
            ARGON2_MIN_PARALLELISM,
            ARGON2_MAX_PARALLELISM,
        ),
    )
    for value, field, minimum, maximum in values:
        parsed = _require_plain_int(value, field)
        if not minimum <= parsed <= maximum:
            raise PasswordSlotPolicyError(
                f"{field} must be between {minimum} and {maximum}"
            )


def validate_password_slot_for_execution(
    slot: PasswordSlot,
    *,
    policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY,
) -> None:
    if not isinstance(slot, PasswordSlot):
        raise PasswordSlotCryptoError("slot must be PasswordSlot")
    key_slot_to_mapping(slot)
    validate_password_kdf_policy(policy)
    if slot.time_cost > policy.max_time_cost:
        raise PasswordSlotPolicyError("time_cost exceeds local KDF policy")
    if slot.memory_kib > policy.max_memory_kib:
        raise PasswordSlotPolicyError("memory_kib exceeds local KDF policy")
    if slot.parallelism > policy.max_parallelism:
        raise PasswordSlotPolicyError("parallelism exceeds local KDF policy")


def _password_bytes(password: Any) -> bytes:
    if not isinstance(password, str):
        raise PasswordInputError("password must be text")
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PasswordInputError("password must be valid UTF-8 text") from exc
    if not 1 <= len(encoded) <= MAX_PASSWORD_UTF8_LEN:
        raise PasswordInputError(
            f"password UTF-8 length must be between 1 and {MAX_PASSWORD_UTF8_LEN} bytes"
        )
    return encoded


def _require_exact_bytes(value: Any, field: str, expected_len: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PasswordInputError(f"{field} must be bytes")
    encoded = bytes(value)
    if len(encoded) != expected_len:
        raise PasswordInputError(
            f"{field} must contain exactly {expected_len} bytes"
        )
    return encoded


def _random_exact(length: int, field: str) -> bytes:
    value = os.urandom(length)
    if not isinstance(value, bytes) or len(value) != length:
        raise PasswordInputError(f"secure random source returned invalid {field}")
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_password_slot_aad(
    file_id: bytes | bytearray | memoryview,
    slot: PasswordSlot,
) -> bytes:
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    mapping = key_slot_to_mapping(slot)
    del mapping["wrapped_dek"]
    mapping["file_id"] = _b64url(exact_file_id)
    canonical_metadata = json.dumps(
        mapping,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return PASSWORD_SLOT_AAD_DOMAIN + canonical_metadata


def derive_password_kek(
    password: str,
    slot: PasswordSlot,
    *,
    policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY,
) -> bytes:
    validate_password_slot_for_execution(slot, policy=policy)
    password_bytes = _password_bytes(password)
    kdf = Argon2id(
        salt=slot.salt,
        length=KEK_LEN,
        iterations=slot.time_cost,
        lanes=slot.parallelism,
        memory_cost=slot.memory_kib,
    )
    kek = kdf.derive(password_bytes)
    if len(kek) != KEK_LEN:
        raise AssertionError("internal Argon2id output-length invariant failed")
    return kek


def create_password_slot(
    password: str,
    dek: bytes | bytearray | memoryview,
    file_id: bytes | bytearray | memoryview,
    *,
    time_cost: int = 3,
    memory_kib: int = 64 * 1024,
    parallelism: int = 4,
    policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY,
) -> PasswordSlot:
    exact_dek = _require_exact_bytes(dek, "dek", DEK_LEN)
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    _password_bytes(password)

    provisional = PasswordSlot(
        slot_id=_random_exact(SLOT_ID_LEN, "slot_id"),
        salt=_random_exact(SALT_LEN, "salt"),
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
        wrap_nonce=_random_exact(GCM_NONCE_LEN, "wrap_nonce"),
        wrapped_dek=b"\x00" * (DEK_LEN + 16),
    )
    validate_password_slot_for_execution(provisional, policy=policy)
    aad = build_password_slot_aad(exact_file_id, provisional)
    kek = derive_password_kek(password, provisional, policy=policy)
    try:
        wrapped_dek = AESGCM(kek).encrypt(
            provisional.wrap_nonce,
            exact_dek,
            aad,
        )
    finally:
        del kek

    result = PasswordSlot(
        slot_id=provisional.slot_id,
        salt=provisional.salt,
        time_cost=provisional.time_cost,
        memory_kib=provisional.memory_kib,
        parallelism=provisional.parallelism,
        wrap_nonce=provisional.wrap_nonce,
        wrapped_dek=wrapped_dek,
    )
    key_slot_to_mapping(result)
    return result


def unwrap_password_slot(
    slot: PasswordSlot,
    password: str,
    file_id: bytes | bytearray | memoryview,
    *,
    policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY,
) -> bytes:
    validate_password_slot_for_execution(slot, policy=policy)
    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    aad = build_password_slot_aad(exact_file_id, slot)
    kek = derive_password_kek(password, slot, policy=policy)
    try:
        try:
            dek = AESGCM(kek).decrypt(slot.wrap_nonce, slot.wrapped_dek, aad)
        except InvalidTag as exc:
            raise PasswordSlotAuthenticationError(
                "password or authenticated password-slot data is invalid"
            ) from exc
    finally:
        del kek
    if len(dek) != DEK_LEN:
        raise PasswordSlotAuthenticationError("unwrapped DEK has invalid length")
    return dek
