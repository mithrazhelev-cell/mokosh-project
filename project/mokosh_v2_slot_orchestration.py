"""Strict in-memory orchestration for MOKOSH v2 key slots.

One builder owns one random file identifier and one random 32-byte DEK.  Each
slot added through it wraps that same DEK.  Unwrapping is deliberately limited
to one explicitly selected slot and one matching credential type; this module
never searches other slots or falls back to a weaker mechanism.

No filesystem, contact trust, Key Vault storage, recovery, network, or GUI
operation is performed here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Sequence

from mokosh_v2_contact_slots import create_contact_slot, unwrap_contact_slot
from mokosh_v2_crypto import generate_dek
from mokosh_v2_key_slots import (
    MAX_KEY_SLOTS,
    SLOT_ID_LEN,
    ContactHybridSlot,
    KeySlot,
    KeySlotError,
    KeyVaultSlot,
    PasswordSlot,
    key_slots_to_list,
    parse_key_slots,
)
from mokosh_v2_password_slots import (
    DEFAULT_PASSWORD_KDF_POLICY,
    PasswordKDFPolicy,
    create_password_slot,
    unwrap_password_slot,
)
from mokosh_v2_vault_slots import create_vault_slot, unwrap_vault_slot


FILE_ID_LEN = 16
DEK_LEN = 32
_PLAN_BUILDER_PROOF = object()


class SlotOrchestrationError(KeySlotError):
    """A slot plan, selection, credential, or builder state is invalid."""


class SlotSelectionError(SlotOrchestrationError):
    """The requested public slot identifier is invalid or not present."""


class SlotCredentialMismatchError(SlotOrchestrationError):
    """The selected slot and supplied credential have different types."""


class SlotBuilderStateError(SlotOrchestrationError):
    """A builder is empty, full, or has already been finalized."""


@dataclass(frozen=True, slots=True)
class PasswordCredential:
    password: str = field(repr=False)
    policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY


@dataclass(frozen=True, slots=True)
class VaultCredential:
    vault_root_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ContactCredential:
    recipient_x25519_private_key: bytes = field(repr=False)
    recipient_mlkem768_private_seed: bytes = field(repr=False)


SlotCredential = PasswordCredential | VaultCredential | ContactCredential


def _require_exact_bytes(value: Any, field_name: str, expected_len: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SlotOrchestrationError(f"{field_name} must be bytes")
    exact = bytes(value)
    if len(exact) != expected_len:
        raise SlotOrchestrationError(
            f"{field_name} must contain exactly {expected_len} bytes"
        )
    return exact


def _random_file_id() -> bytes:
    value = os.urandom(FILE_ID_LEN)
    if not isinstance(value, bytes) or len(value) != FILE_ID_LEN:
        raise SlotOrchestrationError("secure random source returned invalid file_id")
    return value


@dataclass(frozen=True, slots=True)
class EnvelopeKeyPlan:
    """Final immutable in-memory DEK and its independently wrapped slots."""

    file_id: bytes
    dek: bytes = field(repr=False)
    slots: tuple[KeySlot, ...]
    _builder_proof: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._builder_proof is not _PLAN_BUILDER_PROOF:
            raise SlotOrchestrationError(
                "EnvelopeKeyPlan must be finalized by KeySlotPlanBuilder"
            )
        exact_file_id = _require_exact_bytes(self.file_id, "file_id", FILE_ID_LEN)
        exact_dek = _require_exact_bytes(self.dek, "dek", DEK_LEN)
        if not isinstance(self.slots, tuple) or not self.slots:
            raise SlotOrchestrationError("plan must contain at least one key slot")
        key_slots_to_list(self.slots)
        object.__setattr__(self, "file_id", exact_file_id)
        object.__setattr__(self, "dek", exact_dek)

    def header_key_slots(self) -> list[dict[str, Any]]:
        """Return a newly allocated, strictly validated header representation."""

        return key_slots_to_list(self.slots)


class KeySlotPlanBuilder:
    """Create independent wrappers for exactly one in-memory envelope DEK."""

    def __init__(
        self,
        *,
        file_id: bytes | bytearray | memoryview | None = None,
        dek: bytes | bytearray | memoryview | None = None,
    ) -> None:
        self._file_id = (
            _random_file_id()
            if file_id is None
            else _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
        )
        self._dek = (
            generate_dek()
            if dek is None
            else _require_exact_bytes(dek, "dek", DEK_LEN)
        )
        self._slots: list[KeySlot] = []
        self._finished = False

    @property
    def file_id(self) -> bytes:
        return self._file_id

    @property
    def slot_count(self) -> int:
        return len(self._slots)

    def _before_add(self) -> None:
        if self._finished:
            raise SlotBuilderStateError("builder has already been finalized")
        if len(self._slots) >= MAX_KEY_SLOTS:
            raise SlotBuilderStateError(
                f"builder cannot contain more than {MAX_KEY_SLOTS} slots"
            )

    def _append(self, slot: KeySlot) -> KeySlot:
        candidate = (*self._slots, slot)
        key_slots_to_list(candidate)
        self._slots.append(slot)
        return slot

    def add_password(
        self,
        password: str,
        *,
        time_cost: int = 3,
        memory_kib: int = 64 * 1024,
        parallelism: int = 4,
        policy: PasswordKDFPolicy = DEFAULT_PASSWORD_KDF_POLICY,
    ) -> PasswordSlot:
        self._before_add()
        slot = create_password_slot(
            password,
            self._dek,
            self._file_id,
            time_cost=time_cost,
            memory_kib=memory_kib,
            parallelism=parallelism,
            policy=policy,
        )
        return self._append(slot)  # type: ignore[return-value]

    def add_vault(
        self,
        vault_root_key: bytes | bytearray | memoryview,
        vault_key_version: int,
    ) -> KeyVaultSlot:
        self._before_add()
        slot = create_vault_slot(
            vault_root_key,
            vault_key_version,
            self._dek,
            self._file_id,
        )
        return self._append(slot)  # type: ignore[return-value]

    def add_contact(
        self,
        recipient_x25519_public_key: bytes | bytearray | memoryview,
        recipient_mlkem768_public_key: bytes | bytearray | memoryview,
        recipient_key_version: int,
    ) -> ContactHybridSlot:
        self._before_add()
        slot = create_contact_slot(
            recipient_x25519_public_key,
            recipient_mlkem768_public_key,
            recipient_key_version,
            self._dek,
            self._file_id,
        )
        return self._append(slot)  # type: ignore[return-value]

    def finish(self) -> EnvelopeKeyPlan:
        if self._finished:
            raise SlotBuilderStateError("builder has already been finalized")
        if not self._slots:
            raise SlotBuilderStateError("at least one key slot is required")
        plan = EnvelopeKeyPlan(
            self._file_id,
            self._dek,
            tuple(self._slots),
            _builder_proof=_PLAN_BUILDER_PROOF,
        )
        self._finished = True
        self._dek = b""
        self._slots.clear()
        return plan


def select_key_slot(
    key_slots: Sequence[KeySlot] | list[dict[str, Any]],
    slot_id: bytes | bytearray | memoryview,
) -> KeySlot:
    """Select exactly one slot by its public identifier, without fallback."""

    exact_slot_id = _require_exact_bytes(slot_id, "slot_id", SLOT_ID_LEN)
    if isinstance(key_slots, list) and (
        not key_slots or isinstance(key_slots[0], dict)
    ):
        parsed = parse_key_slots(key_slots)
    else:
        try:
            mappings = key_slots_to_list(key_slots)  # type: ignore[arg-type]
        except (TypeError, KeySlotError) as exc:
            raise SlotSelectionError("key_slots are invalid") from exc
        parsed = parse_key_slots(mappings)
    if not parsed:
        raise SlotSelectionError("key_slots must not be empty")
    for slot in parsed:
        if slot.slot_id == exact_slot_id:
            return slot
    raise SlotSelectionError("selected slot_id is not present")


def unwrap_selected_slot(
    key_slots: Sequence[KeySlot] | list[dict[str, Any]],
    file_id: bytes | bytearray | memoryview,
    slot_id: bytes | bytearray | memoryview,
    credential: SlotCredential,
) -> bytes:
    """Unwrap one selected slot using only its exact credential mechanism."""

    exact_file_id = _require_exact_bytes(file_id, "file_id", FILE_ID_LEN)
    slot = select_key_slot(key_slots, slot_id)

    if isinstance(slot, PasswordSlot):
        if not isinstance(credential, PasswordCredential):
            raise SlotCredentialMismatchError(
                "PASSWORD slot requires PasswordCredential"
            )
        dek = unwrap_password_slot(
            slot,
            credential.password,
            exact_file_id,
            policy=credential.policy,
        )
    elif isinstance(slot, KeyVaultSlot):
        if not isinstance(credential, VaultCredential):
            raise SlotCredentialMismatchError(
                "KEY_VAULT slot requires VaultCredential"
            )
        dek = unwrap_vault_slot(slot, credential.vault_root_key, exact_file_id)
    elif isinstance(slot, ContactHybridSlot):
        if not isinstance(credential, ContactCredential):
            raise SlotCredentialMismatchError(
                "CONTACT_HYBRID slot requires ContactCredential"
            )
        dek = unwrap_contact_slot(
            slot,
            credential.recipient_x25519_private_key,
            credential.recipient_mlkem768_private_seed,
            exact_file_id,
        )
    else:  # Defensive: strict parsing above should make this unreachable.
        raise SlotSelectionError("selected slot type is unsupported")

    return _require_exact_bytes(dek, "unwrapped dek", DEK_LEN)
