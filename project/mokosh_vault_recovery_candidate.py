"""Strict in-memory Vault candidate preparation from offline recovery.

Stage 2.6 consumes one exact latest durable schema-two Vault, one verified
private ``.mokr`` record, its separately supplied recovery root, and an
explicit new password.  It creates and verifies a next-revision encrypted
Vault candidate only in memory.  The returned prepared object is a process-
local, one-shot misuse-prevention contract for a later stage.

This module performs no Vault publish, file creation, overwrite, rename,
unlink, key deletion, user-file mutation, GUI work, network access, telemetry,
logging, software update discovery, or automatic recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mokosh_vault_format import (
    DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_VAULT_KDF_POLICY,
    MAX_ARGON2_MEMORY_KIB,
    MAX_ARGON2_PARALLELISM,
    MAX_ARGON2_TIME_COST,
    MAX_VAULT_REVISION,
    VAULT_KEYRING_PAYLOAD_SCHEMA,
    VaultError,
    VaultKDFPolicy,
    _password_bytes,
    _rewrap_keyring_vault,
    _strict_utc,
    _validate_kdf_values,
    parse_vault,
    unlock_keyring_vault,
    utc_now as vault_utc_now,
)
from mokosh_vault_keyring import (
    MAX_KEY_RECORDS,
    MAX_KEY_VERSION,
    VaultKeyringError,
    encode_keyring,
)
from mokosh_vault_recovery import (
    RECOVERY_ID_LEN,
    RECOVERY_ROOT_KEY_LEN,
    RECOVERY_SHA256_LEN,
    VaultRecoveryError,
    _decrypt_keyring,
    rehearse_recovery,
)
from mokosh_vault_recovery_storage import (
    MAX_RECOVERY_FILE_BYTES,
    VaultRecoveryStorageError,
    _ImportedRecoveryFile,
    _read_recovery_path,
    _verified_latest_vault,
)
from mokosh_vault_storage import VaultGenerationReceipt, VaultStorage


RECOVERY_CANDIDATE_AUTHORIZATION_FORMAT = (
    "MOKOSH-VAULT-RECOVERY-CANDIDATE-AUTHORIZATION"
)
RECOVERY_CANDIDATE_AUTHORIZATION_VERSION = 1
RECOVERY_CANDIDATE_AUTHORIZATION_ID_BYTES = 16
VAULT_ID_LEN = 16
SHA256_LEN = 32
MAX_UINT64 = (1 << 64) - 1

_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")
_FORMAT_MAX_KDF_POLICY = VaultKDFPolicy(
    max_time_cost=MAX_ARGON2_TIME_COST,
    max_memory_kib=MAX_ARGON2_MEMORY_KIB,
    max_parallelism=MAX_ARGON2_PARALLELISM,
)


class VaultRecoveryCandidateError(VaultRecoveryError):
    """Base class for strict recovery-candidate failures."""


class VaultRecoveryCandidateInputError(VaultRecoveryCandidateError):
    """An explicit decision, password, KDF, timestamp, or value is invalid."""


class VaultRecoveryCandidateStateError(VaultRecoveryCandidateError):
    """The durable Vault or recovery-file state is not exact and fresh."""


class VaultRecoveryCandidateCreationError(VaultRecoveryCandidateError):
    """A verified in-memory candidate could not be created."""


class VaultRecoveryCandidateVerificationError(VaultRecoveryCandidateError):
    """A candidate, password, keyring digest, or evidence binding failed."""


class VaultRecoveryCandidateAuthorizationError(VaultRecoveryCandidateError):
    """The process-local one-shot authorization is invalid or consumed."""


class RecoveryCandidateDecision(str, Enum):
    PRESERVE = "preserve"
    AUTHORIZE_CANDIDATE = "authorize_candidate"


@dataclass(frozen=True, slots=True)
class VaultRecoveryCandidateEvidence:
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    source_vault_sha256: bytes
    record_sha256: bytes
    keyring_sha256: bytes
    candidate_sha256: bytes
    updated_utc: str
    time_cost: int
    memory_kib: int
    parallelism: int
    active_key_version: int
    key_count: int
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    encoded_size: int


@dataclass(frozen=True, slots=True)
class VaultRecoveryCandidateAuthorization:
    authorization_id: str
    evidence: VaultRecoveryCandidateEvidence
    format: str = RECOVERY_CANDIDATE_AUTHORIZATION_FORMAT
    version: int = RECOVERY_CANDIDATE_AUTHORIZATION_VERSION
    user_confirmed: bool = True
    exact_sources_verified: bool = True
    candidate_verified: bool = True
    executor_rescan_required: bool = True
    single_use_claim: bool = True
    filesystem_publish_permitted: bool = False
    key_deletion_permitted: bool = False
    user_file_mutation_permitted: bool = False


@dataclass(frozen=True, slots=True)
class ClaimedVaultRecoveryCandidate:
    candidate: bytes = field(repr=False)
    authorization: VaultRecoveryCandidateAuthorization
    evidence: VaultRecoveryCandidateEvidence

    def __copy__(self) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "claimed recovery candidate cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "claimed recovery candidate cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "claimed recovery candidate cannot be serialized"
        )


class PreparedVaultRecoveryCandidate:
    """Hold one verified encrypted candidate until it is claimed once."""

    __slots__ = ("_authorization", "_candidate", "_claimed", "_evidence")

    def __init__(
        self,
        candidate: bytes,
        evidence: VaultRecoveryCandidateEvidence,
        authorization: VaultRecoveryCandidateAuthorization,
    ) -> None:
        exact_candidate = _candidate_bytes(candidate)
        exact_evidence = _validate_evidence(
            evidence,
            policy=_FORMAT_MAX_KDF_POLICY,
        )
        exact_authorization = _validate_authorization(authorization)
        if exact_authorization.evidence != exact_evidence:
            raise VaultRecoveryCandidateAuthorizationError(
                "authorization evidence differs from the candidate evidence"
            )
        if not hmac.compare_digest(
            hashlib.sha256(exact_candidate).digest(),
            exact_evidence.candidate_sha256,
        ):
            raise VaultRecoveryCandidateAuthorizationError(
                "prepared candidate digest differs from its authorization"
            )
        self._candidate = exact_candidate
        self._evidence = exact_evidence
        self._authorization = exact_authorization
        self._claimed = False

    @property
    def evidence(self) -> VaultRecoveryCandidateEvidence:
        return self._evidence

    @property
    def claimed(self) -> bool:
        return self._claimed

    def claim_once(self) -> ClaimedVaultRecoveryCandidate:
        if self._claimed:
            raise VaultRecoveryCandidateAuthorizationError(
                "recovery candidate authorization was already claimed"
            )
        self._claimed = True
        return ClaimedVaultRecoveryCandidate(
            candidate=self._candidate,
            authorization=self._authorization,
            evidence=self._evidence,
        )

    def __repr__(self) -> str:
        return f"PreparedVaultRecoveryCandidate(claimed={self._claimed})"

    def __copy__(self) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "prepared recovery candidate cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "prepared recovery candidate cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoveryCandidateAuthorizationError(
            "prepared recovery candidate cannot be serialized"
        )


def _exact_bytes(value: Any, field_name: str, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultRecoveryCandidateInputError(f"{field_name} must be bytes")
    result = bytes(value)
    if len(result) != length:
        raise VaultRecoveryCandidateInputError(
            f"{field_name} must contain exactly {length} bytes"
        )
    return result


def _candidate_bytes(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate must be bytes"
        )
    result = bytes(value)
    if not result:
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate must not be empty"
        )
    return result


def _plain_uint(
    value: Any,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_UINT64,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise VaultRecoveryCandidateVerificationError(
            f"{field_name} must be a bounded integer"
        )
    return value


def _evidence_bytes(value: Any, field_name: str, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise VaultRecoveryCandidateVerificationError(
            f"{field_name} must be exact immutable bytes"
        )
    return value


def _validate_evidence(
    value: Any,
    *,
    policy: VaultKDFPolicy,
) -> VaultRecoveryCandidateEvidence:
    if not isinstance(value, VaultRecoveryCandidateEvidence):
        raise VaultRecoveryCandidateVerificationError(
            "candidate evidence type is invalid"
        )
    _evidence_bytes(value.recovery_id, "recovery_id", RECOVERY_ID_LEN)
    _evidence_bytes(value.vault_id, "vault_id", VAULT_ID_LEN)
    _evidence_bytes(
        value.source_vault_sha256,
        "source_vault_sha256",
        RECOVERY_SHA256_LEN,
    )
    _evidence_bytes(value.record_sha256, "record_sha256", SHA256_LEN)
    _evidence_bytes(value.keyring_sha256, "keyring_sha256", SHA256_LEN)
    _evidence_bytes(value.candidate_sha256, "candidate_sha256", SHA256_LEN)
    source_revision = _plain_uint(
        value.source_revision,
        "source_revision",
        minimum=1,
        maximum=MAX_VAULT_REVISION,
    )
    target_revision = _plain_uint(
        value.target_revision,
        "target_revision",
        minimum=1,
        maximum=MAX_VAULT_REVISION,
    )
    if source_revision >= MAX_VAULT_REVISION or target_revision != source_revision + 1:
        raise VaultRecoveryCandidateVerificationError(
            "candidate revision is not the exact next revision"
        )
    try:
        _strict_utc(value.updated_utc, "updated_utc")
        checked = _validate_kdf_values(
            value.time_cost,
            value.memory_kib,
            value.parallelism,
            policy=policy,
        )
    except VaultError as exc:
        raise VaultRecoveryCandidateVerificationError(
            "candidate timestamp or KDF evidence is invalid"
        ) from exc
    if checked != (value.time_cost, value.memory_kib, value.parallelism):
        raise AssertionError("internal candidate KDF evidence invariant failed")
    active_version = _plain_uint(
        value.active_key_version,
        "active_key_version",
        minimum=1,
        maximum=MAX_KEY_VERSION,
    )
    key_count = _plain_uint(
        value.key_count,
        "key_count",
        minimum=1,
        maximum=MAX_KEY_RECORDS,
    )
    if active_version != key_count:
        raise VaultRecoveryCandidateVerificationError(
            "candidate keyring evidence is not contiguous"
        )
    _plain_uint(value.directory_device, "directory_device")
    _plain_uint(value.directory_inode, "directory_inode")
    _plain_uint(value.file_device, "file_device")
    _plain_uint(value.file_inode, "file_inode")
    _plain_uint(
        value.encoded_size,
        "encoded_size",
        minimum=1,
        maximum=MAX_RECOVERY_FILE_BYTES,
    )
    return value


def _validate_authorization(
    value: Any,
) -> VaultRecoveryCandidateAuthorization:
    if not isinstance(value, VaultRecoveryCandidateAuthorization):
        raise VaultRecoveryCandidateAuthorizationError(
            "recovery candidate authorization type is invalid"
        )
    if value.format != RECOVERY_CANDIDATE_AUTHORIZATION_FORMAT:
        raise VaultRecoveryCandidateAuthorizationError(
            "recovery candidate authorization format is unsupported"
        )
    if (
        type(value.version) is not int
        or value.version != RECOVERY_CANDIDATE_AUTHORIZATION_VERSION
    ):
        raise VaultRecoveryCandidateAuthorizationError(
            "recovery candidate authorization version is unsupported"
        )
    if (
        not isinstance(value.authorization_id, str)
        or len(value.authorization_id)
        != RECOVERY_CANDIDATE_AUTHORIZATION_ID_BYTES * 2
        or _LOWER_HEX_RE.fullmatch(value.authorization_id) is None
    ):
        raise VaultRecoveryCandidateAuthorizationError(
            "authorization_id must be canonical lowercase hexadecimal"
        )
    try:
        _validate_evidence(value.evidence, policy=_FORMAT_MAX_KDF_POLICY)
    except VaultRecoveryCandidateVerificationError as exc:
        raise VaultRecoveryCandidateAuthorizationError(
            "authorization evidence is invalid"
        ) from exc
    required_true = (
        value.user_confirmed,
        value.exact_sources_verified,
        value.candidate_verified,
        value.executor_rescan_required,
        value.single_use_claim,
    )
    if any(item is not True for item in required_true):
        raise VaultRecoveryCandidateAuthorizationError(
            "recovery candidate authorization policy is incomplete"
        )
    required_false = (
        value.filesystem_publish_permitted,
        value.key_deletion_permitted,
        value.user_file_mutation_permitted,
    )
    if any(item is not False for item in required_false):
        raise VaultRecoveryCandidateAuthorizationError(
            "Stage 2.6 authorization cannot permit mutation"
        )
    return value


def _new_authorization_id() -> str:
    try:
        value = os.urandom(RECOVERY_CANDIDATE_AUTHORIZATION_ID_BYTES)
    except Exception as exc:
        raise VaultRecoveryCandidateAuthorizationError(
            "authorization random source failed"
        ) from exc
    if (
        not isinstance(value, bytes)
        or len(value) != RECOVERY_CANDIDATE_AUTHORIZATION_ID_BYTES
    ):
        raise VaultRecoveryCandidateAuthorizationError(
            "authorization random source returned invalid bytes"
        )
    return value.hex()


def _validate_explicit_inputs(
    recovery_key: Any,
    new_password: Any,
    decision: Any,
    updated_utc: Any,
    time_cost: Any,
    memory_kib: Any,
    parallelism: Any,
    policy: VaultKDFPolicy,
) -> tuple[bytes, str | None, tuple[int, int, int]]:
    if not isinstance(decision, RecoveryCandidateDecision):
        raise VaultRecoveryCandidateInputError(
            "recovery candidate decision type is invalid"
        )
    if decision is not RecoveryCandidateDecision.AUTHORIZE_CANDIDATE:
        raise VaultRecoveryCandidateInputError(
            "recovery candidate creation was not explicitly authorized"
        )
    exact_key = _exact_bytes(
        recovery_key,
        "recovery_key",
        RECOVERY_ROOT_KEY_LEN,
    )
    try:
        _password_bytes(new_password)
        checked = _validate_kdf_values(
            time_cost,
            memory_kib,
            parallelism,
            policy=policy,
        )
        exact_updated = (
            None
            if updated_utc is None
            else _strict_utc(updated_utc, "updated_utc")
        )
    except VaultError as exc:
        raise VaultRecoveryCandidateInputError(
            "new password, KDF policy, or timestamp is invalid"
        ) from exc
    return exact_key, exact_updated, checked


def _same_imported_file(
    first: _ImportedRecoveryFile,
    second: _ImportedRecoveryFile,
) -> bool:
    return (
        first.directory_device == second.directory_device
        and first.directory_inode == second.directory_inode
        and first.file_device == second.file_device
        and first.file_inode == second.file_inode
        and first.encoded_size == second.encoded_size
        and hmac.compare_digest(first.record_sha256, second.record_sha256)
        and hmac.compare_digest(first.record, second.record)
    )


def verify_recovery_candidate(
    candidate: bytes | bytearray | memoryview,
    new_password: str,
    expected: VaultRecoveryCandidateEvidence,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> VaultRecoveryCandidateEvidence:
    """Verify one exact candidate and return only its non-secret evidence."""

    try:
        _password_bytes(new_password)
    except VaultError as exc:
        raise VaultRecoveryCandidateInputError(
            "new password is invalid"
        ) from exc
    evidence = _validate_evidence(expected, policy=policy)
    exact_candidate = _candidate_bytes(candidate)
    if not hmac.compare_digest(
        hashlib.sha256(exact_candidate).digest(),
        evidence.candidate_sha256,
    ):
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate digest differs from expected evidence"
        )
    try:
        parsed = parse_vault(
            exact_candidate,
            policy=policy,
            minimum_revision=evidence.target_revision,
        )
    except VaultError as exc:
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate format or policy is invalid"
        ) from exc
    header = parsed.header
    if (
        header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA
        or not hmac.compare_digest(header.vault_id, evidence.vault_id)
        or header.revision != evidence.target_revision
        or header.updated_utc != evidence.updated_utc
        or header.time_cost != evidence.time_cost
        or header.memory_kib != evidence.memory_kib
        or header.parallelism != evidence.parallelism
    ):
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate header differs from expected evidence"
        )
    try:
        confirmed, keyring = unlock_keyring_vault(
            exact_candidate,
            new_password,
            policy=policy,
            minimum_revision=evidence.target_revision,
        )
        keyring_bytes = encode_keyring(keyring)
    except (VaultError, VaultKeyringError) as exc:
        raise VaultRecoveryCandidateVerificationError(
            "Vault candidate password or authenticated payload is invalid"
        ) from exc
    try:
        if (
            confirmed.header != header
            or not hmac.compare_digest(
                hashlib.sha256(keyring_bytes).digest(),
                evidence.keyring_sha256,
            )
            or keyring.active_key_version != evidence.active_key_version
            or len(keyring.keys) != evidence.key_count
        ):
            raise VaultRecoveryCandidateVerificationError(
                "Vault candidate keyring differs from expected evidence"
            )
        return evidence
    finally:
        del keyring_bytes
        del keyring


def prepare_recovery_candidate(
    recovery_path: Any,
    recovery_key: bytes | bytearray | memoryview,
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    new_password: str,
    decision: RecoveryCandidateDecision,
    *,
    updated_utc: str | None = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> PreparedVaultRecoveryCandidate:
    """Prepare and verify one next-revision candidate without publishing it."""

    exact_key, requested_updated, checked_kdf = _validate_explicit_inputs(
        recovery_key,
        new_password,
        decision,
        updated_utc,
        time_cost,
        memory_kib,
        parallelism,
        policy,
    )
    try:
        current = _verified_latest_vault(storage, latest)
        source = parse_vault(
            current,
            policy=policy,
            minimum_revision=latest.revision,
        )
    except (VaultRecoveryStorageError, VaultError, AttributeError) as exc:
        raise VaultRecoveryCandidateStateError(
            "exact latest durable Vault state cannot be verified"
        ) from exc
    if (
        source.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA
        or source.header.revision != latest.revision
        or not hmac.compare_digest(source.header.vault_id, latest.vault_id)
        or not hmac.compare_digest(
            hashlib.sha256(current).digest(), latest.sha256
        )
    ):
        raise VaultRecoveryCandidateStateError(
            "latest receipt differs from the parsed schema-two Vault"
        )
    if source.header.revision >= MAX_VAULT_REVISION:
        raise VaultRecoveryCandidateStateError(
            "Vault revision counter is exhausted"
        )
    try:
        first = _read_recovery_path(recovery_path)
        first_rehearsal = rehearse_recovery(first.record, exact_key, current)
        keyring, keyring_digest = _decrypt_keyring(first.parsed, exact_key)
    except (OSError, VaultRecoveryError, VaultRecoveryStorageError) as exc:
        raise VaultRecoveryCandidateStateError(
            "recovery file, root, or Vault binding is invalid"
        ) from exc
    try:
        if not hmac.compare_digest(
            keyring_digest, first_rehearsal.keyring_sha256
        ):
            raise VaultRecoveryCandidateVerificationError(
                "recovered keyring digest differs from rehearsal evidence"
            )
        timestamp = requested_updated or vault_utc_now()
        try:
            timestamp = _strict_utc(timestamp, "updated_utc")
        except VaultError as exc:
            raise VaultRecoveryCandidateInputError(
                "candidate timestamp is invalid"
            ) from exc
        if (
            timestamp < source.header.updated_utc
            or timestamp < first.parsed.created_utc
        ):
            raise VaultRecoveryCandidateInputError(
                "candidate timestamp precedes its verified recovery state"
            )
        try:
            candidate = _rewrap_keyring_vault(
                source,
                keyring,
                new_password,
                updated_utc=timestamp,
                time_cost=checked_kdf[0],
                memory_kib=checked_kdf[1],
                parallelism=checked_kdf[2],
                policy=policy,
            )
            candidate_parsed = parse_vault(
                candidate,
                policy=policy,
                minimum_revision=source.header.revision + 1,
            )
        except Exception as exc:
            raise VaultRecoveryCandidateCreationError(
                "in-memory Vault candidate creation failed"
            ) from exc
        evidence = VaultRecoveryCandidateEvidence(
            recovery_id=first_rehearsal.recovery_id,
            vault_id=source.header.vault_id,
            source_revision=source.header.revision,
            target_revision=candidate_parsed.header.revision,
            source_vault_sha256=hashlib.sha256(current).digest(),
            record_sha256=first.record_sha256,
            keyring_sha256=keyring_digest,
            candidate_sha256=hashlib.sha256(candidate).digest(),
            updated_utc=candidate_parsed.header.updated_utc,
            time_cost=candidate_parsed.header.time_cost,
            memory_kib=candidate_parsed.header.memory_kib,
            parallelism=candidate_parsed.header.parallelism,
            active_key_version=keyring.active_key_version,
            key_count=len(keyring.keys),
            directory_device=first.directory_device,
            directory_inode=first.directory_inode,
            file_device=first.file_device,
            file_inode=first.file_inode,
            encoded_size=first.encoded_size,
        )
        verify_recovery_candidate(
            candidate,
            new_password,
            evidence,
            policy=policy,
        )
    finally:
        del keyring
    try:
        second = _read_recovery_path(recovery_path)
        confirmed = _verified_latest_vault(storage, latest)
        second_rehearsal = rehearse_recovery(
            second.record,
            exact_key,
            confirmed,
        )
    except (OSError, VaultRecoveryError, VaultRecoveryStorageError) as exc:
        raise VaultRecoveryCandidateStateError(
            "recovery sources cannot be reverified after candidate creation"
        ) from exc
    if (
        not hmac.compare_digest(confirmed, current)
        or not _same_imported_file(first, second)
        or second_rehearsal != first_rehearsal
    ):
        raise VaultRecoveryCandidateStateError(
            "Vault or recovery file changed during candidate preparation"
        )
    authorization = VaultRecoveryCandidateAuthorization(
        authorization_id=_new_authorization_id(),
        evidence=evidence,
    )
    return PreparedVaultRecoveryCandidate(
        candidate,
        evidence,
        authorization,
    )
