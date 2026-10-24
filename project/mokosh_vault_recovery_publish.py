"""Strict immutable publish executor for one verified recovery candidate.

Stage 2.7 consumes the process-local one-shot handoff created by Stage 2.6,
revalidates the exact Vault and private recovery sources, unlocks the encrypted
candidate with the explicitly supplied new password, and delegates the only
filesystem mutation to the frozen Stage 2.2 no-clobber publisher.

The executor never overwrites or removes a Vault generation or recovery file.
It performs no key rotation, migration, key deletion, user-file mutation, GUI
work, network access, telemetry, logging, update discovery, or automatic
recovery.  Any failure after the publish boundary is reported as uncertain.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mokosh_vault_format import (
    DEFAULT_VAULT_KDF_POLICY,
    VAULT_KEYRING_PAYLOAD_SCHEMA,
    VaultError,
    VaultKDFPolicy,
    VaultSession,
    _password_bytes,
    parse_vault,
    validate_vault_kdf_policy,
)
from mokosh_vault_keyring import VaultKeyringError, encode_keyring
from mokosh_vault_recovery import (
    RECOVERY_ROOT_KEY_LEN,
    VaultRecoveryError,
    rehearse_recovery,
)
from mokosh_vault_recovery_candidate import (
    ClaimedVaultRecoveryCandidate,
    PreparedVaultRecoveryCandidate,
    VaultRecoveryCandidateAuthorizationError,
    VaultRecoveryCandidateEvidence,
    VaultRecoveryCandidateError,
    VaultRecoveryCandidateVerificationError,
    _same_imported_file,
    _validate_authorization,
    _validate_evidence,
    verify_recovery_candidate,
)
from mokosh_vault_recovery_storage import (
    VaultRecoveryStorageError,
    _ImportedRecoveryFile,
    _read_recovery_path,
    _verified_latest_vault,
)
from mokosh_vault_storage import (
    MAX_GENERATION_BYTES,
    VaultGenerationReceipt,
    VaultPublishUncertainError,
    VaultStorage,
    VaultStorageError,
)


class VaultRecoveryPublishError(VaultRecoveryCandidateError):
    """Base class for strict recovery-candidate publish failures."""


class VaultRecoveryPublishInputError(VaultRecoveryPublishError):
    """An explicit decision, credential, policy, or handoff type is invalid."""


class VaultRecoveryPublishStateError(VaultRecoveryPublishError):
    """The exact Vault, recovery file, or candidate state is not publishable."""


class VaultRecoveryPublishVerificationError(VaultRecoveryPublishError):
    """A source, candidate, receipt, or post-publish binding failed."""


class VaultRecoveryPublishUncertainError(VaultRecoveryPublishError):
    """A generation may be durable; read-only reconciliation is required."""


class RecoveryPublishDecision(str, Enum):
    PRESERVE = "preserve"
    AUTHORIZE_IMMUTABLE_PUBLISH = "authorize_immutable_publish"


@dataclass(frozen=True, slots=True)
class VaultRecoveryPublishResult:
    """Non-secret evidence for one independently verified durable publish."""

    authorization_id: str
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    source_vault_sha256: bytes
    record_sha256: bytes
    keyring_sha256: bytes
    candidate_sha256: bytes
    receipt: VaultGenerationReceipt
    source_generation_preserved: bool = True
    recovery_record_preserved: bool = True
    key_history_preserved: bool = True
    recovery_record_now_stale: bool = True
    key_deletion_performed: bool = False
    user_file_mutation_performed: bool = False


def _exact_recovery_key(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultRecoveryPublishInputError("recovery_key must be bytes")
    result = bytes(value)
    if len(result) != RECOVERY_ROOT_KEY_LEN:
        raise VaultRecoveryPublishInputError(
            f"recovery_key must contain exactly {RECOVERY_ROOT_KEY_LEN} bytes"
        )
    return result


def _validate_explicit_inputs(
    prepared: Any,
    recovery_key: Any,
    storage: Any,
    latest: Any,
    new_password: Any,
    decision: Any,
    policy: Any,
) -> tuple[bytes, VaultRecoveryCandidateEvidence]:
    if not isinstance(decision, RecoveryPublishDecision):
        raise VaultRecoveryPublishInputError(
            "recovery publish decision type is invalid"
        )
    if decision is not RecoveryPublishDecision.AUTHORIZE_IMMUTABLE_PUBLISH:
        raise VaultRecoveryPublishInputError(
            "immutable recovery publish was not explicitly authorized"
        )
    if not isinstance(prepared, PreparedVaultRecoveryCandidate):
        raise VaultRecoveryPublishInputError(
            "publish requires a Stage 2.6 prepared recovery candidate"
        )
    if prepared.claimed:
        raise VaultRecoveryPublishInputError(
            "recovery candidate was already claimed or consumed"
        )
    if not isinstance(storage, VaultStorage):
        raise VaultRecoveryPublishInputError("storage must be an open VaultStorage")
    if not isinstance(latest, VaultGenerationReceipt):
        raise VaultRecoveryPublishInputError(
            "latest must be a durable VaultGenerationReceipt"
        )
    try:
        _password_bytes(new_password)
        validate_vault_kdf_policy(policy)
        _validate_evidence(
            prepared.evidence,
            policy=DEFAULT_VAULT_KDF_POLICY,
        )
        evidence = _validate_evidence(prepared.evidence, policy=policy)
    except (VaultError, VaultRecoveryCandidateVerificationError) as exc:
        raise VaultRecoveryPublishInputError(
            "new password, KDF policy, or candidate evidence is invalid"
        ) from exc
    return _exact_recovery_key(recovery_key), evidence


def _validate_claimed_handoff(
    claimed: Any,
    expected: VaultRecoveryCandidateEvidence,
) -> tuple[bytes, str]:
    if not isinstance(claimed, ClaimedVaultRecoveryCandidate):
        raise VaultRecoveryPublishStateError(
            "Stage 2.6 claimed handoff type is invalid"
        )
    try:
        authorization = _validate_authorization(claimed.authorization)
    except (AttributeError, VaultRecoveryCandidateAuthorizationError) as exc:
        raise VaultRecoveryPublishStateError(
            "Stage 2.6 one-shot authorization is invalid"
        ) from exc
    if claimed.evidence != expected or authorization.evidence != expected:
        raise VaultRecoveryPublishStateError(
            "claimed candidate evidence differs from the prepared handoff"
        )
    if authorization.filesystem_publish_permitted is not False:
        raise VaultRecoveryPublishStateError(
            "Stage 2.6 authorization must not pre-authorize filesystem mutation"
        )
    candidate = claimed.candidate
    if (
        type(candidate) is not bytes
        or not 1 <= len(candidate) <= MAX_GENERATION_BYTES
        or not hmac.compare_digest(
            hashlib.sha256(candidate).digest(), expected.candidate_sha256
        )
    ):
        raise VaultRecoveryPublishStateError(
            "claimed candidate bytes differ from their exact digest"
        )
    return candidate, authorization.authorization_id


def _validate_latest_source(
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    evidence: VaultRecoveryCandidateEvidence,
    policy: VaultKDFPolicy,
) -> bytes:
    try:
        current = _verified_latest_vault(storage, latest)
        parsed = parse_vault(
            current,
            policy=policy,
            minimum_revision=evidence.source_revision,
        )
    except (VaultRecoveryStorageError, VaultStorageError, VaultError) as exc:
        raise VaultRecoveryPublishStateError(
            "exact latest durable source Vault cannot be verified"
        ) from exc
    if (
        parsed.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA
        or parsed.header.revision != evidence.source_revision
        or latest.revision != evidence.source_revision
        or not hmac.compare_digest(parsed.header.vault_id, evidence.vault_id)
        or not hmac.compare_digest(latest.vault_id, evidence.vault_id)
        or not hmac.compare_digest(latest.sha256, evidence.source_vault_sha256)
        or not hmac.compare_digest(
            hashlib.sha256(current).digest(), evidence.source_vault_sha256
        )
    ):
        raise VaultRecoveryPublishStateError(
            "latest durable source differs from Stage 2.6 evidence"
        )
    return current


def _validate_recovery_observation(
    imported: _ImportedRecoveryFile,
    evidence: VaultRecoveryCandidateEvidence,
) -> None:
    if (
        not hmac.compare_digest(imported.parsed.recovery_id, evidence.recovery_id)
        or imported.directory_device != evidence.directory_device
        or imported.directory_inode != evidence.directory_inode
        or imported.file_device != evidence.file_device
        or imported.file_inode != evidence.file_inode
        or imported.encoded_size != evidence.encoded_size
        or not hmac.compare_digest(imported.record_sha256, evidence.record_sha256)
    ):
        raise VaultRecoveryPublishStateError(
            "recovery file differs from Stage 2.6 evidence"
        )


def _read_and_rehearse(
    recovery_path: Any,
    recovery_key: bytes,
    current: bytes,
    evidence: VaultRecoveryCandidateEvidence,
) -> tuple[_ImportedRecoveryFile, Any]:
    try:
        imported = _read_recovery_path(recovery_path)
        _validate_recovery_observation(imported, evidence)
        rehearsal = rehearse_recovery(imported.record, recovery_key, current)
    except VaultRecoveryPublishError:
        raise
    except (OSError, VaultRecoveryError, VaultRecoveryStorageError) as exc:
        raise VaultRecoveryPublishStateError(
            "recovery file, root, or source binding is invalid"
        ) from exc
    if (
        not hmac.compare_digest(rehearsal.recovery_id, evidence.recovery_id)
        or not hmac.compare_digest(rehearsal.vault_id, evidence.vault_id)
        or rehearsal.source_revision != evidence.source_revision
        or not hmac.compare_digest(
            rehearsal.source_vault_sha256, evidence.source_vault_sha256
        )
        or not hmac.compare_digest(
            rehearsal.keyring_sha256, evidence.keyring_sha256
        )
        or rehearsal.active_key_version != evidence.active_key_version
        or rehearsal.key_count != evidence.key_count
    ):
        raise VaultRecoveryPublishVerificationError(
            "fresh recovery rehearsal differs from Stage 2.6 evidence"
        )
    return imported, rehearsal


def _unlock_candidate_session(
    candidate: bytes,
    new_password: str,
    evidence: VaultRecoveryCandidateEvidence,
    policy: VaultKDFPolicy,
) -> VaultSession:
    session: VaultSession | None = None
    try:
        verify_recovery_candidate(
            candidate,
            new_password,
            evidence,
            policy=policy,
        )
        session = VaultSession(
            candidate,
            policy=policy,
            minimum_revision=evidence.target_revision,
        )
        session.unlock(new_password)
        keyring = session.keyring_copy()
        keyring_digest = hashlib.sha256(encode_keyring(keyring)).digest()
    except (VaultError, VaultKeyringError, VaultRecoveryCandidateError) as exc:
        if session is not None:
            session.close()
        raise VaultRecoveryPublishVerificationError(
            "candidate password or authenticated contents are invalid"
        ) from exc
    try:
        if (
            session.revision != evidence.target_revision
            or not hmac.compare_digest(session.encoded, candidate)
            or not hmac.compare_digest(keyring_digest, evidence.keyring_sha256)
            or keyring.active_key_version != evidence.active_key_version
            or len(keyring.keys) != evidence.key_count
        ):
            raise VaultRecoveryPublishVerificationError(
                "unlocked candidate session differs from exact evidence"
            )
        return session
    except BaseException:
        session.close()
        raise
    finally:
        del keyring_digest
        del keyring


def _post_publish_verify(
    *,
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    receipt: VaultGenerationReceipt,
    generations_before: tuple[VaultGenerationReceipt, ...],
    current: bytes,
    recovery_path: Any,
    recovery_key: bytes,
    recovery_before: _ImportedRecoveryFile,
    rehearsal_before: Any,
    candidate: bytes,
    new_password: str,
    evidence: VaultRecoveryCandidateEvidence,
    policy: VaultKDFPolicy,
) -> None:
    if (
        receipt.revision != evidence.target_revision
        or not hmac.compare_digest(receipt.vault_id, evidence.vault_id)
        or not hmac.compare_digest(receipt.sha256, evidence.candidate_sha256)
        or receipt.encoded_size != len(candidate)
        or receipt.durable is not True
    ):
        raise VaultRecoveryPublishVerificationError(
            "published receipt differs from exact candidate evidence"
        )
    readback = storage.verify_receipt(receipt)
    old_readback = storage.verify_receipt(latest)
    report = storage.scan()
    if (
        not hmac.compare_digest(readback, candidate)
        or not hmac.compare_digest(old_readback, current)
        or not report.complete
        or report.has_conflict
        or report.generations != generations_before + (receipt,)
    ):
        raise VaultRecoveryPublishVerificationError(
            "immutable Vault history cannot be confirmed after publish"
        )
    verify_recovery_candidate(
        readback,
        new_password,
        evidence,
        policy=policy,
    )
    recovery_after, rehearsal_after = _read_and_rehearse(
        recovery_path,
        recovery_key,
        current,
        evidence,
    )
    if (
        not _same_imported_file(recovery_before, recovery_after)
        or rehearsal_after != rehearsal_before
    ):
        raise VaultRecoveryPublishVerificationError(
            "recovery file changed across the publish boundary"
        )


def publish_recovery_candidate(
    prepared: PreparedVaultRecoveryCandidate,
    recovery_path: Any,
    recovery_key: bytes | bytearray | memoryview,
    storage: VaultStorage,
    latest: VaultGenerationReceipt,
    new_password: str,
    decision: RecoveryPublishDecision,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> VaultRecoveryPublishResult:
    """Publish exactly one Stage 2.6 candidate as an immutable next generation."""

    exact_key, expected = _validate_explicit_inputs(
        prepared,
        recovery_key,
        storage,
        latest,
        new_password,
        decision,
        policy,
    )
    try:
        claimed = prepared.claim_once()
        candidate, authorization_id = _validate_claimed_handoff(
            claimed,
            expected,
        )
    except (VaultRecoveryCandidateError, AttributeError) as exc:
        raise VaultRecoveryPublishStateError(
            "Stage 2.6 one-shot handoff cannot be consumed"
        ) from exc

    current = _validate_latest_source(storage, latest, expected, policy)
    first_file, first_rehearsal = _read_and_rehearse(
        recovery_path,
        exact_key,
        current,
        expected,
    )
    session = _unlock_candidate_session(
        candidate,
        new_password,
        expected,
        policy,
    )
    receipt: VaultGenerationReceipt | None = None
    try:
        confirmed = _validate_latest_source(storage, latest, expected, policy)
        second_file, second_rehearsal = _read_and_rehearse(
            recovery_path,
            exact_key,
            confirmed,
            expected,
        )
        if (
            not hmac.compare_digest(confirmed, current)
            or not _same_imported_file(first_file, second_file)
            or second_rehearsal != first_rehearsal
        ):
            raise VaultRecoveryPublishStateError(
                "Vault or recovery source changed before publish"
            )
        try:
            before = storage.scan()
        except VaultStorageError as exc:
            raise VaultRecoveryPublishStateError(
                "fresh pre-publish Vault scan failed"
            ) from exc
        if (
            not before.complete
            or before.has_conflict
            or not before.generations
            or before.generations[-1] != latest
        ):
            raise VaultRecoveryPublishStateError(
                "fresh pre-publish Vault scan is not exact and clean"
            )
        try:
            receipt = storage.publish(session, previous=latest)
        except VaultPublishUncertainError as exc:
            raise VaultRecoveryPublishUncertainError(
                "recovery generation may be durable; reconcile read-only"
            ) from exc
        except VaultStorageError as exc:
            raise VaultRecoveryPublishStateError(
                "immutable recovery generation was not published"
            ) from exc
        except Exception as exc:
            raise VaultRecoveryPublishStateError(
                "immutable recovery publisher failed before confirmation"
            ) from exc

        try:
            _post_publish_verify(
                storage=storage,
                latest=latest,
                receipt=receipt,
                generations_before=before.generations,
                current=current,
                recovery_path=recovery_path,
                recovery_key=exact_key,
                recovery_before=second_file,
                rehearsal_before=second_rehearsal,
                candidate=candidate,
                new_password=new_password,
                evidence=expected,
                policy=policy,
            )
        except BaseException as exc:
            raise VaultRecoveryPublishUncertainError(
                "generation was published but final verification is uncertain"
            ) from exc
    finally:
        session.close()

    assert receipt is not None
    return VaultRecoveryPublishResult(
        authorization_id=authorization_id,
        recovery_id=expected.recovery_id,
        vault_id=expected.vault_id,
        source_revision=expected.source_revision,
        target_revision=expected.target_revision,
        source_vault_sha256=expected.source_vault_sha256,
        record_sha256=expected.record_sha256,
        keyring_sha256=expected.keyring_sha256,
        candidate_sha256=expected.candidate_sha256,
        receipt=receipt,
    )
