"""Strict read-only reconciliation for an uncertain recovery publish.

Stage 2.8 classifies one explicitly expected next Vault revision after a
Stage 2.7 publish returned an uncertain result.  It revalidates the old source
receipt, the private recovery record and its separate recovery root, and—when
present—the observed target with the explicitly supplied new password.

The module never publishes, creates, writes, replaces, renames, unlinks, or
deletes a filesystem object.  It performs no key rotation, migration,
user-file mutation, GUI work, network access, telemetry, logging, update
discovery, automatic retry, rollback, cleanup, or recovery.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mokosh_vault_format import (
    DEFAULT_VAULT_KDF_POLICY,
    MAX_VAULT_REVISION,
    VAULT_KEYRING_PAYLOAD_SCHEMA,
    ParsedVault,
    VaultError,
    VaultKDFPolicy,
    _password_bytes,
    parse_vault,
    unlock_keyring_vault,
    validate_vault_kdf_policy,
)
from mokosh_vault_keyring import VaultKeyringError, encode_keyring
from mokosh_vault_recovery import (
    RECOVERY_ROOT_KEY_LEN,
    VaultRecoveryError,
    VaultRecoveryRehearsal,
    rehearse_recovery,
)
from mokosh_vault_recovery_storage import (
    VaultRecoveryStorageError,
    _ImportedRecoveryFile,
    _read_recovery_path,
)
from mokosh_vault_storage import (
    FileIdentity,
    VaultGenerationReceipt,
    VaultStorage,
    VaultStorageError,
    VaultStorageFinding,
    VaultStorageReport,
    _validate_receipt,
)


class VaultRecoveryReconciliationError(VaultRecoveryError):
    """Base class for strict read-only recovery reconciliation failures."""


class VaultRecoveryReconciliationInputError(VaultRecoveryReconciliationError):
    """An explicit receipt, revision, credential, or policy is invalid."""


class VaultRecoveryReconciliationStateError(VaultRecoveryReconciliationError):
    """The source, recovery file, or storage cannot be observed safely."""


class VaultRecoveryReconciliationVerificationError(
    VaultRecoveryReconciliationError
):
    """The recovery root or its exact source binding cannot be verified."""


class RecoveryPublishClassification(str, Enum):
    TARGET_ABSENT = "target_absent"
    TARGET_EXACT_DURABLE = "target_exact_durable"
    CONFLICT = "conflict"


class RecoveryReconciliationAction(str, Enum):
    PREPARE_NEW_CANDIDATE = "prepare_new_candidate"
    REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY = (
        "review_target_then_setup_new_recovery"
    )
    STOP_FOR_MANUAL_REVIEW = "stop_for_manual_review"


@dataclass(frozen=True, slots=True)
class VaultRecoveryReconciliationResult:
    """Fixed-size non-secret evidence; never a mutation authorization."""

    classification: RecoveryPublishClassification
    recommended_action: RecoveryReconciliationAction
    recovery_id: bytes
    vault_id: bytes
    source_revision: int
    target_revision: int
    source_vault_sha256: bytes
    record_sha256: bytes
    keyring_sha256: bytes
    source_receipt: VaultGenerationReceipt
    target_receipt: VaultGenerationReceipt | None
    target_vault_sha256: bytes | None
    generation_count: int
    finding_count: int
    omitted_entries: int
    storage_complete: bool
    stable_observation: bool
    source_verified: bool = True
    recovery_record_verified: bool = True
    new_password_verified: bool = False
    keyring_verified: bool = False
    read_only: bool = True
    mutation_authorized: bool = False
    publish_performed: bool = False
    rollback_performed: bool = False
    cleanup_performed: bool = False
    key_deletion_performed: bool = False
    user_file_mutation_performed: bool = False


class _ReportState(Enum):
    ABSENT = "absent"
    TARGET_PRESENT = "target_present"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class _TargetObservation:
    exact: bool
    receipt: VaultGenerationReceipt
    encoded: bytes | None = field(default=None, repr=False)


def _exact_recovery_key(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise VaultRecoveryReconciliationInputError(
            "recovery_key must be bytes"
        )
    result = bytes(value)
    if len(result) != RECOVERY_ROOT_KEY_LEN:
        raise VaultRecoveryReconciliationInputError(
            f"recovery_key must contain exactly {RECOVERY_ROOT_KEY_LEN} bytes"
        )
    return result


def _validate_explicit_inputs(
    storage: Any,
    source: Any,
    expected_target_revision: Any,
    recovery_key: Any,
    new_password: Any,
    policy: Any,
) -> bytes:
    if not isinstance(storage, VaultStorage):
        raise VaultRecoveryReconciliationInputError(
            "storage must be an open VaultStorage"
        )
    if not isinstance(source, VaultGenerationReceipt):
        raise VaultRecoveryReconciliationInputError(
            "source must be a durable VaultGenerationReceipt"
        )
    try:
        _validate_receipt(source)
    except VaultStorageError as exc:
        raise VaultRecoveryReconciliationInputError(
            "source receipt is invalid"
        ) from exc
    if (
        type(expected_target_revision) is not int
        or source.revision >= MAX_VAULT_REVISION
        or expected_target_revision != source.revision + 1
        or expected_target_revision > MAX_VAULT_REVISION
    ):
        raise VaultRecoveryReconciliationInputError(
            "expected_target_revision must be the exact next revision"
        )
    exact_key = _exact_recovery_key(recovery_key)
    try:
        _password_bytes(new_password)
        validate_vault_kdf_policy(policy)
    except VaultError as exc:
        raise VaultRecoveryReconciliationInputError(
            "new password or KDF policy is invalid"
        ) from exc
    return exact_key


def _verify_source(
    storage: VaultStorage,
    source: VaultGenerationReceipt,
    expected_target_revision: int,
    policy: VaultKDFPolicy,
) -> tuple[bytes, ParsedVault]:
    try:
        encoded = storage.verify_receipt(source)
        parsed = parse_vault(
            encoded,
            policy=policy,
            minimum_revision=source.revision,
        )
    except (VaultStorageError, VaultError) as exc:
        raise VaultRecoveryReconciliationStateError(
            "exact source Vault receipt cannot be verified"
        ) from exc
    if (
        parsed.header.payload_schema != VAULT_KEYRING_PAYLOAD_SCHEMA
        or parsed.header.revision != source.revision
        or expected_target_revision != source.revision + 1
        or not hmac.compare_digest(parsed.header.vault_id, source.vault_id)
        or not hmac.compare_digest(
            hashlib.sha256(encoded).digest(), source.sha256
        )
    ):
        raise VaultRecoveryReconciliationStateError(
            "source receipt differs from its authenticated schema-two Vault"
        )
    return encoded, parsed


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


def _read_and_rehearse(
    recovery_path: Any,
    recovery_key: bytes,
    source_bytes: bytes,
    source: VaultGenerationReceipt,
) -> tuple[_ImportedRecoveryFile, VaultRecoveryRehearsal]:
    try:
        imported = _read_recovery_path(recovery_path)
        rehearsal = rehearse_recovery(
            imported.record,
            recovery_key,
            source_bytes,
        )
    except (OSError, VaultRecoveryError, VaultRecoveryStorageError) as exc:
        raise VaultRecoveryReconciliationVerificationError(
            "recovery file, root, or exact source binding is invalid"
        ) from exc
    if (
        not hmac.compare_digest(rehearsal.recovery_id, imported.parsed.recovery_id)
        or not hmac.compare_digest(rehearsal.vault_id, source.vault_id)
        or rehearsal.source_revision != source.revision
        or not hmac.compare_digest(
            rehearsal.source_vault_sha256, source.sha256
        )
    ):
        raise VaultRecoveryReconciliationVerificationError(
            "recovery rehearsal differs from the exact source receipt"
        )
    return imported, rehearsal


def _identity_signature(value: FileIdentity | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    return (
        value.device,
        value.inode,
        value.mode,
        value.links,
        value.size,
        value.uid,
    )


def _finding_signature(value: VaultStorageFinding) -> tuple[Any, ...]:
    return (
        value.kind.value,
        value.object_token,
        -1 if value.revision is None else value.revision,
        _identity_signature(value.identity),
    )


def _receipt_signature(value: VaultGenerationReceipt) -> tuple[Any, ...]:
    return (
        value.directory_device,
        value.directory_inode,
        value.vault_id,
        value.revision,
        value.sha256,
        value.file_device,
        value.file_inode,
        value.encoded_size,
        value.durable,
    )


def _report_signature(report: VaultStorageReport) -> tuple[Any, ...]:
    return (
        report.directory_device,
        report.directory_inode,
        tuple(sorted(_finding_signature(item) for item in report.findings)),
        tuple(_receipt_signature(item) for item in report.generations),
        report.omitted_entries,
        report.complete,
    )


def _scan(
    storage: VaultStorage,
) -> tuple[VaultStorageReport, tuple[Any, ...]]:
    try:
        report = storage.scan()
    except VaultStorageError as exc:
        raise VaultRecoveryReconciliationStateError(
            "Vault storage cannot be scanned read-only"
        ) from exc
    if not isinstance(report, VaultStorageReport):
        raise VaultRecoveryReconciliationStateError(
            "Vault storage returned an invalid report type"
        )
    return report, _report_signature(report)


def _classify_report(
    report: VaultStorageReport,
    source: VaultGenerationReceipt,
    expected_target_revision: int,
) -> tuple[_ReportState, VaultGenerationReceipt | None]:
    if (
        report.directory_device != source.directory_device
        or report.directory_inode != source.directory_inode
        or not report.complete
        or report.has_conflict
    ):
        return _ReportState.CONFLICT, None
    generations = report.generations
    source_position = source.revision - 1
    if (
        source_position >= len(generations)
        or generations[source_position] != source
    ):
        return _ReportState.CONFLICT, None
    if len(generations) == source.revision and generations[-1] == source:
        return _ReportState.ABSENT, None
    if (
        len(generations) == expected_target_revision
        and generations[-1].revision == expected_target_revision
        and hmac.compare_digest(generations[-1].vault_id, source.vault_id)
    ):
        return _ReportState.TARGET_PRESENT, generations[-1]
    return _ReportState.CONFLICT, None


def _observe_target(
    storage: VaultStorage,
    receipt: VaultGenerationReceipt,
    source_parsed: ParsedVault,
    expected_target_revision: int,
    new_password: str,
    rehearsal: VaultRecoveryRehearsal,
    policy: VaultKDFPolicy,
) -> _TargetObservation:
    try:
        encoded = storage.verify_receipt(receipt)
        parsed = parse_vault(
            encoded,
            policy=policy,
            minimum_revision=expected_target_revision,
        )
        confirmed, recovered = unlock_keyring_vault(
            encoded,
            new_password,
            policy=policy,
            minimum_revision=expected_target_revision,
        )
        keyring_bytes = encode_keyring(recovered)
        keyring_digest = hashlib.sha256(keyring_bytes).digest()
    except (VaultStorageError, VaultError, VaultKeyringError):
        return _TargetObservation(False, receipt)
    try:
        exact = (
            confirmed.header == parsed.header
            and parsed.header.payload_schema == VAULT_KEYRING_PAYLOAD_SCHEMA
            and parsed.header.revision == expected_target_revision
            and parsed.header.created_utc == source_parsed.header.created_utc
            and parsed.header.updated_utc >= source_parsed.header.updated_utc
            and parsed.header.updated_utc >= rehearsal.created_utc
            and hmac.compare_digest(parsed.header.vault_id, rehearsal.vault_id)
            and hmac.compare_digest(receipt.vault_id, rehearsal.vault_id)
            and hmac.compare_digest(
                hashlib.sha256(encoded).digest(), receipt.sha256
            )
            and hmac.compare_digest(keyring_digest, rehearsal.keyring_sha256)
            and recovered.active_key_version == rehearsal.active_key_version
            and len(recovered.keys) == rehearsal.key_count
        )
        return _TargetObservation(exact, receipt, encoded if exact else None)
    finally:
        del keyring_digest
        del keyring_bytes
        del recovered


def _make_result(
    *,
    classification: RecoveryPublishClassification,
    action: RecoveryReconciliationAction,
    source: VaultGenerationReceipt,
    expected_target_revision: int,
    imported: _ImportedRecoveryFile,
    rehearsal: VaultRecoveryRehearsal,
    report: VaultStorageReport,
    stable: bool,
    target: _TargetObservation | None,
) -> VaultRecoveryReconciliationResult:
    exact_target = (
        target
        if classification is RecoveryPublishClassification.TARGET_EXACT_DURABLE
        else None
    )
    return VaultRecoveryReconciliationResult(
        classification=classification,
        recommended_action=action,
        recovery_id=rehearsal.recovery_id,
        vault_id=rehearsal.vault_id,
        source_revision=source.revision,
        target_revision=expected_target_revision,
        source_vault_sha256=source.sha256,
        record_sha256=imported.record_sha256,
        keyring_sha256=rehearsal.keyring_sha256,
        source_receipt=source,
        target_receipt=None if exact_target is None else exact_target.receipt,
        target_vault_sha256=(
            None if exact_target is None else exact_target.receipt.sha256
        ),
        generation_count=len(report.generations),
        finding_count=len(report.findings),
        omitted_entries=report.omitted_entries,
        storage_complete=report.complete,
        stable_observation=stable,
        new_password_verified=exact_target is not None,
        keyring_verified=exact_target is not None,
    )


def reconcile_recovery_publish(
    recovery_path: Any,
    recovery_key: bytes | bytearray | memoryview,
    storage: VaultStorage,
    source: VaultGenerationReceipt,
    expected_target_revision: int,
    new_password: str,
    *,
    policy: VaultKDFPolicy = DEFAULT_VAULT_KDF_POLICY,
) -> VaultRecoveryReconciliationResult:
    """Classify an uncertain Stage 2.7 outcome without filesystem mutation."""

    exact_key = _validate_explicit_inputs(
        storage,
        source,
        expected_target_revision,
        recovery_key,
        new_password,
        policy,
    )
    first_source, first_parsed = _verify_source(
        storage,
        source,
        expected_target_revision,
        policy,
    )
    first_file, first_rehearsal = _read_and_rehearse(
        recovery_path,
        exact_key,
        first_source,
        source,
    )
    first_report, first_signature = _scan(storage)
    first_state, first_target_receipt = _classify_report(
        first_report,
        source,
        expected_target_revision,
    )
    first_target = (
        None
        if first_target_receipt is None
        else _observe_target(
            storage,
            first_target_receipt,
            first_parsed,
            expected_target_revision,
            new_password,
            first_rehearsal,
            policy,
        )
    )

    second_source, second_parsed = _verify_source(
        storage,
        source,
        expected_target_revision,
        policy,
    )
    second_file, second_rehearsal = _read_and_rehearse(
        recovery_path,
        exact_key,
        second_source,
        source,
    )
    if (
        not hmac.compare_digest(first_source, second_source)
        or first_parsed.header != second_parsed.header
        or not _same_imported_file(first_file, second_file)
        or first_rehearsal != second_rehearsal
    ):
        raise VaultRecoveryReconciliationStateError(
            "source Vault or recovery file changed during reconciliation"
        )

    second_report, second_signature = _scan(storage)
    second_state, second_target_receipt = _classify_report(
        second_report,
        source,
        expected_target_revision,
    )
    second_target = (
        None
        if second_target_receipt is None
        else _observe_target(
            storage,
            second_target_receipt,
            second_parsed,
            expected_target_revision,
            new_password,
            second_rehearsal,
            policy,
        )
    )

    stable = first_signature == second_signature
    if (
        stable
        and first_state is _ReportState.ABSENT
        and second_state is _ReportState.ABSENT
    ):
        return _make_result(
            classification=RecoveryPublishClassification.TARGET_ABSENT,
            action=RecoveryReconciliationAction.PREPARE_NEW_CANDIDATE,
            source=source,
            expected_target_revision=expected_target_revision,
            imported=second_file,
            rehearsal=second_rehearsal,
            report=second_report,
            stable=True,
            target=None,
        )

    exact_target = (
        stable
        and first_state is _ReportState.TARGET_PRESENT
        and second_state is _ReportState.TARGET_PRESENT
        and first_target is not None
        and second_target is not None
        and first_target.exact
        and second_target.exact
        and first_target.receipt == second_target.receipt
        and first_target.encoded is not None
        and second_target.encoded is not None
        and hmac.compare_digest(first_target.encoded, second_target.encoded)
    )
    if exact_target:
        return _make_result(
            classification=(
                RecoveryPublishClassification.TARGET_EXACT_DURABLE
            ),
            action=(
                RecoveryReconciliationAction.REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY
            ),
            source=source,
            expected_target_revision=expected_target_revision,
            imported=second_file,
            rehearsal=second_rehearsal,
            report=second_report,
            stable=True,
            target=second_target,
        )

    return _make_result(
        classification=RecoveryPublishClassification.CONFLICT,
        action=RecoveryReconciliationAction.STOP_FOR_MANUAL_REVIEW,
        source=source,
        expected_target_revision=expected_target_revision,
        imported=second_file,
        rehearsal=second_rehearsal,
        report=second_report,
        stable=stable,
        target=None,
    )
