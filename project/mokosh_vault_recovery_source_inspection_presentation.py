"""Bounded presentation model for exact Stage 2.32 inspection evidence.

The module converts one exact positive secure source-inspection outcome into a
domain-separated evidence digest plus fixed message and confirmation keys.  It
does not retain or render raw evidence and performs no filesystem access,
recovery operation, authentication, GUI work, localization, logging, network
access, or mutation.

The evidence digest is a process-local mismatch binding.  It is not a digital
signature, provenance proof, anti-rollback anchor, or cryptographic
authentication of the inspected recovery ciphertext.
"""

from __future__ import annotations

import hashlib as _hashlib
import struct as _struct
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_execution import (
    RECOVERY_SOURCE_INSPECTION_EXECUTION_SEQUENCE,
    RecoverySourceInspectionExecutionDecision,
    VaultRecoverySourceInspectionExecutionOutcome,
    _validate_source_inspection_execution_outcome,
)


RECOVERY_SOURCE_INSPECTION_PRESENTATION_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_PRESENTATION"
)
RECOVERY_SOURCE_INSPECTION_PRESENTATION_VERSION = 1
RECOVERY_SOURCE_INSPECTION_PRESENTATION_EVIDENCE_SHA256_LEN = 32
RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT = 7
RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT = 3

_EVIDENCE_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-SOURCE-INSPECTION-PRESENTATION\x00"
    b"EXECUTION-EVIDENCE-V1\x00"
)
_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)


class VaultRecoverySourceInspectionPresentationError(ValueError):
    """Base class for strict Stage 2.33 presentation failures."""


class VaultRecoverySourceInspectionPresentationSourceError(
    VaultRecoverySourceInspectionPresentationError
):
    """The exact positive Stage 2.32 source outcome is invalid."""


class VaultRecoverySourceInspectionPresentationFormatError(
    VaultRecoverySourceInspectionPresentationError
):
    """A bounded Stage 2.33 presentation violates the frozen schema."""


class RecoverySourceInspectionPresentationMessageKey(str, Enum):
    """Fixed localization identifiers; these are not rendered prose."""

    INSPECTION_COMPLETED = "recovery.source_inspection.completed"
    HEADER_STRUCTURALLY_VALIDATED = (
        "recovery.source_inspection.header_structurally_validated"
    )
    CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED = (
        "recovery.source_inspection.cryptographic_authenticity_not_established"
    )
    RECOVERY_SECRET_NOT_RECEIVED = (
        "recovery.source_inspection.recovery_secret_not_received"
    )
    FRESH_SECURE_REOPEN_REQUIRED = (
        "recovery.source_inspection.fresh_secure_reopen_required"
    )
    NO_RECOVERY_PERFORMED = "recovery.source_inspection.no_recovery_performed"
    NO_OPERATION_AUTHORIZED = (
        "recovery.source_inspection.no_operation_authorized"
    )


class RecoverySourceInspectionPresentationConfirmationKey(str, Enum):
    """Exact ordered acknowledgements for a future adapter."""

    ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY = (
        "recovery.source_inspection.confirm.structure_is_not_authenticity"
    )
    ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED = (
        "recovery.source_inspection.confirm.fresh_secure_reopen_required"
    )
    ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION = (
        "recovery.source_inspection.confirm.no_recovery_or_operation"
    )


_MESSAGE_KEYS = (
    RecoverySourceInspectionPresentationMessageKey.INSPECTION_COMPLETED,
    RecoverySourceInspectionPresentationMessageKey.HEADER_STRUCTURALLY_VALIDATED,
    RecoverySourceInspectionPresentationMessageKey.CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED,
    RecoverySourceInspectionPresentationMessageKey.RECOVERY_SECRET_NOT_RECEIVED,
    RecoverySourceInspectionPresentationMessageKey.FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationMessageKey.NO_RECOVERY_PERFORMED,
    RecoverySourceInspectionPresentationMessageKey.NO_OPERATION_AUTHORIZED,
)
_CONFIRMATION_REQUIREMENTS = (
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionPresentation:
    """Fixed no-authority view model retaining no raw inspection evidence."""

    locale: RecoveryLocalizationLocale
    inspection_evidence_sha256: bytes = _field(repr=False)
    message_keys: tuple[RecoverySourceInspectionPresentationMessageKey, ...]
    confirmation_requirements: tuple[
        RecoverySourceInspectionPresentationConfirmationKey, ...
    ]
    inspection_completed: bool = True
    header_structurally_validated: bool = True
    cryptographic_authenticity_established: bool = False
    future_secure_source_reopen_required: bool = True
    exact_execution_outcome_validated: bool = True
    fixed_message_keys_only: bool = True
    raw_text_included: bool = False
    raw_evidence_included: bool = False
    original_execution_outcome_retained: bool = False
    source_path_metadata_retained: bool = False
    source_descriptor_retained: bool = False
    source_content_retained: bool = False
    source_identifiers_retained: bool = False
    source_revision_retained: bool = False
    source_hashes_retained: bool = False
    source_size_retained: bool = False
    recovery_secret_received: bool = False
    recovery_performed: bool = False
    rehearsal_performed: bool = False
    stage2_8_used: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    filesystem_access_performed: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    logging_used: bool = False
    gui_used: bool = False
    process_local: bool = True
    evidence_digest_is_digital_signature: bool = False
    evidence_digest_is_provenance_proof: bool = False
    evidence_digest_is_anti_rollback_anchor: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_PRESENTATION_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_PRESENTATION_VERSION

    def __post_init__(self) -> None:
        _validate_source_inspection_presentation(self)

    def __copy__(self) -> None:
        raise TypeError("recovery source inspection presentation cannot be copied")

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise TypeError("recovery source inspection presentation cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError(
            "recovery source inspection presentation cannot be serialized"
        )


def _validate_execution_source(
    value: _Any,
) -> VaultRecoverySourceInspectionExecutionOutcome:
    if type(value) is not VaultRecoverySourceInspectionExecutionOutcome:
        raise VaultRecoverySourceInspectionPresentationSourceError(
            "source inspection execution outcome type is invalid"
        )
    try:
        _validate_source_inspection_execution_outcome(value)
    except Exception:
        raise VaultRecoverySourceInspectionPresentationSourceError(
            "source inspection execution outcome is invalid"
        ) from None
    if (
        value.execution_decision
        is not RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION
        or value.secure_source_inspection_performed is not True
        or value.preserved_and_stopped is not False
        or value.header_structurally_validated is not True
        or value.cryptographically_authenticated is not False
        or value.recovery_id is None
        or value.vault_id is None
        or value.source_revision is None
        or value.source_vault_sha256 is None
        or value.record_sha256 is None
        or value.encoded_size is None
    ):
        raise VaultRecoverySourceInspectionPresentationSourceError(
            "only a completed positive source inspection can be presented"
        )
    return value


def _evidence_transcript(
    value: VaultRecoverySourceInspectionExecutionOutcome,
) -> bytes:
    locale_code = {
        RecoveryLocalizationLocale.BULGARIAN_BULGARIA: 1,
        RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM: 2,
    }[value.locale]
    flags = (
        value.secure_source_inspection_performed,
        value.preserved_and_stopped,
        value.header_structurally_validated,
        value.cryptographically_authenticated,
        value.source_path_metadata_retained,
        value.source_descriptor_retained,
        value.source_content_retained,
        value.ciphertext_retained,
        value.recovery_secret_received,
        value.recovery_performed,
        value.rehearsal_performed,
        value.stage2_8_used,
        value.review_session_prepared,
        value.operation_authorized,
        value.operation_performed,
        value.filesystem_mutation_performed,
        value.network_used,
        value.logging_used,
        value.gui_used,
        value.one_shot,
        value.process_local,
        value.global_source_outcome_consumption_enforced,
        value.memory_zeroization_proven,
        value.filesystem_identity_future_validity_claimed,
        value.exact_preparation_request_outcome_validated,
        value.exact_execution_decision_validated,
    )
    format_bytes = value.format.encode("ascii")
    return b"".join(
        (
            _EVIDENCE_DIGEST_DOMAIN,
            _struct.pack(">BB", locale_code, 1),
            value.recovery_id,
            value.vault_id,
            _struct.pack(">QQ", value.source_revision, value.encoded_size),
            value.source_vault_sha256,
            value.record_sha256,
            _struct.pack(">26?", *flags),
            _struct.pack(
                ">6I",
                value.entry_request_sequence,
                value.transition_sequence,
                value.selection_sequence,
                value.inspection_request_sequence,
                value.preparation_request_sequence,
                value.execution_sequence,
            ),
            _struct.pack(">H", len(format_bytes)),
            format_bytes,
            _struct.pack(">I", value.version),
        )
    )


def _validate_source_inspection_presentation(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionPresentation:
        raise VaultRecoverySourceInspectionPresentationFormatError(
            "source inspection presentation type is invalid"
        )
    false_values = (
        value.cryptographic_authenticity_established,
        value.raw_text_included,
        value.raw_evidence_included,
        value.original_execution_outcome_retained,
        value.source_path_metadata_retained,
        value.source_descriptor_retained,
        value.source_content_retained,
        value.source_identifiers_retained,
        value.source_revision_retained,
        value.source_hashes_retained,
        value.source_size_retained,
        value.recovery_secret_received,
        value.recovery_performed,
        value.rehearsal_performed,
        value.stage2_8_used,
        value.review_session_prepared,
        value.operation_authorized,
        value.operation_performed,
        value.filesystem_access_performed,
        value.filesystem_mutation_performed,
        value.network_used,
        value.logging_used,
        value.gui_used,
        value.evidence_digest_is_digital_signature,
        value.evidence_digest_is_provenance_proof,
        value.evidence_digest_is_anti_rollback_anchor,
    )
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.inspection_evidence_sha256) is not bytes
        or len(value.inspection_evidence_sha256)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_EVIDENCE_SHA256_LEN
        or type(value.message_keys) is not tuple
        or value.message_keys != _MESSAGE_KEYS
        or any(
            type(item) is not RecoverySourceInspectionPresentationMessageKey
            for item in value.message_keys
        )
        or len(value.message_keys)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or type(value.confirmation_requirements) is not tuple
        or value.confirmation_requirements != _CONFIRMATION_REQUIREMENTS
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value.confirmation_requirements
        )
        or len(value.confirmation_requirements)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or value.inspection_completed is not True
        or value.header_structurally_validated is not True
        or value.future_secure_source_reopen_required is not True
        or value.exact_execution_outcome_validated is not True
        or value.fixed_message_keys_only is not True
        or value.process_local is not True
        or any(item is not False for item in false_values)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_PRESENTATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_PRESENTATION_VERSION
    ):
        raise VaultRecoverySourceInspectionPresentationFormatError(
            "source inspection presentation is invalid"
        )


def prepare_recovery_source_inspection_presentation(
    execution_outcome: VaultRecoverySourceInspectionExecutionOutcome,
) -> VaultRecoverySourceInspectionPresentation:
    """Create one fixed presentation from exact positive Stage 2.32 evidence."""

    exact = _validate_execution_source(execution_outcome)
    digest = _hashlib.sha256(_evidence_transcript(exact)).digest()
    return VaultRecoverySourceInspectionPresentation(
        locale=exact.locale,
        inspection_evidence_sha256=digest,
        message_keys=_MESSAGE_KEYS,
        confirmation_requirements=_CONFIRMATION_REQUIREMENTS,
    )
