"""One-shot acknowledgement of an exact Stage 2.33 inspection presentation.

This module records receipt of the complete ordered tuple of fixed Stage 2.33
confirmation tokens.  It does not prove that a human read or understood a
message, identify a user, record informed consent, authenticate a recovery
source, or grant recovery or operation authority.

The implementation is process-local and non-mutating.  It performs no GUI,
localization rendering, filesystem, storage, recovery, network, logging,
clock, randomness, callback, executor, or operation work.
"""

from __future__ import annotations

import hashlib as _hashlib
import hmac as _hmac
import struct as _struct
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum
from threading import Lock as _Lock
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_presentation import (
    RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT,
    RecoverySourceInspectionPresentationConfirmationKey,
    VaultRecoverySourceInspectionPresentation,
    _validate_source_inspection_presentation,
)


RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT"
)
RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_VERSION = 1
RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_PRESENTATION_SHA256_LEN = 32
RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_SEQUENCE = 1

_PRESENTATION_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-SOURCE-INSPECTION-ACKNOWLEDGEMENT\x00"
    b"PRESENTATION-V1\x00"
)
_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
)
_REQUIRED_CONFIRMATIONS = (
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
)


class VaultRecoverySourceInspectionAcknowledgementError(ValueError):
    """Base class for strict Stage 2.34 acknowledgement failures."""


class VaultRecoverySourceInspectionAcknowledgementPresentationError(
    VaultRecoverySourceInspectionAcknowledgementError
):
    """The supplied exact Stage 2.33 presentation is invalid."""


class VaultRecoverySourceInspectionAcknowledgementConfirmationError(
    VaultRecoverySourceInspectionAcknowledgementError
):
    """Confirmation tokens are malformed, incomplete, or out of order."""


class VaultRecoverySourceInspectionAcknowledgementMismatchError(
    VaultRecoverySourceInspectionAcknowledgementError
):
    """The supplied presentation differs from the prepared binding."""


class VaultRecoverySourceInspectionAcknowledgementReplayError(
    VaultRecoverySourceInspectionAcknowledgementError
):
    """A prepared acknowledgement is consumed or cannot be duplicated."""


class VaultRecoverySourceInspectionAcknowledgementFormatError(
    VaultRecoverySourceInspectionAcknowledgementError
):
    """An acknowledgement object violates the frozen Stage 2.34 schema."""


class RecoverySourceInspectionAcknowledgementState(str, Enum):
    """Process-local state; neither member is operation authorization."""

    AWAITING_CONFIRMATIONS = "awaiting_confirmations"
    ACKNOWLEDGED = "acknowledged"


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionAcknowledgementReceipt:
    """Bounded acknowledgement evidence retaining no source evidence or power."""

    presentation_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    acknowledgement_state: RecoverySourceInspectionAcknowledgementState
    acknowledged_confirmations: tuple[
        RecoverySourceInspectionPresentationConfirmationKey, ...
    ]
    confirmation_count: int
    acknowledgement_sequence: int = (
        RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_SEQUENCE
    )
    presentation_validated: bool = True
    exact_confirmation_tokens_received: bool = True
    confirmation_order_validated: bool = True
    all_confirmations_acknowledged: bool = True
    one_shot: bool = True
    read_only: bool = True
    process_local: bool = True
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    digital_signature_created: bool = False
    source_provenance_proven: bool = False
    cryptographic_authenticity_established: bool = False
    source_freshness_established: bool = False
    recovery_secret_received: bool = False
    recovery_performed: bool = False
    rehearsal_performed: bool = False
    stage2_8_used: bool = False
    review_session_prepared: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    gate_invoked: bool = False
    automatic_transition: bool = False
    filesystem_access_performed: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    logging_used: bool = False
    gui_used: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_VERSION

    def __post_init__(self) -> None:
        _validate_source_inspection_acknowledgement_receipt(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "source inspection acknowledgement receipt cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "source inspection acknowledgement receipt cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "source inspection acknowledgement receipt cannot be serialized"
        )


@_dataclass(frozen=True, slots=True)
class _AcknowledgementBinding:
    presentation_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    required_confirmations: tuple[
        RecoverySourceInspectionPresentationConfirmationKey, ...
    ]


class PreparedVaultRecoverySourceInspectionAcknowledgement:
    """Bind one exact presentation for exactly one successful acknowledgement."""

    __slots__ = ("_binding", "_receipt", "_lock")

    def __init__(self, binding: _AcknowledgementBinding) -> None:
        _validate_acknowledgement_binding(binding)
        self._binding = binding
        self._receipt: (
            VaultRecoverySourceInspectionAcknowledgementReceipt | None
        ) = None
        self._lock = _Lock()

    @property
    def required_confirmations(
        self,
    ) -> tuple[RecoverySourceInspectionPresentationConfirmationKey, ...]:
        return self._binding.required_confirmations

    @property
    def acknowledged(self) -> bool:
        return self._receipt is not None

    @property
    def current_state(self) -> RecoverySourceInspectionAcknowledgementState:
        if self._receipt is None:
            return RecoverySourceInspectionAcknowledgementState.AWAITING_CONFIRMATIONS
        return RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED

    @property
    def receipt(
        self,
    ) -> VaultRecoverySourceInspectionAcknowledgementReceipt | None:
        return self._receipt

    def acknowledge_once(
        self,
        presentation: VaultRecoverySourceInspectionPresentation,
        confirmations: tuple[
            RecoverySourceInspectionPresentationConfirmationKey, ...
        ],
    ) -> VaultRecoverySourceInspectionAcknowledgementReceipt:
        """Record one exact ordered token acknowledgement without authority."""

        with self._lock:
            if self._receipt is not None:
                raise VaultRecoverySourceInspectionAcknowledgementReplayError(
                    "source inspection presentation was already acknowledged"
                )

            observed = _binding_from_presentation(presentation)
            if (
                not _hmac.compare_digest(
                    observed.presentation_sha256,
                    self._binding.presentation_sha256,
                )
                or observed.locale is not self._binding.locale
                or observed.required_confirmations
                != self._binding.required_confirmations
            ):
                raise VaultRecoverySourceInspectionAcknowledgementMismatchError(
                    "presentation differs from the prepared acknowledgement"
                )

            exact_confirmations = _validate_confirmation_input(confirmations)
            if exact_confirmations != self._binding.required_confirmations:
                raise VaultRecoverySourceInspectionAcknowledgementConfirmationError(
                    "confirmations must match the complete exact ordered tuple"
                )

            receipt = VaultRecoverySourceInspectionAcknowledgementReceipt(
                presentation_sha256=self._binding.presentation_sha256,
                locale=self._binding.locale,
                acknowledgement_state=(
                    RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED
                ),
                acknowledged_confirmations=exact_confirmations,
                confirmation_count=len(exact_confirmations),
            )
            # This is the only lifecycle commit.  An interrupt before it leaves
            # the object fresh; an interrupt after it leaves it safely consumed.
            self._receipt = receipt
            return receipt

    def __repr__(self) -> str:
        return (
            "PreparedVaultRecoverySourceInspectionAcknowledgement("
            f"locale={self._binding.locale.value!r}, "
            f"state={self.current_state.value!r})"
        )

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "prepared source inspection acknowledgement cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "prepared source inspection acknowledgement cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionAcknowledgementReplayError(
            "prepared source inspection acknowledgement cannot be serialized"
        )


def _pack_enum(value: Enum) -> bytes:
    encoded = value.value.encode("ascii")
    return _struct.pack(">H", len(encoded)) + encoded


def _pack_enum_tuple(value: tuple[Enum, ...]) -> bytes:
    return _struct.pack(">B", len(value)) + b"".join(
        _pack_enum(item) for item in value
    )


def _presentation_transcript(
    value: VaultRecoverySourceInspectionPresentation,
) -> bytes:
    locale_code = {
        RecoveryLocalizationLocale.BULGARIAN_BULGARIA: 1,
        RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM: 2,
    }[value.locale]
    flags = (
        value.inspection_completed,
        value.header_structurally_validated,
        value.cryptographic_authenticity_established,
        value.future_secure_source_reopen_required,
        value.exact_execution_outcome_validated,
        value.fixed_message_keys_only,
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
        value.process_local,
        value.evidence_digest_is_digital_signature,
        value.evidence_digest_is_provenance_proof,
        value.evidence_digest_is_anti_rollback_anchor,
    )
    format_bytes = value.format.encode("ascii")
    return b"".join(
        (
            _PRESENTATION_DIGEST_DOMAIN,
            _struct.pack(">B", locale_code),
            value.inspection_evidence_sha256,
            _pack_enum_tuple(value.message_keys),
            _pack_enum_tuple(value.confirmation_requirements),
            _struct.pack(">32?", *flags),
            _struct.pack(">H", len(format_bytes)),
            format_bytes,
            _struct.pack(">I", value.version),
        )
    )


def _validate_source_presentation(
    value: _Any,
) -> VaultRecoverySourceInspectionPresentation:
    if type(value) is not VaultRecoverySourceInspectionPresentation:
        raise VaultRecoverySourceInspectionAcknowledgementPresentationError(
            "presentation type is invalid"
        )
    try:
        _validate_source_inspection_presentation(value)
    except Exception:
        raise VaultRecoverySourceInspectionAcknowledgementPresentationError(
            "presentation violates the Stage 2.33 contract"
        ) from None
    return value


def _binding_from_presentation(value: _Any) -> _AcknowledgementBinding:
    exact = _validate_source_presentation(value)
    return _AcknowledgementBinding(
        presentation_sha256=_hashlib.sha256(
            _presentation_transcript(exact)
        ).digest(),
        locale=exact.locale,
        required_confirmations=exact.confirmation_requirements,
    )


def _validate_acknowledgement_binding(value: _Any) -> None:
    if (
        type(value) is not _AcknowledgementBinding
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_PRESENTATION_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.required_confirmations) is not tuple
        or value.required_confirmations != _REQUIRED_CONFIRMATIONS
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value.required_confirmations
        )
    ):
        raise VaultRecoverySourceInspectionAcknowledgementFormatError(
            "source inspection acknowledgement binding is invalid"
        )


def _validate_confirmation_input(
    value: _Any,
) -> tuple[RecoverySourceInspectionPresentationConfirmationKey, ...]:
    if (
        type(value) is not tuple
        or len(value)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise VaultRecoverySourceInspectionAcknowledgementConfirmationError(
            "confirmations must be the bounded unique exact-enum tuple"
        )
    return value


def _validate_source_inspection_acknowledgement_receipt(
    value: _Any,
) -> None:
    if type(value) is not VaultRecoverySourceInspectionAcknowledgementReceipt:
        raise VaultRecoverySourceInspectionAcknowledgementFormatError(
            "source inspection acknowledgement receipt type is invalid"
        )
    required_true = (
        value.presentation_validated,
        value.exact_confirmation_tokens_received,
        value.confirmation_order_validated,
        value.all_confirmations_acknowledged,
        value.one_shot,
        value.read_only,
        value.process_local,
    )
    required_false = (
        value.human_understanding_proven,
        value.user_identity_verified,
        value.informed_consent_proven,
        value.digital_signature_created,
        value.source_provenance_proven,
        value.cryptographic_authenticity_established,
        value.source_freshness_established,
        value.recovery_secret_received,
        value.recovery_performed,
        value.rehearsal_performed,
        value.stage2_8_used,
        value.review_session_prepared,
        value.operation_authorized,
        value.operation_performed,
        value.gate_invoked,
        value.automatic_transition,
        value.filesystem_access_performed,
        value.filesystem_mutation_performed,
        value.network_used,
        value.logging_used,
        value.gui_used,
    )
    if (
        type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_PRESENTATION_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.acknowledgement_state)
        is not RecoverySourceInspectionAcknowledgementState
        or value.acknowledgement_state
        is not RecoverySourceInspectionAcknowledgementState.ACKNOWLEDGED
        or type(value.acknowledged_confirmations) is not tuple
        or value.acknowledged_confirmations != _REQUIRED_CONFIRMATIONS
        or any(
            type(item)
            is not RecoverySourceInspectionPresentationConfirmationKey
            for item in value.acknowledged_confirmations
        )
        or type(value.confirmation_count) is not int
        or value.confirmation_count
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or type(value.acknowledgement_sequence) is not int
        or value.acknowledgement_sequence
        != RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_SEQUENCE
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_ACKNOWLEDGEMENT_VERSION
    ):
        raise VaultRecoverySourceInspectionAcknowledgementFormatError(
            "source inspection acknowledgement receipt is invalid"
        )


def prepare_recovery_source_inspection_acknowledgement(
    presentation: VaultRecoverySourceInspectionPresentation,
) -> PreparedVaultRecoverySourceInspectionAcknowledgement:
    """Bind one exact Stage 2.33 presentation for one acknowledgement."""

    return PreparedVaultRecoverySourceInspectionAcknowledgement(
        _binding_from_presentation(presentation)
    )
