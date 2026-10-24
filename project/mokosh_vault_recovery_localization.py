"""Versioned fixed localization registry for Vault recovery review.

Stage 2.13 binds every Stage 2.10 message and confirmation key to one
reviewed, bounded Bulgarian or English string.  It can localize one exact
validated Stage 2.12 view into deterministic display records, but it does not
create widgets, accept interaction, acknowledge a workflow, or invoke an
operation.

The module performs no filesystem access, Vault unlock, recovery rehearsal,
candidate creation, recovery setup, publish, retry, repair, cleanup, callback,
executor, mutation, GUI work, network access, telemetry, logging, clock access,
randomness, update discovery, download, or installation.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import unicodedata
from dataclasses import dataclass as _dataclass, field as _field
from typing import Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale

from mokosh_vault_recovery_presentation import (
    MAX_PRESENTATION_CONFIRMATIONS,
    MAX_PRESENTATION_MESSAGE_KEYS,
    RecoveryPresentationConfirmationKey,
    RecoveryPresentationMessageKey,
)
from mokosh_vault_recovery_reconciliation import RecoveryPublishClassification
from mokosh_vault_recovery_ui_adapter import (
    RECOVERY_UI_ADAPTER_PRESENTATION_SHA256_LEN,
    RecoveryUIAdapterState,
    VaultRecoveryUIAdapterError,
    VaultRecoveryUIAdapterView,
    _expected_route,
    _validate_adapter_view,
)
from mokosh_vault_recovery_workflow import (
    RecoveryWorkflowDecision,
    RecoveryWorkflowState,
)


RECOVERY_LOCALIZATION_FORMAT = "MOKOSH_VAULT_RECOVERY_LOCALIZATION"
RECOVERY_LOCALIZATION_VERSION = 1
RECOVERY_LOCALIZATION_CATALOG_SHA256_LEN = 32
MAX_RECOVERY_LOCALIZED_TEXT_CODEPOINTS = 240
MAX_RECOVERY_LOCALIZED_TEXT_UTF8_LEN = 768

_CATALOG_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-LOCALIZATION\x00CATALOG-V1\x00"
)
_FORBIDDEN_BIDI_CLASSES = frozenset(
    {"BN", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
)


class VaultRecoveryLocalizationError(ValueError):
    """Base class for strict Stage 2.13 localization failures."""


class VaultRecoveryLocalizationLocaleError(VaultRecoveryLocalizationError):
    """A locale identifier is unsupported, ambiguous, or not exact."""


class VaultRecoveryLocalizationCatalogError(VaultRecoveryLocalizationError):
    """A catalog is incomplete, mixed, altered, unsafe, or malformed."""


class VaultRecoveryLocalizationSourceError(VaultRecoveryLocalizationError):
    """The supplied Stage 2.12 view is malformed or unsupported."""


class VaultRecoveryLocalizationFormatError(VaultRecoveryLocalizationError):
    """A localized record violates the fixed Stage 2.13 schema."""


_BG_MESSAGE_TEXTS = (
    (RecoveryPresentationMessageKey.WORKFLOW_RESULT_REVIEWED,
     "Резултатът от проверката на възстановяването е прегледан."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_ABSENT,
     "Целевото поколение на Vault липсва."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_EXACT,
     "Целевото поколение на Vault съществува и съвпада точно с проверения резултат."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_CONFLICT,
     "Открито е противоречие в целевото поколение на Vault."),
    (RecoveryPresentationMessageKey.DECISION_PRESERVE_AND_STOP,
     "Избрано е текущото състояние да бъде запазено и процесът да спре."),
    (RecoveryPresentationMessageKey.DECISION_TARGET_ABSENT_ACKNOWLEDGED,
     "Липсващото целево поколение е потвърдено за преглед."),
    (RecoveryPresentationMessageKey.DECISION_EXACT_TARGET_ACKNOWLEDGED,
     "Точното целево поколение е потвърдено за преглед."),
    (RecoveryPresentationMessageKey.DECISION_CONFLICT_ACKNOWLEDGED,
     "Противоречието е потвърдено за ръчен преглед."),
    (RecoveryPresentationMessageKey.ROUTE_FRESH_CANDIDATE_DECISION_REQUIRED,
     "Необходимо е отделно решение за създаване на нов кандидат за възстановяване."),
    (RecoveryPresentationMessageKey.ROUTE_NORMAL_UNLOCK_REQUIRED,
     "Следва нормално отключване на Vault с отделна проверка."),
    (RecoveryPresentationMessageKey.ROUTE_MANUAL_REVIEW_STOP,
     "Процесът спира за ръчен преглед."),
    (RecoveryPresentationMessageKey.ROUTE_PRESERVED_STOP,
     "Текущото състояние е запазено и процесът е спрян."),
    (RecoveryPresentationMessageKey.GATE_FRESH_STAGE_2_6_DECISION_REQUIRED,
     "Преди продължаване е необходимо отделно решение за нов кандидат за възстановяване."),
    (RecoveryPresentationMessageKey.GATE_NORMAL_VAULT_UNLOCK_REQUIRED,
     "Преди продължаване Vault трябва да бъде отключен по нормалния начин."),
    (RecoveryPresentationMessageKey.GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
     "След отключването е необходимо отделно решение за нов запис за възстановяване."),
    (RecoveryPresentationMessageKey.GATE_MANUAL_REVIEW_ONLY,
     "Разрешен е само ръчен преглед; няма автоматично продължаване."),
    (RecoveryPresentationMessageKey.DOWNSTREAM_REVERIFICATION_REQUIRED,
     "Преди следващата стъпка всички входни данни трябва да бъдат проверени отново."),
    (RecoveryPresentationMessageKey.FRESH_INPUTS_REQUIRED,
     "Следващата стъпка изисква нови и актуално проверени входни данни."),
    (RecoveryPresentationMessageKey.OLD_RECOVERY_RECORD_REMAINS_STALE,
     "Старият запис за възстановяване остава неактуален и не трябва да се използва."),
    (RecoveryPresentationMessageKey.TERMINAL_STOP,
     "Това е крайна точка за спиране; процесът не продължава автоматично."),
    (RecoveryPresentationMessageKey.RECOVERY_PROBLEM_NOT_RESOLVED,
     "Проблемът с възстановяването не е решен."),
    (RecoveryPresentationMessageKey.NO_OPERATION_PERFORMED,
     "Не е извършена операция за възстановяване."),
    (RecoveryPresentationMessageKey.NO_OPERATION_AUTHORIZED,
     "Не е разрешена операция за възстановяване."),
    (RecoveryPresentationMessageKey.NO_AUTOMATIC_RETRY_REPAIR_OR_CLEANUP,
     "Няма автоматичен повторен опит, поправка или почистване."),
)

_EN_MESSAGE_TEXTS = (
    (RecoveryPresentationMessageKey.WORKFLOW_RESULT_REVIEWED,
     "The recovery review result has been examined."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_ABSENT,
     "The target Vault generation is absent."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_TARGET_EXACT,
     "The target Vault generation exists and exactly matches the verified result."),
    (RecoveryPresentationMessageKey.CLASSIFICATION_CONFLICT,
     "A conflict was detected in the target Vault generation."),
    (RecoveryPresentationMessageKey.DECISION_PRESERVE_AND_STOP,
     "The current state will be preserved and the process will stop."),
    (RecoveryPresentationMessageKey.DECISION_TARGET_ABSENT_ACKNOWLEDGED,
     "The absent target generation has been acknowledged for review."),
    (RecoveryPresentationMessageKey.DECISION_EXACT_TARGET_ACKNOWLEDGED,
     "The exact target generation has been acknowledged for review."),
    (RecoveryPresentationMessageKey.DECISION_CONFLICT_ACKNOWLEDGED,
     "The conflict has been acknowledged for manual review."),
    (RecoveryPresentationMessageKey.ROUTE_FRESH_CANDIDATE_DECISION_REQUIRED,
     "A separate decision is required before creating a new recovery candidate."),
    (RecoveryPresentationMessageKey.ROUTE_NORMAL_UNLOCK_REQUIRED,
     "A normal Vault unlock with separate verification is required next."),
    (RecoveryPresentationMessageKey.ROUTE_MANUAL_REVIEW_STOP,
     "The process stops for manual review."),
    (RecoveryPresentationMessageKey.ROUTE_PRESERVED_STOP,
     "The current state has been preserved and the process has stopped."),
    (RecoveryPresentationMessageKey.GATE_FRESH_STAGE_2_6_DECISION_REQUIRED,
     "A separate decision for a new recovery candidate is required before continuing."),
    (RecoveryPresentationMessageKey.GATE_NORMAL_VAULT_UNLOCK_REQUIRED,
     "The Vault must be unlocked normally before continuing."),
    (RecoveryPresentationMessageKey.GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
     "After unlock, a separate decision for a new recovery record is required."),
    (RecoveryPresentationMessageKey.GATE_MANUAL_REVIEW_ONLY,
     "Only manual review is allowed; there is no automatic continuation."),
    (RecoveryPresentationMessageKey.DOWNSTREAM_REVERIFICATION_REQUIRED,
     "All inputs must be verified again before the next step."),
    (RecoveryPresentationMessageKey.FRESH_INPUTS_REQUIRED,
     "The next step requires fresh, currently verified inputs."),
    (RecoveryPresentationMessageKey.OLD_RECOVERY_RECORD_REMAINS_STALE,
     "The old recovery record remains stale and must not be used."),
    (RecoveryPresentationMessageKey.TERMINAL_STOP,
     "This is a terminal stop; the process will not continue automatically."),
    (RecoveryPresentationMessageKey.RECOVERY_PROBLEM_NOT_RESOLVED,
     "The recovery problem has not been resolved."),
    (RecoveryPresentationMessageKey.NO_OPERATION_PERFORMED,
     "No recovery operation has been performed."),
    (RecoveryPresentationMessageKey.NO_OPERATION_AUTHORIZED,
     "No recovery operation has been authorized."),
    (RecoveryPresentationMessageKey.NO_AUTOMATIC_RETRY_REPAIR_OR_CLEANUP,
     "There is no automatic retry, repair, or cleanup."),
)

_BG_CONFIRMATION_TEXTS = (
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_OPERATION_PERFORMED,
     "Разбирам, че не е извършена операция за възстановяване."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
     "Разбирам, че преди следващата стъпка е необходима нова проверка."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED,
     "Разбирам, че е необходимо отделно решение за нов кандидат за възстановяване."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED,
     "Разбирам, че е необходимо нормално отключване на Vault."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
     "Разбирам, че е необходимо отделно решение за нов запис за възстановяване."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP,
     "Разбирам, че процесът спира за ръчен преглед."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
     "Разбирам, че няма автоматичен повторен опит или поправка."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_PRESERVED_STOP,
     "Разбирам, че текущото състояние е запазено и процесът е спрян."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_RECOVERY_NOT_RESOLVED,
     "Разбирам, че проблемът с възстановяването не е решен."),
)

_EN_CONFIRMATION_TEXTS = (
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_OPERATION_PERFORMED,
     "I understand that no recovery operation has been performed."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_DOWNSTREAM_REVERIFICATION_REQUIRED,
     "I understand that all inputs must be verified again before the next step."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_FRESH_STAGE_2_6_DECISION_REQUIRED,
     "I understand that a separate decision for a new recovery candidate is required."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NORMAL_UNLOCK_REQUIRED,
     "I understand that a normal Vault unlock is required."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED,
     "I understand that a separate decision for a new recovery record is required."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_MANUAL_REVIEW_STOP,
     "I understand that the process stops for manual review."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_NO_AUTOMATIC_REPAIR,
     "I understand that there is no automatic retry or repair."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_PRESERVED_STOP,
     "I understand that the current state is preserved and the process has stopped."),
    (RecoveryPresentationConfirmationKey.ACKNOWLEDGE_RECOVERY_NOT_RESOLVED,
     "I understand that the recovery problem has not been resolved."),
)


@_dataclass(frozen=True, slots=True)
class RecoveryMessageTranslation:
    locale: RecoveryLocalizationLocale
    message_key: RecoveryPresentationMessageKey
    text: str

    def __post_init__(self) -> None:
        _validate_message_translation(self)


@_dataclass(frozen=True, slots=True)
class RecoveryConfirmationTranslation:
    locale: RecoveryLocalizationLocale
    confirmation_key: RecoveryPresentationConfirmationKey
    text: str

    def __post_init__(self) -> None:
        _validate_confirmation_translation(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryLocalizationCatalog:
    locale: RecoveryLocalizationLocale
    catalog_sha256: bytes = _field(repr=False)
    message_translations: tuple[RecoveryMessageTranslation, ...]
    confirmation_translations: tuple[RecoveryConfirmationTranslation, ...]
    complete: bool = True
    fixed_reviewed_text: bool = True
    fallback_allowed: bool = False
    dynamic_interpolation_allowed: bool = False
    format: str = RECOVERY_LOCALIZATION_FORMAT
    version: int = RECOVERY_LOCALIZATION_VERSION

    def __post_init__(self) -> None:
        _validate_catalog(self)


@_dataclass(frozen=True, slots=True)
class RecoveryLocalizedMessageItem:
    ordinal: int
    locale: RecoveryLocalizationLocale
    message_key: RecoveryPresentationMessageKey
    text: str
    accessible_text: str
    is_gate_message: bool
    visible: bool = True

    def __post_init__(self) -> None:
        _validate_localized_message_item(self)


@_dataclass(frozen=True, slots=True)
class RecoveryLocalizedConfirmationControl:
    ordinal: int
    locale: RecoveryLocalizationLocale
    confirmation_key: RecoveryPresentationConfirmationKey
    text: str
    accessible_text: str
    visible: bool = True
    required: bool = True
    individually_selectable: bool = True
    default_selected: bool = False

    def __post_init__(self) -> None:
        _validate_localized_confirmation_control(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoveryLocalizedUIAdapterView:
    presentation_sha256: bytes = _field(repr=False)
    catalog_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    classification: RecoveryPublishClassification
    decision: RecoveryWorkflowDecision
    state: RecoveryWorkflowState
    adapter_state: RecoveryUIAdapterState
    message_items: tuple[RecoveryLocalizedMessageItem, ...]
    confirmation_controls: tuple[RecoveryLocalizedConfirmationControl, ...]
    terminal_stop: bool
    downstream_reverification_required: bool
    source_view_validated: bool = True
    catalog_validated: bool = True
    exact_locale_selected: bool = True
    complete_fixed_text: bool = True
    fixed_user_facing_text_included: bool = True
    fallback_used: bool = False
    dynamic_interpolation_used: bool = False
    operation_controls_included: bool = False
    operation_performed: bool = False
    operation_authorized: bool = False
    secrets_retained: bool = False
    format: str = RECOVERY_LOCALIZATION_FORMAT
    version: int = RECOVERY_LOCALIZATION_VERSION

    def __post_init__(self) -> None:
        _validate_localized_view(self)


def _validate_text(value: Any, field_name: str) -> str:
    if type(value) is not str:
        raise VaultRecoveryLocalizationCatalogError(
            f"{field_name} is not bounded fixed normalized text"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultRecoveryLocalizationCatalogError(
            f"{field_name} is not valid UTF-8 text"
        ) from exc
    if (
        not 1 <= len(value) <= MAX_RECOVERY_LOCALIZED_TEXT_CODEPOINTS
        or len(encoded) > MAX_RECOVERY_LOCALIZED_TEXT_UTF8_LEN
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or "{" in value
        or "}" in value
    ):
        raise VaultRecoveryLocalizationCatalogError(
            f"{field_name} is not bounded fixed normalized text"
        )
    for character in value:
        if (
            unicodedata.category(character).startswith("C")
            or unicodedata.bidirectional(character) in _FORBIDDEN_BIDI_CLASSES
        ):
            raise VaultRecoveryLocalizationCatalogError(
                f"{field_name} contains a forbidden control or bidi character"
            )
    return value


def _validate_message_translation(value: Any) -> RecoveryMessageTranslation:
    if (
        type(value) is not RecoveryMessageTranslation
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.message_key) is not RecoveryPresentationMessageKey
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "message translation schema is invalid"
        )
    _validate_text(value.text, "message translation")
    return value


def _validate_confirmation_translation(
    value: Any,
) -> RecoveryConfirmationTranslation:
    if (
        type(value) is not RecoveryConfirmationTranslation
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.confirmation_key)
        is not RecoveryPresentationConfirmationKey
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "confirmation translation schema is invalid"
        )
    _validate_text(value.text, "confirmation translation")
    return value


def _catalog_pairs(
    locale: RecoveryLocalizationLocale,
) -> tuple[tuple[tuple[Any, str], ...], tuple[tuple[Any, str], ...]]:
    if locale is RecoveryLocalizationLocale.BULGARIAN_BULGARIA:
        return _BG_MESSAGE_TEXTS, _BG_CONFIRMATION_TEXTS
    if locale is RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM:
        return _EN_MESSAGE_TEXTS, _EN_CONFIRMATION_TEXTS
    raise VaultRecoveryLocalizationLocaleError("locale is unsupported")


def _length_prefixed(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _catalog_digest(locale: RecoveryLocalizationLocale) -> bytes:
    messages, confirmations = _catalog_pairs(locale)
    parts = [_CATALOG_DIGEST_DOMAIN, _length_prefixed(locale.value.encode("ascii"))]
    for kind, pairs in ((b"M", messages), (b"C", confirmations)):
        parts.append(struct.pack(">cI", kind, len(pairs)))
        for key, text in pairs:
            parts.append(_length_prefixed(key.value.encode("ascii")))
            parts.append(_length_prefixed(text.encode("utf-8")))
    return hashlib.sha256(b"".join(parts)).digest()


def _validate_catalog(value: Any) -> VaultRecoveryLocalizationCatalog:
    if type(value) is not VaultRecoveryLocalizationCatalog:
        raise VaultRecoveryLocalizationCatalogError("catalog type is invalid")
    if (
        value.format != RECOVERY_LOCALIZATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_LOCALIZATION_VERSION
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.catalog_sha256) is not bytes
        or len(value.catalog_sha256) != RECOVERY_LOCALIZATION_CATALOG_SHA256_LEN
    ):
        raise VaultRecoveryLocalizationCatalogError("catalog schema is invalid")
    if (
        type(value.message_translations) is not tuple
        or len(value.message_translations) != len(RecoveryPresentationMessageKey)
        or type(value.confirmation_translations) is not tuple
        or len(value.confirmation_translations)
        != len(RecoveryPresentationConfirmationKey)
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "catalog must contain every key exactly once"
        )
    for entry in value.message_translations:
        _validate_message_translation(entry)
    for entry in value.confirmation_translations:
        _validate_confirmation_translation(entry)

    expected_messages, expected_confirmations = _catalog_pairs(value.locale)
    observed_messages = tuple(
        (entry.message_key, entry.text) for entry in value.message_translations
    )
    observed_confirmations = tuple(
        (entry.confirmation_key, entry.text)
        for entry in value.confirmation_translations
    )
    if (
        observed_messages != expected_messages
        or observed_confirmations != expected_confirmations
        or any(entry.locale is not value.locale for entry in value.message_translations)
        or any(
            entry.locale is not value.locale
            for entry in value.confirmation_translations
        )
        or not hmac.compare_digest(value.catalog_sha256, _catalog_digest(value.locale))
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "catalog is incomplete, mixed-locale, reordered, or altered"
        )
    bool_fields = (
        "complete",
        "fixed_reviewed_text",
        "fallback_allowed",
        "dynamic_interpolation_allowed",
    )
    if (
        any(type(getattr(value, name)) is not bool for name in bool_fields)
        or value.complete is not True
        or value.fixed_reviewed_text is not True
        or value.fallback_allowed is not False
        or value.dynamic_interpolation_allowed is not False
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "catalog completeness or fallback policy is invalid"
        )
    return value


def _build_catalog(
    locale: RecoveryLocalizationLocale,
) -> VaultRecoveryLocalizationCatalog:
    messages, confirmations = _catalog_pairs(locale)
    return VaultRecoveryLocalizationCatalog(
        locale=locale,
        catalog_sha256=_catalog_digest(locale),
        message_translations=tuple(
            RecoveryMessageTranslation(locale, key, text)
            for key, text in messages
        ),
        confirmation_translations=tuple(
            RecoveryConfirmationTranslation(locale, key, text)
            for key, text in confirmations
        ),
    )


RECOVERY_LOCALIZATION_REGISTRY = tuple(
    _build_catalog(locale) for locale in RecoveryLocalizationLocale
)


def _validate_registry(value: Any) -> tuple[VaultRecoveryLocalizationCatalog, ...]:
    if (
        type(value) is not tuple
        or len(value) != len(RecoveryLocalizationLocale)
        or any(type(item) is not VaultRecoveryLocalizationCatalog for item in value)
        or tuple(item.locale for item in value) != tuple(RecoveryLocalizationLocale)
    ):
        raise VaultRecoveryLocalizationCatalogError(
            "localization registry is missing, duplicated, or reordered"
        )
    for catalog in value:
        _validate_catalog(catalog)
    return value


_validate_registry(RECOVERY_LOCALIZATION_REGISTRY)


def supported_recovery_locale_ids() -> tuple[str, ...]:
    """Return the exact locale allowlist; order is part of version 1."""

    _validate_registry(RECOVERY_LOCALIZATION_REGISTRY)
    return tuple(locale.value for locale in RecoveryLocalizationLocale)


def get_recovery_localization_catalog(
    locale_id: str,
) -> VaultRecoveryLocalizationCatalog:
    """Resolve one exact supported locale without normalization or fallback."""

    if type(locale_id) is not str:
        raise VaultRecoveryLocalizationLocaleError(
            "locale_id must be an exact plain string"
        )
    _validate_registry(RECOVERY_LOCALIZATION_REGISTRY)
    for catalog in RECOVERY_LOCALIZATION_REGISTRY:
        if locale_id == catalog.locale.value:
            return _validate_catalog(catalog)
    raise VaultRecoveryLocalizationLocaleError(
        "locale_id is unsupported; no fallback was used"
    )


def _message_text(
    catalog: VaultRecoveryLocalizationCatalog,
    key: RecoveryPresentationMessageKey,
) -> str:
    for entry in catalog.message_translations:
        if entry.message_key is key:
            return entry.text
    raise VaultRecoveryLocalizationCatalogError(
        "catalog is missing a required message key"
    )


def _confirmation_text(
    catalog: VaultRecoveryLocalizationCatalog,
    key: RecoveryPresentationConfirmationKey,
) -> str:
    for entry in catalog.confirmation_translations:
        if entry.confirmation_key is key:
            return entry.text
    raise VaultRecoveryLocalizationCatalogError(
        "catalog is missing a required confirmation key"
    )


def _validate_localized_message_item(
    value: Any,
) -> RecoveryLocalizedMessageItem:
    if (
        type(value) is not RecoveryLocalizedMessageItem
        or type(value.ordinal) is not int
        or not 1 <= value.ordinal <= MAX_PRESENTATION_MESSAGE_KEYS
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.message_key) is not RecoveryPresentationMessageKey
        or type(value.is_gate_message) is not bool
        or type(value.visible) is not bool
        or value.visible is not True
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized message item schema is invalid"
        )
    try:
        expected = _message_text(
            get_recovery_localization_catalog(value.locale.value),
            value.message_key,
        )
        _validate_text(value.text, "localized message text")
        _validate_text(value.accessible_text, "localized accessible text")
    except VaultRecoveryLocalizationCatalogError as exc:
        raise VaultRecoveryLocalizationFormatError(
            "localized message text is invalid"
        ) from exc
    if value.text != expected or value.accessible_text != expected:
        raise VaultRecoveryLocalizationFormatError(
            "localized message differs from the exact reviewed text"
        )
    return value


def _validate_localized_confirmation_control(
    value: Any,
) -> RecoveryLocalizedConfirmationControl:
    if (
        type(value) is not RecoveryLocalizedConfirmationControl
        or type(value.ordinal) is not int
        or not 1 <= value.ordinal <= MAX_PRESENTATION_CONFIRMATIONS
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.confirmation_key)
        is not RecoveryPresentationConfirmationKey
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized confirmation control schema is invalid"
        )
    bool_fields = (
        "visible",
        "required",
        "individually_selectable",
        "default_selected",
    )
    if (
        any(type(getattr(value, name)) is not bool for name in bool_fields)
        or value.visible is not True
        or value.required is not True
        or value.individually_selectable is not True
        or value.default_selected is not False
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized confirmation visibility policy is invalid"
        )
    try:
        expected = _confirmation_text(
            get_recovery_localization_catalog(value.locale.value),
            value.confirmation_key,
        )
        _validate_text(value.text, "localized confirmation text")
        _validate_text(value.accessible_text, "localized accessible text")
    except VaultRecoveryLocalizationCatalogError as exc:
        raise VaultRecoveryLocalizationFormatError(
            "localized confirmation text is invalid"
        ) from exc
    if value.text != expected or value.accessible_text != expected:
        raise VaultRecoveryLocalizationFormatError(
            "localized confirmation differs from the exact reviewed text"
        )
    return value


def _validate_localized_view(
    value: Any,
) -> VaultRecoveryLocalizedUIAdapterView:
    if type(value) is not VaultRecoveryLocalizedUIAdapterView:
        raise VaultRecoveryLocalizationFormatError("localized view type is invalid")
    if (
        value.format != RECOVERY_LOCALIZATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_LOCALIZATION_VERSION
        or type(value.locale) is not RecoveryLocalizationLocale
        or type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.catalog_sha256) is not bytes
        or len(value.catalog_sha256) != RECOVERY_LOCALIZATION_CATALOG_SHA256_LEN
        or type(value.classification) is not RecoveryPublishClassification
        or type(value.decision) is not RecoveryWorkflowDecision
        or type(value.state) is not RecoveryWorkflowState
        or type(value.adapter_state) is not RecoveryUIAdapterState
        or value.adapter_state
        is not RecoveryUIAdapterState.AWAITING_USER_CONFIRMATIONS
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized view schema is invalid"
        )
    if (
        type(value.message_items) is not tuple
        or not 1 <= len(value.message_items) <= MAX_PRESENTATION_MESSAGE_KEYS
        or any(
            type(item) is not RecoveryLocalizedMessageItem
            for item in value.message_items
        )
        or type(value.confirmation_controls) is not tuple
        or not 1
        <= len(value.confirmation_controls)
        <= MAX_PRESENTATION_CONFIRMATIONS
        or any(
            type(item) is not RecoveryLocalizedConfirmationControl
            for item in value.confirmation_controls
        )
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized view items are invalid"
        )
    for item in value.message_items:
        _validate_localized_message_item(item)
    for item in value.confirmation_controls:
        _validate_localized_confirmation_control(item)

    bool_fields = (
        "terminal_stop",
        "downstream_reverification_required",
        "source_view_validated",
        "catalog_validated",
        "exact_locale_selected",
        "complete_fixed_text",
        "fixed_user_facing_text_included",
        "fallback_used",
        "dynamic_interpolation_used",
        "operation_controls_included",
        "operation_performed",
        "operation_authorized",
        "secrets_retained",
    )
    if any(type(getattr(value, name)) is not bool for name in bool_fields):
        raise VaultRecoveryLocalizationFormatError(
            "localized view safety flags must be exact booleans"
        )
    required_true = (
        value.source_view_validated,
        value.catalog_validated,
        value.exact_locale_selected,
        value.complete_fixed_text,
        value.fixed_user_facing_text_included,
    )
    required_false = (
        value.fallback_used,
        value.dynamic_interpolation_used,
        value.operation_controls_included,
        value.operation_performed,
        value.operation_authorized,
        value.secrets_retained,
    )
    if any(item is not True for item in required_true) or any(
        item is not False for item in required_false
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized view contains fallback, dynamic, or authoritative state"
        )

    catalog = get_recovery_localization_catalog(value.locale.value)
    if not hmac.compare_digest(value.catalog_sha256, catalog.catalog_sha256):
        raise VaultRecoveryLocalizationFormatError(
            "localized view catalog digest is invalid"
        )
    try:
        expected_messages, expected_gates, expected_confirmations = _expected_route(
            value.classification,
            value.decision,
            value.state,
            value.terminal_stop,
            value.downstream_reverification_required,
        )
    except VaultRecoveryUIAdapterError as exc:
        raise VaultRecoveryLocalizationFormatError(
            "localized view route is invalid"
        ) from exc
    if (
        tuple(item.message_key for item in value.message_items)
        != expected_messages
        or tuple(
            item.message_key for item in value.message_items
            if item.is_gate_message
        )
        != expected_gates
        or tuple(
            item.confirmation_key for item in value.confirmation_controls
        )
        != expected_confirmations
        or tuple(item.ordinal for item in value.message_items)
        != tuple(range(1, len(value.message_items) + 1))
        or tuple(item.ordinal for item in value.confirmation_controls)
        != tuple(range(1, len(value.confirmation_controls) + 1))
        or any(item.locale is not value.locale for item in value.message_items)
        or any(
            item.locale is not value.locale
            for item in value.confirmation_controls
        )
    ):
        raise VaultRecoveryLocalizationFormatError(
            "localized view differs from the exact ordered route or locale"
        )
    return value


def localize_recovery_ui_adapter_view(
    view: VaultRecoveryUIAdapterView,
    locale_id: str,
) -> VaultRecoveryLocalizedUIAdapterView:
    """Localize one exact Stage 2.12 view with no fallback or interpolation."""

    if type(view) is not VaultRecoveryUIAdapterView:
        raise VaultRecoveryLocalizationSourceError(
            "view must be an exact VaultRecoveryUIAdapterView"
        )
    try:
        validated = _validate_adapter_view(view)
    except VaultRecoveryUIAdapterError as exc:
        raise VaultRecoveryLocalizationSourceError(
            "view violates the Stage 2.12 contract"
        ) from exc
    catalog = get_recovery_localization_catalog(locale_id)
    messages = tuple(
        RecoveryLocalizedMessageItem(
            ordinal=item.ordinal,
            locale=catalog.locale,
            message_key=item.message_key,
            text=_message_text(catalog, item.message_key),
            accessible_text=_message_text(catalog, item.message_key),
            is_gate_message=item.is_gate_message,
            visible=item.visible,
        )
        for item in validated.message_items
    )
    confirmations = tuple(
        RecoveryLocalizedConfirmationControl(
            ordinal=item.ordinal,
            locale=catalog.locale,
            confirmation_key=item.confirmation_key,
            text=_confirmation_text(catalog, item.confirmation_key),
            accessible_text=_confirmation_text(catalog, item.confirmation_key),
            visible=item.visible,
            required=item.required,
            individually_selectable=item.individually_selectable,
            default_selected=item.default_selected,
        )
        for item in validated.confirmation_controls
    )
    return VaultRecoveryLocalizedUIAdapterView(
        presentation_sha256=validated.presentation_sha256,
        catalog_sha256=catalog.catalog_sha256,
        locale=catalog.locale,
        classification=validated.classification,
        decision=validated.decision,
        state=validated.state,
        adapter_state=validated.adapter_state,
        message_items=messages,
        confirmation_controls=confirmations,
        terminal_stop=validated.terminal_stop,
        downstream_reverification_required=(
            validated.downstream_reverification_required
        ),
    )
