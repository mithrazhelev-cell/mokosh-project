"""Fixed Bulgarian/English localization for the Stage 2.35 adapter view.

This pure registry binds every exact source-inspection message and confirmation
key to one reviewed bounded string.  It accepts one fully revalidated Stage
2.35 view and selects only the locale already bound into that view.

The module is not a GUI, renderer, accessibility certificate, consent record,
source reader, acknowledgement mechanism, or recovery operation.  It performs
no filesystem, network, logging, clock, randomness, or mutation work.
"""

from __future__ import annotations

import hashlib as _hashlib
import hmac as _hmac
import struct as _struct
import unicodedata as _unicodedata
from dataclasses import dataclass as _dataclass, field as _field
from typing import Any as _Any

from mokosh_vault_recovery_locale import RecoveryLocalizationLocale
from mokosh_vault_recovery_source_inspection_presentation import (
    RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT,
    RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT,
    RecoverySourceInspectionPresentationConfirmationKey,
    RecoverySourceInspectionPresentationMessageKey,
)
from mokosh_vault_recovery_source_inspection_ui_adapter import (
    RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN,
    RecoverySourceInspectionUIAdapterState,
    VaultRecoverySourceInspectionUIAdapterError,
    VaultRecoverySourceInspectionUIAdapterView,
    _validate_adapter_view,
)


RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT = (
    "MOKOSH_VAULT_RECOVERY_SOURCE_INSPECTION_LOCALIZATION"
)
RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION = 1
RECOVERY_SOURCE_INSPECTION_LOCALIZATION_CATALOG_SHA256_LEN = 32
MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_CODEPOINTS = 240
MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_UTF8_LEN = 768

_CATALOG_DIGEST_DOMAIN = (
    b"MOKOSH\x00VAULT-RECOVERY-SOURCE-INSPECTION-LOCALIZATION\x00CATALOG-V1\x00"
)
_SUPPORTED_LOCALES = (
    RecoveryLocalizationLocale.BULGARIAN_BULGARIA,
    RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM,
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
_CONFIRMATION_KEYS = (
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
    RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
)
_FORBIDDEN_BIDI_CLASSES = frozenset(
    {"BN", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
)
_FORBIDDEN_TEMPLATE_CHARACTERS = frozenset({"{", "}", "%", "$"})


class VaultRecoverySourceInspectionLocalizationError(ValueError):
    """Base class for strict Stage 2.36 localization failures."""


class VaultRecoverySourceInspectionLocalizationLocaleError(
    VaultRecoverySourceInspectionLocalizationError
):
    """A locale identifier is unsupported or not exact."""


class VaultRecoverySourceInspectionLocalizationCatalogError(
    VaultRecoverySourceInspectionLocalizationError
):
    """A fixed catalog is incomplete, mixed, altered, or malformed."""


class VaultRecoverySourceInspectionLocalizationSourceError(
    VaultRecoverySourceInspectionLocalizationError
):
    """The supplied exact Stage 2.35 view is malformed."""


class VaultRecoverySourceInspectionLocalizationFormatError(
    VaultRecoverySourceInspectionLocalizationError
):
    """A localized record violates the frozen Stage 2.36 schema."""


class VaultRecoverySourceInspectionLocalizationReplayError(
    VaultRecoverySourceInspectionLocalizationError
):
    """A bounded localization object cannot be copied or serialized."""


_BG_MESSAGE_TEXTS = (
    (
        RecoverySourceInspectionPresentationMessageKey.INSPECTION_COMPLETED,
        "Проверката на източника за възстановяване е завършена.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.HEADER_STRUCTURALLY_VALIDATED,
        "Заглавната структура на източника е валидирана.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED,
        "Криптографската автентичност на източника не е установена.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.RECOVERY_SECRET_NOT_RECEIVED,
        "Не е получена тайна за възстановяване.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.FRESH_SECURE_REOPEN_REQUIRED,
        "Преди бъдеща употреба източникът трябва да бъде отворен и проверен отново по защитен начин.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.NO_RECOVERY_PERFORMED,
        "Не е извършено възстановяване.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.NO_OPERATION_AUTHORIZED,
        "Не е разрешена операция.",
    ),
)
_EN_MESSAGE_TEXTS = (
    (
        RecoverySourceInspectionPresentationMessageKey.INSPECTION_COMPLETED,
        "The recovery source inspection has been completed.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.HEADER_STRUCTURALLY_VALIDATED,
        "The source header structure has been validated.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.CRYPTOGRAPHIC_AUTHENTICITY_NOT_ESTABLISHED,
        "The cryptographic authenticity of the source has not been established.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.RECOVERY_SECRET_NOT_RECEIVED,
        "No recovery secret has been received.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.FRESH_SECURE_REOPEN_REQUIRED,
        "The source must be securely reopened and inspected again before future use.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.NO_RECOVERY_PERFORMED,
        "No recovery has been performed.",
    ),
    (
        RecoverySourceInspectionPresentationMessageKey.NO_OPERATION_AUTHORIZED,
        "No operation has been authorized.",
    ),
)
_BG_CONFIRMATION_TEXTS = (
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
        "Потвърждавам, че структурната валидност не доказва криптографска автентичност.",
    ),
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
        "Потвърждавам, че преди бъдеща употреба е необходимо ново защитено отваряне и проверка на източника.",
    ),
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
        "Потвърждавам, че не е извършено възстановяване и не е разрешена операция.",
    ),
)
_EN_CONFIRMATION_TEXTS = (
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_STRUCTURE_IS_NOT_AUTHENTICITY,
        "I acknowledge that structural validity does not prove cryptographic authenticity.",
    ),
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_FRESH_SECURE_REOPEN_REQUIRED,
        "I acknowledge that the source must be securely reopened and inspected again before future use.",
    ),
    (
        RecoverySourceInspectionPresentationConfirmationKey.ACKNOWLEDGE_NO_RECOVERY_OR_OPERATION,
        "I acknowledge that no recovery has been performed and no operation has been authorized.",
    ),
)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionMessageTranslation:
    locale: RecoveryLocalizationLocale
    message_key: RecoverySourceInspectionPresentationMessageKey
    text: str

    def __post_init__(self) -> None:
        _validate_message_translation(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionConfirmationTranslation:
    locale: RecoveryLocalizationLocale
    confirmation_key: RecoverySourceInspectionPresentationConfirmationKey
    text: str

    def __post_init__(self) -> None:
        _validate_confirmation_translation(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionLocalizationCatalog:
    locale: RecoveryLocalizationLocale
    catalog_sha256: bytes = _field(repr=False)
    message_translations: tuple[RecoverySourceInspectionMessageTranslation, ...]
    confirmation_translations: tuple[
        RecoverySourceInspectionConfirmationTranslation, ...
    ]
    complete: bool = True
    fixed_reviewed_text: bool = True
    fallback_allowed: bool = False
    dynamic_interpolation_allowed: bool = False
    external_catalog_allowed: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION

    def __post_init__(self) -> None:
        _validate_catalog(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "source inspection localization catalog cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "source inspection localization catalog cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "source inspection localization catalog cannot be serialized"
        )


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionLocalizedMessageItem:
    ordinal: int
    locale: RecoveryLocalizationLocale
    message_key: RecoverySourceInspectionPresentationMessageKey
    text: str
    accessible_text: str
    visible: bool = True

    def __post_init__(self) -> None:
        _validate_localized_message_item(self)


@_dataclass(frozen=True, slots=True)
class RecoverySourceInspectionLocalizedConfirmationControl:
    ordinal: int
    locale: RecoveryLocalizationLocale
    confirmation_key: RecoverySourceInspectionPresentationConfirmationKey
    text: str
    accessible_text: str
    visible: bool = True
    required: bool = True
    individually_selectable: bool = True
    default_selected: bool = False
    select_all_available: bool = False

    def __post_init__(self) -> None:
        _validate_localized_confirmation_control(self)


@_dataclass(frozen=True, slots=True)
class VaultRecoverySourceInspectionLocalizedUIAdapterView:
    presentation_sha256: bytes = _field(repr=False)
    catalog_sha256: bytes = _field(repr=False)
    locale: RecoveryLocalizationLocale
    adapter_state: RecoverySourceInspectionUIAdapterState
    message_items: tuple[RecoverySourceInspectionLocalizedMessageItem, ...]
    confirmation_controls: tuple[
        RecoverySourceInspectionLocalizedConfirmationControl, ...
    ]
    source_view_validated: bool = True
    catalog_validated: bool = True
    exact_bound_locale_selected: bool = True
    complete_fixed_text: bool = True
    fixed_user_facing_text_included: bool = True
    accessible_text_equals_visible_text: bool = True
    all_required_messages_visible: bool = True
    all_confirmation_controls_visible: bool = True
    confirmations_individually_selectable: bool = True
    all_controls_default_unselected: bool = True
    fallback_used: bool = False
    dynamic_interpolation_used: bool = False
    external_catalog_used: bool = False
    selection_events_included: bool = False
    acknowledgement_performed: bool = False
    actual_gui_rendering_proven: bool = False
    accessibility_conformance_proven: bool = False
    human_understanding_proven: bool = False
    user_identity_verified: bool = False
    informed_consent_proven: bool = False
    operation_controls_included: bool = False
    operation_authorized: bool = False
    operation_performed: bool = False
    secrets_retained: bool = False
    filesystem_access_performed: bool = False
    filesystem_mutation_performed: bool = False
    network_used: bool = False
    logging_used: bool = False
    gui_used: bool = False
    format: str = RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT
    version: int = RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION

    def __post_init__(self) -> None:
        _validate_localized_view(self)

    def __copy__(self) -> None:
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "localized source inspection UI adapter view cannot be copied"
        )

    def __deepcopy__(self, memo: _Any) -> None:
        del memo
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "localized source inspection UI adapter view cannot be copied"
        )

    def __reduce__(self) -> None:
        raise VaultRecoverySourceInspectionLocalizationReplayError(
            "localized source inspection UI adapter view cannot be serialized"
        )


def _validate_text(value: _Any, field_name: str) -> str:
    if type(value) is not str:
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            f"{field_name} is not bounded fixed normalized text"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            f"{field_name} is not valid UTF-8 text"
        ) from exc
    if (
        not 1 <= len(value) <= MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_CODEPOINTS
        or len(encoded) > MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_UTF8_LEN
        or value != value.strip()
        or value != _unicodedata.normalize("NFC", value)
        or any(character in value for character in _FORBIDDEN_TEMPLATE_CHARACTERS)
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            f"{field_name} is not bounded fixed normalized text"
        )
    for character in value:
        if (
            _unicodedata.category(character).startswith("C")
            or _unicodedata.bidirectional(character) in _FORBIDDEN_BIDI_CLASSES
        ):
            raise VaultRecoverySourceInspectionLocalizationCatalogError(
                f"{field_name} contains a forbidden control or bidi character"
            )
    return value


def _validate_message_translation(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionMessageTranslation
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.message_key)
        is not RecoverySourceInspectionPresentationMessageKey
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection message translation schema is invalid"
        )
    _validate_text(value.text, "source inspection message translation")


def _validate_confirmation_translation(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionConfirmationTranslation
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.confirmation_key)
        is not RecoverySourceInspectionPresentationConfirmationKey
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection confirmation translation schema is invalid"
        )
    _validate_text(value.text, "source inspection confirmation translation")


def _catalog_pairs(
    locale: RecoveryLocalizationLocale,
) -> tuple[tuple[tuple[_Any, str], ...], tuple[tuple[_Any, str], ...]]:
    if locale is RecoveryLocalizationLocale.BULGARIAN_BULGARIA:
        return _BG_MESSAGE_TEXTS, _BG_CONFIRMATION_TEXTS
    if locale is RecoveryLocalizationLocale.ENGLISH_UNITED_KINGDOM:
        return _EN_MESSAGE_TEXTS, _EN_CONFIRMATION_TEXTS
    raise VaultRecoverySourceInspectionLocalizationLocaleError(
        "source inspection locale is unsupported"
    )


def _length_prefixed(value: bytes) -> bytes:
    return _struct.pack(">I", len(value)) + value


def _catalog_digest(locale: RecoveryLocalizationLocale) -> bytes:
    messages, confirmations = _catalog_pairs(locale)
    parts = [
        _CATALOG_DIGEST_DOMAIN,
        _length_prefixed(locale.value.encode("ascii")),
    ]
    for kind, pairs in ((b"M", messages), (b"C", confirmations)):
        parts.append(_struct.pack(">cI", kind, len(pairs)))
        for key, value in pairs:
            parts.append(_length_prefixed(key.value.encode("ascii")))
            parts.append(_length_prefixed(value.encode("utf-8")))
    return _hashlib.sha256(b"".join(parts)).digest()


def _validate_catalog(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionLocalizationCatalog:
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection localization catalog type is invalid"
        )
    required_true = (value.complete, value.fixed_reviewed_text)
    required_false = (
        value.fallback_allowed,
        value.dynamic_interpolation_allowed,
        value.external_catalog_allowed,
    )
    if (
        type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.catalog_sha256) is not bytes
        or len(value.catalog_sha256)
        != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_CATALOG_SHA256_LEN
        or type(value.message_translations) is not tuple
        or len(value.message_translations)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or any(
            type(item) is not RecoverySourceInspectionMessageTranslation
            for item in value.message_translations
        )
        or type(value.confirmation_translations) is not tuple
        or len(value.confirmation_translations)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or any(
            type(item) is not RecoverySourceInspectionConfirmationTranslation
            for item in value.confirmation_translations
        )
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection localization catalog schema is invalid"
        )
    for item in value.message_translations:
        _validate_message_translation(item)
    for item in value.confirmation_translations:
        _validate_confirmation_translation(item)
    expected_messages, expected_confirmations = _catalog_pairs(value.locale)
    if (
        tuple((item.message_key, item.text) for item in value.message_translations)
        != expected_messages
        or tuple(
            (item.confirmation_key, item.text)
            for item in value.confirmation_translations
        )
        != expected_confirmations
        or any(item.locale is not value.locale for item in value.message_translations)
        or any(
            item.locale is not value.locale
            for item in value.confirmation_translations
        )
        or not _hmac.compare_digest(
            value.catalog_sha256,
            _catalog_digest(value.locale),
        )
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection localization catalog is incomplete or altered"
        )


def _build_catalog(
    locale: RecoveryLocalizationLocale,
) -> VaultRecoverySourceInspectionLocalizationCatalog:
    messages, confirmations = _catalog_pairs(locale)
    return VaultRecoverySourceInspectionLocalizationCatalog(
        locale=locale,
        catalog_sha256=_catalog_digest(locale),
        message_translations=tuple(
            RecoverySourceInspectionMessageTranslation(locale, key, text)
            for key, text in messages
        ),
        confirmation_translations=tuple(
            RecoverySourceInspectionConfirmationTranslation(locale, key, text)
            for key, text in confirmations
        ),
    )


RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY = tuple(
    _build_catalog(locale) for locale in _SUPPORTED_LOCALES
)


def _validate_registry(value: _Any) -> None:
    if (
        type(value) is not tuple
        or len(value) != len(_SUPPORTED_LOCALES)
        or any(
            type(item) is not VaultRecoverySourceInspectionLocalizationCatalog
            for item in value
        )
        or tuple(item.locale for item in value) != _SUPPORTED_LOCALES
    ):
        raise VaultRecoverySourceInspectionLocalizationCatalogError(
            "source inspection localization registry is invalid"
        )
    for item in value:
        _validate_catalog(item)


_validate_registry(RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY)


def supported_recovery_source_inspection_locale_ids() -> tuple[str, ...]:
    """Return the exact ordered locale allowlist."""

    _validate_registry(RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY)
    return tuple(locale.value for locale in _SUPPORTED_LOCALES)


def get_recovery_source_inspection_localization_catalog(
    locale_id: str,
) -> VaultRecoverySourceInspectionLocalizationCatalog:
    """Resolve one exact built-in catalog without fallback."""

    if type(locale_id) is not str:
        raise VaultRecoverySourceInspectionLocalizationLocaleError(
            "locale_id must be an exact plain string"
        )
    _validate_registry(RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY)
    for catalog in RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY:
        if locale_id == catalog.locale.value:
            _validate_catalog(catalog)
            return catalog
    raise VaultRecoverySourceInspectionLocalizationLocaleError(
        "locale_id is unsupported; no fallback was used"
    )


def _message_text(
    catalog: VaultRecoverySourceInspectionLocalizationCatalog,
    key: RecoverySourceInspectionPresentationMessageKey,
) -> str:
    for item in catalog.message_translations:
        if item.message_key is key:
            return item.text
    raise VaultRecoverySourceInspectionLocalizationCatalogError(
        "catalog is missing an exact source inspection message"
    )


def _confirmation_text(
    catalog: VaultRecoverySourceInspectionLocalizationCatalog,
    key: RecoverySourceInspectionPresentationConfirmationKey,
) -> str:
    for item in catalog.confirmation_translations:
        if item.confirmation_key is key:
            return item.text
    raise VaultRecoverySourceInspectionLocalizationCatalogError(
        "catalog is missing an exact source inspection confirmation"
    )


def _validate_localized_message_item(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionLocalizedMessageItem
        or type(value.ordinal) is not int
        or not 1
        <= value.ordinal
        <= RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.message_key)
        is not RecoverySourceInspectionPresentationMessageKey
        or value.visible is not True
    ):
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection message item is invalid"
        )
    try:
        catalog = get_recovery_source_inspection_localization_catalog(
            value.locale.value
        )
        expected = _message_text(catalog, value.message_key)
        _validate_text(value.text, "localized source inspection message")
        _validate_text(
            value.accessible_text,
            "localized source inspection accessible message",
        )
    except VaultRecoverySourceInspectionLocalizationError as exc:
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection message text is invalid"
        ) from exc
    if value.text != expected or value.accessible_text != expected:
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection message differs from reviewed text"
        )


def _validate_localized_confirmation_control(value: _Any) -> None:
    if (
        type(value) is not RecoverySourceInspectionLocalizedConfirmationControl
        or type(value.ordinal) is not int
        or not 1
        <= value.ordinal
        <= RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.confirmation_key)
        is not RecoverySourceInspectionPresentationConfirmationKey
        or value.visible is not True
        or value.required is not True
        or value.individually_selectable is not True
        or value.default_selected is not False
        or value.select_all_available is not False
    ):
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection confirmation control is invalid"
        )
    try:
        catalog = get_recovery_source_inspection_localization_catalog(
            value.locale.value
        )
        expected = _confirmation_text(catalog, value.confirmation_key)
        _validate_text(value.text, "localized source inspection confirmation")
        _validate_text(
            value.accessible_text,
            "localized source inspection accessible confirmation",
        )
    except VaultRecoverySourceInspectionLocalizationError as exc:
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection confirmation text is invalid"
        ) from exc
    if value.text != expected or value.accessible_text != expected:
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection confirmation differs from reviewed text"
        )


def _validate_localized_view(value: _Any) -> None:
    if type(value) is not VaultRecoverySourceInspectionLocalizedUIAdapterView:
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection view type is invalid"
        )
    required_true = (
        value.source_view_validated,
        value.catalog_validated,
        value.exact_bound_locale_selected,
        value.complete_fixed_text,
        value.fixed_user_facing_text_included,
        value.accessible_text_equals_visible_text,
        value.all_required_messages_visible,
        value.all_confirmation_controls_visible,
        value.confirmations_individually_selectable,
        value.all_controls_default_unselected,
    )
    required_false = (
        value.fallback_used,
        value.dynamic_interpolation_used,
        value.external_catalog_used,
        value.selection_events_included,
        value.acknowledgement_performed,
        value.actual_gui_rendering_proven,
        value.accessibility_conformance_proven,
        value.human_understanding_proven,
        value.user_identity_verified,
        value.informed_consent_proven,
        value.operation_controls_included,
        value.operation_authorized,
        value.operation_performed,
        value.secrets_retained,
        value.filesystem_access_performed,
        value.filesystem_mutation_performed,
        value.network_used,
        value.logging_used,
        value.gui_used,
    )
    if (
        type(value.presentation_sha256) is not bytes
        or len(value.presentation_sha256)
        != RECOVERY_SOURCE_INSPECTION_UI_ADAPTER_PRESENTATION_SHA256_LEN
        or type(value.catalog_sha256) is not bytes
        or len(value.catalog_sha256)
        != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_CATALOG_SHA256_LEN
        or type(value.locale) is not RecoveryLocalizationLocale
        or value.locale not in _SUPPORTED_LOCALES
        or type(value.adapter_state)
        is not RecoverySourceInspectionUIAdapterState
        or value.adapter_state
        is not RecoverySourceInspectionUIAdapterState.AWAITING_USER_CONFIRMATIONS
        or type(value.message_items) is not tuple
        or len(value.message_items)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT
        or any(
            type(item) is not RecoverySourceInspectionLocalizedMessageItem
            for item in value.message_items
        )
        or type(value.confirmation_controls) is not tuple
        or len(value.confirmation_controls)
        != RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT
        or any(
            type(item)
            is not RecoverySourceInspectionLocalizedConfirmationControl
            for item in value.confirmation_controls
        )
        or any(item is not True for item in required_true)
        or any(item is not False for item in required_false)
        or type(value.format) is not str
        or value.format != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT
        or type(value.version) is not int
        or value.version != RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION
    ):
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection view schema is invalid"
        )
    for item in value.message_items:
        _validate_localized_message_item(item)
    for item in value.confirmation_controls:
        _validate_localized_confirmation_control(item)
    catalog = get_recovery_source_inspection_localization_catalog(
        value.locale.value
    )
    if (
        not _hmac.compare_digest(value.catalog_sha256, catalog.catalog_sha256)
        or tuple(item.ordinal for item in value.message_items)
        != tuple(range(1, RECOVERY_SOURCE_INSPECTION_PRESENTATION_MESSAGE_COUNT + 1))
        or tuple(item.message_key for item in value.message_items) != _MESSAGE_KEYS
        or tuple(item.ordinal for item in value.confirmation_controls)
        != tuple(
            range(
                1,
                RECOVERY_SOURCE_INSPECTION_PRESENTATION_CONFIRMATION_COUNT + 1,
            )
        )
        or tuple(
            item.confirmation_key for item in value.confirmation_controls
        )
        != _CONFIRMATION_KEYS
        or any(item.locale is not value.locale for item in value.message_items)
        or any(
            item.locale is not value.locale
            for item in value.confirmation_controls
        )
    ):
        raise VaultRecoverySourceInspectionLocalizationFormatError(
            "localized source inspection view differs from exact locale or order"
        )


def localize_recovery_source_inspection_ui_adapter_view(
    view: VaultRecoverySourceInspectionUIAdapterView,
) -> VaultRecoverySourceInspectionLocalizedUIAdapterView:
    """Localize one exact Stage 2.35 view using its already-bound locale."""

    if type(view) is not VaultRecoverySourceInspectionUIAdapterView:
        raise VaultRecoverySourceInspectionLocalizationSourceError(
            "view must be an exact Stage 2.35 source inspection adapter view"
        )
    try:
        _validate_adapter_view(view)
    except VaultRecoverySourceInspectionUIAdapterError as exc:
        raise VaultRecoverySourceInspectionLocalizationSourceError(
            "view violates the Stage 2.35 contract"
        ) from exc
    catalog = get_recovery_source_inspection_localization_catalog(
        view.locale.value
    )
    return VaultRecoverySourceInspectionLocalizedUIAdapterView(
        presentation_sha256=view.presentation_sha256,
        catalog_sha256=catalog.catalog_sha256,
        locale=view.locale,
        adapter_state=view.adapter_state,
        message_items=tuple(
            RecoverySourceInspectionLocalizedMessageItem(
                ordinal=item.ordinal,
                locale=view.locale,
                message_key=item.message_key,
                text=_message_text(catalog, item.message_key),
                accessible_text=_message_text(catalog, item.message_key),
                visible=item.visible,
            )
            for item in view.message_items
        ),
        confirmation_controls=tuple(
            RecoverySourceInspectionLocalizedConfirmationControl(
                ordinal=item.ordinal,
                locale=view.locale,
                confirmation_key=item.confirmation_key,
                text=_confirmation_text(catalog, item.confirmation_key),
                accessible_text=_confirmation_text(
                    catalog,
                    item.confirmation_key,
                ),
                visible=item.visible,
                required=item.required,
                individually_selectable=item.individually_selectable,
                default_selected=item.default_selected,
                select_all_available=item.select_all_available,
            )
            for item in view.confirmation_controls
        ),
    )


__all__ = (
    "MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_CODEPOINTS",
    "MAX_RECOVERY_SOURCE_INSPECTION_LOCALIZED_TEXT_UTF8_LEN",
    "RECOVERY_SOURCE_INSPECTION_LOCALIZATION_CATALOG_SHA256_LEN",
    "RECOVERY_SOURCE_INSPECTION_LOCALIZATION_FORMAT",
    "RECOVERY_SOURCE_INSPECTION_LOCALIZATION_REGISTRY",
    "RECOVERY_SOURCE_INSPECTION_LOCALIZATION_VERSION",
    "RecoverySourceInspectionConfirmationTranslation",
    "RecoverySourceInspectionLocalizedConfirmationControl",
    "RecoverySourceInspectionLocalizedMessageItem",
    "RecoverySourceInspectionMessageTranslation",
    "VaultRecoverySourceInspectionLocalizationCatalog",
    "VaultRecoverySourceInspectionLocalizationCatalogError",
    "VaultRecoverySourceInspectionLocalizationError",
    "VaultRecoverySourceInspectionLocalizationFormatError",
    "VaultRecoverySourceInspectionLocalizationLocaleError",
    "VaultRecoverySourceInspectionLocalizationReplayError",
    "VaultRecoverySourceInspectionLocalizationSourceError",
    "VaultRecoverySourceInspectionLocalizedUIAdapterView",
    "get_recovery_source_inspection_localization_catalog",
    "localize_recovery_source_inspection_ui_adapter_view",
    "supported_recovery_source_inspection_locale_ids",
)
