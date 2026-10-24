"""MOKOSH-RP1 human transcription for one 256-bit recovery root.

MOKOSH-RP1 is deliberately not BIP39.  It uses the pinned BIP39 English
word list only as a reviewed 2048-word vocabulary.  The encoded payload is
three version bits, the existing 256-bit random Vault recovery root, and a
16-bit domain-separated transcription checksum: exactly 25 full words.

Apart from loading and digest-checking that pinned local vocabulary, this
module performs no key derivation, Vault access, file I/O, clipboard operation,
logging, translation, fuzzy correction, or wallet-seed handling.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from types import MappingProxyType
from typing import Any

from mokosh_vault_recovery import RECOVERY_ROOT_KEY_LEN


RECOVERY_PHRASE_FORMAT = "MOKOSH-RP1"
RECOVERY_PHRASE_VERSION = 1
RECOVERY_PHRASE_VERSION_BITS = 3
RECOVERY_PHRASE_CHECKSUM_BITS = 16
RECOVERY_PHRASE_WORD_BITS = 11
RECOVERY_PHRASE_WORD_COUNT = 25
RECOVERY_PHRASE_WORDLIST_SIZE = 1 << RECOVERY_PHRASE_WORD_BITS
RECOVERY_PHRASE_WORDLIST_SHA256 = (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)
RECOVERY_PHRASE_MAX_TEXT_BYTES = 512
RECOVERY_PHRASE_MAX_WORD_CHARS = 8
_CHECKSUM_DOMAIN = b"MOKOSH-RP1\x00transcription-checksum\x00"
_WORDLIST_PATH = (
    Path(__file__).resolve().parent / "third_party" / "bip39" / "english.txt"
)


class RecoveryPhraseError(ValueError):
    """Base class for bounded MOKOSH-RP1 failures."""


class RecoveryPhraseWordlistError(RecoveryPhraseError):
    """The pinned vocabulary is absent, changed, or structurally invalid."""


class RecoveryPhraseFormatError(RecoveryPhraseError):
    """A supplied phrase is not an exact canonical MOKOSH-RP1 phrase."""


class RecoveryPhraseChecksumError(RecoveryPhraseFormatError):
    """The phrase transcription checksum does not match its recovery root."""


def _load_wordlist() -> tuple[str, ...]:
    try:
        encoded = _WORDLIST_PATH.read_bytes()
    except OSError as exc:
        raise RecoveryPhraseWordlistError(
            "the pinned recovery vocabulary is unavailable"
        ) from exc
    if hashlib.sha256(encoded).hexdigest() != RECOVERY_PHRASE_WORDLIST_SHA256:
        raise RecoveryPhraseWordlistError(
            "the pinned recovery vocabulary digest is invalid"
        )
    try:
        text = encoded.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RecoveryPhraseWordlistError(
            "the pinned recovery vocabulary is not ASCII"
        ) from exc
    words = tuple(text.splitlines())
    if (
        len(words) != RECOVERY_PHRASE_WORDLIST_SIZE
        or len(set(words)) != len(words)
        or words != tuple(sorted(words))
        or any(
            not word
            or not word.isascii()
            or not word.islower()
            or not word.isalpha()
            or len(word) > RECOVERY_PHRASE_MAX_WORD_CHARS
            for word in words
        )
        or encoded != ("\n".join(words) + "\n").encode("ascii")
    ):
        raise RecoveryPhraseWordlistError(
            "the pinned recovery vocabulary structure is invalid"
        )
    return words


RECOVERY_PHRASE_WORDLIST = _load_wordlist()
_WORD_TO_INDEX = MappingProxyType(
    {word: index for index, word in enumerate(RECOVERY_PHRASE_WORDLIST)}
)


def _exact_recovery_key(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryPhraseFormatError("recovery root must be bytes")
    result = bytes(value)
    if len(result) != RECOVERY_ROOT_KEY_LEN:
        raise RecoveryPhraseFormatError(
            f"recovery root must contain exactly {RECOVERY_ROOT_KEY_LEN} bytes"
        )
    return result


def _checksum(version: int, recovery_key: bytes) -> int:
    digest = hashlib.sha256(
        _CHECKSUM_DOMAIN + bytes((version,)) + recovery_key
    ).digest()
    return int.from_bytes(digest[:2], "big")


def _canonical_words(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        if len(value) > RECOVERY_PHRASE_MAX_TEXT_BYTES:
            raise RecoveryPhraseFormatError("recovery phrase text is too large")
        try:
            encoded = value.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise RecoveryPhraseFormatError(
                "recovery phrase must contain exact ASCII words"
            ) from exc
        if len(encoded) > RECOVERY_PHRASE_MAX_TEXT_BYTES:
            raise RecoveryPhraseFormatError("recovery phrase text is too large")
        words = tuple(value.split())
    elif isinstance(value, (tuple, list)):
        if any(type(word) is not str for word in value):
            raise RecoveryPhraseFormatError("recovery phrase words must be text")
        words = tuple(value)
    else:
        raise RecoveryPhraseFormatError(
            "recovery phrase must be text or a word sequence"
        )
    if len(words) != RECOVERY_PHRASE_WORD_COUNT:
        raise RecoveryPhraseFormatError(
            f"recovery phrase must contain exactly {RECOVERY_PHRASE_WORD_COUNT} words"
        )
    if any(
        len(word) > RECOVERY_PHRASE_MAX_WORD_CHARS
        or not word.isascii()
        or word not in _WORD_TO_INDEX
        for word in words
    ):
        raise RecoveryPhraseFormatError(
            "recovery phrase contains an unknown or non-canonical word"
        )
    return words


def encode_recovery_phrase(
    recovery_key: bytes | bytearray | memoryview,
) -> tuple[str, ...]:
    """Return the exact 25-word MOKOSH-RP1 representation of one root."""

    exact_key = _exact_recovery_key(recovery_key)
    checksum = _checksum(RECOVERY_PHRASE_VERSION, exact_key)
    value = RECOVERY_PHRASE_VERSION
    value = (value << (RECOVERY_ROOT_KEY_LEN * 8)) | int.from_bytes(
        exact_key, "big"
    )
    value = (value << RECOVERY_PHRASE_CHECKSUM_BITS) | checksum
    indices = tuple(
        (value >> (RECOVERY_PHRASE_WORD_BITS * position))
        & (RECOVERY_PHRASE_WORDLIST_SIZE - 1)
        for position in reversed(range(RECOVERY_PHRASE_WORD_COUNT))
    )
    return tuple(RECOVERY_PHRASE_WORDLIST[index] for index in indices)


def decode_recovery_phrase(value: Any) -> bytes:
    """Decode and checksum one exact phrase; never correct or guess words."""

    words = _canonical_words(value)
    encoded = 0
    for word in words:
        encoded = (encoded << RECOVERY_PHRASE_WORD_BITS) | _WORD_TO_INDEX[word]
    checksum_mask = (1 << RECOVERY_PHRASE_CHECKSUM_BITS) - 1
    observed_checksum = encoded & checksum_mask
    encoded >>= RECOVERY_PHRASE_CHECKSUM_BITS
    key_mask = (1 << (RECOVERY_ROOT_KEY_LEN * 8)) - 1
    recovery_key = (encoded & key_mask).to_bytes(RECOVERY_ROOT_KEY_LEN, "big")
    version = encoded >> (RECOVERY_ROOT_KEY_LEN * 8)
    if version != RECOVERY_PHRASE_VERSION:
        raise RecoveryPhraseFormatError("recovery phrase version is unsupported")
    expected_checksum = _checksum(version, recovery_key).to_bytes(2, "big")
    if not hmac.compare_digest(
        observed_checksum.to_bytes(2, "big"), expected_checksum
    ):
        raise RecoveryPhraseChecksumError(
            "recovery phrase transcription checksum is invalid"
        )
    return recovery_key


def recovery_phrase_text(value: Any) -> str:
    """Return one canonical single-line phrase after full validation."""

    words = _canonical_words(value)
    decode_recovery_phrase(words)
    return " ".join(words)


def numbered_recovery_words(value: Any) -> tuple[tuple[int, str], ...]:
    """Return validated words with one-based positions for human display."""

    words = _canonical_words(value)
    decode_recovery_phrase(words)
    return tuple(enumerate(words, start=1))


__all__ = [
    "RECOVERY_PHRASE_CHECKSUM_BITS",
    "RECOVERY_PHRASE_FORMAT",
    "RECOVERY_PHRASE_MAX_TEXT_BYTES",
    "RECOVERY_PHRASE_MAX_WORD_CHARS",
    "RECOVERY_PHRASE_VERSION",
    "RECOVERY_PHRASE_WORDLIST",
    "RECOVERY_PHRASE_WORDLIST_SHA256",
    "RECOVERY_PHRASE_WORD_COUNT",
    "RecoveryPhraseChecksumError",
    "RecoveryPhraseError",
    "RecoveryPhraseFormatError",
    "RecoveryPhraseWordlistError",
    "decode_recovery_phrase",
    "encode_recovery_phrase",
    "numbered_recovery_words",
    "recovery_phrase_text",
]
