"""Strict, non-cryptographic MOKOSH v2 envelope structure codec.

The codec implements the fixed preamble, authenticated-header representation,
strict Stage 1.9 key-slot schema, bounded frame structure, and deterministic
nonce/AAD binding described by ``MOKOSH_V2_FORMAT_SPEC_BG.md``. It does not
encrypt, decrypt, read user files, derive keys, or write output files.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from mokosh_v2_key_slots import (
    MAX_KEY_SLOTS as STRICT_MAX_KEY_SLOTS,
    KeySlotError,
    parse_key_slots,
)


MAGIC = b"MOKOSH2\x00"
MAJOR_VERSION = 2
MINOR_VERSION = 0
PREAMBLE_STRUCT = struct.Struct(">8sBBHII")
PREAMBLE_LEN = PREAMBLE_STRUCT.size
FRAME_HEADER_STRUCT = struct.Struct(">IIB")
FRAME_HEADER_LEN = FRAME_HEADER_STRUCT.size
GCM_TAG_LEN = 16
NONCE_PREFIX_LEN = 8
FRAME_NONCE_LEN = 12
PREFIX_DIGEST_LEN = 32
FRAME_AAD_DOMAIN = b"MOKOSH2\x00FRAME-AAD\x00"

MAX_HEADER_LEN = 65_536
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 1024 * 1024
MAX_KEY_SLOTS = STRICT_MAX_KEY_SLOTS
MAX_FRAME_INDEX = 0xFFFFFFFF

FRAME_FLAG_FINAL = 0x01
SUPPORTED_FRAME_FLAGS = FRAME_FLAG_FINAL

# Stage 1.1 defines no optional or mandatory flags.  Unknown bits fail closed.
SUPPORTED_FLAGS = 0

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUIRED_HEADER_FIELDS = frozenset(
    {
        "format",
        "version",
        "file_id",
        "content_aead",
        "nonce_prefix",
        "chunk_size",
        "key_slots",
        "created_utc",
        "writer",
    }
)


class V2FormatError(ValueError):
    """Base class for malformed or unsupported v2 envelope data."""


class TruncatedDataError(V2FormatError):
    """The input ends before a declared structure is complete."""


class UnsupportedVersionError(V2FormatError):
    """The major/minor version is not supported by this parser."""


class UnknownFlagsError(V2FormatError):
    """The preamble contains a flag this parser does not understand."""


class FormatLimitError(V2FormatError):
    """A parser limit is exceeded or a bounded value is outside its range."""


class DuplicateHeaderKeyError(V2FormatError):
    """The JSON header contains a duplicate object key."""


class FrameSequenceError(V2FormatError):
    """Frame indexes or FINAL markers violate the v2 sequence rules."""


@dataclass(frozen=True, slots=True)
class Preamble:
    major: int
    minor: int
    flags: int
    header_len: int
    chunk_size: int

    def to_bytes(self) -> bytes:
        validate_preamble_fields(
            major=self.major,
            minor=self.minor,
            flags=self.flags,
            header_len=self.header_len,
            chunk_size=self.chunk_size,
        )
        return PREAMBLE_STRUCT.pack(
            MAGIC,
            self.major,
            self.minor,
            self.flags,
            self.header_len,
            self.chunk_size,
        )


@dataclass(frozen=True, slots=True)
class EnvelopePrefix:
    preamble: Preamble
    header_bytes: bytes
    header: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FrameHeader:
    index: int
    plaintext_len: int
    flags: int

    @property
    def is_final(self) -> bool:
        return bool(self.flags & FRAME_FLAG_FINAL)

    @property
    def encoded_len(self) -> int:
        return FRAME_HEADER_LEN + self.plaintext_len + GCM_TAG_LEN

    def to_bytes(self, *, chunk_size: int) -> bytes:
        validate_frame_fields(
            index=self.index,
            plaintext_len=self.plaintext_len,
            flags=self.flags,
            chunk_size=chunk_size,
        )
        return FRAME_HEADER_STRUCT.pack(self.index, self.plaintext_len, self.flags)


@dataclass(frozen=True, slots=True)
class FrameRecord:
    header: FrameHeader
    ciphertext_and_tag: bytes


@dataclass(slots=True)
class FrameSequenceValidator:
    """Incrementally enforce contiguous indexes and one terminal FINAL flag."""

    chunk_size: int = DEFAULT_CHUNK_SIZE
    next_index: int = 0
    final_seen: bool = False

    def accept(self, header: FrameHeader) -> None:
        if not isinstance(header, FrameHeader):
            raise V2FormatError("frame sequence accepts only validated FrameHeader values")
        validate_frame_fields(
            index=header.index,
            plaintext_len=header.plaintext_len,
            flags=header.flags,
            chunk_size=self.chunk_size,
        )
        if self.final_seen:
            raise FrameSequenceError("frame appears after the FINAL frame")
        if header.index != self.next_index:
            raise FrameSequenceError(
                f"expected frame index {self.next_index}; received {header.index}"
            )
        if self.next_index == MAX_FRAME_INDEX and not header.is_final:
            raise FrameSequenceError("frame counter exhausted without FINAL")

        if header.is_final:
            self.final_seen = True
        else:
            self.next_index += 1

    def finish(self) -> None:
        if not self.final_seen:
            raise FrameSequenceError("frame sequence is missing the FINAL flag")


def _require_plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise V2FormatError(f"{field} must be an integer")
    return value


def validate_preamble_fields(
    *, major: int, minor: int, flags: int, header_len: int, chunk_size: int
) -> None:
    for value, name in (
        (major, "major"),
        (minor, "minor"),
        (flags, "flags"),
        (header_len, "header_len"),
        (chunk_size, "chunk_size"),
    ):
        _require_plain_int(value, name)

    if major != MAJOR_VERSION or minor != MINOR_VERSION:
        raise UnsupportedVersionError(f"unsupported MOKOSH version {major}.{minor}")
    if flags < 0 or flags > 0xFFFF:
        raise FormatLimitError("flags must fit in uint16")
    unknown = flags & ~SUPPORTED_FLAGS
    if unknown:
        raise UnknownFlagsError(f"unknown v2 flags: 0x{unknown:04x}")
    if not 1 <= header_len <= MAX_HEADER_LEN:
        raise FormatLimitError(
            f"header_len must be between 1 and {MAX_HEADER_LEN} bytes"
        )
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatLimitError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
        )


def build_preamble(
    header_len: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    flags: int = 0,
) -> bytes:
    return Preamble(
        major=MAJOR_VERSION,
        minor=MINOR_VERSION,
        flags=flags,
        header_len=header_len,
        chunk_size=chunk_size,
    ).to_bytes()


def parse_preamble(data: bytes | bytearray | memoryview) -> Preamble:
    view = memoryview(data)
    if len(view) < PREAMBLE_LEN:
        raise TruncatedDataError(
            f"preamble requires {PREAMBLE_LEN} bytes; received {len(view)}"
        )

    magic, major, minor, flags, header_len, chunk_size = PREAMBLE_STRUCT.unpack(
        view[:PREAMBLE_LEN]
    )
    if magic != MAGIC:
        raise V2FormatError("invalid MOKOSH v2 magic")

    validate_preamble_fields(
        major=major,
        minor=minor,
        flags=flags,
        header_len=header_len,
        chunk_size=chunk_size,
    )
    return Preamble(major, minor, flags, header_len, chunk_size)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateHeaderKeyError(f"duplicate JSON header key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise V2FormatError(f"non-standard JSON constant is forbidden: {value}")


def _decode_base64url_exact(value: Any, field: str, expected_len: int) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        raise V2FormatError(f"{field} must be unpadded base64url text")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise V2FormatError(f"{field} is not valid base64url") from exc
    if len(decoded) != expected_len:
        raise V2FormatError(
            f"{field} must decode to exactly {expected_len} bytes"
        )
    return decoded


def _validate_created_utc(value: Any) -> None:
    if not isinstance(value, str):
        raise V2FormatError("created_utc must be an RFC3339 UTC string")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise V2FormatError("created_utc must use YYYY-MM-DDTHH:MM:SSZ") from exc


def validate_header(header: Mapping[str, Any], *, chunk_size: int) -> None:
    if not isinstance(header, Mapping):
        raise V2FormatError("header must be a JSON object")

    missing = sorted(_REQUIRED_HEADER_FIELDS - set(header))
    if missing:
        raise V2FormatError(f"header is missing required fields: {', '.join(missing)}")

    if header["format"] != "MOKOSH":
        raise V2FormatError("header format must be MOKOSH")
    if _require_plain_int(header["version"], "header.version") != MAJOR_VERSION:
        raise UnsupportedVersionError("header version is not MOKOSH v2")
    if header["content_aead"] != "AES-256-GCM-CHUNKED":
        raise V2FormatError("unsupported content_aead suite")

    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatLimitError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
        )

    declared_chunk_size = _require_plain_int(header["chunk_size"], "header.chunk_size")
    if declared_chunk_size != chunk_size:
        raise V2FormatError("header chunk_size does not match preamble")

    _decode_base64url_exact(header["file_id"], "file_id", 16)
    _decode_base64url_exact(
        header["nonce_prefix"], "nonce_prefix", NONCE_PREFIX_LEN
    )

    key_slots = header["key_slots"]
    if not isinstance(key_slots, list):
        raise V2FormatError("key_slots must be a JSON array")
    if len(key_slots) > MAX_KEY_SLOTS:
        raise FormatLimitError(f"key_slots exceeds the limit of {MAX_KEY_SLOTS}")
    try:
        parse_key_slots(key_slots)
    except KeySlotError as exc:
        raise V2FormatError(f"invalid key_slots: {exc}") from exc

    _validate_created_utc(header["created_utc"])
    writer = header["writer"]
    if not isinstance(writer, str) or not 1 <= len(writer) <= 128:
        raise FormatLimitError("writer must contain 1 to 128 characters")


def parse_header_bytes(header_bytes: bytes, *, chunk_size: int) -> dict[str, Any]:
    if not 1 <= len(header_bytes) <= MAX_HEADER_LEN:
        raise FormatLimitError(
            f"header must contain between 1 and {MAX_HEADER_LEN} bytes"
        )
    try:
        text = header_bytes.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise V2FormatError("header is not valid UTF-8") from exc
    except DuplicateHeaderKeyError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise V2FormatError("header is not valid bounded JSON") from exc

    if not isinstance(parsed, dict):
        raise V2FormatError("header root must be a JSON object")
    validate_header(parsed, chunk_size=chunk_size)
    return parsed


def encode_header(header: Mapping[str, Any], *, chunk_size: int) -> bytes:
    validate_header(header, chunk_size=chunk_size)
    try:
        encoded = json.dumps(
            dict(header),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise V2FormatError("header contains a non-JSON value") from exc
    if len(encoded) > MAX_HEADER_LEN:
        raise FormatLimitError(f"encoded header exceeds {MAX_HEADER_LEN} bytes")
    return encoded


def build_envelope_prefix(
    header: Mapping[str, Any],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    flags: int = 0,
) -> bytes:
    header_bytes = encode_header(header, chunk_size=chunk_size)
    return build_preamble(len(header_bytes), chunk_size, flags=flags) + header_bytes


def parse_envelope_prefix(
    data: bytes | bytearray | memoryview,
) -> tuple[EnvelopePrefix, bytes]:
    view = memoryview(data)
    preamble = parse_preamble(view)
    prefix_end = PREAMBLE_LEN + preamble.header_len
    if len(view) < prefix_end:
        raise TruncatedDataError(
            f"declared header requires {prefix_end} prefix bytes; received {len(view)}"
        )

    header_bytes = bytes(view[PREAMBLE_LEN:prefix_end])
    header = parse_header_bytes(header_bytes, chunk_size=preamble.chunk_size)
    prefix = EnvelopePrefix(preamble, header_bytes, header)
    return prefix, bytes(view[prefix_end:])


def validate_frame_fields(
    *, index: int, plaintext_len: int, flags: int, chunk_size: int
) -> None:
    for value, name in (
        (index, "frame.index"),
        (plaintext_len, "frame.plaintext_len"),
        (flags, "frame.flags"),
        (chunk_size, "chunk_size"),
    ):
        _require_plain_int(value, name)

    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatLimitError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
        )
    if not 0 <= index <= MAX_FRAME_INDEX:
        raise FormatLimitError("frame index must fit in uint32")
    if not 0 <= plaintext_len <= chunk_size:
        raise FormatLimitError(
            f"frame plaintext_len must be between 0 and {chunk_size} bytes"
        )
    if not 0 <= flags <= 0xFF:
        raise FormatLimitError("frame flags must fit in uint8")
    unknown = flags & ~SUPPORTED_FRAME_FLAGS
    if unknown:
        raise UnknownFlagsError(f"unknown frame flags: 0x{unknown:02x}")


def build_frame(
    *,
    index: int,
    plaintext_len: int,
    flags: int,
    ciphertext_and_tag: bytes | bytearray | memoryview,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    header = FrameHeader(index, plaintext_len, flags)
    header_bytes = header.to_bytes(chunk_size=chunk_size)
    payload = bytes(ciphertext_and_tag)
    expected_len = plaintext_len + GCM_TAG_LEN
    if len(payload) != expected_len:
        raise V2FormatError(
            "ciphertext_and_tag length must equal plaintext_len plus the 16-byte tag"
        )
    return header_bytes + payload


def parse_frame(
    data: bytes | bytearray | memoryview,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[FrameRecord, bytes]:
    view = memoryview(data)
    if len(view) < FRAME_HEADER_LEN:
        raise TruncatedDataError(
            f"frame header requires {FRAME_HEADER_LEN} bytes; received {len(view)}"
        )

    index, plaintext_len, flags = FRAME_HEADER_STRUCT.unpack(view[:FRAME_HEADER_LEN])
    validate_frame_fields(
        index=index,
        plaintext_len=plaintext_len,
        flags=flags,
        chunk_size=chunk_size,
    )
    header = FrameHeader(index, plaintext_len, flags)
    frame_end = header.encoded_len
    if len(view) < frame_end:
        raise TruncatedDataError(
            f"declared frame requires {frame_end} bytes; received {len(view)}"
        )

    record = FrameRecord(
        header=header,
        ciphertext_and_tag=bytes(view[FRAME_HEADER_LEN:frame_end]),
    )
    return record, bytes(view[frame_end:])


def _require_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise V2FormatError(f"{field} must be bytes")
    return bytes(value)


def derive_frame_nonce(
    nonce_prefix: bytes | bytearray | memoryview,
    index: int,
) -> bytes:
    prefix = _require_bytes(nonce_prefix, "nonce_prefix")
    if len(prefix) != NONCE_PREFIX_LEN:
        raise V2FormatError(
            f"nonce_prefix must contain exactly {NONCE_PREFIX_LEN} bytes"
        )
    _require_plain_int(index, "frame.index")
    if not 0 <= index <= MAX_FRAME_INDEX:
        raise FormatLimitError("frame index must fit in uint32")
    nonce = prefix + index.to_bytes(4, "big")
    if len(nonce) != FRAME_NONCE_LEN:
        raise AssertionError("internal v2 nonce length invariant failed")
    return nonce


def hash_envelope_prefix(
    prefix_bytes: bytes | bytearray | memoryview,
) -> bytes:
    exact_prefix = _require_bytes(prefix_bytes, "envelope prefix")
    _, remainder = parse_envelope_prefix(exact_prefix)
    if remainder:
        raise V2FormatError(
            "envelope prefix digest input must not contain frame or trailer bytes"
        )
    return hashlib.sha256(exact_prefix).digest()


def build_frame_aad(
    prefix_digest: bytes | bytearray | memoryview,
    header: FrameHeader,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    digest = _require_bytes(prefix_digest, "prefix_digest")
    if len(digest) != PREFIX_DIGEST_LEN:
        raise V2FormatError(
            f"prefix_digest must contain exactly {PREFIX_DIGEST_LEN} bytes"
        )
    if not isinstance(header, FrameHeader):
        raise V2FormatError("frame AAD requires a FrameHeader")
    return FRAME_AAD_DOMAIN + digest + header.to_bytes(chunk_size=chunk_size)


def build_frame_aad_from_prefix(
    prefix_bytes: bytes | bytearray | memoryview,
    header: FrameHeader,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    return build_frame_aad(
        hash_envelope_prefix(prefix_bytes),
        header,
        chunk_size=chunk_size,
    )
