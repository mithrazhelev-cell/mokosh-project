"""Strict plaintext codec for the encrypted MOKOSH v2 frame-0 manifest.

The encoded bytes are intended to be encrypted as frame 0.  This module does
not read paths, inspect files, hash user data, or perform encryption itself.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from mokosh_v2_format import (
    MAX_CHUNK_SIZE,
    MAX_FRAME_INDEX,
    MIN_CHUNK_SIZE,
    FormatLimitError,
    V2FormatError,
)


MAX_MANIFEST_LEN = 4096
MAX_FILENAME_UTF8_LEN = 255
SHA256_LEN = 32

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MIME_RE = re.compile(
    r"^[A-Za-z0-9!#$&^_.+-]{1,127}/[A-Za-z0-9!#$&^_.+-]{1,127}$"
)
_REQUIRED_FIELDS = frozenset(
    {"original_name", "original_size", "data_frames", "plaintext_sha256"}
)
_OPTIONAL_FIELDS = frozenset({"content_type"})


class ManifestError(V2FormatError):
    """The decrypted frame-0 manifest is malformed or inconsistent."""


class DuplicateManifestKeyError(ManifestError):
    """The manifest JSON contains a duplicate object key."""


@dataclass(frozen=True, slots=True)
class Manifest:
    original_name: str
    original_size: int
    data_frames: int
    plaintext_sha256: bytes
    content_type: str | None = None

    def to_json_object(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "original_name": self.original_name,
            "original_size": self.original_size,
            "data_frames": self.data_frames,
            "plaintext_sha256": _encode_base64url(self.plaintext_sha256),
        }
        if self.content_type is not None:
            result["content_type"] = self.content_type
        return result


def _require_plain_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise ManifestError(f"{field} must be an integer")
    return value


def _validate_chunk_size(chunk_size: int) -> None:
    _require_plain_int(chunk_size, "chunk_size")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise FormatLimitError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
        )


def expected_data_frames(original_size: int, *, chunk_size: int) -> int:
    _validate_chunk_size(chunk_size)
    size = _require_plain_int(original_size, "original_size")
    if size < 0:
        raise ManifestError("original_size must not be negative")
    maximum_size = MAX_FRAME_INDEX * chunk_size
    if size > maximum_size:
        raise FormatLimitError("original_size exceeds the v2 frame-index capacity")
    return max(1, (size + chunk_size - 1) // chunk_size)


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_sha256(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        raise ManifestError("plaintext_sha256 must be unpadded base64url text")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ManifestError("plaintext_sha256 is not valid base64url") from exc
    if len(decoded) != SHA256_LEN:
        raise ManifestError(
            f"plaintext_sha256 must decode to exactly {SHA256_LEN} bytes"
        )
    return decoded


def _validate_original_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ManifestError("original_name must be text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ManifestError("original_name is not valid Unicode") from exc
    if not 1 <= len(encoded) <= MAX_FILENAME_UTF8_LEN:
        raise FormatLimitError(
            f"original_name must contain 1 to {MAX_FILENAME_UTF8_LEN} UTF-8 bytes"
        )
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise ManifestError("original_name must be one basename without separators")
    for character in value:
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            raise ManifestError(
                "original_name contains a forbidden control or format character"
            )
    return value


def _validate_content_type(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _MIME_RE.fullmatch(value):
        raise ManifestError("content_type must be a simple type/subtype media type")
    return value


def validate_manifest_object(
    value: Mapping[str, Any], *, chunk_size: int
) -> Manifest:
    _validate_chunk_size(chunk_size)
    if not isinstance(value, Mapping):
        raise ManifestError("manifest must be a JSON object")

    keys = set(value)
    missing = sorted(_REQUIRED_FIELDS - keys)
    if missing:
        raise ManifestError(
            f"manifest is missing required fields: {', '.join(missing)}"
        )
    unknown = sorted(keys - _REQUIRED_FIELDS - _OPTIONAL_FIELDS)
    if unknown:
        raise ManifestError(
            f"manifest contains unsupported fields: {', '.join(unknown)}"
        )

    original_name = _validate_original_name(value["original_name"])
    original_size = _require_plain_int(value["original_size"], "original_size")
    calculated_frames = expected_data_frames(original_size, chunk_size=chunk_size)
    data_frames = _require_plain_int(value["data_frames"], "data_frames")
    if data_frames != calculated_frames:
        raise ManifestError(
            f"data_frames must be exactly {calculated_frames} for original_size"
        )
    digest = _decode_sha256(value["plaintext_sha256"])
    content_type = _validate_content_type(value.get("content_type"))
    return Manifest(
        original_name=original_name,
        original_size=original_size,
        data_frames=data_frames,
        plaintext_sha256=digest,
        content_type=content_type,
    )


def build_manifest(
    *,
    original_name: str,
    original_size: int,
    plaintext_sha256: bytes | bytearray | memoryview,
    chunk_size: int,
    content_type: str | None = None,
) -> Manifest:
    if not isinstance(plaintext_sha256, (bytes, bytearray, memoryview)):
        raise ManifestError("plaintext_sha256 must be bytes")
    digest = bytes(plaintext_sha256)
    if len(digest) != SHA256_LEN:
        raise ManifestError(
            f"plaintext_sha256 must contain exactly {SHA256_LEN} bytes"
        )
    candidate = Manifest(
        original_name=original_name,
        original_size=original_size,
        data_frames=expected_data_frames(original_size, chunk_size=chunk_size),
        plaintext_sha256=digest,
        content_type=content_type,
    )
    return validate_manifest_object(
        candidate.to_json_object(),
        chunk_size=chunk_size,
    )


def encode_manifest(manifest: Manifest, *, chunk_size: int) -> bytes:
    if not isinstance(manifest, Manifest):
        raise ManifestError("encode_manifest requires a Manifest")
    validated = validate_manifest_object(
        manifest.to_json_object(),
        chunk_size=chunk_size,
    )
    try:
        encoded = json.dumps(
            validated.to_json_object(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ManifestError("manifest cannot be encoded as strict UTF-8 JSON") from exc
    if len(encoded) > min(MAX_MANIFEST_LEN, chunk_size):
        raise FormatLimitError(
            f"encoded manifest exceeds the limit of {MAX_MANIFEST_LEN} bytes"
        )
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise DuplicateManifestKeyError(f"duplicate manifest key: {key}")
        result[key] = item
    return result


def _reject_json_constant(value: str) -> None:
    raise ManifestError(f"non-standard JSON constant is forbidden: {value}")


def parse_manifest(data: bytes | bytearray | memoryview, *, chunk_size: int) -> Manifest:
    _validate_chunk_size(chunk_size)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ManifestError("manifest input must be bytes")
    encoded = bytes(data)
    if not 1 <= len(encoded) <= min(MAX_MANIFEST_LEN, chunk_size):
        raise FormatLimitError(
            f"manifest must contain 1 to {MAX_MANIFEST_LEN} bytes"
        )
    try:
        text = encoded.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ManifestError("manifest is not valid UTF-8") from exc
    except DuplicateManifestKeyError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError("manifest is not valid bounded JSON") from exc
    if not isinstance(parsed, dict):
        raise ManifestError("manifest root must be a JSON object")
    return validate_manifest_object(parsed, chunk_size=chunk_size)
