"""Fail-closed MOK1 creation and bounded legacy decryption compatibility.

MOK1 did not authenticate its JSON header.  New MOK1 creation is therefore
retired.  The decryption entry points remain only so owners can recover
existing files.  They strictly allow-list the security parameters, ignore
advisory metadata, authenticate the complete ciphertext twice, and publish
plaintext through the existing private no-clobber quarantine primitive.

This module does not migrate data, delete originals, activate MOKOSH v2, read
contacts, access a Vault, use the network, or claim that historical MOK1
metadata has become authenticated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from argon2 import Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if TYPE_CHECKING:
    from mokosh_v2_filesystem import (
        ExclusiveFileQuarantineSink,
        FileIdentity,
        VerifiedFileSource,
    )


MAGIC = b"MOK1"
VERSION = 1
KDF_ITERATIONS = 200_000
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16
GCM_TAG_LEN = 16
HEADER_PREFIX_LEN = len(MAGIC) + 1 + 4
MAX_HEADER_LEN = 65_536
LEGACY_IO_CHUNK_SIZE = 1024 * 1024

# These values are fixed compatibility parameters used by every historical
# MOK1 Argon2id writer in the repository history.  Header values must match
# them exactly; attacker-selected KDF costs are never executed.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 65_536
ARGON2_PARALLELISM = 4

_PASSWORD_KDFS = frozenset({"Argon2id", "PBKDF2-HMAC-SHA256"})
_SUPPORTED_KDFS = _PASSWORD_KDFS | {"raw-key"}


class MOK1Error(Exception):
    """Base class for an explicit legacy MOK1 refusal or failure."""


class MOK1EncryptionRetiredError(MOK1Error):
    """New MOK1 ciphertext creation is permanently unavailable."""


class MOK1FormatError(MOK1Error, ValueError):
    """A legacy container is malformed or outside the compatibility policy."""


class MOK1CredentialError(MOK1Error, ValueError):
    """A legacy password, nickname, or raw key has an invalid type or size."""


class MOK1AuthenticationError(MOK1Error):
    """The password/key is wrong or the authenticated payload was modified."""


class MOK1CleanupError(MOK1Error):
    """A private quarantine output could not be proven clean after failure."""


@dataclass(frozen=True, slots=True)
class _LegacyPrologue:
    header_bytes: bytes
    header: dict[str, Any]
    salt: bytes
    nonce: bytes
    ciphertext_len: int


@dataclass(frozen=True, slots=True)
class _AuthenticatedLegacySource:
    identity: FileIdentity
    prologue: _LegacyPrologue
    tag: bytes
    plaintext_size: int
    key: bytes


def _credential_text(value: Any, field: str) -> str:
    if type(value) is not str:
        raise MOK1CredentialError(f"legacy {field} must be text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MOK1CredentialError(
            f"legacy {field} must be valid UTF-8 text"
        ) from exc
    return value


def _legacy_password_material(password: Any, nickname: Any) -> bytes:
    exact_password = _credential_text(password, "password")
    exact_nickname = _credential_text(nickname, "nickname").strip()
    # The delimiter construction is retained only to recover old data.  New
    # MOK1 creation is disabled, so no new ambiguous credentials are created.
    return f"{exact_password}|{exact_nickname}".encode("utf-8")


def _derive_key(
    password: str,
    salt: bytes,
    iterations: int = KDF_ITERATIONS,
    nickname: str = "",
) -> bytes:
    """Reproduce the historical PBKDF2 key only after strict policy checks."""

    if type(iterations) is not int or iterations != KDF_ITERATIONS:
        raise MOK1FormatError("legacy PBKDF2 work factor is not supported")
    if type(salt) is not bytes or len(salt) != SALT_LEN:
        raise MOK1FormatError("legacy salt has invalid length")
    return hashlib.pbkdf2_hmac(
        "sha256",
        _legacy_password_material(password, nickname),
        salt,
        iterations,
        dklen=KEY_LEN,
    )


def _derive_key_argon2(
    password: str,
    salt: bytes,
    nickname: str = "",
) -> bytes:
    """Reproduce the historical fixed Argon2id key for compatibility."""

    # Keep the heavier low-level primitive out of normal GUI import.  It is
    # needed only when an owner explicitly recovers an Argon2id MOK1 file.
    from argon2.low_level import hash_secret_raw

    if type(salt) is not bytes or len(salt) != SALT_LEN:
        raise MOK1FormatError("legacy salt has invalid length")
    return hash_secret_raw(
        _legacy_password_material(password, nickname),
        salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _reject_json_constant(value: str) -> None:
    raise MOK1FormatError("legacy header contains a non-JSON numeric constant")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MOK1FormatError("legacy header contains a duplicate JSON key")
        result[key] = value
    return result


def _decode_header(header_bytes: bytes) -> dict[str, Any]:
    if type(header_bytes) is not bytes:
        raise MOK1FormatError("legacy header must be bytes")
    if not 1 <= len(header_bytes) <= MAX_HEADER_LEN:
        raise MOK1FormatError("legacy header length is outside the safe limit")
    try:
        text = header_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MOK1FormatError("legacy header is not valid UTF-8") from exc
    try:
        header = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except MOK1FormatError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise MOK1FormatError("legacy header is not valid bounded JSON") from exc
    if type(header) is not dict:
        raise MOK1FormatError("legacy header must be a JSON object")
    _validate_common_header(header)
    return header


def _validate_common_header(header: dict[str, Any]) -> None:
    if header.get("alg") != "AES-256-GCM":
        raise MOK1FormatError("legacy algorithm is missing or unsupported")
    kdf = header.get("kdf")
    if type(kdf) is not str or kdf not in _SUPPORTED_KDFS:
        raise MOK1FormatError("legacy KDF is missing or unsupported")


def _require_exact_integer(
    header: dict[str, Any],
    field: str,
    expected: int,
) -> None:
    value = header.get(field)
    if type(value) is not int or value != expected:
        raise MOK1FormatError(f"legacy {field} is outside the compatibility policy")


def _validate_password_header(header: dict[str, Any]) -> None:
    kdf = header["kdf"]
    if kdf == "Argon2id":
        _require_exact_integer(header, "argon2_time", ARGON2_TIME_COST)
        _require_exact_integer(header, "argon2_memory", ARGON2_MEMORY_COST)
        _require_exact_integer(header, "argon2_parallelism", ARGON2_PARALLELISM)
        return
    if kdf == "PBKDF2-HMAC-SHA256":
        _require_exact_integer(header, "iterations", KDF_ITERATIONS)
        return
    raise MOK1FormatError("raw-key MOK1 requires the raw-key recovery entry point")


def _validate_raw_key_header(header: dict[str, Any]) -> None:
    if header["kdf"] != "raw-key":
        raise MOK1FormatError("password MOK1 requires the password recovery entry point")
    _require_exact_integer(header, "iterations", 0)


def _parse_header(data: bytes) -> tuple[dict[str, Any], bytes]:
    """Parse one already-buffered legacy prefix under the same strict limits."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MOK1FormatError("legacy container must be bytes")
    exact = bytes(data)
    if len(exact) < HEADER_PREFIX_LEN:
        raise MOK1FormatError("legacy container is too short for its header")
    if exact[: len(MAGIC)] != MAGIC:
        raise MOK1FormatError("legacy magic is invalid")
    if exact[len(MAGIC)] != VERSION:
        raise MOK1FormatError("legacy version is unsupported")
    header_len = int.from_bytes(exact[len(MAGIC) + 1 : HEADER_PREFIX_LEN], "big")
    if not 1 <= header_len <= MAX_HEADER_LEN:
        raise MOK1FormatError("legacy header length is outside the safe limit")
    header_end = HEADER_PREFIX_LEN + header_len
    if len(exact) < header_end:
        raise MOK1FormatError("legacy JSON header is truncated")
    header = _decode_header(exact[HEADER_PREFIX_LEN:header_end])
    return header, exact[header_end:]


def _text_path(value: Any, field: str) -> str:
    try:
        path = os.fspath(value)
    except TypeError as exc:
        raise MOK1FormatError(f"legacy {field} must be path-like") from exc
    if type(path) is not str or not path or "\x00" in path:
        raise MOK1FormatError(
            f"legacy {field} must be non-empty text without NUL"
        )
    return path


def _select_output_path(input_path: Any, output_path: Any) -> str:
    source = _text_path(input_path, "source path")
    if output_path is not None:
        return _text_path(output_path, "output path")
    base = source[:-4] if source.endswith(".mok") else source
    return base + "_dec"


def _read_exact(source: VerifiedFileSource, size: int, field: str) -> bytes:
    if type(size) is not int or size < 0:
        raise AssertionError("internal legacy read length is invalid")
    result = bytearray()
    while len(result) < size:
        request = min(size - len(result), LEGACY_IO_CHUNK_SIZE)
        chunk = source.read(request)
        if not chunk:
            raise MOK1FormatError(f"legacy {field} is truncated")
        result.extend(chunk)
    return bytes(result)


def _read_prologue(
    source: VerifiedFileSource,
    *,
    credential_kind: str,
) -> _LegacyPrologue:
    prefix = _read_exact(source, HEADER_PREFIX_LEN, "header prefix")
    if prefix[: len(MAGIC)] != MAGIC:
        raise MOK1FormatError("legacy magic is invalid")
    if prefix[len(MAGIC)] != VERSION:
        raise MOK1FormatError("legacy version is unsupported")
    header_len = int.from_bytes(prefix[len(MAGIC) + 1 :], "big")
    if not 1 <= header_len <= MAX_HEADER_LEN:
        raise MOK1FormatError("legacy header length is outside the safe limit")
    header_bytes = _read_exact(source, header_len, "JSON header")
    header = _decode_header(header_bytes)
    if credential_kind == "password":
        _validate_password_header(header)
    elif credential_kind == "raw-key":
        _validate_raw_key_header(header)
    else:
        raise AssertionError("internal legacy credential kind is invalid")

    salt = _read_exact(source, SALT_LEN, "salt")
    nonce = _read_exact(source, NONCE_LEN, "nonce")
    ciphertext_and_tag = source.identity.size - source.bytes_read
    if ciphertext_and_tag < GCM_TAG_LEN:
        raise MOK1FormatError("legacy ciphertext or authentication tag is truncated")
    return _LegacyPrologue(
        header_bytes=header_bytes,
        header=header,
        salt=salt,
        nonce=nonce,
        ciphertext_len=ciphertext_and_tag - GCM_TAG_LEN,
    )


def _raw_key_bytes(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise MOK1CredentialError("legacy raw key must be bytes")
    exact = bytes(value)
    if len(exact) != KEY_LEN:
        raise MOK1CredentialError("legacy raw key must contain exactly 32 bytes")
    return exact


def _write_all(sink: ExclusiveFileQuarantineSink, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = sink.write(data[offset:])
        if not 1 <= written <= len(data) - offset:
            raise MOK1CleanupError("private legacy output write made invalid progress")
        offset += written


def _consume_authenticated_payload(
    source: VerifiedFileSource,
    prologue: _LegacyPrologue,
    key: bytes,
    *,
    sink: ExclusiveFileQuarantineSink | None,
) -> tuple[bytes, int]:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(prologue.nonce, min_tag_length=GCM_TAG_LEN),
    ).decryptor()
    remaining = prologue.ciphertext_len
    plaintext_size = 0
    while remaining:
        chunk = _read_exact(
            source,
            min(remaining, LEGACY_IO_CHUNK_SIZE),
            "ciphertext",
        )
        remaining -= len(chunk)
        plaintext = decryptor.update(chunk)
        plaintext_size += len(plaintext)
        if sink is not None:
            _write_all(sink, plaintext)

    tag = _read_exact(source, GCM_TAG_LEN, "authentication tag")
    try:
        final_plaintext = decryptor.finalize_with_tag(tag)
    except (InvalidTag, ValueError) as exc:
        raise MOK1AuthenticationError(
            "legacy MOK1 password/key is wrong or payload authentication failed"
        ) from exc
    plaintext_size += len(final_plaintext)
    if sink is not None:
        _write_all(sink, final_plaintext)
    if source.bytes_read != source.identity.size:
        raise MOK1FormatError("legacy container length changed while reading")
    return tag, plaintext_size


def _same_prologue(left: _LegacyPrologue, right: _LegacyPrologue) -> bool:
    return (
        hmac.compare_digest(left.header_bytes, right.header_bytes)
        and hmac.compare_digest(left.salt, right.salt)
        and hmac.compare_digest(left.nonce, right.nonce)
        and left.ciphertext_len == right.ciphertext_len
    )


def _close_source(source: VerifiedFileSource) -> None:
    if not source.closed:
        source.close()


def _authenticate_first_pass(
    input_path: str,
    *,
    credential_kind: str,
    key_factory: Callable[[dict[str, Any], bytes], bytes],
) -> _AuthenticatedLegacySource:
    from mokosh_v2_filesystem import VerifiedFileSource

    source = VerifiedFileSource(
        input_path,
        max_read_size=LEGACY_IO_CHUNK_SIZE,
    )
    try:
        prologue = _read_prologue(source, credential_kind=credential_kind)
        key = key_factory(prologue.header, prologue.salt)
        if type(key) is not bytes or len(key) != KEY_LEN:
            raise MOK1CredentialError("legacy key derivation returned invalid bytes")
        tag, plaintext_size = _consume_authenticated_payload(
            source,
            prologue,
            key,
            sink=None,
        )
        identity = source.verify_and_close()
    except BaseException:
        _close_source(source)
        raise
    return _AuthenticatedLegacySource(
        identity=identity,
        prologue=prologue,
        tag=tag,
        plaintext_size=plaintext_size,
        key=key,
    )


def _abort_transaction(
    transaction: ExclusiveFileQuarantineSink | None,
) -> None:
    if transaction is None or transaction.committed or transaction.aborted:
        return
    try:
        transaction.abort()
    except BaseException as exc:
        raise MOK1CleanupError(
            "legacy plaintext quarantine cleanup could not be proven"
        ) from exc


def _decrypt_authenticated_legacy(
    input_path: Any,
    output_path: Any,
    *,
    credential_kind: str,
    key_factory: Callable[[dict[str, Any], bytes], bytes],
) -> str:
    from mokosh_v2_filesystem import (
        ExclusiveFileQuarantineSink,
        SourceChangedError,
        VerifiedFileSource,
    )

    source_path = _text_path(input_path, "source path")
    final_path = _select_output_path(source_path, output_path)
    authenticated = _authenticate_first_pass(
        source_path,
        credential_kind=credential_kind,
        key_factory=key_factory,
    )

    second = VerifiedFileSource(
        source_path,
        max_read_size=LEGACY_IO_CHUNK_SIZE,
    )
    transaction: ExclusiveFileQuarantineSink | None = None
    try:
        if second.identity != authenticated.identity:
            raise SourceChangedError(
                "legacy source identity changed between authentication passes"
            )
        second_prologue = _read_prologue(
            second,
            credential_kind=credential_kind,
        )
        if not _same_prologue(authenticated.prologue, second_prologue):
            raise SourceChangedError(
                "legacy source prologue changed between authentication passes"
            )

        transaction = ExclusiveFileQuarantineSink(final_path)
        second_tag, plaintext_size = _consume_authenticated_payload(
            second,
            second_prologue,
            authenticated.key,
            sink=transaction,
        )
        if (
            not hmac.compare_digest(authenticated.tag, second_tag)
            or plaintext_size != authenticated.plaintext_size
        ):
            raise SourceChangedError(
                "legacy authenticated payload changed between passes"
            )
        second.verify_and_close()
        sealed = transaction.seal_for_verification()
        if sealed.size != plaintext_size or sealed.mode != 0o600:
            raise MOK1CleanupError(
                "private legacy plaintext output metadata is invalid"
            )
        transaction.commit()
        return transaction.final_path
    except BaseException:
        _close_source(second)
        _abort_transaction(transaction)
        raise


def encrypt_file(
    input_path: str,
    output_path: Optional[str],
    password: str,
    meta: Optional[dict[str, Any]] = None,
    nickname: str = "",
    use_argon2: bool = True,
) -> str:
    """Refuse creation of the unauthenticated-header MOK1 format."""

    raise MOK1EncryptionRetiredError(
        "MOK1 encryption is retired; new files require the MOKOSH v2 pipeline"
    )


def decrypt_file(
    input_path: str,
    output_path: Optional[str],
    password: str,
    nickname: str = "",
) -> str:
    """Recover one historical password-based MOK1 file without overwriting."""

    exact_password = _credential_text(password, "password")
    exact_nickname = _credential_text(nickname, "nickname")

    def key_factory(header: dict[str, Any], salt: bytes) -> bytes:
        if header["kdf"] == "Argon2id":
            return _derive_key_argon2(
                exact_password,
                salt,
                exact_nickname,
            )
        if header["kdf"] == "PBKDF2-HMAC-SHA256":
            return _derive_key(
                exact_password,
                salt,
                KDF_ITERATIONS,
                exact_nickname,
            )
        raise MOK1FormatError("legacy password KDF is unsupported")

    return _decrypt_authenticated_legacy(
        input_path,
        output_path,
        credential_kind="password",
        key_factory=key_factory,
    )


def encrypt_file_with_raw_key(
    input_path: str,
    output_path: Optional[str],
    key: bytes,
    meta: Optional[dict[str, Any]] = None,
) -> str:
    """Refuse creation of raw-key MOK1 contact-era ciphertext."""

    raise MOK1EncryptionRetiredError(
        "MOK1 raw-key encryption is retired; new files require MOKOSH v2"
    )


def decrypt_file_with_raw_key(
    input_path: str,
    output_path: Optional[str],
    key: bytes,
) -> str:
    """Recover one historical raw-key MOK1 file without trusting metadata."""

    exact_key = _raw_key_bytes(key)

    def key_factory(header: dict[str, Any], salt: bytes) -> bytes:
        del header, salt
        return exact_key

    return _decrypt_authenticated_legacy(
        input_path,
        output_path,
        credential_kind="raw-key",
        key_factory=key_factory,
    )


__all__ = (
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_TIME_COST",
    "GCM_TAG_LEN",
    "KDF_ITERATIONS",
    "KEY_LEN",
    "MAGIC",
    "MAX_HEADER_LEN",
    "MOK1AuthenticationError",
    "MOK1CleanupError",
    "MOK1CredentialError",
    "MOK1EncryptionRetiredError",
    "MOK1Error",
    "MOK1FormatError",
    "NONCE_LEN",
    "SALT_LEN",
    "VERSION",
    "decrypt_file",
    "decrypt_file_with_raw_key",
    "encrypt_file",
    "encrypt_file_with_raw_key",
)
