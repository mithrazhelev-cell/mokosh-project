import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from argon2 import Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_core
from crypto_core import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KDF_ITERATIONS,
    LEGACY_IO_CHUNK_SIZE,
    MAGIC,
    MOK1AuthenticationError,
    MOK1EncryptionRetiredError,
    VERSION,
    decrypt_file,
    decrypt_file_with_raw_key,
    encrypt_file,
    encrypt_file_with_raw_key,
)
from mokosh_v2_filesystem import SourceChangedError, VerifiedFileSource


PASSWORD = "correct-test-password"
NICKNAME = "test-user"
RAW_KEY = bytes(range(96, 128))
ARGON2_PLAINTEXT = b"MOKOSH historical Argon2id fixture\x00\x01\x02"
PBKDF2_PLAINTEXT = b"MOKOSH historical PBKDF2 fixture"
RAW_KEY_PLAINTEXT = b"MOKOSH historical raw-key contact fixture"

# These exact containers were produced independently with the historical MOK1
# layout and fixed inputs.  Production encryption is not called by the tests.
ARGON2_FIXTURE = bytes.fromhex(
    "4d4f4b31010000009b"
    "7b22616c67223a224145532d3235362d47434d222c226b6466223a224172676f"
    "6e326964222c226172676f6e325f74696d65223a322c226172676f6e325f6d65"
    "6d6f7279223a36353533362c226172676f6e325f706172616c6c656c69736d22"
    "3a342c2263726561746564223a313730303030303030302c226d6f6465223a22"
    "73696e676c65222c226e69636b223a22746573742d75736572227d"
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b"
    "76fd1f30e2aef72540406dae160c23213ad53fecea3db7dc826160b1b3af1161"
    "4b6c05ae441d394e22686020ce982d27ca6d8e40d3"
)
ARGON2_FIXTURE_SHA256 = (
    "7fb6e5d8e074a9444767df96d3c249505740ed732e3a3e35d8b3353828bb1cbc"
)

PBKDF2_FIXTURE = bytes.fromhex(
    "4d4f4b31010000007b"
    "7b22616c67223a224145532d3235362d47434d222c226b6466223a2250424b44"
    "46322d484d41432d534841323536222c22697465726174696f6e73223a323030"
    "3030302c2263726561746564223a313730303030303030312c226d6f6465223a"
    "227661756c74222c226e69636b223a22746573742d75736572227d"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b"
    "b9f5a055f8f75fa4c43da1edbc2cbd16d033dcb70c03b2c95b2641c3521b6f"
    "1a2faef1425f4589657e7956b348977ed7"
)
PBKDF2_FIXTURE_SHA256 = (
    "5cc9679389016aec05633e5550ebeea1186a95f11eb22bb8ec900ef577133882"
)

RAW_KEY_FIXTURE = bytes.fromhex(
    "4d4f4b3101000000d2"
    "7b22616c67223a224145532d3235362d47434d222c226b6466223a227261772d"
    "6b6579222c22697465726174696f6e73223a302c2263726561746564223a3137"
    "30303030303030322c226d6f6465223a22636f6e74616374222c22636f6e7461"
    "63745f6964223a2273796e7468657469632d626f62222c226e69636b223a2273"
    "796e7468657469632d616c696365222c22656e635f6b65795f636c6173736963"
    "223a2273796e746865746963222c22656e635f6b65795f636c61737369635f6e"
    "6f6e6365223a2273796e746865746963227d"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b"
    "fb9e6a86d4caaeaea6d5954c5e3a6813244eb86db5b2a00b16b9febf2d9c9714"
    "16ee76bb13b79f3e3f1aa066944333e3605e327428e36f69be"
)
RAW_KEY_FIXTURE_SHA256 = (
    "831db0c2e2579cac28cb976a0559b5bc471a00dced9435c73b8c62fda1b1e7d1"
)


def write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_header(container: bytes, header: dict) -> bytes:
    header_len = int.from_bytes(container[5:9], "big")
    body = container[9 + header_len :]
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return MAGIC + bytes([VERSION]) + len(encoded).to_bytes(4, "big") + encoded + body


def fixture_header(container: bytes) -> dict:
    header_len = int.from_bytes(container[5:9], "big")
    return json.loads(container[9 : 9 + header_len].decode("utf-8"))


def build_raw_key_fixture(
    plaintext: bytes,
    *,
    key: bytes = RAW_KEY,
    metadata: dict | None = None,
) -> bytes:
    header = {
        "alg": "AES-256-GCM",
        "kdf": "raw-key",
        "iterations": 0,
        "created": 1_700_000_003,
        "mode": "contact",
    }
    if metadata:
        header.update(metadata)
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    salt = bytes(range(128, 144))
    nonce = bytes(range(144, 156))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return (
        MAGIC
        + bytes([VERSION])
        + len(encoded).to_bytes(4, "big")
        + encoded
        + salt
        + nonce
        + ciphertext
    )


class CryptoCoreLegacyCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def install_fixture(self, name: str, data: bytes) -> Path:
        path = self.root / name
        write_private(path, data)
        return path

    def test_new_mok1_creation_is_retired_before_any_io_or_crypto(self):
        missing_input = self.root / "must-not-be-read.txt"
        password_output = self.root / "must-not-exist-password.mok"
        raw_output = self.root / "must-not-exist-raw.mok"
        before = set(self.root.iterdir())

        forbidden = AssertionError("retired encryption touched a forbidden boundary")
        with (
            patch.object(crypto_core, "_authenticate_first_pass", side_effect=forbidden),
            patch.object(crypto_core, "_decrypt_authenticated_legacy", side_effect=forbidden),
            patch.object(crypto_core, "_derive_key_argon2", side_effect=forbidden),
            patch.object(crypto_core, "_derive_key", side_effect=forbidden),
            patch.object(crypto_core.hashlib, "pbkdf2_hmac", side_effect=forbidden),
            patch.object(crypto_core.os, "urandom", side_effect=forbidden),
        ):
            with self.assertRaises(MOK1EncryptionRetiredError):
                encrypt_file(
                    str(missing_input),
                    str(password_output),
                    "secret-not-for-errors",
                    meta={"nick": "private-not-for-errors"},
                    nickname="private-not-for-errors",
                )
            with self.assertRaises(MOK1EncryptionRetiredError):
                encrypt_file_with_raw_key(
                    str(missing_input),
                    str(raw_output),
                    b"not-even-validated",
                )

        self.assertEqual(set(self.root.iterdir()), before)
        self.assertFalse(password_output.exists())
        self.assertFalse(raw_output.exists())

    def test_exact_historical_argon2id_fixture_decrypts_privately(self):
        self.assertEqual(
            hashlib.sha256(ARGON2_FIXTURE).hexdigest(),
            ARGON2_FIXTURE_SHA256,
        )
        source = self.install_fixture("argon2.mok", ARGON2_FIXTURE)
        output = self.root / "argon2.dec"

        result = decrypt_file(
            str(source),
            str(output),
            PASSWORD,
            nickname=NICKNAME,
        )

        self.assertEqual(result, str(output.resolve()))
        self.assertEqual(output.read_bytes(), ARGON2_PLAINTEXT)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_nlink, 1)
        self.assertEqual(source.read_bytes(), ARGON2_FIXTURE)
        self.assertEqual(set(self.root.iterdir()), {source, output})

    def test_exact_historical_pbkdf2_fixture_decrypts_privately(self):
        self.assertEqual(
            hashlib.sha256(PBKDF2_FIXTURE).hexdigest(),
            PBKDF2_FIXTURE_SHA256,
        )
        source = self.install_fixture("pbkdf2.mok", PBKDF2_FIXTURE)
        output = self.root / "pbkdf2.dec"

        decrypt_file(str(source), str(output), PASSWORD, nickname=NICKNAME)

        self.assertEqual(output.read_bytes(), PBKDF2_PLAINTEXT)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(set(self.root.iterdir()), {source, output})

    def test_exact_historical_raw_key_contact_fixture_decrypts_privately(self):
        self.assertEqual(
            hashlib.sha256(RAW_KEY_FIXTURE).hexdigest(),
            RAW_KEY_FIXTURE_SHA256,
        )
        source = self.install_fixture("contact.mok", RAW_KEY_FIXTURE)
        output = self.root / "contact.dec"

        decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertEqual(output.read_bytes(), RAW_KEY_PLAINTEXT)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(set(self.root.iterdir()), {source, output})

    def test_empty_historical_raw_key_payload_decrypts_to_private_empty_file(self):
        source = self.install_fixture(
            "empty-contact.mok",
            build_raw_key_fixture(b""),
        )
        output = self.root / "empty-contact.dec"

        decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertEqual(output.read_bytes(), b"")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_nlink, 1)
        self.assertEqual(set(self.root.iterdir()), {source, output})

    def test_wrong_password_and_wrong_raw_key_publish_nothing(self):
        password_source = self.install_fixture("wrong-password.mok", ARGON2_FIXTURE)
        raw_source = self.install_fixture("wrong-key.mok", RAW_KEY_FIXTURE)
        password_output = self.root / "wrong-password.dec"
        raw_output = self.root / "wrong-key.dec"
        before = set(self.root.iterdir())

        with self.assertRaises(MOK1AuthenticationError):
            decrypt_file(
                str(password_source),
                str(password_output),
                "wrong-password",
                nickname=NICKNAME,
            )
        with self.assertRaises(MOK1AuthenticationError):
            decrypt_file_with_raw_key(
                str(raw_source),
                str(raw_output),
                bytes(reversed(RAW_KEY)),
            )

        self.assertEqual(set(self.root.iterdir()), before)
        self.assertFalse(password_output.exists())
        self.assertFalse(raw_output.exists())

    def test_ciphertext_tamper_publishes_no_plaintext_or_residue(self):
        damaged = bytearray(PBKDF2_FIXTURE)
        damaged[-17] ^= 1
        source = self.install_fixture("tampered.mok", bytes(damaged))
        output = self.root / "tampered.dec"
        before = set(self.root.iterdir())

        with self.assertRaises(MOK1AuthenticationError):
            decrypt_file(str(source), str(output), PASSWORD, nickname=NICKNAME)

        self.assertEqual(set(self.root.iterdir()), before)
        self.assertFalse(output.exists())

    def test_large_payload_uses_only_bounded_reads(self):
        plaintext = (b"MOKOSH-stream-boundary\x00" * 150_000) + b"end"
        container = build_raw_key_fixture(plaintext)
        source = self.install_fixture("large.mok", container)
        output = self.root / "large.dec"
        read_sizes = []
        original_read = VerifiedFileSource.read

        def recording_read(instance, size):
            read_sizes.append(size)
            return original_read(instance, size)

        with patch.object(
            VerifiedFileSource,
            "read",
            new=recording_read,
        ):
            decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertEqual(output.read_bytes(), plaintext)
        self.assertTrue(read_sizes)
        self.assertGreater(read_sizes.count(LEGACY_IO_CHUNK_SIZE), 2)
        self.assertLessEqual(max(read_sizes), LEGACY_IO_CHUNK_SIZE)

    def test_source_inode_change_between_passes_is_rejected(self):
        source = self.install_fixture("replace-between-passes.mok", RAW_KEY_FIXTURE)
        output = self.root / "replace-between-passes.dec"
        replacement = self.root / "replacement.tmp"
        original_authenticate = crypto_core._authenticate_first_pass

        def authenticate_then_replace(*args, **kwargs):
            result = original_authenticate(*args, **kwargs)
            write_private(replacement, RAW_KEY_FIXTURE)
            os.replace(replacement, source)
            return result

        with patch.object(
            crypto_core,
            "_authenticate_first_pass",
            side_effect=authenticate_then_replace,
        ):
            with self.assertRaises(SourceChangedError):
                decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_fixture_kdf_parameters_match_frozen_legacy_values(self):
        header = fixture_header(ARGON2_FIXTURE)
        self.assertEqual(header["argon2_time"], ARGON2_TIME_COST)
        self.assertEqual(header["argon2_memory"], ARGON2_MEMORY_COST)
        self.assertEqual(header["argon2_parallelism"], ARGON2_PARALLELISM)
        self.assertEqual(fixture_header(PBKDF2_FIXTURE)["iterations"], KDF_ITERATIONS)


if __name__ == "__main__":
    unittest.main()
