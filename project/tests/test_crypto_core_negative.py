import ast
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import crypto_core
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_core import (
    MAGIC,
    MAX_HEADER_LEN,
    MOK1AuthenticationError,
    MOK1CredentialError,
    MOK1EncryptionRetiredError,
    MOK1FormatError,
    VERSION,
    _parse_header,
    decrypt_file,
    decrypt_file_with_raw_key,
    encrypt_file,
    encrypt_file_with_raw_key,
)
from mokosh_v2_filesystem import (
    ExclusiveFileQuarantineSink,
    OutputCollisionError,
    SourceChangedError,
    UnsafePathError,
    VerifiedFileSource,
)
from tests.test_crypto_core import (
    ARGON2_FIXTURE,
    NICKNAME,
    PASSWORD,
    PBKDF2_FIXTURE,
    RAW_KEY,
    RAW_KEY_FIXTURE,
    RAW_KEY_PLAINTEXT,
    fixture_header,
    replace_header,
    write_private,
)


def build_pbkdf2_credential_fixture(
    password: str,
    nickname: str,
    plaintext: bytes,
) -> bytes:
    header = {
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 200_000,
        "created": 1_700_000_004,
        "mode": "file",
        "nick": nickname,
    }
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    salt = bytes(range(160, 176))
    nonce = bytes(range(176, 188))
    key = hashlib.pbkdf2_hmac(
        "sha256",
        f"{password}|{nickname.strip()}".encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )
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


class CryptoCoreNegativeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def install(self, name: str, data: bytes) -> Path:
        path = self.root / name
        write_private(path, data)
        return path

    def assert_password_rejected_without_output(self, container: bytes) -> None:
        source = self.install("rejected-password.mok", container)
        output = self.root / "rejected-password.dec"
        before = set(self.root.iterdir())
        with self.assertRaises(MOK1FormatError):
            decrypt_file(str(source), str(output), PASSWORD, nickname=NICKNAME)
        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def assert_raw_rejected_without_output(self, container: bytes) -> None:
        source = self.install("rejected-raw.mok", container)
        output = self.root / "rejected-raw.dec"
        before = set(self.root.iterdir())
        with self.assertRaises(MOK1FormatError):
            decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)
        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_invalid_magic_and_unsupported_version_are_rejected(self):
        with self.assertRaises(MOK1FormatError):
            _parse_header(b"BAD!" + bytes([VERSION]) + (2).to_bytes(4, "big") + b"{}")
        with self.assertRaises(MOK1FormatError):
            _parse_header(MAGIC + bytes([VERSION + 1]) + (2).to_bytes(4, "big") + b"{}")

    def test_empty_and_oversized_headers_are_rejected_before_json(self):
        with self.assertRaises(MOK1FormatError):
            _parse_header(MAGIC + bytes([VERSION]) + (0).to_bytes(4, "big"))
        oversized = b"{" + (b" " * (MAX_HEADER_LEN - 1)) + b"}"
        self.assertEqual(len(oversized), MAX_HEADER_LEN + 1)
        data = MAGIC + bytes([VERSION]) + len(oversized).to_bytes(4, "big") + oversized
        with self.assertRaises(MOK1FormatError):
            _parse_header(data)

    def test_duplicate_keys_non_object_nan_and_invalid_utf8_are_rejected(self):
        invalid_headers = (
            b'{"alg":"AES-256-GCM","kdf":"raw-key","kdf":"raw-key"}',
            b"[]",
            b'{"alg":"AES-256-GCM","kdf":"raw-key","value":NaN}',
            b'\xff{"alg":"AES-256-GCM","kdf":"raw-key"}',
        )
        for encoded in invalid_headers:
            with self.subTest(encoded=encoded[:24]):
                data = MAGIC + bytes([VERSION]) + len(encoded).to_bytes(4, "big") + encoded
                with self.assertRaises(MOK1FormatError):
                    _parse_header(data)

    def test_missing_or_unknown_algorithm_is_rejected(self):
        for value in (None, "AES-128-GCM", "aes-256-gcm", 256, True):
            header = fixture_header(RAW_KEY_FIXTURE)
            if value is None:
                del header["alg"]
            else:
                header["alg"] = value
            with self.subTest(value=value):
                self.assert_raw_rejected_without_output(
                    replace_header(RAW_KEY_FIXTURE, header)
                )
                for child in tuple(self.root.iterdir()):
                    child.unlink()

    def test_unknown_kdf_never_falls_back_to_pbkdf2(self):
        header = fixture_header(PBKDF2_FIXTURE)
        header["kdf"] = "unknown-attacker-kdf"
        source = self.install(
            "unknown-kdf.mok",
            replace_header(PBKDF2_FIXTURE, header),
        )
        output = self.root / "unknown-kdf.dec"
        forbidden = AssertionError("unknown KDF reached PBKDF2")

        with patch.object(
            crypto_core.hashlib,
            "pbkdf2_hmac",
            side_effect=forbidden,
        ):
            with self.assertRaises(MOK1FormatError):
                decrypt_file(str(source), str(output), PASSWORD, nickname=NICKNAME)

        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_pbkdf2_work_factor_must_match_historical_writer(self):
        for value in (None, True, 0, 1, 199_999, 200_001, 2**63):
            header = fixture_header(PBKDF2_FIXTURE)
            if value is None:
                del header["iterations"]
            else:
                header["iterations"] = value
            with self.subTest(value=value):
                self.assert_password_rejected_without_output(
                    replace_header(PBKDF2_FIXTURE, header)
                )
                for child in tuple(self.root.iterdir()):
                    child.unlink()

    def test_argon2_parameters_must_match_historical_writer(self):
        fields = {
            "argon2_time": (None, True, 1, 3),
            "argon2_memory": (None, True, 19_456, 65_535, 65_537),
            "argon2_parallelism": (None, True, 1, 5),
        }
        for field, values in fields.items():
            for value in values:
                header = fixture_header(ARGON2_FIXTURE)
                if value is None:
                    del header[field]
                else:
                    header[field] = value
                with self.subTest(field=field, value=value):
                    self.assert_password_rejected_without_output(
                        replace_header(ARGON2_FIXTURE, header)
                    )
                    for child in tuple(self.root.iterdir()):
                        child.unlink()

    def test_password_and_raw_key_entry_points_cannot_be_confused(self):
        password_source = self.install("password.mok", PBKDF2_FIXTURE)
        raw_source = self.install("raw.mok", RAW_KEY_FIXTURE)
        password_output = self.root / "password.dec"
        raw_output = self.root / "raw.dec"
        before = set(self.root.iterdir())

        with self.assertRaises(MOK1FormatError):
            decrypt_file_with_raw_key(str(password_source), str(password_output), RAW_KEY)
        with self.assertRaises(MOK1FormatError):
            decrypt_file(str(raw_source), str(raw_output), PASSWORD, nickname=NICKNAME)

        self.assertEqual(set(self.root.iterdir()), before)

    def test_truncated_header_salt_nonce_ciphertext_and_tag_are_rejected(self):
        header_len = int.from_bytes(RAW_KEY_FIXTURE[5:9], "big")
        prologue_end = 9 + header_len
        cases = (
            RAW_KEY_FIXTURE[:8],
            RAW_KEY_FIXTURE[: prologue_end - 1],
            RAW_KEY_FIXTURE[: prologue_end + 15],
            RAW_KEY_FIXTURE[: prologue_end + 16 + 11],
            RAW_KEY_FIXTURE[: prologue_end + 16 + 12 + 15],
        )
        for index, container in enumerate(cases):
            source = self.install(f"truncated-{index}.mok", container)
            output = self.root / f"truncated-{index}.dec"
            with self.subTest(index=index):
                with self.assertRaises(MOK1FormatError):
                    decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)
                self.assertFalse(output.exists())
            source.unlink()

    def test_modified_tag_is_rejected_with_generic_secret_free_error(self):
        damaged = bytearray(ARGON2_FIXTURE)
        damaged[-1] ^= 1
        source = self.install("bad-tag.mok", bytes(damaged))
        output = self.root / "bad-tag.dec"
        secret_password = "DO-NOT-LEAK-PASSWORD"
        secret_nickname = "DO-NOT-LEAK-NICKNAME"

        with self.assertRaises(MOK1AuthenticationError) as caught:
            decrypt_file(
                str(source),
                str(output),
                secret_password,
                nickname=secret_nickname,
            )

        message = str(caught.exception)
        self.assertNotIn(secret_password, message)
        self.assertNotIn(secret_nickname, message)
        self.assertNotIn(str(source), message)
        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_failed_first_pass_never_creates_plaintext_quarantine(self):
        damaged = bytearray(RAW_KEY_FIXTURE)
        damaged[-1] ^= 1
        source = self.install("first-pass-tag-failure.mok", bytes(damaged))
        output = self.root / "first-pass-tag-failure.dec"
        forbidden = AssertionError("plaintext quarantine created before authentication")

        with patch(
            "mokosh_v2_filesystem.ExclusiveFileQuarantineSink",
            side_effect=forbidden,
        ):
            with self.assertRaises(MOK1AuthenticationError):
                decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_second_pass_payload_change_releases_nothing_and_cleans_residue(self):
        source = self.install("second-pass-change.mok", RAW_KEY_FIXTURE)
        output = self.root / "second-pass-change.dec"
        payload_offset = 9 + int.from_bytes(RAW_KEY_FIXTURE[5:9], "big") + 16 + 12
        original_read = VerifiedFileSource.read
        instances = []
        changed = False

        def change_before_second_payload_read(instance, size):
            nonlocal changed
            if instance not in instances:
                instances.append(instance)
            if (
                len(instances) == 2
                and instance is instances[1]
                and instance.bytes_read == payload_offset
                and not changed
            ):
                with source.open("r+b", buffering=0) as handle:
                    handle.seek(payload_offset)
                    original = handle.read(1)
                    self.assertEqual(len(original), 1)
                    handle.seek(payload_offset)
                    handle.write(bytes([original[0] ^ 1]))
                    os.fsync(handle.fileno())
                changed = True
            return original_read(instance, size)

        with patch.object(
            VerifiedFileSource,
            "read",
            new=change_before_second_payload_read,
        ):
            with self.assertRaises((MOK1AuthenticationError, SourceChangedError)):
                decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertTrue(changed)
        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_second_pass_write_failure_aborts_private_quarantine(self):
        source = self.install("write-failure.mok", RAW_KEY_FIXTURE)
        output = self.root / "write-failure.dec"
        failure = OSError("synthetic private output write failure")

        with patch.object(
            ExclusiveFileQuarantineSink,
            "write",
            side_effect=failure,
        ):
            with self.assertRaisesRegex(OSError, "synthetic private output write failure"):
                decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), {source})

    def test_existing_output_is_not_overwritten(self):
        source = self.install("collision.mok", RAW_KEY_FIXTURE)
        output = self.install("collision.dec", b"existing-output-sentinel")
        before = set(self.root.iterdir())

        with self.assertRaises(OutputCollisionError):
            decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertEqual(output.read_bytes(), b"existing-output-sentinel")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_output_symlink_is_not_followed_or_overwritten(self):
        source = self.install("symlink-output.mok", RAW_KEY_FIXTURE)
        target = self.install("symlink-target.txt", b"target-sentinel")
        output = self.root / "symlink-output.dec"
        output.symlink_to(target)
        before = set(self.root.iterdir())

        with self.assertRaises(OutputCollisionError):
            decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertTrue(output.is_symlink())
        self.assertEqual(target.read_bytes(), b"target-sentinel")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_source_and_output_parent_symlinks_are_rejected(self):
        real_source = self.install("real-source.mok", RAW_KEY_FIXTURE)
        source_link = self.root / "source-link.mok"
        source_link.symlink_to(real_source)
        output = self.root / "source-link.dec"
        with self.assertRaises(UnsafePathError):
            decrypt_file_with_raw_key(str(source_link), str(output), RAW_KEY)
        self.assertFalse(output.exists())

        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        linked_output = parent_link / "output.dec"
        with self.assertRaises(UnsafePathError):
            decrypt_file_with_raw_key(str(real_source), str(linked_output), RAW_KEY)
        self.assertFalse((real_parent / "output.dec").exists())

    def test_default_output_collision_is_rejected(self):
        source = self.install("default-name.mok", RAW_KEY_FIXTURE)
        output = self.install("default-name_dec", b"default-sentinel")
        with self.assertRaises(OutputCollisionError):
            decrypt_file_with_raw_key(str(source), None, RAW_KEY)
        self.assertEqual(output.read_bytes(), b"default-sentinel")

    def test_output_mode_is_private_even_with_permissive_caller_umask(self):
        source = self.install("umask.mok", RAW_KEY_FIXTURE)
        output = self.root / "umask.dec"
        old_umask = os.umask(0)
        try:
            decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)
        finally:
            os.umask(old_umask)
        self.assertEqual(output.read_bytes(), RAW_KEY_PLAINTEXT)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_advisory_metadata_is_unauthenticated_but_cannot_control_output(self):
        header = fixture_header(RAW_KEY_FIXTURE)
        header.update(
            {
                "created": -1,
                "mode": "../../attacker-controlled-mode",
                "nick": "attacker-controlled-nickname",
                "contact_id": "attacker-controlled-contact",
                "original_name": "../../must-not-be-used.txt",
            }
        )
        container = replace_header(RAW_KEY_FIXTURE, header)
        source = self.install("advisory-tamper.mok", container)
        output = self.root / "explicit-safe-output.dec"

        result = decrypt_file_with_raw_key(str(source), str(output), RAW_KEY)

        self.assertEqual(result, str(output.resolve()))
        self.assertEqual(output.read_bytes(), RAW_KEY_PLAINTEXT)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertFalse((self.root.parent / "must-not-be-used.txt").exists())

    def test_historical_plaintext_metadata_disclosure_is_explicitly_contained(self):
        self.assertIn(b'"created":1700000000', ARGON2_FIXTURE)
        self.assertIn(b'"mode":"single"', ARGON2_FIXTURE)
        self.assertIn(b'"nick":"test-user"', ARGON2_FIXTURE)
        with self.assertRaises(MOK1EncryptionRetiredError):
            encrypt_file("unused", "unused", "unused", meta={"private": "value"})

    def test_historical_password_nickname_collision_is_explicitly_contained(self):
        plaintext = b"legacy delimiter collision is compatibility-only"
        container = build_pbkdf2_credential_fixture(
            "alpha|beta",
            "gamma",
            plaintext,
        )
        source = self.install("delimiter-collision.mok", container)
        output = self.root / "delimiter-collision.dec"

        # Both pairs produced the same historical `password|nickname` bytes.
        decrypt_file(
            str(source),
            str(output),
            "alpha",
            nickname="beta|gamma",
        )

        self.assertEqual(output.read_bytes(), plaintext)
        with self.assertRaises(MOK1EncryptionRetiredError):
            encrypt_file("unused", "unused", "alpha", nickname="beta|gamma")

    def test_invalid_credential_types_are_rejected_before_source_access(self):
        forbidden = AssertionError("invalid credential reached the filesystem")
        with patch.object(crypto_core, "_authenticate_first_pass", side_effect=forbidden):
            for password, nickname in ((None, ""), (b"password", ""), ("password", None)):
                with self.subTest(password=password, nickname=nickname):
                    with self.assertRaises(MOK1CredentialError):
                        decrypt_file("unused", "unused", password, nickname=nickname)
            for key in (None, "key", b"", b"x" * 31, b"x" * 33):
                with self.subTest(key=key):
                    with self.assertRaises(MOK1CredentialError):
                        decrypt_file_with_raw_key("unused", "unused", key)

    def test_retired_encryption_does_not_follow_an_output_symlink(self):
        target = self.install("retired-target.txt", b"retired-target-sentinel")
        output = self.root / "retired-output.mok"
        output.symlink_to(target)
        before = set(self.root.iterdir())

        with self.assertRaises(MOK1EncryptionRetiredError):
            encrypt_file("unused", str(output), "unused")
        with self.assertRaises(MOK1EncryptionRetiredError):
            encrypt_file_with_raw_key("unused", str(output), b"unused")

        self.assertEqual(target.read_bytes(), b"retired-target-sentinel")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_production_source_has_no_unbounded_file_read_or_mok1_writer(self):
        path = Path(crypto_core.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        open_calls = []
        zero_argument_reads = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                open_calls.append(node.lineno)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "read"
                and not node.args
                and not node.keywords
            ):
                zero_argument_reads.append(node.lineno)
        self.assertEqual(open_calls, [])
        self.assertEqual(zero_argument_reads, [])
        self.assertNotIn("AESGCM", path.read_text(encoding="utf-8"))

    def test_no_expected_failure_decorator_remains_in_crypto_tests(self):
        for relative in ("test_crypto_core.py", "test_crypto_core_negative.py"):
            tree = ast.parse((Path(__file__).parent / relative).read_text(encoding="utf-8"))
            decorators = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "unittest"
                and node.attr == "expectedFailure"
            ]
            self.assertEqual(decorators, [], relative)


if __name__ == "__main__":
    unittest.main()
