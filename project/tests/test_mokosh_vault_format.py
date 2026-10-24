import ast
import copy
import inspect
import json
import pickle
import struct
import unittest
from dataclasses import replace
from unittest import mock

import mokosh_vault_format as vault


PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "нова правилна парола с интервали"
ROOT_KEY = bytes(range(32))
VAULT_ID = bytes(range(16))
CREATED = "2026-08-11T08:00:00Z"
UPDATED = "2026-08-11T09:00:00Z"


def make_vault(password=PASSWORD):
    return vault.create_vault(
        password,
        root_key=ROOT_KEY,
        vault_id=VAULT_ID,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


def split_encoded(encoded):
    fields = list(vault.VAULT_PREAMBLE_STRUCT.unpack(encoded[: vault.VAULT_PREAMBLE_LEN]))
    header_len = fields[4]
    header_start = vault.VAULT_PREAMBLE_LEN
    header_end = header_start + header_len
    return fields, encoded[header_start:header_end], encoded[header_end:]


def rebuild(fields, header_bytes, ciphertext):
    fields[4] = len(header_bytes)
    fields[5] = len(ciphertext)
    return vault.VAULT_PREAMBLE_STRUCT.pack(*fields) + header_bytes + ciphertext


class VaultFormatTests(unittest.TestCase):
    def test_create_parse_unlock_roundtrip(self):
        encoded = make_vault()
        parsed, root_key = vault.unlock_vault(encoded, PASSWORD)
        self.assertEqual(root_key, ROOT_KEY)
        self.assertEqual(parsed.header.vault_id, VAULT_ID)
        self.assertEqual(parsed.header.revision, 1)
        self.assertEqual(parsed.encoded, encoded)

    def test_vault_format_is_distinct_from_file_envelope(self):
        encoded = make_vault()
        self.assertTrue(encoded.startswith(vault.VAULT_MAGIC))
        self.assertFalse(encoded.startswith(b"MOKOSH2\x00"))

    def test_wrong_magic_is_rejected(self):
        encoded = bytearray(make_vault())
        encoded[0] ^= 1
        with self.assertRaises(vault.VaultFormatError):
            vault.parse_vault(encoded)

    def test_unsupported_version_and_flags_are_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        for index, replacement in ((1, 2), (2, 1), (3, 1)):
            changed = fields.copy()
            changed[index] = replacement
            with self.subTest(index=index):
                with self.assertRaises(vault.VaultUnsupportedVersionError):
                    vault.parse_vault(rebuild(changed, header, ciphertext))

    def test_truncation_and_trailing_data_are_rejected(self):
        encoded = make_vault()
        for changed in (encoded[:10], encoded[:-1], encoded + b"x"):
            with self.subTest(length=len(changed)):
                with self.assertRaises(vault.VaultFormatError):
                    vault.parse_vault(changed)

    def test_declared_header_and_ciphertext_bounds_are_enforced(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        cases = ((4, 0), (4, vault.MAX_VAULT_HEADER_LEN + 1), (5, 16), (5, vault.MAX_VAULT_CIPHERTEXT_LEN + 1))
        for index, replacement in cases:
            changed = fields.copy()
            changed[index] = replacement
            with self.subTest(index=index, replacement=replacement):
                with self.assertRaises(vault.VaultFormatError):
                    vault.parse_vault(vault.VAULT_PREAMBLE_STRUCT.pack(*changed) + header + ciphertext)

    def test_duplicate_header_key_is_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        text = header.decode("ascii")
        duplicate = (text[:-1] + ',"version":1}').encode("ascii")
        with self.assertRaises(vault.VaultDuplicateKeyError):
            vault.parse_vault(rebuild(fields, duplicate, ciphertext))

    def test_missing_and_unknown_header_fields_are_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        cases = []
        missing = dict(mapping)
        del missing["vault_id"]
        cases.append(missing)
        unknown = dict(mapping)
        unknown["future"] = 1
        cases.append(unknown)
        for changed in cases:
            data = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")
            with self.subTest(keys=sorted(changed)):
                with self.assertRaises(vault.VaultFormatError):
                    vault.parse_vault(rebuild(fields, data, ciphertext))

    def test_noncanonical_header_is_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        noncanonical = json.dumps(mapping, sort_keys=False, indent=1).encode("ascii")
        with self.assertRaises(vault.VaultFormatError):
            vault.parse_vault(rebuild(fields, noncanonical, ciphertext))

    def test_boolean_revision_is_not_an_integer(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        mapping["revision"] = True
        changed = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaises(vault.VaultFormatError):
            vault.parse_vault(rebuild(fields, changed, ciphertext))

    def test_invalid_or_non_utc_timestamp_is_rejected(self):
        for value in ("2026-08-11 08:00:00", "2026-02-30T08:00:00Z", "2026-08-11T08:00:00+00:00"):
            with self.subTest(value=value):
                with self.assertRaises(vault.VaultFormatError):
                    vault.create_vault(
                        PASSWORD,
                        root_key=ROOT_KEY,
                        vault_id=VAULT_ID,
                        created_utc=value,
                        time_cost=1,
                        memory_kib=8192,
                        parallelism=1,
                    )

    def test_updated_timestamp_cannot_move_backwards(self):
        parsed, root = vault.unlock_vault(make_vault(), PASSWORD)
        with self.assertRaises(vault.VaultPolicyError):
            vault.rewrap_vault(
                parsed,
                root,
                NEW_PASSWORD,
                updated_utc="2026-08-11T07:59:59Z",
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )

    def test_padded_or_wrong_length_base64_is_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        for value in (mapping["vault_id"] + "=", "AA"):
            changed = dict(mapping)
            changed["vault_id"] = value
            data = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")
            with self.subTest(value=value):
                with self.assertRaises(vault.VaultFormatError):
                    vault.parse_vault(rebuild(fields, data, ciphertext))

    def test_unknown_kdf_aead_and_nested_fields_are_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        cases = []
        bad_kdf = copy.deepcopy(mapping)
        bad_kdf["kdf"]["algorithm"] = "PBKDF2"
        cases.append(bad_kdf)
        extra_kdf = copy.deepcopy(mapping)
        extra_kdf["kdf"]["extra"] = 1
        cases.append(extra_kdf)
        bad_aead = copy.deepcopy(mapping)
        bad_aead["aead"]["algorithm"] = "AES-CTR"
        cases.append(bad_aead)
        for changed in cases:
            data = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")
            with self.subTest(changed=changed):
                with self.assertRaises(vault.VaultError):
                    vault.parse_vault(rebuild(fields, data, ciphertext))

    def test_kdf_policy_is_checked_before_argon2_execution(self):
        encoded = make_vault()
        restrictive = vault.VaultKDFPolicy(
            max_time_cost=1, max_memory_kib=8192, max_parallelism=1
        )
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        mapping["kdf"]["memory_kib"] = 16384
        changed_header = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode("ascii")
        changed = rebuild(fields, changed_header, ciphertext)
        with mock.patch.object(vault, "Argon2id") as argon:
            with self.assertRaises(vault.VaultPolicyError):
                vault.unlock_vault(changed, PASSWORD, policy=restrictive)
            argon.assert_not_called()

    def test_kdf_boolean_and_out_of_range_parameters_are_rejected(self):
        for field, value in (("time_cost", True), ("memory_kib", 1), ("parallelism", 0)):
            kwargs = dict(time_cost=1, memory_kib=8192, parallelism=1)
            kwargs[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(vault.VaultError):
                    vault.create_vault(
                        PASSWORD,
                        root_key=ROOT_KEY,
                        vault_id=VAULT_ID,
                        created_utc=CREATED,
                        **kwargs,
                    )

    def test_minimum_revision_rejects_rollback(self):
        with self.assertRaises(vault.VaultPolicyError):
            vault.parse_vault(make_vault(), minimum_revision=2)

    def test_invalid_minimum_revision_is_rejected(self):
        for value in (-1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(vault.VaultPolicyError):
                    vault.parse_vault(make_vault(), minimum_revision=value)

    def test_wrong_password_and_ciphertext_tamper_are_rejected(self):
        encoded = make_vault()
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_vault(encoded, "wrong password")
        changed = bytearray(encoded)
        changed[-1] ^= 1
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_vault(changed, PASSWORD)

    def test_authenticated_header_tamper_is_rejected(self):
        encoded = make_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        mapping["updated_utc"] = "2026-08-11T08:00:01Z"
        changed_header = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_vault(rebuild(fields, changed_header, ciphertext), PASSWORD)

    def test_password_and_binary_input_bounds(self):
        with self.assertRaises(vault.VaultFormatError):
            vault.create_vault("")
        with self.assertRaises(vault.VaultFormatError):
            vault.create_vault("x" * 1025)
        with self.assertRaises(vault.VaultFormatError):
            vault.create_vault(PASSWORD, root_key=b"x")
        with self.assertRaises(vault.VaultFormatError):
            vault.create_vault(PASSWORD, vault_id=b"x")

    def test_secure_random_length_is_verified(self):
        with mock.patch.object(vault.os, "urandom", return_value=b"x"):
            with self.assertRaises(vault.VaultError):
                vault.create_vault(PASSWORD)

    def test_password_rewrap_preserves_root_and_identity(self):
        original = make_vault()
        parsed, root = vault.unlock_vault(original, PASSWORD)
        changed = vault.rewrap_vault(
            parsed,
            root,
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        changed_parsed, changed_root = vault.unlock_vault(changed, NEW_PASSWORD)
        self.assertEqual(changed_root, ROOT_KEY)
        self.assertEqual(changed_parsed.header.vault_id, VAULT_ID)
        self.assertEqual(changed_parsed.header.revision, 2)
        self.assertNotEqual(changed_parsed.header.salt, parsed.header.salt)
        self.assertNotEqual(changed_parsed.header.nonce, parsed.header.nonce)
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_vault(changed, PASSWORD)

    def test_revision_exhaustion_is_rejected(self):
        parsed, root = vault.unlock_vault(make_vault(), PASSWORD)
        exhausted = replace(parsed, header=replace(parsed.header, revision=vault.MAX_VAULT_REVISION))
        with self.assertRaises(vault.VaultPolicyError):
            vault.rewrap_vault(exhausted, root, NEW_PASSWORD, updated_utc=UPDATED)


class VaultModuleBoundaryTests(unittest.TestCase):
    def test_module_has_no_path_mutation_network_or_gui_calls(self):
        tree = ast.parse(inspect.getsource(vault))
        forbidden_calls = {
            "open", "unlink", "remove", "rename", "replace", "link",
            "mkdir", "makedirs", "rmdir", "socket", "urlopen", "request",
        }
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    found.add(node.func.id)
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in forbidden_calls
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id
                    in {"os", "pathlib", "requests", "shutil", "socket", "urllib"}
                ):
                    found.add(node.func.attr)
        self.assertEqual(found, set())

    def test_root_key_and_password_are_absent_from_authenticated_header(self):
        encoded = make_vault()
        _, header, _ = split_encoded(encoded)
        mapping = json.loads(header)
        self.assertNotIn("vault_root_key", mapping)
        self.assertNotIn("password", mapping)
        self.assertNotIn(PASSWORD, header.decode("ascii"))

    def test_session_has_no_password_storage_slot(self):
        self.assertNotIn("password", vault.VaultSession.__slots__)


class FakeClock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value


class VaultStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.session = vault.VaultSession(
            make_vault(), inactivity_timeout=10, clock=self.clock
        )

    def tearDown(self):
        self.session.close()

    def test_initial_state_and_unlock(self):
        self.assertIs(self.session.state, vault.VaultSessionState.LOCKED)
        self.session.unlock(PASSWORD)
        self.assertIs(self.session.state, vault.VaultSessionState.UNLOCKED)
        self.assertEqual(self.session.root_key_copy(), ROOT_KEY)

    def test_wrong_password_enters_failed_state_and_requires_reset(self):
        with self.assertRaises(vault.VaultAuthenticationError):
            self.session.unlock("wrong")
        self.assertIs(self.session.state, vault.VaultSessionState.FAILED)
        with self.assertRaises(vault.VaultStateError):
            self.session.unlock(PASSWORD)
        self.session.reset_failure()
        self.session.unlock(PASSWORD)
        self.assertIs(self.session.state, vault.VaultSessionState.UNLOCKED)

    def test_invalid_transitions_are_rejected(self):
        with self.assertRaises(vault.VaultStateError):
            self.session.root_key_copy()
        with self.assertRaises(vault.VaultStateError):
            self.session.reset_failure()
        self.session.unlock(PASSWORD)
        with self.assertRaises(vault.VaultStateError):
            self.session.unlock(PASSWORD)

    def test_explicit_lock_is_idempotent_and_removes_key_access(self):
        self.session.unlock(PASSWORD)
        self.session.lock()
        self.session.lock()
        self.assertIs(self.session.state, vault.VaultSessionState.LOCKED)
        with self.assertRaises(vault.VaultStateError):
            self.session.root_key_copy()

    def test_inactivity_timeout_locks_session(self):
        self.session.unlock(PASSWORD)
        self.clock.value = 110.0
        self.assertTrue(self.session.check_inactivity())
        self.assertIs(self.session.state, vault.VaultSessionState.LOCKED)

    def test_activity_extends_timeout(self):
        self.session.unlock(PASSWORD)
        self.clock.value = 109.0
        self.session.touch()
        self.clock.value = 118.0
        self.assertFalse(self.session.check_inactivity())
        self.clock.value = 119.0
        self.assertTrue(self.session.check_inactivity())

    def test_clock_rollback_fails_closed(self):
        self.session.unlock(PASSWORD)
        self.clock.value = 99.0
        with self.assertRaises(vault.VaultStateError):
            self.session.check_inactivity()
        self.assertIs(self.session.state, vault.VaultSessionState.FAILED)
        with self.assertRaises(vault.VaultStateError):
            self.session.root_key_copy()

    def test_invalid_clock_value_fails_closed(self):
        self.session.unlock(PASSWORD)
        self.clock.value = float("nan")
        with self.assertRaises(vault.VaultStateError):
            self.session.check_inactivity()
        self.assertIs(self.session.state, vault.VaultSessionState.FAILED)
        with self.assertRaises(vault.VaultStateError):
            self.session.root_key_copy()

    def test_timeout_and_clock_inputs_are_strict(self):
        for timeout in (0, -1, True, float("inf"), float("nan")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(vault.VaultStateError):
                    vault.VaultSession(make_vault(), inactivity_timeout=timeout)

    def test_repr_copy_and_pickle_do_not_expose_or_duplicate_secret(self):
        self.session.unlock(PASSWORD)
        rendered = repr(self.session)
        self.assertIn("unlocked", rendered)
        self.assertNotIn(ROOT_KEY.hex(), rendered)
        with self.assertRaises(TypeError):
            copy.copy(self.session)
        with self.assertRaises(TypeError):
            copy.deepcopy(self.session)
        with self.assertRaises(TypeError):
            pickle.dumps(self.session)

    def test_session_password_change_keeps_unlocked_root(self):
        self.session.unlock(PASSWORD)
        changed = self.session.change_password(
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        self.assertEqual(self.session.revision, 2)
        self.assertEqual(self.session.root_key_copy(), ROOT_KEY)
        self.session.lock()
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_vault(changed, PASSWORD)
        _, root = vault.unlock_vault(changed, NEW_PASSWORD, minimum_revision=2)
        self.assertEqual(root, ROOT_KEY)

    def test_previous_image_is_rejected_after_revision_anchor_advances(self):
        original = self.session.encoded
        self.session.unlock(PASSWORD)
        self.session.change_password(
            NEW_PASSWORD,
            updated_utc=UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        with self.assertRaises(vault.VaultPolicyError):
            vault.VaultSession(original, minimum_revision=self.session.revision)


if __name__ == "__main__":
    unittest.main()
