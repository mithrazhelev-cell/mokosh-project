import ast
import copy
import inspect
import json
import os
import pickle
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_storage as storage
from mokosh_v2_vault_slots import VaultSlotAuthenticationError


PASSWORD = "Stage 2.3 correct password"
NEW_PASSWORD = "Stage 2.3 new password"
WRONG_PASSWORD = "Stage 2.3 wrong password"
VAULT_ID = bytes(range(16))
KEY_ONE = b"A" * 32
KEY_TWO = b"B" * 32
KEY_OTHER = b"C" * 32
DEK = b"D" * 32
FILE_ID = b"F" * 16
CREATED = "2026-08-12T08:00:00Z"
ROTATED = "2026-08-12T09:00:00Z"
REWRAPPED = "2026-08-12T10:00:00Z"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def initial_keyring():
    with mock.patch.object(keyring.os, "urandom", return_value=KEY_ONE):
        return keyring.create_keyring(created_utc=CREATED)


def rotated_keyring():
    original = initial_keyring()
    with mock.patch.object(keyring.os, "urandom", return_value=KEY_TWO):
        return keyring.rotate_keyring(original, rotated_utc=ROTATED)


def make_keyring_vault(password=PASSWORD, exact_keyring=None):
    return vault.create_keyring_vault(
        password,
        keyring=exact_keyring or initial_keyring(),
        vault_id=VAULT_ID,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


def make_legacy_vault(password=PASSWORD):
    return vault.create_vault(
        password,
        root_key=KEY_ONE,
        vault_id=VAULT_ID,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


def split_encoded(encoded):
    fields = list(
        vault.VAULT_PREAMBLE_STRUCT.unpack(encoded[: vault.VAULT_PREAMBLE_LEN])
    )
    start = vault.VAULT_PREAMBLE_LEN
    end = start + fields[4]
    return fields, encoded[start:end], encoded[end:]


def rebuild(fields, header, ciphertext):
    fields = list(fields)
    fields[4] = len(header)
    fields[5] = len(ciphertext)
    return vault.VAULT_PREAMBLE_STRUCT.pack(*fields) + header + ciphertext


class FakeClock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value


class KeyringCodecTests(unittest.TestCase):
    def test_canonical_roundtrip_and_exact_metadata(self):
        original = rotated_keyring()
        encoded = keyring.encode_keyring(original)
        decoded = keyring.parse_keyring(encoded)
        self.assertEqual(decoded, original)
        mapping = json.loads(encoded)
        self.assertEqual(mapping["format"], keyring.KEYRING_FORMAT_NAME)
        self.assertEqual(mapping["version"], keyring.KEYRING_SCHEMA)
        self.assertEqual(mapping["purpose"], keyring.KEYRING_PURPOSE)
        self.assertEqual(mapping["algorithm"], keyring.KEYRING_ALGORITHM)
        self.assertEqual(mapping["active_key_version"], 2)

    def test_duplicate_and_noncanonical_json_are_rejected(self):
        encoded = keyring.encode_keyring(initial_keyring())
        duplicate = encoded[:-1] + b',"version":1}'
        with self.assertRaises(keyring.VaultKeyringDuplicateKeyError):
            keyring.parse_keyring(duplicate)
        mapping = json.loads(encoded)
        noncanonical = json.dumps(mapping, indent=1).encode("ascii")
        with self.assertRaises(keyring.VaultKeyringFormatError):
            keyring.parse_keyring(noncanonical)

    def test_missing_unknown_and_wrong_fixed_fields_are_rejected(self):
        mapping = json.loads(keyring.encode_keyring(initial_keyring()))
        cases = []
        missing = copy.deepcopy(mapping)
        del missing["purpose"]
        cases.append(missing)
        unknown = copy.deepcopy(mapping)
        unknown["future"] = 1
        cases.append(unknown)
        for field, value in (
            ("format", "OTHER"),
            ("version", 2),
            ("purpose", "OTHER"),
            ("algorithm", "OTHER"),
        ):
            changed = copy.deepcopy(mapping)
            changed[field] = value
            cases.append(changed)
        for changed in cases:
            with self.subTest(keys=sorted(changed)):
                with self.assertRaises(keyring.VaultKeyringError):
                    keyring.parse_keyring(canonical(changed))

    def test_key_record_missing_unknown_and_state_fields_are_rejected(self):
        mapping = json.loads(keyring.encode_keyring(initial_keyring()))
        cases = []
        missing = copy.deepcopy(mapping)
        del missing["keys"][0]["state"]
        cases.append(missing)
        unknown = copy.deepcopy(mapping)
        unknown["keys"][0]["future"] = 1
        cases.append(unknown)
        bad_state = copy.deepcopy(mapping)
        bad_state["keys"][0]["state"] = "decrypt-maybe"
        cases.append(bad_state)
        bad_retired_type = copy.deepcopy(mapping)
        bad_retired_type["keys"][0]["retired_utc"] = False
        cases.append(bad_retired_type)
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringError):
                    keyring.parse_keyring(canonical(changed))

    def test_versions_are_plain_positive_uint32(self):
        mapping = json.loads(keyring.encode_keyring(initial_keyring()))
        for field_path, value in (
            ("active", True),
            ("active", 0),
            ("active", keyring.MAX_KEY_VERSION + 1),
            ("record", True),
            ("record", 0),
            ("record", keyring.MAX_KEY_VERSION + 1),
        ):
            changed = copy.deepcopy(mapping)
            if field_path == "active":
                changed["active_key_version"] = value
            else:
                changed["keys"][0]["key_version"] = value
            with self.subTest(field_path=field_path, value=value):
                with self.assertRaises(keyring.VaultKeyringFormatError):
                    keyring.parse_keyring(canonical(changed))

    def test_duplicate_gap_and_out_of_order_versions_are_rejected(self):
        mapping = json.loads(keyring.encode_keyring(rotated_keyring()))
        duplicate = copy.deepcopy(mapping)
        duplicate["keys"][1]["key_version"] = 1
        gap = copy.deepcopy(mapping)
        gap["keys"][1]["key_version"] = 3
        out_of_order = copy.deepcopy(mapping)
        out_of_order["keys"].reverse()
        for changed in (duplicate, gap, out_of_order):
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringFormatError):
                    keyring.parse_keyring(canonical(changed))

    def test_exactly_one_highest_active_key_is_required(self):
        mapping = json.loads(keyring.encode_keyring(rotated_keyring()))
        old_active = copy.deepcopy(mapping)
        old_active["keys"][0]["state"] = "active"
        old_active["keys"][0]["retired_utc"] = None
        final_retired = copy.deepcopy(mapping)
        final_retired["keys"][1]["state"] = "retired"
        final_retired["keys"][1]["retired_utc"] = REWRAPPED
        wrong_pointer = copy.deepcopy(mapping)
        wrong_pointer["active_key_version"] = 1
        for changed in (old_active, final_retired, wrong_pointer):
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringFormatError):
                    keyring.parse_keyring(canonical(changed))

    def test_retirement_timeline_is_exact_and_monotonic(self):
        mapping = json.loads(keyring.encode_keyring(rotated_keyring()))
        mismatch = copy.deepcopy(mapping)
        mismatch["keys"][0]["retired_utc"] = REWRAPPED
        backwards = copy.deepcopy(mapping)
        backwards["keys"][0]["created_utc"] = REWRAPPED
        invalid = copy.deepcopy(mapping)
        invalid["keys"][1]["created_utc"] = "2026-02-30T00:00:00Z"
        for changed in (mismatch, backwards, invalid):
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringError):
                    keyring.parse_keyring(canonical(changed))

    def test_duplicate_or_noncanonical_key_material_is_rejected(self):
        mapping = json.loads(keyring.encode_keyring(rotated_keyring()))
        duplicate = copy.deepcopy(mapping)
        duplicate["keys"][1]["wrapping_key"] = duplicate["keys"][0][
            "wrapping_key"
        ]
        padded = copy.deepcopy(mapping)
        padded["keys"][0]["wrapping_key"] += "="
        short = copy.deepcopy(mapping)
        short["keys"][0]["wrapping_key"] = "AA"
        for changed in (duplicate, padded, short):
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringFormatError):
                    keyring.parse_keyring(canonical(changed))

    def test_empty_oversized_and_wrong_container_types_are_rejected(self):
        mapping = json.loads(keyring.encode_keyring(initial_keyring()))
        empty = copy.deepcopy(mapping)
        empty["keys"] = []
        wrong = copy.deepcopy(mapping)
        wrong["keys"] = {}
        for changed in (empty, wrong):
            with self.subTest(changed=changed):
                with self.assertRaises(keyring.VaultKeyringError):
                    keyring.parse_keyring(canonical(changed))
        with mock.patch.object(keyring, "MAX_KEY_RECORDS", 0):
            with self.assertRaises(keyring.VaultKeyringPolicyError):
                keyring.encode_keyring(initial_keyring())

    def test_secret_objects_do_not_repr_copy_or_pickle(self):
        record = initial_keyring().keys[0]
        ring = initial_keyring()
        self.assertNotIn(KEY_ONE.hex(), repr(record))
        self.assertNotIn(KEY_ONE.hex(), repr(ring))
        for value in (record, ring):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    copy.copy(value)
                with self.assertRaises(TypeError):
                    copy.deepcopy(value)
                with self.assertRaises(TypeError):
                    pickle.dumps(value)


class KeyringRotationTests(unittest.TestCase):
    def test_creation_uses_exact_random_32_byte_key(self):
        with mock.patch.object(keyring.os, "urandom", return_value=KEY_ONE) as random:
            result = keyring.create_keyring(created_utc=CREATED)
        random.assert_called_once_with(32)
        self.assertEqual(result.active_key_version, 1)
        self.assertEqual(result.keys[0].wrapping_key, KEY_ONE)

    def test_invalid_random_source_fails_closed(self):
        for value in (b"short", bytearray(KEY_ONE), "not-bytes"):
            with self.subTest(value=type(value).__name__):
                with mock.patch.object(keyring.os, "urandom", return_value=value):
                    with self.assertRaises(keyring.VaultKeyringPolicyError):
                        keyring.create_keyring(created_utc=CREATED)

    def test_rotation_retires_old_key_and_appends_independent_key(self):
        original = initial_keyring()
        original_bytes = keyring.encode_keyring(original)
        with mock.patch.object(keyring.os, "urandom", return_value=KEY_TWO):
            changed = keyring.rotate_keyring(original, rotated_utc=ROTATED)
        self.assertEqual(keyring.encode_keyring(original), original_bytes)
        self.assertEqual(changed.active_key_version, 2)
        self.assertEqual([record.key_version for record in changed.keys], [1, 2])
        self.assertEqual(changed.keys[0].state, keyring.KEY_STATE_RETIRED)
        self.assertEqual(changed.keys[0].retired_utc, ROTATED)
        self.assertEqual(changed.keys[0].wrapping_key, KEY_ONE)
        self.assertEqual(changed.keys[1].state, keyring.KEY_STATE_ACTIVE)
        self.assertEqual(changed.keys[1].wrapping_key, KEY_TWO)

    def test_rotation_rejects_clock_rollback_collision_and_exhaustion(self):
        original = initial_keyring()
        with mock.patch.object(keyring.os, "urandom", return_value=KEY_TWO):
            with self.assertRaises(keyring.VaultKeyringPolicyError):
                keyring.rotate_keyring(
                    original, rotated_utc="2026-08-12T07:59:59Z"
                )
        with mock.patch.object(keyring.os, "urandom", return_value=KEY_ONE):
            with self.assertRaises(keyring.VaultKeyringPolicyError):
                keyring.rotate_keyring(original, rotated_utc=ROTATED)
        with mock.patch.object(keyring, "MAX_KEY_RECORDS", 1):
            with self.assertRaises(keyring.VaultKeyringPolicyError):
                keyring.rotate_keyring(original, rotated_utc=ROTATED)

    def test_legacy_import_is_explicit_and_never_randomizes_version_one(self):
        with mock.patch.object(keyring.os, "urandom") as random:
            result = keyring.keyring_from_legacy_key(
                KEY_ONE, created_utc=CREATED
            )
        random.assert_not_called()
        self.assertEqual(result.active_key_version, 1)
        self.assertEqual(result.keys[0].wrapping_key, KEY_ONE)


class ExactVersionSlotTests(unittest.TestCase):
    def test_new_slot_uses_only_the_active_key_version(self):
        ring = rotated_keyring()
        slot = keyring.create_vault_slot_for_keyring(ring, DEK, FILE_ID)
        self.assertEqual(slot.vault_key_version, 2)
        self.assertEqual(
            keyring.unwrap_vault_slot_for_keyring(ring, slot, FILE_ID), DEK
        )

    def test_retired_key_still_decrypts_old_slot_without_reencryption(self):
        original = initial_keyring()
        old_slot = keyring.create_vault_slot_for_keyring(original, DEK, FILE_ID)
        with mock.patch.object(keyring.os, "urandom", return_value=KEY_TWO):
            changed = keyring.rotate_keyring(original, rotated_utc=ROTATED)
        self.assertEqual(old_slot.vault_key_version, 1)
        self.assertEqual(
            keyring.unwrap_vault_slot_for_keyring(changed, old_slot, FILE_ID),
            DEK,
        )

    def test_missing_version_fails_before_unwrap_and_never_falls_back(self):
        ring = initial_keyring()
        slot = keyring.create_vault_slot_for_keyring(ring, DEK, FILE_ID)
        missing = replace(slot, vault_key_version=2)
        with mock.patch.object(keyring, "unwrap_vault_slot") as unwrap:
            with self.assertRaises(keyring.VaultKeyVersionNotFoundError):
                keyring.unwrap_vault_slot_for_keyring(ring, missing, FILE_ID)
        unwrap.assert_not_called()

    def test_authentication_failure_on_exact_version_never_tries_another_key(self):
        slot = keyring.create_vault_slot_for_keyring(
            initial_keyring(), DEK, FILE_ID
        )
        wrong_ring = keyring.keyring_from_legacy_key(
            KEY_OTHER, created_utc=CREATED
        )
        real_unwrap = keyring.unwrap_vault_slot
        with mock.patch.object(
            keyring, "unwrap_vault_slot", wraps=real_unwrap
        ) as unwrap:
            with self.assertRaises(VaultSlotAuthenticationError):
                keyring.unwrap_vault_slot_for_keyring(
                    wrong_ring, slot, FILE_ID
                )
        self.assertEqual(unwrap.call_count, 1)

    def test_requested_version_is_strict_uint32(self):
        ring = initial_keyring()
        for value in (True, 0, -1, keyring.MAX_KEY_VERSION + 1):
            with self.subTest(value=value):
                with self.assertRaises(keyring.VaultKeyringFormatError):
                    keyring.key_record_for_decryption(ring, value)


class KeyringVaultPayloadTests(unittest.TestCase):
    def test_schema_two_vault_roundtrip(self):
        ring = initial_keyring()
        encoded = make_keyring_vault(exact_keyring=ring)
        parsed, unlocked = vault.unlock_keyring_vault(encoded, PASSWORD)
        self.assertEqual(parsed.header.payload_schema, 2)
        self.assertEqual(parsed.header.revision, 1)
        self.assertEqual(parsed.header.vault_id, VAULT_ID)
        self.assertEqual(keyring.encode_keyring(unlocked), keyring.encode_keyring(ring))

    def test_new_vault_cannot_import_pre_rotated_history(self):
        with self.assertRaises(vault.VaultPolicyError):
            make_keyring_vault(exact_keyring=rotated_keyring())

    def test_legacy_and_keyring_apis_never_silently_cross_schemas(self):
        legacy = make_legacy_vault()
        modern = make_keyring_vault()
        parsed, root = vault.unlock_vault(legacy, PASSWORD)
        self.assertEqual(parsed.header.payload_schema, 1)
        self.assertEqual(root, KEY_ONE)
        with self.assertRaises(vault.VaultMigrationRequiredError):
            vault.unlock_keyring_vault(legacy, PASSWORD)
        with self.assertRaises(vault.VaultUnsupportedVersionError):
            vault.unlock_vault(modern, PASSWORD)

    def test_explicit_migration_preserves_legacy_key_id_and_history(self):
        legacy = make_legacy_vault()
        migrated = vault.migrate_legacy_vault_to_keyring(
            legacy,
            PASSWORD,
            updated_utc=ROTATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        old_parsed, old_root = vault.unlock_vault(legacy, PASSWORD)
        parsed, ring = vault.unlock_keyring_vault(
            migrated, PASSWORD, minimum_revision=2
        )
        self.assertEqual(old_root, KEY_ONE)
        self.assertEqual(parsed.header.vault_id, old_parsed.header.vault_id)
        self.assertEqual(parsed.header.created_utc, old_parsed.header.created_utc)
        self.assertEqual(parsed.header.revision, 2)
        self.assertEqual(ring.active_key_version, 1)
        self.assertEqual(ring.keys[0].wrapping_key, KEY_ONE)

    def test_migrated_version_one_still_opens_existing_file_slot(self):
        legacy_ring = keyring.keyring_from_legacy_key(
            KEY_ONE, created_utc=CREATED
        )
        old_slot = keyring.create_vault_slot_for_keyring(
            legacy_ring, DEK, FILE_ID
        )
        migrated = vault.migrate_legacy_vault_to_keyring(
            make_legacy_vault(),
            PASSWORD,
            updated_utc=ROTATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        _, migrated_ring = vault.unlock_keyring_vault(migrated, PASSWORD)
        self.assertEqual(
            keyring.unwrap_vault_slot_for_keyring(
                migrated_ring, old_slot, FILE_ID
            ),
            DEK,
        )

    def test_migration_rejects_wrong_password_already_modern_and_rollback(self):
        legacy = make_legacy_vault()
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.migrate_legacy_vault_to_keyring(legacy, WRONG_PASSWORD)
        with self.assertRaises(vault.VaultMigrationRequiredError):
            vault.migrate_legacy_vault_to_keyring(
                make_keyring_vault(), PASSWORD
            )
        with self.assertRaises(vault.VaultPolicyError):
            vault.migrate_legacy_vault_to_keyring(
                legacy,
                PASSWORD,
                updated_utc="2026-08-12T07:59:59Z",
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )

    def test_migration_revision_rollback_is_rejected_before_password_kdf(self):
        legacy = make_legacy_vault()
        with mock.patch.object(vault, "_derive_kek") as derive:
            with self.assertRaises(vault.VaultPolicyError):
                vault.migrate_legacy_vault_to_keyring(
                    legacy,
                    PASSWORD,
                    minimum_revision=2,
                )
        derive.assert_not_called()

    def test_keyring_password_rewrap_keeps_keys_and_changes_revision(self):
        original = make_keyring_vault()
        parsed, ring = vault.unlock_keyring_vault(original, PASSWORD)
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.rewrap_keyring_vault(
                original,
                WRONG_PASSWORD,
                NEW_PASSWORD,
                updated_utc=ROTATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
        changed = vault.rewrap_keyring_vault(
            original,
            PASSWORD,
            NEW_PASSWORD,
            updated_utc=ROTATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_keyring_vault(changed, PASSWORD)
        changed_parsed, changed_ring = vault.unlock_keyring_vault(
            changed, NEW_PASSWORD, minimum_revision=2
        )
        self.assertEqual(changed_parsed.header.revision, 2)
        self.assertNotEqual(changed_parsed.header.salt, parsed.header.salt)
        self.assertNotEqual(changed_parsed.header.nonce, parsed.header.nonce)
        self.assertEqual(
            keyring.encode_keyring(changed_ring), keyring.encode_keyring(ring)
        )

    def test_authenticated_malformed_keyring_payload_is_rejected(self):
        encoded = make_keyring_vault()
        parsed = vault.parse_vault(encoded)
        malformed = {
            "format": vault.VAULT_PAYLOAD_NAME,
            "revision": parsed.header.revision,
            "vault_id": vault._b64encode(parsed.header.vault_id),
            "version": vault.VAULT_KEYRING_PAYLOAD_SCHEMA,
        }
        changed_header = replace(parsed.header, nonce=os.urandom(12))
        forged = vault._seal_payload(
            changed_header,
            canonical(malformed),
            PASSWORD,
            policy=vault.DEFAULT_VAULT_KDF_POLICY,
        )
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_keyring_vault(forged, PASSWORD)

    def test_unknown_payload_schema_is_rejected_before_kdf(self):
        encoded = make_keyring_vault()
        fields, header, ciphertext = split_encoded(encoded)
        mapping = json.loads(header)
        mapping["payload_schema"] = 3
        changed = rebuild(fields, canonical(mapping), ciphertext)
        with mock.patch.object(vault, "_derive_kek") as derive:
            with self.assertRaises(vault.VaultUnsupportedVersionError):
                vault.parse_vault(changed)
        derive.assert_not_called()


class KeyringSessionAndStorageTests(unittest.TestCase):
    def make_session(self):
        clock = FakeClock()
        session = vault.VaultSession(
            make_keyring_vault(), inactivity_timeout=10, clock=clock
        )
        session.unlock(PASSWORD)
        return session, clock

    def test_session_exposes_keyring_not_legacy_root(self):
        session, _ = self.make_session()
        try:
            self.assertEqual(session.keyring_copy(), initial_keyring())
            with self.assertRaises(vault.VaultMigrationRequiredError):
                session.root_key_copy()
            session.lock()
            with self.assertRaises(vault.VaultStateError):
                session.keyring_copy()
        finally:
            session.close()

    def test_legacy_session_requires_explicit_migration_for_keyring(self):
        session = vault.VaultSession(make_legacy_vault())
        try:
            session.unlock(PASSWORD)
            with self.assertRaises(vault.VaultMigrationRequiredError):
                session.keyring_copy()
            self.assertEqual(session.root_key_copy(), KEY_ONE)
        finally:
            session.close()

    def test_session_rotation_verifies_password_and_advances_both_versions(self):
        session, _ = self.make_session()
        try:
            before = session.encoded
            with mock.patch.object(keyring, "_random_key", return_value=KEY_TWO):
                changed = session.rotate_keyring(
                    PASSWORD,
                    rotated_utc=ROTATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
            ring = session.keyring_copy()
            self.assertNotEqual(changed, before)
            self.assertEqual(session.revision, 2)
            self.assertEqual(ring.active_key_version, 2)
            self.assertEqual(ring.keys[0].wrapping_key, KEY_ONE)
            self.assertEqual(ring.keys[1].wrapping_key, KEY_TWO)
        finally:
            session.close()

    def test_wrong_rotation_password_never_mutates_session(self):
        session, _ = self.make_session()
        try:
            before = session.encoded
            before_ring = keyring.encode_keyring(session.keyring_copy())
            with self.assertRaises(vault.VaultAuthenticationError):
                session.rotate_keyring(
                    WRONG_PASSWORD,
                    rotated_utc=ROTATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
            self.assertEqual(session.encoded, before)
            self.assertEqual(session.revision, 1)
            self.assertEqual(
                keyring.encode_keyring(session.keyring_copy()), before_ring
            )
            self.assertIs(session.state, vault.VaultSessionState.UNLOCKED)
        finally:
            session.close()

    def test_rotation_fault_or_clock_rollback_never_mutates_session(self):
        session, _ = self.make_session()
        try:
            before = session.encoded
            before_ring = keyring.encode_keyring(session.keyring_copy())
            with mock.patch.object(
                vault,
                "_rewrap_keyring_vault",
                side_effect=vault.VaultError("injected rotation fault"),
            ):
                with mock.patch.object(
                    keyring, "_random_key", return_value=KEY_TWO
                ):
                    with self.assertRaises(vault.VaultError):
                        session.rotate_keyring(
                            PASSWORD,
                            rotated_utc=ROTATED,
                            time_cost=1,
                            memory_kib=8192,
                            parallelism=1,
                        )
            self.assertEqual(session.encoded, before)
            self.assertEqual(
                keyring.encode_keyring(session.keyring_copy()), before_ring
            )
            with self.assertRaises(keyring.VaultKeyringPolicyError):
                session.rotate_keyring(
                    PASSWORD,
                    rotated_utc="2026-08-12T07:59:59Z",
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
            self.assertEqual(session.encoded, before)
            self.assertIs(session.state, vault.VaultSessionState.UNLOCKED)
        finally:
            session.close()

    def test_keyring_session_clock_rollback_fails_closed(self):
        session, clock = self.make_session()
        try:
            clock.value = 99.0
            with self.assertRaises(vault.VaultStateError):
                session.check_inactivity()
            self.assertIs(session.state, vault.VaultSessionState.FAILED)
            with self.assertRaises(vault.VaultStateError):
                session.keyring_copy()
        finally:
            session.close()

    def test_keyring_session_password_change_and_timeout(self):
        session, clock = self.make_session()
        try:
            changed = session.change_password(
                NEW_PASSWORD,
                updated_utc=ROTATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            self.assertEqual(session.revision, 2)
            _, ring = vault.unlock_keyring_vault(changed, NEW_PASSWORD)
            self.assertEqual(ring, initial_keyring())
            clock.value = 110.0
            self.assertTrue(session.check_inactivity())
            with self.assertRaises(vault.VaultStateError):
                session.keyring_copy()
        finally:
            session.close()

    def test_storage_publishes_rotation_as_next_immutable_generation(self):
        parent_context = tempfile.TemporaryDirectory(
            prefix="mokosh-stage2-3-storage-"
        )
        parent = Path(parent_context.name)
        os.chmod(parent, 0o700)
        store = storage.VaultStorage.create(parent / "vault")
        session, _ = self.make_session()
        try:
            first = store.publish(session)
            first_bytes = store.verify_receipt(first)
            with mock.patch.object(keyring, "_random_key", return_value=KEY_TWO):
                session.rotate_keyring(
                    PASSWORD,
                    rotated_utc=ROTATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
            second = store.publish(session, previous=first)
            self.assertEqual(second.revision, 2)
            self.assertEqual(store.verify_receipt(first), first_bytes)
            self.assertEqual(store.verify_receipt(second), session.encoded)
        finally:
            session.close()
            store.close()
            parent_context.cleanup()


class KeyringContractTests(unittest.TestCase):
    def test_module_has_no_path_network_logging_or_deletion_calls(self):
        source = inspect.getsource(keyring)
        tree = ast.parse(source)
        forbidden = {
            "open",
            "unlink",
            "remove",
            "rename",
            "replace",
            "mkdir",
            "makedirs",
            "rmdir",
            "socket",
            "urlopen",
            "print",
        }
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in forbidden:
                found.add(node.func.id)
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id
                in {"os", "pathlib", "requests", "shutil", "socket", "urllib"}
            ):
                found.add(node.func.attr)
        self.assertEqual(found, set())

    def test_keyring_schema_contains_no_password_path_or_contact_fields(self):
        fields = set(keyring.VaultKeyring.__dataclass_fields__)
        record_fields = set(keyring.VaultKeyRecord.__dataclass_fields__)
        for forbidden in {
            "password",
            "path",
            "filename",
            "contact",
            "recipient",
        }:
            self.assertNotIn(forbidden, fields)
            self.assertNotIn(forbidden, record_fields)


if __name__ == "__main__":
    unittest.main()
