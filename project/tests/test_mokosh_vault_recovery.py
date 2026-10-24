import ast
import copy
import hashlib
import inspect
import json
import pickle
import unittest
from dataclasses import replace
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_recovery as recovery


PASSWORD = "Stage 2.4 correct password"
NEW_PASSWORD = "Stage 2.4 new password"
VAULT_ID = bytes(range(16))
OTHER_VAULT_ID = bytes(range(16, 32))
KEY_ONE = b"K" * 32
KEY_TWO = b"L" * 32
RECOVERY_KEY = b"R" * 32
RECOVERY_ID = b"I" * 16
RECOVERY_NONCE = b"N" * 12
CREATED = "2026-08-13T08:00:00Z"
RECOVERY_CREATED = "2026-08-13T09:00:00Z"
UPDATED = "2026-08-13T10:00:00Z"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def initial_keyring(material=KEY_ONE):
    record = keyring.VaultKeyRecord(
        key_version=1,
        state=keyring.KEY_STATE_ACTIVE,
        created_utc=CREATED,
        retired_utc=None,
        wrapping_key=material,
    )
    result = keyring.VaultKeyring(active_key_version=1, keys=(record,))
    keyring.validate_keyring(result)
    return result


def make_encoded_vault(*, vault_id=VAULT_ID, material=KEY_ONE, password=PASSWORD):
    def exact_random(length, field):
        values = {"salt": b"S" * 16, "nonce": b"V" * 12}
        result = values[field]
        if len(result) != length:
            raise AssertionError("test random length mismatch")
        return result

    with mock.patch.object(vault, "_random_exact", side_effect=exact_random):
        return vault.create_keyring_vault(
            password,
            keyring=initial_keyring(material),
            vault_id=vault_id,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )


def make_legacy_vault():
    return vault.create_vault(
        PASSWORD,
        root_key=KEY_ONE,
        vault_id=VAULT_ID,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


def make_session(*, vault_id=VAULT_ID, material=KEY_ONE):
    session = vault.VaultSession(make_encoded_vault(vault_id=vault_id, material=material))
    session.unlock(PASSWORD)
    return session


def make_setup(session=None):
    owned = session is None
    exact_session = session or make_session()
    try:
        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
        ):
            return recovery.create_recovery_record(
                exact_session, created_utc=RECOVERY_CREATED
            )
    finally:
        if owned:
            exact_session.close()


def split_record(encoded):
    fields = list(
        recovery.RECOVERY_PREAMBLE_STRUCT.unpack(
            encoded[: recovery.RECOVERY_PREAMBLE_LEN]
        )
    )
    start = recovery.RECOVERY_PREAMBLE_LEN
    end = start + fields[4]
    return fields, encoded[start:end], encoded[end:]


def rebuild_record(fields, header, ciphertext):
    exact = list(fields)
    exact[4] = len(header)
    exact[5] = len(ciphertext)
    return recovery.RECOVERY_PREAMBLE_STRUCT.pack(*exact) + header + ciphertext


def rewrite_payload(setup, transform):
    parsed = recovery.parse_recovery_record(setup.record)
    aead_key = recovery._derive_aead_key(
        setup.recovery_key, parsed.recovery_id, parsed.vault_id
    )
    old_aad = (
        recovery.RECOVERY_AAD_DOMAIN
        + parsed.preamble_bytes
        + parsed.header_bytes
    )
    plaintext = AESGCM(aead_key).decrypt(
        parsed.nonce, parsed.ciphertext, old_aad
    )
    changed = transform(plaintext)
    fields = list(
        recovery.RECOVERY_PREAMBLE_STRUCT.unpack(parsed.preamble_bytes)
    )
    fields[5] = len(changed) + recovery.RECOVERY_GCM_TAG_LEN
    preamble = recovery.RECOVERY_PREAMBLE_STRUCT.pack(*fields)
    new_aad = recovery.RECOVERY_AAD_DOMAIN + preamble + parsed.header_bytes
    ciphertext = AESGCM(aead_key).encrypt(parsed.nonce, changed, new_aad)
    return preamble + parsed.header_bytes + ciphertext


class RecoveryRoundTripTests(unittest.TestCase):
    def test_setup_and_rehearsal_bind_exact_vault_and_keyring(self):
        session = make_session()
        original = session.encoded
        try:
            setup = make_setup(session)
            parsed = recovery.parse_recovery_record(setup.record)
            result = recovery.rehearse_recovery(
                setup.record, setup.recovery_key, original
            )
            self.assertEqual(parsed.vault_id, VAULT_ID)
            self.assertEqual(parsed.source_revision, 1)
            self.assertEqual(
                parsed.source_vault_sha256, hashlib.sha256(original).digest()
            )
            self.assertEqual(result.recovery_id, RECOVERY_ID)
            self.assertEqual(result.active_key_version, 1)
            self.assertEqual(result.key_count, 1)
            self.assertEqual(
                result.keyring_sha256,
                hashlib.sha256(keyring.encode_keyring(initial_keyring())).digest(),
            )
            self.assertEqual(session.encoded, original)
            self.assertIs(session.state, vault.VaultSessionState.UNLOCKED)
        finally:
            session.close()

    def test_setup_secret_is_independent_and_not_rendered_or_serialized(self):
        setup = make_setup()
        self.assertEqual(setup.recovery_key, RECOVERY_KEY)
        self.assertNotEqual(setup.recovery_key, KEY_ONE)
        rendered = repr(setup)
        self.assertNotIn(RECOVERY_KEY.hex(), rendered)
        self.assertNotIn(KEY_ONE.hex(), rendered)
        with self.assertRaises(TypeError):
            copy.copy(setup)
        with self.assertRaises(TypeError):
            copy.deepcopy(setup)
        with self.assertRaises(TypeError):
            pickle.dumps(setup)

    def test_rehearsal_result_contains_no_recovered_secret(self):
        setup = make_setup()
        result = recovery.rehearse_recovery(
            setup.record, setup.recovery_key, make_encoded_vault()
        )
        fields = set(result.__dataclass_fields__)
        self.assertFalse(
            fields
            & {
                "keyring",
                "wrapping_key",
                "recovery_key",
                "password",
                "plaintext",
                "ciphertext",
            }
        )
        self.assertNotIn(KEY_ONE.hex(), repr(result))
        self.assertNotIn(RECOVERY_KEY.hex(), repr(result))

    def test_fresh_setup_uses_fresh_root_identifier_and_nonce(self):
        session = make_session()
        try:
            first = make_setup(session)
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"S" * 32, b"J" * 16, b"O" * 12],
            ):
                second = recovery.create_recovery_record(
                    session, created_utc=RECOVERY_CREATED
                )
            self.assertNotEqual(first.recovery_key, second.recovery_key)
            self.assertNotEqual(first.recovery_id, second.recovery_id)
            self.assertNotEqual(
                recovery.parse_recovery_record(first.record).nonce,
                recovery.parse_recovery_record(second.record).nonce,
            )
            self.assertNotEqual(first.record, second.record)
        finally:
            session.close()


class RecoveryFormatTests(unittest.TestCase):
    def test_exact_preamble_header_and_payload_algorithms(self):
        setup = make_setup()
        fields, header, _ = split_record(setup.record)
        mapping = json.loads(header)
        self.assertEqual(fields[0], recovery.RECOVERY_MAGIC)
        self.assertEqual(mapping["format"], recovery.RECOVERY_FORMAT_NAME)
        self.assertEqual(mapping["purpose"], recovery.RECOVERY_PURPOSE)
        self.assertEqual(mapping["kdf"]["algorithm"], "HKDF-SHA-256")
        self.assertEqual(mapping["aead"]["algorithm"], "AES-256-GCM")

    def test_wrong_magic_version_flags_truncation_and_trailing_are_rejected(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        cases = []
        for index, value in ((0, b"BADMAGIC"), (1, 2), (2, 1), (3, 1)):
            changed = fields.copy()
            changed[index] = value
            cases.append(rebuild_record(changed, header, ciphertext))
        cases.extend((setup.record[:10], setup.record[:-1], setup.record + b"x"))
        for changed in cases:
            with self.subTest(length=len(changed)):
                with self.assertRaises(recovery.VaultRecoveryFormatError):
                    recovery.parse_recovery_record(changed)

    def test_declared_lengths_are_bounded_before_json_or_crypto(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        for index, value in (
            (4, 0),
            (4, recovery.MAX_RECOVERY_HEADER_LEN + 1),
            (5, recovery.RECOVERY_GCM_TAG_LEN),
            (5, recovery.MAX_RECOVERY_CIPHERTEXT_LEN + 1),
        ):
            changed = fields.copy()
            changed[index] = value
            with self.subTest(index=index, value=value):
                with self.assertRaises(recovery.VaultRecoveryFormatError):
                    recovery.parse_recovery_record(
                        recovery.RECOVERY_PREAMBLE_STRUCT.pack(*changed)
                        + header
                        + ciphertext
                    )

    def test_duplicate_missing_unknown_and_noncanonical_header_are_rejected(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        duplicate = header[:-1] + b',"version":1}'
        mapping = json.loads(header)
        missing = dict(mapping)
        del missing["purpose"]
        unknown = dict(mapping)
        unknown["future"] = 1
        noncanonical = json.dumps(mapping, indent=1).encode("ascii")
        cases = (
            rebuild_record(fields, duplicate, ciphertext),
            rebuild_record(fields, canonical(missing), ciphertext),
            rebuild_record(fields, canonical(unknown), ciphertext),
            rebuild_record(fields, noncanonical, ciphertext),
        )
        for changed in cases:
            with self.subTest(length=len(changed)):
                with self.assertRaises(recovery.VaultRecoveryFormatError):
                    recovery.parse_recovery_record(changed)

    def test_boolean_revision_bad_base64_timestamp_and_algorithm_are_rejected(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        original = json.loads(header)
        cases = []
        for field, value in (
            ("source_revision", True),
            ("vault_id", "AA"),
            ("recovery_id", original["recovery_id"] + "="),
            ("source_vault_sha256", "AA"),
            ("created_utc", "2026-02-30T00:00:00Z"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        bad_kdf = copy.deepcopy(original)
        bad_kdf["kdf"]["algorithm"] = "Argon2id"
        cases.append(bad_kdf)
        bad_aead = copy.deepcopy(original)
        bad_aead["aead"]["algorithm"] = "AES-CTR"
        cases.append(bad_aead)
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(recovery.VaultRecoveryError):
                    recovery.parse_recovery_record(
                        rebuild_record(fields, canonical(changed), ciphertext)
                    )

    def test_unsupported_header_is_rejected_before_hkdf(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        mapping = json.loads(header)
        mapping["kdf"]["algorithm"] = "OTHER"
        changed = rebuild_record(fields, canonical(mapping), ciphertext)
        with mock.patch.object(recovery, "HKDF") as kdf:
            with self.assertRaises(recovery.VaultRecoveryUnsupportedVersionError):
                recovery.rehearse_recovery(
                    changed, setup.recovery_key, make_encoded_vault()
                )
            kdf.assert_not_called()


class RecoveryAuthenticationTests(unittest.TestCase):
    def test_wrong_key_and_ciphertext_tamper_fail_generically(self):
        setup = make_setup()
        tampered = bytearray(setup.record)
        tampered[-1] ^= 1
        current = make_encoded_vault()
        for record, secret in (
            (setup.record, b"W" * 32),
            (bytes(tampered), setup.recovery_key),
        ):
            with self.subTest(tampered=record != setup.record):
                with self.assertRaises(recovery.VaultRecoveryAuthenticationError):
                    recovery.rehearse_recovery(record, secret, current)

    def test_header_tamper_is_authenticated(self):
        setup = make_setup()
        fields, header, ciphertext = split_record(setup.record)
        mapping = json.loads(header)
        mapping["created_utc"] = UPDATED
        changed = rebuild_record(fields, canonical(mapping), ciphertext)
        with self.assertRaises(recovery.VaultRecoveryAuthenticationError):
            recovery.rehearse_recovery(
                changed, setup.recovery_key, make_encoded_vault()
            )

    def test_authenticated_duplicate_or_malformed_payload_is_rejected(self):
        setup = make_setup()

        def duplicate(data):
            return data[:-1] + b',"version":1}'

        def unknown(data):
            mapping = json.loads(data)
            mapping["future"] = 1
            return canonical(mapping)

        def noncanonical(data):
            return json.dumps(json.loads(data), indent=1).encode("ascii")

        for transform in (duplicate, unknown, noncanonical):
            changed = rewrite_payload(setup, transform)
            with self.subTest(transform=transform.__name__):
                with self.assertRaises(recovery.VaultRecoveryAuthenticationError):
                    recovery.rehearse_recovery(
                        changed, setup.recovery_key, make_encoded_vault()
                    )

    def test_authenticated_keyring_digest_and_metadata_mismatch_are_rejected(self):
        setup = make_setup()

        def bad_digest(data):
            mapping = json.loads(data)
            mapping["keyring_sha256"] = recovery._b64encode(b"D" * 32)
            return canonical(mapping)

        def bad_revision(data):
            mapping = json.loads(data)
            mapping["source_revision"] = 2
            return canonical(mapping)

        def duplicate_key_material(data):
            mapping = json.loads(data)
            record = copy.deepcopy(mapping["keyring"]["keys"][0])
            record["state"] = "active"
            record["key_version"] = 2
            mapping["keyring"]["keys"][0]["state"] = "retired"
            mapping["keyring"]["keys"][0]["retired_utc"] = RECOVERY_CREATED
            record["created_utc"] = RECOVERY_CREATED
            mapping["keyring"]["keys"].append(record)
            mapping["keyring"]["active_key_version"] = 2
            mapping["keyring_sha256"] = recovery._b64encode(
                hashlib.sha256(canonical(mapping["keyring"])).digest()
            )
            return canonical(mapping)

        for transform in (bad_digest, bad_revision, duplicate_key_material):
            changed = rewrite_payload(setup, transform)
            with self.subTest(transform=transform.__name__):
                with self.assertRaises(recovery.VaultRecoveryAuthenticationError):
                    recovery.rehearse_recovery(
                        changed, setup.recovery_key, make_encoded_vault()
                    )

    def test_recovery_key_type_and_length_are_exact(self):
        setup = make_setup()
        current = make_encoded_vault()
        for value in (None, "secret", b"", b"R" * 31, b"R" * 33):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(recovery.VaultRecoveryFormatError):
                    recovery.rehearse_recovery(setup.record, value, current)


class RecoveryPolicyTests(unittest.TestCase):
    def test_setup_requires_unlocked_schema_two_session(self):
        locked = vault.VaultSession(make_encoded_vault())
        legacy = vault.VaultSession(make_legacy_vault())
        legacy.unlock(PASSWORD)
        try:
            for candidate in (object(), locked, legacy):
                with self.subTest(candidate=type(candidate).__name__):
                    with self.assertRaises(recovery.VaultRecoveryError):
                        recovery.create_recovery_record(
                            candidate, created_utc=RECOVERY_CREATED
                        )
        finally:
            locked.close()
            legacy.close()

    def test_setup_timestamp_cannot_precede_vault_update(self):
        session = make_session()
        try:
            with self.assertRaises(recovery.VaultRecoveryPolicyError):
                recovery.create_recovery_record(
                    session, created_utc="2026-08-13T07:59:59Z"
                )
        finally:
            session.close()

    def test_setup_rejects_reused_vault_key_material(self):
        session = make_session()
        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[KEY_ONE, RECOVERY_ID, RECOVERY_NONCE],
            ):
                with self.assertRaises(recovery.VaultRecoveryPolicyError):
                    recovery.create_recovery_record(
                        session, created_utc=RECOVERY_CREATED
                    )
        finally:
            session.close()

    def test_stale_record_is_rejected_after_password_rewrap(self):
        session = make_session()
        try:
            setup = make_setup(session)
            newer = session.change_password(
                NEW_PASSWORD,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            with self.assertRaises(recovery.VaultRecoveryStaleError):
                recovery.rehearse_recovery(
                    setup.record, setup.recovery_key, newer
                )
        finally:
            session.close()

    def test_key_rotation_makes_the_previous_recovery_record_stale(self):
        session = make_session()
        try:
            setup = make_setup(session)
            with mock.patch.object(keyring, "_random_key", return_value=KEY_TWO):
                newer = session.rotate_keyring(
                    PASSWORD,
                    rotated_utc=UPDATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
            with self.assertRaises(recovery.VaultRecoveryStaleError):
                recovery.rehearse_recovery(
                    setup.record, setup.recovery_key, newer
                )
        finally:
            session.close()

    def test_newer_record_rejects_rolled_back_current_vault(self):
        session = make_session()
        original = session.encoded
        try:
            session.change_password(
                NEW_PASSWORD,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
            ):
                setup = recovery.create_recovery_record(
                    session, created_utc=UPDATED
                )
            with self.assertRaises(recovery.VaultRecoveryRollbackError):
                recovery.rehearse_recovery(
                    setup.record, setup.recovery_key, original
                )
        finally:
            session.close()

    def test_mixed_vault_and_same_revision_conflict_are_distinct(self):
        setup = make_setup()
        with self.assertRaises(recovery.VaultRecoveryMixedVaultError):
            recovery.rehearse_recovery(
                setup.record,
                setup.recovery_key,
                make_encoded_vault(vault_id=OTHER_VAULT_ID),
            )
        with self.assertRaises(recovery.VaultRecoveryConflictError):
            recovery.rehearse_recovery(
                setup.record,
                setup.recovery_key,
                make_encoded_vault(material=KEY_TWO),
            )

    def test_duplicate_and_mixed_candidate_sets_are_rejected(self):
        first = make_setup()
        session = make_session()
        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"S" * 32, b"J" * 16, b"O" * 12],
            ):
                second = recovery.create_recovery_record(
                    session, created_utc=RECOVERY_CREATED
                )
        finally:
            session.close()
        accepted = recovery.validate_recovery_record_set(
            (first.record, second.record)
        )
        self.assertEqual(len(accepted), 2)
        with self.assertRaises(recovery.VaultRecoveryDuplicateRecordError):
            recovery.validate_recovery_record_set((first.record, first.record))

        other_session = make_session(vault_id=OTHER_VAULT_ID)
        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"T" * 32, b"Q" * 16, b"P" * 12],
            ):
                other = recovery.create_recovery_record(
                    other_session, created_utc=RECOVERY_CREATED
                )
        finally:
            other_session.close()
        with self.assertRaises(recovery.VaultRecoveryMixedVaultError):
            recovery.validate_recovery_record_set((first.record, other.record))

    def test_candidate_set_rejects_mixed_revisions_of_the_same_vault(self):
        session = make_session()
        try:
            first = make_setup(session)
            session.change_password(
                NEW_PASSWORD,
                updated_utc=UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            )
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"T" * 32, b"Q" * 16, b"P" * 12],
            ):
                second = recovery.create_recovery_record(
                    session, created_utc=UPDATED
                )
            with self.assertRaises(recovery.VaultRecoveryConflictError):
                recovery.validate_recovery_record_set(
                    (first.record, second.record)
                )
        finally:
            session.close()

    def test_candidate_set_is_exact_bounded_tuple(self):
        setup = make_setup()
        for value in ([], (), (setup.record,) * (recovery.MAX_RECOVERY_RECORDS + 1)):
            with self.subTest(length=len(value)):
                with self.assertRaises(recovery.VaultRecoveryPolicyError):
                    recovery.validate_recovery_record_set(value)

    def test_legacy_current_vault_is_not_recovery_compatible(self):
        setup = make_setup()
        with self.assertRaises(recovery.VaultRecoveryUnsupportedVersionError):
            recovery.rehearse_recovery(
                setup.record, setup.recovery_key, make_legacy_vault()
            )

    def test_random_and_encrypt_faults_never_change_session(self):
        session = make_session()
        original = session.encoded
        try:
            with mock.patch.object(recovery.os, "urandom", return_value=b"bad"):
                with self.assertRaises(recovery.VaultRecoveryPolicyError):
                    recovery.create_recovery_record(
                        session, created_utc=RECOVERY_CREATED
                    )
            self.assertEqual(session.encoded, original)
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
            ), mock.patch.object(
                recovery.AESGCM, "encrypt", side_effect=RuntimeError("fault")
            ):
                with self.assertRaises(RuntimeError):
                    recovery.create_recovery_record(
                        session, created_utc=RECOVERY_CREATED
                    )
            self.assertEqual(session.encoded, original)
            self.assertIs(session.state, vault.VaultSessionState.UNLOCKED)
        finally:
            session.close()

    def test_expired_session_fails_closed_before_random_generation(self):
        clock = mock.Mock(return_value=100.0)
        session = vault.VaultSession(
            make_encoded_vault(), inactivity_timeout=1.0, clock=clock
        )
        session.unlock(PASSWORD)
        clock.return_value = 101.0
        try:
            with mock.patch.object(recovery.os, "urandom") as random_source:
                with self.assertRaises(recovery.VaultRecoveryStateError):
                    recovery.create_recovery_record(
                        session, created_utc=RECOVERY_CREATED
                    )
                random_source.assert_not_called()
            self.assertIs(session.state, vault.VaultSessionState.LOCKED)
        finally:
            session.close()

    def test_session_expiry_during_setup_returns_no_recovery_material(self):
        clock_value = {"value": 100.0}
        session = vault.VaultSession(
            make_encoded_vault(),
            inactivity_timeout=1.0,
            clock=lambda: clock_value["value"],
        )
        session.unlock(PASSWORD)
        real_encrypt = recovery.AESGCM.encrypt

        def encrypt_then_expire(aead, *args, **kwargs):
            result = real_encrypt(aead, *args, **kwargs)
            clock_value["value"] = 101.0
            return result

        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
            ), mock.patch.object(
                recovery.AESGCM, "encrypt", new=encrypt_then_expire
            ):
                with self.assertRaises(recovery.VaultRecoveryStateError):
                    recovery.create_recovery_record(
                        session, created_utc=RECOVERY_CREATED
                    )
            self.assertIs(session.state, vault.VaultSessionState.LOCKED)
        finally:
            session.close()


class RecoveryScopeTests(unittest.TestCase):
    def test_module_has_no_filesystem_network_logging_publish_or_deletion(self):
        source = inspect.getsource(recovery)
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
            "publish",
        }
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in forbidden:
                found.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden:
                found.add(node.func.attr)
        self.assertEqual(found, set())
        self.assertNotIn("mokosh_vault_storage", source)

    def test_public_contract_has_no_password_path_contact_licensing_or_gui(self):
        for value in (
            recovery.ParsedVaultRecoveryRecord,
            recovery.VaultRecoverySetup,
            recovery.VaultRecoveryRehearsal,
        ):
            fields = set(value.__dataclass_fields__)
            for forbidden in {
                "password",
                "path",
                "filename",
                "contact",
                "license",
                "gui",
            }:
                self.assertNotIn(forbidden, fields)
        parameters = set(
            inspect.signature(recovery.create_recovery_record).parameters
        )
        self.assertNotIn("password", parameters)

    def test_rehearsal_is_in_memory_and_leaves_exact_inputs_unchanged(self):
        setup = make_setup()
        record = bytes(setup.record)
        current = make_encoded_vault()
        current_copy = bytes(current)
        recovery.rehearse_recovery(record, setup.recovery_key, current)
        self.assertEqual(record, setup.record)
        self.assertEqual(current, current_copy)


if __name__ == "__main__":
    unittest.main()
