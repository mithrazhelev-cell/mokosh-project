import ast
import copy
import hashlib
import inspect
import os
import pickle
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest import mock

import mokosh_vault_format as vault
import mokosh_vault_keyring as keyring
import mokosh_vault_recovery as recovery
import mokosh_vault_recovery_candidate as candidate
import mokosh_vault_recovery_storage as recovery_storage
import mokosh_vault_storage as vault_storage


OLD_PASSWORD = "Stage 2.6 old password"
NEW_PASSWORD = "Stage 2.6 explicit new password"
WRONG_PASSWORD = "Stage 2.6 wrong password"
VAULT_ID = bytes(range(16))
OTHER_VAULT_ID = bytes(range(16, 32))
KEY_ONE = b"K" * 32
KEY_TWO = b"L" * 32
RECOVERY_KEY = b"R" * 32
RECOVERY_ID = b"I" * 16
RECOVERY_NONCE = b"N" * 12
CANDIDATE_SALT = b"S" * 16
CANDIDATE_NONCE = b"C" * 12
AUTHORIZATION_ID = "41" * 16
CREATED = "2026-08-13T08:00:00Z"
RECOVERY_CREATED = "2026-08-13T09:00:00Z"
CANDIDATE_UPDATED = "2026-08-13T10:00:00Z"
LATER = "2026-08-13T11:00:00Z"


def initial_keyring(*, vault_key=KEY_ONE):
    record = keyring.VaultKeyRecord(
        key_version=1,
        state=keyring.KEY_STATE_ACTIVE,
        created_utc=CREATED,
        retired_utc=None,
        wrapping_key=vault_key,
    )
    result = keyring.VaultKeyring(active_key_version=1, keys=(record,))
    keyring.validate_keyring(result)
    return result


def make_session(*, vault_id=VAULT_ID, vault_key=KEY_ONE):
    encoded = vault.create_keyring_vault(
        OLD_PASSWORD,
        keyring=initial_keyring(vault_key=vault_key),
        vault_id=vault_id,
        created_utc=CREATED,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )
    session = vault.VaultSession(encoded)
    session.unlock(OLD_PASSWORD)
    return session


def exact_candidate_random(length, field):
    values = {"salt": CANDIDATE_SALT, "nonce": CANDIDATE_NONCE}
    result = values[field]
    if len(result) != length:
        raise AssertionError("test random length mismatch")
    return result


class RecoveryCandidateTestCase(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(
            prefix="mokosh-recovery-candidate-test-"
        )
        self.parent = Path(self.context.name)
        os.chmod(self.parent, 0o700)
        self.vault_path = self.parent / "vault"
        self.recovery_directory = self.parent / "offline-recovery"
        self.recovery_directory.mkdir(mode=0o700)
        os.chmod(self.recovery_directory, 0o700)
        self.store = vault_storage.VaultStorage.create(self.vault_path)
        self.session = make_session()
        self.receipt = self.store.publish(self.session)
        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[RECOVERY_KEY, RECOVERY_ID, RECOVERY_NONCE],
        ):
            self.setup = recovery_storage.prepare_recovery_export(
                self.store,
                self.receipt,
                self.session,
                created_utc=RECOVERY_CREATED,
            )
        self.export_receipt = recovery_storage.export_recovery_record(
            self.setup,
            self.store,
            self.receipt,
            self.recovery_directory,
        )
        self.recovery_path = self.recovery_directory / (
            recovery_storage.recovery_record_name(RECOVERY_ID)
        )

    def tearDown(self):
        self.session.close()
        self.store.close()
        self.context.cleanup()

    def prepare(self, **overrides):
        values = {
            "recovery_path": self.recovery_path,
            "recovery_key": RECOVERY_KEY,
            "storage": self.store,
            "latest": self.receipt,
            "new_password": NEW_PASSWORD,
            "decision": candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
            "updated_utc": CANDIDATE_UPDATED,
            "time_cost": 1,
            "memory_kib": 8192,
            "parallelism": 1,
        }
        values.update(overrides)
        with mock.patch.object(
            vault,
            "_random_exact",
            side_effect=exact_candidate_random,
        ), mock.patch.object(
            candidate,
            "_new_authorization_id",
            return_value=AUTHORIZATION_ID,
        ):
            return candidate.prepare_recovery_candidate(**values)

    def snapshot(self):
        result = {}
        for root in (self.vault_path, self.recovery_directory):
            for path in sorted(root.iterdir()):
                info = path.stat(follow_symlinks=False)
                result[str(path)] = (
                    path.read_bytes() if path.is_file() else None,
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                )
        return result

    def write_setup(self, setup, directory_name):
        directory = self.parent / directory_name
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
        path = directory / recovery_storage.recovery_record_name(
            setup.recovery_id
        )
        path.write_bytes(setup.record)
        os.chmod(path, 0o600)
        return path


class RecoveryCandidateRoundTripTests(RecoveryCandidateTestCase):
    def test_candidate_is_exact_next_revision_with_same_vault_and_keyring(self):
        prepared = self.prepare()
        evidence = prepared.evidence
        claimed = prepared.claim_once()
        parsed, recovered = vault.unlock_keyring_vault(
            claimed.candidate,
            NEW_PASSWORD,
            minimum_revision=2,
        )
        self.assertEqual(evidence.source_revision, 1)
        self.assertEqual(evidence.target_revision, 2)
        self.assertEqual(parsed.header.vault_id, VAULT_ID)
        self.assertEqual(parsed.header.revision, 2)
        self.assertEqual(parsed.header.created_utc, CREATED)
        self.assertEqual(parsed.header.updated_utc, CANDIDATE_UPDATED)
        self.assertEqual(parsed.header.payload_schema, 2)
        self.assertEqual(parsed.header.salt, CANDIDATE_SALT)
        self.assertEqual(parsed.header.nonce, CANDIDATE_NONCE)
        self.assertEqual(
            keyring.encode_keyring(recovered),
            keyring.encode_keyring(initial_keyring()),
        )

    def test_new_password_opens_candidate_and_old_password_does_not(self):
        claimed = self.prepare().claim_once()
        vault.unlock_keyring_vault(claimed.candidate, NEW_PASSWORD)
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.unlock_keyring_vault(claimed.candidate, OLD_PASSWORD)

    def test_candidate_preserves_retired_and_active_key_history_exactly(self):
        self.session.rotate_keyring(
            OLD_PASSWORD,
            rotated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        second_receipt = self.store.publish(self.session, previous=self.receipt)
        self.receipt = second_receipt
        second_directory = self.parent / "second-recovery"
        second_directory.mkdir(mode=0o700)
        os.chmod(second_directory, 0o700)
        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[b"Q" * 32, b"J" * 16, b"O" * 12],
        ):
            setup = recovery_storage.prepare_recovery_export(
                self.store,
                self.receipt,
                self.session,
                created_utc=LATER,
            )
        recovery_storage.export_recovery_record(
            setup,
            self.store,
            self.receipt,
            second_directory,
        )
        path = second_directory / recovery_storage.recovery_record_name(
            setup.recovery_id
        )
        prepared = self.prepare(
            recovery_path=path,
            recovery_key=setup.recovery_key,
            updated_utc=LATER,
        )
        _, recovered = vault.unlock_keyring_vault(
            prepared.claim_once().candidate,
            NEW_PASSWORD,
        )
        expected = self.session.keyring_copy()
        self.assertEqual(keyring.encode_keyring(recovered), keyring.encode_keyring(expected))
        self.assertEqual(recovered.active_key_version, 2)
        self.assertEqual(len(recovered.keys), 2)

    def test_evidence_and_verifier_return_no_secret_material(self):
        prepared = self.prepare()
        claimed = prepared.claim_once()
        verified = candidate.verify_recovery_candidate(
            claimed.candidate,
            NEW_PASSWORD,
            claimed.evidence,
        )
        self.assertEqual(verified, claimed.evidence)
        evidence_fields = {item.name for item in fields(verified)}
        self.assertFalse(
            evidence_fields
            & {
                "candidate",
                "keyring",
                "wrapping_key",
                "recovery_key",
                "password",
                "plaintext",
            }
        )
        rendered = repr(verified) + repr(prepared) + repr(claimed)
        for secret in (KEY_ONE, RECOVERY_KEY):
            self.assertNotIn(secret.hex(), rendered)
        self.assertNotIn(NEW_PASSWORD, rendered)

    def test_prepared_candidate_is_process_local_and_claimed_once(self):
        prepared = self.prepare()
        self.assertFalse(prepared.claimed)
        for action in (
            lambda: copy.copy(prepared),
            lambda: copy.deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with self.subTest(action=action):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateAuthorizationError
                ):
                    action()
        claimed = prepared.claim_once()
        self.assertTrue(prepared.claimed)
        with self.assertRaises(
            candidate.VaultRecoveryCandidateAuthorizationError
        ):
            prepared.claim_once()
        for action in (
            lambda: copy.copy(claimed),
            lambda: copy.deepcopy(claimed),
            lambda: pickle.dumps(claimed),
        ):
            with self.subTest(claimed_action=action):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateAuthorizationError
                ):
                    action()

    def test_authorization_binds_every_nonsecret_candidate_fact(self):
        claimed = self.prepare().claim_once()
        authorization = claimed.authorization
        evidence = claimed.evidence
        self.assertEqual(authorization.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(
            authorization.format,
            candidate.RECOVERY_CANDIDATE_AUTHORIZATION_FORMAT,
        )
        self.assertEqual(
            authorization.version,
            candidate.RECOVERY_CANDIDATE_AUTHORIZATION_VERSION,
        )
        self.assertEqual(authorization.evidence, evidence)
        self.assertEqual(evidence.recovery_id, RECOVERY_ID)
        self.assertEqual(evidence.source_vault_sha256, self.receipt.sha256)
        self.assertEqual(evidence.record_sha256, self.export_receipt.record_sha256)
        self.assertEqual(
            evidence.candidate_sha256,
            hashlib.sha256(claimed.candidate).digest(),
        )
        self.assertEqual(
            (evidence.time_cost, evidence.memory_kib, evidence.parallelism),
            (1, 8192, 1),
        )
        self.assertTrue(authorization.user_confirmed)
        self.assertTrue(authorization.exact_sources_verified)
        self.assertTrue(authorization.candidate_verified)
        self.assertTrue(authorization.executor_rescan_required)
        self.assertTrue(authorization.single_use_claim)
        self.assertFalse(authorization.filesystem_publish_permitted)
        self.assertFalse(authorization.key_deletion_permitted)
        self.assertFalse(authorization.user_file_mutation_permitted)

    def test_preparation_reads_only_and_does_not_publish_candidate(self):
        before = self.snapshot()
        prepared = self.prepare()
        self.assertEqual(self.snapshot(), before)
        report = self.store.scan()
        self.assertEqual(report.generations, (self.receipt,))
        self.assertEqual(len(report.generations), 1)
        self.assertEqual(prepared.evidence.target_revision, 2)
        self.assertFalse((self.vault_path / vault_storage.generation_name(2)).exists())

    def test_separate_preparations_use_fresh_salt_nonce_and_authorization(self):
        first = self.prepare().claim_once()

        values = {
            "salt": b"T" * 16,
            "nonce": b"D" * 12,
        }

        def second_random(length, field):
            result = values[field]
            self.assertEqual(len(result), length)
            return result

        with mock.patch.object(vault, "_random_exact", side_effect=second_random), \
                mock.patch.object(candidate, "_new_authorization_id", return_value="42" * 16):
            second = candidate.prepare_recovery_candidate(
                self.recovery_path,
                RECOVERY_KEY,
                self.store,
                self.receipt,
                NEW_PASSWORD,
                candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
                updated_utc=CANDIDATE_UPDATED,
                time_cost=1,
                memory_kib=8192,
                parallelism=1,
            ).claim_once()
        first_header = vault.parse_vault(first.candidate).header
        second_header = vault.parse_vault(second.candidate).header
        self.assertNotEqual(first_header.salt, second_header.salt)
        self.assertNotEqual(first_header.nonce, second_header.nonce)
        self.assertNotEqual(first.candidate, second.candidate)
        self.assertNotEqual(
            first.authorization.authorization_id,
            second.authorization.authorization_id,
        )


class RecoveryCandidateInputRefusalTests(RecoveryCandidateTestCase):
    def test_preserve_and_non_enum_decisions_stop_before_any_source_access(self):
        for decision in (
            candidate.RecoveryCandidateDecision.PRESERVE,
            True,
            "authorize_candidate",
        ):
            with self.subTest(decision=decision), mock.patch.object(
                candidate, "_verified_latest_vault"
            ) as verify_source, mock.patch.object(
                vault, "_derive_kek"
            ) as derive:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateInputError
                ):
                    self.prepare(decision=decision)
                verify_source.assert_not_called()
                derive.assert_not_called()

    def test_invalid_recovery_root_stops_before_source_access(self):
        for recovery_key in (None, "R" * 32, b"", b"R" * 31, b"R" * 33):
            with self.subTest(value=recovery_key), mock.patch.object(
                candidate, "_verified_latest_vault"
            ) as verify_source:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateInputError
                ):
                    self.prepare(recovery_key=recovery_key)
                verify_source.assert_not_called()

    def test_invalid_new_password_stops_before_source_or_kdf(self):
        invalid = (None, b"password", "", "x" * 1025, "\ud800")
        for password in invalid:
            with self.subTest(password=repr(password)), mock.patch.object(
                candidate, "_verified_latest_vault"
            ) as verify_source, mock.patch.object(
                vault, "_derive_kek"
            ) as derive:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateInputError
                ):
                    self.prepare(new_password=password)
                verify_source.assert_not_called()
                derive.assert_not_called()

    def test_invalid_kdf_values_and_policy_stop_before_argon2(self):
        cases = (
            {"time_cost": True},
            {"time_cost": 0},
            {"time_cost": 6},
            {"memory_kib": 8191},
            {"memory_kib": 300000},
            {"parallelism": 0},
            {"parallelism": 9},
            {"policy": object()},
        )
        for values in cases:
            with self.subTest(values=values), mock.patch.object(
                vault, "_derive_kek"
            ) as derive, mock.patch.object(
                candidate, "_verified_latest_vault"
            ) as verify_source:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateInputError
                ):
                    self.prepare(**values)
                derive.assert_not_called()
                verify_source.assert_not_called()

    def test_invalid_explicit_timestamp_stops_before_source_access(self):
        for value in ("", "2026-08-13", "2026-02-30T00:00:00Z", True):
            with self.subTest(value=value), mock.patch.object(
                candidate, "_verified_latest_vault"
            ) as verify_source:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateInputError
                ):
                    self.prepare(updated_utc=value)
                verify_source.assert_not_called()

    def test_wrong_storage_receipt_and_dirty_history_are_rejected(self):
        for values in (
            {"storage": object()},
            {"latest": object()},
            {"latest": replace(self.receipt, sha256=b"F" * 32)},
        ):
            with self.subTest(values=values):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateStateError
                ):
                    self.prepare(**values)
        unknown = self.vault_path / "unknown"
        unknown.write_bytes(b"do not touch")
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare()
        self.assertEqual(unknown.read_bytes(), b"do not touch")

    def test_stale_record_and_nonlatest_receipt_are_rejected(self):
        first = self.receipt
        self.session.change_password(
            OLD_PASSWORD,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        second = self.store.publish(self.session, previous=first)
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare(latest=first)
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare(latest=second)

    def test_mixed_vault_record_is_rejected(self):
        other = make_session(vault_id=OTHER_VAULT_ID, vault_key=KEY_TWO)
        try:
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"Q" * 32, b"J" * 16, b"O" * 12],
            ):
                other_setup = recovery.create_recovery_record(
                    other,
                    created_utc=RECOVERY_CREATED,
                )
            path = self.write_setup(other_setup, "other-vault-recovery")
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare(
                    recovery_path=path,
                    recovery_key=other_setup.recovery_key,
                )
        finally:
            other.close()

    def test_same_revision_different_source_bytes_are_rejected(self):
        other = make_session()
        try:
            self.assertNotEqual(other.encoded, self.session.encoded)
            with mock.patch.object(
                recovery.os,
                "urandom",
                side_effect=[b"Q" * 32, b"J" * 16, b"O" * 12],
            ):
                other_setup = recovery.create_recovery_record(
                    other,
                    created_utc=RECOVERY_CREATED,
                )
            path = self.write_setup(other_setup, "conflicting-recovery")
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare(
                    recovery_path=path,
                    recovery_key=other_setup.recovery_key,
                )
        finally:
            other.close()

    def test_current_vault_rollback_against_newer_record_is_rejected(self):
        self.session.change_password(
            OLD_PASSWORD,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        with mock.patch.object(
            recovery.os,
            "urandom",
            side_effect=[b"Q" * 32, b"J" * 16, b"O" * 12],
        ):
            newer_setup = recovery.create_recovery_record(
                self.session,
                created_utc=LATER,
            )
        path = self.write_setup(newer_setup, "newer-recovery")
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare(
                recovery_path=path,
                recovery_key=newer_setup.recovery_key,
            )

    def test_tamper_noncanonical_path_and_hardlink_are_rejected(self):
        original = self.recovery_path.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 1
        self.recovery_path.write_bytes(changed)
        os.chmod(self.recovery_path, 0o600)
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare()
        self.recovery_path.write_bytes(original)
        os.chmod(self.recovery_path, 0o600)

        noncanonical = self.recovery_directory / "recovery.mokr"
        noncanonical.write_bytes(original)
        os.chmod(noncanonical, 0o600)
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare(recovery_path=noncanonical)

        linked = self.parent / "linked-copy.mokr"
        os.link(self.recovery_path, linked)
        with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
            self.prepare()

    def test_timestamp_must_not_precede_recovery_record(self):
        with self.assertRaises(candidate.VaultRecoveryCandidateInputError):
            self.prepare(updated_utc=CREATED)

    def test_revision_exhaustion_is_rejected_before_recovery_read(self):
        source = vault.parse_vault(self.session.encoded)
        maximum_header = replace(
            source.header,
            revision=vault.MAX_VAULT_REVISION,
            updated_utc=CANDIDATE_UPDATED,
            salt=b"M" * 16,
            nonce=b"X" * 12,
        )
        maximum = vault._seal_keyring(
            maximum_header,
            self.session.keyring_copy(),
            OLD_PASSWORD,
            policy=vault.DEFAULT_VAULT_KDF_POLICY,
        )
        forged = replace(
            self.receipt,
            revision=vault.MAX_VAULT_REVISION,
            sha256=hashlib.sha256(maximum).digest(),
        )
        with mock.patch.object(
            candidate,
            "_verified_latest_vault",
            return_value=maximum,
        ), mock.patch.object(candidate, "_read_recovery_path") as read_recovery:
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare(latest=forged)
            read_recovery.assert_not_called()

    def test_source_change_after_candidate_creation_returns_no_authorization(self):
        real_read = candidate._read_recovery_path
        first = real_read(self.recovery_path)
        changed = replace(first, file_inode=first.file_inode + 1)
        with mock.patch.object(
            candidate,
            "_read_recovery_path",
            side_effect=[first, changed],
        ), mock.patch.object(candidate, "_new_authorization_id") as new_id:
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare()
            new_id.assert_not_called()

    def test_vault_change_after_candidate_creation_returns_no_authorization(self):
        current = self.store.verify_receipt(self.receipt)
        with mock.patch.object(
            candidate,
            "_verified_latest_vault",
            side_effect=[current, current + b"x"],
        ), mock.patch.object(candidate, "_new_authorization_id") as new_id:
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare()
            new_id.assert_not_called()

    def test_authorization_random_failure_returns_no_prepared_object(self):
        before = self.snapshot()
        with mock.patch.object(
            vault,
            "_random_exact",
            side_effect=exact_candidate_random,
        ), mock.patch.object(
            candidate.os,
            "urandom",
            side_effect=OSError("random unavailable"),
        ):
            with self.assertRaises(
                candidate.VaultRecoveryCandidateAuthorizationError
            ):
                candidate.prepare_recovery_candidate(
                    self.recovery_path,
                    RECOVERY_KEY,
                    self.store,
                    self.receipt,
                    NEW_PASSWORD,
                    candidate.RecoveryCandidateDecision.AUTHORIZE_CANDIDATE,
                    updated_utc=CANDIDATE_UPDATED,
                    time_cost=1,
                    memory_kib=8192,
                    parallelism=1,
                )
        self.assertEqual(self.snapshot(), before)


class RecoveryCandidateVerificationTests(RecoveryCandidateTestCase):
    def claimed(self):
        return self.prepare().claim_once()

    def test_wrong_password_is_rejected(self):
        claimed = self.claimed()
        with self.assertRaises(
            candidate.VaultRecoveryCandidateVerificationError
        ):
            candidate.verify_recovery_candidate(
                claimed.candidate,
                WRONG_PASSWORD,
                claimed.evidence,
            )

    def test_candidate_mutation_truncation_and_trailing_are_rejected_before_kdf(self):
        claimed = self.claimed()
        mutated = bytearray(claimed.candidate)
        mutated[-1] ^= 1
        cases = (bytes(mutated), claimed.candidate[:-1], claimed.candidate + b"x")
        for value in cases:
            with self.subTest(length=len(value)), mock.patch.object(
                vault, "_derive_kek"
            ) as derive:
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateVerificationError
                ):
                    candidate.verify_recovery_candidate(
                        value,
                        NEW_PASSWORD,
                        claimed.evidence,
                    )
                derive.assert_not_called()

    def test_deterministic_candidate_mutation_corpus_is_rejected(self):
        claimed = self.claimed()
        step = max(1, len(claimed.candidate) // 100)
        offsets = tuple(range(0, len(claimed.candidate), step))[:100]
        self.assertGreaterEqual(len(offsets), 90)
        with mock.patch.object(vault, "_derive_kek") as derive:
            for offset in offsets:
                changed = bytearray(claimed.candidate)
                changed[offset] ^= 1
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateVerificationError
                ):
                    candidate.verify_recovery_candidate(
                        bytes(changed),
                        NEW_PASSWORD,
                        claimed.evidence,
                    )
            derive.assert_not_called()

    def test_forged_evidence_bindings_are_rejected(self):
        claimed = self.claimed()
        variants = (
            replace(claimed.evidence, vault_id=OTHER_VAULT_ID),
            replace(claimed.evidence, source_revision=2, target_revision=3),
            replace(claimed.evidence, target_revision=3),
            replace(claimed.evidence, candidate_sha256=b"F" * 32),
            replace(claimed.evidence, updated_utc=LATER),
            replace(claimed.evidence, time_cost=2),
            replace(claimed.evidence, active_key_version=2, key_count=2),
        )
        for evidence in variants:
            with self.subTest(field_difference=evidence):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateVerificationError
                ):
                    candidate.verify_recovery_candidate(
                        claimed.candidate,
                        NEW_PASSWORD,
                        evidence,
                    )

    def test_source_only_evidence_is_bound_by_authorization_not_vault_format(self):
        claimed = self.claimed()
        source_only_variants = (
            replace(claimed.evidence, recovery_id=b"J" * 16),
            replace(claimed.evidence, source_vault_sha256=b"F" * 32),
            replace(claimed.evidence, record_sha256=b"F" * 32),
            replace(
                claimed.evidence,
                file_inode=claimed.evidence.file_inode + 1,
            ),
        )
        for evidence in source_only_variants:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    candidate.verify_recovery_candidate(
                        claimed.candidate,
                        NEW_PASSWORD,
                        evidence,
                    ),
                    evidence,
                )
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateAuthorizationError
                ):
                    candidate.PreparedVaultRecoveryCandidate(
                        claimed.candidate,
                        evidence,
                        claimed.authorization,
                    )

    def test_boolean_or_nonimmutable_evidence_fields_are_rejected(self):
        claimed = self.claimed()
        variants = (
            replace(claimed.evidence, source_revision=True),
            replace(claimed.evidence, target_revision=True),
            replace(claimed.evidence, recovery_id=bytearray(RECOVERY_ID)),
            replace(claimed.evidence, candidate_sha256=bytearray(b"F" * 32)),
            replace(claimed.evidence, encoded_size=False),
        )
        for evidence in variants:
            with self.subTest(evidence=evidence):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateVerificationError
                ):
                    candidate.verify_recovery_candidate(
                        claimed.candidate,
                        NEW_PASSWORD,
                        evidence,
                    )

    def test_other_vault_candidate_is_rejected_even_with_matching_digest(self):
        claimed = self.claimed()
        parsed, recovered = vault.unlock_keyring_vault(
            claimed.candidate,
            NEW_PASSWORD,
        )
        other_header = replace(
            parsed.header,
            vault_id=OTHER_VAULT_ID,
            salt=b"T" * 16,
            nonce=b"D" * 12,
        )
        other = vault._seal_keyring(
            other_header,
            recovered,
            NEW_PASSWORD,
            policy=vault.DEFAULT_VAULT_KDF_POLICY,
        )
        evidence = replace(
            claimed.evidence,
            candidate_sha256=hashlib.sha256(other).digest(),
        )
        with mock.patch.object(vault, "_derive_kek") as derive:
            with self.assertRaises(
                candidate.VaultRecoveryCandidateVerificationError
            ):
                candidate.verify_recovery_candidate(
                    other,
                    NEW_PASSWORD,
                    evidence,
                )
            derive.assert_not_called()

    def test_keyring_digest_and_count_mismatch_are_rejected_after_unlock(self):
        claimed = self.claimed()
        variants = (
            replace(claimed.evidence, keyring_sha256=b"F" * 32),
            replace(claimed.evidence, active_key_version=2, key_count=2),
        )
        for evidence in variants:
            with self.subTest(evidence=evidence):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateVerificationError
                ):
                    candidate.verify_recovery_candidate(
                        claimed.candidate,
                        NEW_PASSWORD,
                        evidence,
                    )

    def test_legacy_schema_candidate_is_rejected_before_password_kdf(self):
        claimed = self.claimed()
        legacy = vault.create_vault(
            NEW_PASSWORD,
            root_key=KEY_ONE,
            vault_id=VAULT_ID,
            created_utc=CREATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        parsed, root = vault.unlock_vault(legacy, NEW_PASSWORD)
        legacy_two = vault.rewrap_vault(
            parsed,
            root,
            NEW_PASSWORD,
            updated_utc=CANDIDATE_UPDATED,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        )
        evidence = replace(
            claimed.evidence,
            candidate_sha256=hashlib.sha256(legacy_two).digest(),
        )
        with mock.patch.object(vault, "_derive_kek") as derive:
            with self.assertRaises(
                candidate.VaultRecoveryCandidateVerificationError
            ):
                candidate.verify_recovery_candidate(
                    legacy_two,
                    NEW_PASSWORD,
                    evidence,
                )
            derive.assert_not_called()

    def test_invalid_password_and_policy_are_rejected_before_kdf(self):
        claimed = self.claimed()
        for password, policy in (("", vault.DEFAULT_VAULT_KDF_POLICY), (NEW_PASSWORD, object())):
            with self.subTest(password=password, policy=type(policy).__name__), \
                    mock.patch.object(vault, "_derive_kek") as derive:
                with self.assertRaises(candidate.VaultRecoveryCandidateError):
                    candidate.verify_recovery_candidate(
                        claimed.candidate,
                        password,
                        claimed.evidence,
                        policy=policy,
                    )
                derive.assert_not_called()


class RecoveryCandidateAuthorizationTests(RecoveryCandidateTestCase):
    def test_prepared_constructor_rejects_candidate_or_authorization_forgery(self):
        claimed = self.prepare().claim_once()
        authorization = claimed.authorization
        variants = (
            replace(authorization, format="OTHER"),
            replace(authorization, version=2),
            replace(authorization, authorization_id="A" * 32),
            replace(authorization, user_confirmed=False),
            replace(authorization, exact_sources_verified=False),
            replace(authorization, candidate_verified=False),
            replace(authorization, executor_rescan_required=False),
            replace(authorization, single_use_claim=False),
            replace(authorization, filesystem_publish_permitted=True),
            replace(authorization, key_deletion_permitted=True),
            replace(authorization, user_file_mutation_permitted=True),
            replace(
                authorization,
                evidence=replace(claimed.evidence, record_sha256=b"F" * 32),
            ),
        )
        for forged in variants:
            with self.subTest(forged=forged):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateAuthorizationError
                ):
                    candidate.PreparedVaultRecoveryCandidate(
                        claimed.candidate,
                        claimed.evidence,
                        forged,
                    )

        changed = bytearray(claimed.candidate)
        changed[-1] ^= 1
        with self.assertRaises(
            candidate.VaultRecoveryCandidateAuthorizationError
        ):
            candidate.PreparedVaultRecoveryCandidate(
                bytes(changed),
                claimed.evidence,
                authorization,
            )

    def test_authorization_random_bytes_must_be_exact(self):
        for value in (b"", b"A" * 15, b"A" * 17, bytearray(b"A" * 16)):
            with self.subTest(value_type=type(value).__name__, length=len(value)), \
                    mock.patch.object(candidate.os, "urandom", return_value=value):
                with self.assertRaises(
                    candidate.VaultRecoveryCandidateAuthorizationError
                ):
                    candidate._new_authorization_id()

    def test_authorization_is_created_only_after_second_source_verification(self):
        real_read = candidate._read_recovery_path
        first = real_read(self.recovery_path)
        with mock.patch.object(
            candidate,
            "_read_recovery_path",
            side_effect=[first, candidate.VaultRecoveryCandidateStateError("late")],
        ), mock.patch.object(candidate, "_new_authorization_id") as new_id:
            with self.assertRaises(candidate.VaultRecoveryCandidateStateError):
                self.prepare()
            new_id.assert_not_called()

    def test_process_local_claim_is_not_a_cryptographic_or_publish_capability(self):
        claimed = self.prepare().claim_once()
        self.assertFalse(claimed.authorization.filesystem_publish_permitted)
        self.assertFalse(claimed.authorization.key_deletion_permitted)
        self.assertFalse(claimed.authorization.user_file_mutation_permitted)
        self.assertEqual(len(self.store.scan().generations), 1)
        self.assertNotIn("password", {item.name for item in fields(claimed.authorization)})
        self.assertNotIn("recovery_key", {item.name for item in fields(claimed.authorization)})


class RecoveryCandidateFaultAndBoundaryTests(RecoveryCandidateTestCase):
    def test_high_level_faults_return_no_candidate_and_do_not_mutate_files(self):
        before = self.snapshot()
        real_read = candidate._read_recovery_path
        first = real_read(self.recovery_path)
        current = self.store.verify_receipt(self.receipt)
        cases = (
            (
                "first_read",
                mock.patch.object(
                    candidate,
                    "_read_recovery_path",
                    side_effect=OSError("read"),
                ),
            ),
            (
                "decrypt",
                mock.patch.object(
                    candidate,
                    "_decrypt_keyring",
                    side_effect=recovery.VaultRecoveryAuthenticationError(
                        "decrypt"
                    ),
                ),
            ),
            (
                "seal",
                mock.patch.object(
                    candidate,
                    "_rewrap_keyring_vault",
                    side_effect=OSError("seal"),
                ),
            ),
            (
                "verify",
                mock.patch.object(
                    candidate,
                    "verify_recovery_candidate",
                    side_effect=(
                        candidate.VaultRecoveryCandidateVerificationError(
                            "verify"
                        )
                    ),
                ),
            ),
            (
                "second_read",
                mock.patch.object(
                    candidate,
                    "_read_recovery_path",
                    side_effect=[first, OSError("second")],
                ),
            ),
            (
                "second_vault",
                mock.patch.object(
                    candidate,
                    "_verified_latest_vault",
                    side_effect=[current, OSError("second")],
                ),
            ),
        )
        for label, patcher in cases:
            with self.subTest(label=label), patcher:
                with self.assertRaises(candidate.VaultRecoveryCandidateError):
                    self.prepare()
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(len(self.store.scan().generations), 1)

    def test_module_has_no_direct_mutating_or_network_calls(self):
        source = inspect.getsource(candidate)
        tree = ast.parse(source)
        forbidden_names = {
            "open",
            "unlink",
            "remove",
            "rename",
            "replace",
            "rmdir",
            "mkdir",
            "makedirs",
            "link",
            "symlink",
            "truncate",
            "write",
            "send",
            "connect",
            "urlopen",
        }
        observed = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    observed.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    observed.add(node.func.attr)
        self.assertFalse(observed & forbidden_names)
        imported_roots = {
            alias.name.split(".")[0]
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imported_roots
            & {"socket", "http", "urllib", "requests", "logging", "subprocess"}
        )

    def test_public_contract_has_no_old_password_or_output_path(self):
        signature = inspect.signature(candidate.prepare_recovery_candidate)
        self.assertNotIn("old_password", signature.parameters)
        self.assertNotIn("current_password", signature.parameters)
        self.assertNotIn("output_path", signature.parameters)
        self.assertNotIn("publish", signature.parameters)
        self.assertIn("new_password", signature.parameters)
        self.assertIn("recovery_path", signature.parameters)

    def test_prepared_objects_never_store_recovery_root_or_password(self):
        prepared = self.prepare()
        claimed = prepared.claim_once()
        for value in (prepared, claimed, claimed.authorization, claimed.evidence):
            names = set(getattr(value, "__slots__", ()))
            if hasattr(value, "__dataclass_fields__"):
                names |= set(value.__dataclass_fields__)
            self.assertNotIn("recovery_key", names)
            self.assertNotIn("password", names)
            rendered = repr(value)
            self.assertNotIn(RECOVERY_KEY.hex(), rendered)
            self.assertNotIn(NEW_PASSWORD, rendered)


if __name__ == "__main__":
    unittest.main()
