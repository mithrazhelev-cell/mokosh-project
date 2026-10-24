import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from mokosh_v2_key_slots import KeyVaultSlot, PasswordSlot
from mokosh_v2_password_slots import (
    DEFAULT_PASSWORD_KDF_POLICY,
    PASSWORD_SLOT_AAD_DOMAIN,
    PasswordInputError,
    PasswordKDFPolicy,
    PasswordSlotAuthenticationError,
    PasswordSlotCryptoError,
    PasswordSlotPolicyError,
    build_password_slot_aad,
    create_password_slot,
    derive_password_kek,
    unwrap_password_slot,
    validate_password_kdf_policy,
    validate_password_slot_for_execution,
)

FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
PASSWORD = "correct horse battery staple"


def fixed_slot(**changes):
    slot = PasswordSlot(
        slot_id=b"I" * 16,
        salt=b"S" * 16,
        time_cost=2,
        memory_kib=64 * 1024,
        parallelism=1,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )
    return replace(slot, **changes)


class PasswordKDFTests(unittest.TestCase):
    def test_argon2id_known_answer(self):
        self.assertEqual(
            derive_password_kek(PASSWORD, fixed_slot()).hex(),
            "3ba8747a4f1f931dfea3432d7fd6bc8571b00f831b9fa18f7316032a38864111",
        )

    def test_password_is_exact_utf8_without_hidden_normalization(self):
        composed = derive_password_kek("caf\u00e9", fixed_slot())
        decomposed = derive_password_kek("cafe\u0301", fixed_slot())
        self.assertNotEqual(composed, decomposed)

    def test_empty_non_text_and_oversized_passwords_are_rejected(self):
        for password in ("", b"password", "x" * 1025, "\ud800"):
            with self.subTest(password_type=type(password).__name__):
                with self.assertRaises(PasswordInputError):
                    derive_password_kek(password, fixed_slot())

    def test_invalid_policy_is_rejected(self):
        invalid = (
            object(),
            PasswordKDFPolicy(max_time_cost=True),
            PasswordKDFPolicy(max_memory_kib=(64 * 1024) - 1),
            PasswordKDFPolicy(max_parallelism=17),
        )
        for policy in invalid:
            with self.subTest(policy=policy):
                with self.assertRaises(PasswordSlotPolicyError):
                    validate_password_kdf_policy(policy)

    def test_excessive_cost_is_rejected_before_argon2id_construction(self):
        slot = fixed_slot(memory_kib=512 * 1024)
        with patch("mokosh_v2_password_slots.Argon2id") as argon2:
            with self.assertRaises(PasswordSlotPolicyError):
                derive_password_kek(PASSWORD, slot)
        argon2.assert_not_called()

    def test_explicit_bounded_policy_can_accept_higher_cost(self):
        policy = PasswordKDFPolicy(max_time_cost=6, max_memory_kib=512 * 1024)
        validate_password_slot_for_execution(
            fixed_slot(time_cost=6, memory_kib=512 * 1024), policy=policy
        )

    def test_non_password_slot_is_rejected(self):
        vault_slot = KeyVaultSlot(b"I" * 16, 1, b"N" * 12, b"W" * 48)
        with self.assertRaises(PasswordSlotCryptoError):
            validate_password_slot_for_execution(vault_slot)


class PasswordSlotAADTests(unittest.TestCase):
    def test_aad_has_domain_and_exact_canonical_metadata(self):
        aad = build_password_slot_aad(FILE_ID, fixed_slot())
        self.assertTrue(aad.startswith(PASSWORD_SLOT_AAD_DOMAIN))
        metadata = json.loads(aad[len(PASSWORD_SLOT_AAD_DOMAIN) :])
        self.assertEqual(
            set(metadata),
            {
                "file_id", "memory_kib", "parallelism", "salt", "slot_id",
                "suite", "time_cost", "type", "wrap_nonce",
            },
        )
        self.assertNotIn("wrapped_dek", metadata)
        self.assertEqual(
            aad[len(PASSWORD_SLOT_AAD_DOMAIN) :],
            json.dumps(
                metadata, ensure_ascii=True, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii"),
        )

    def test_aad_changes_with_file_id_and_each_bound_field(self):
        baseline = build_password_slot_aad(FILE_ID, fixed_slot())
        variants = (
            (b"F" * 16, fixed_slot()),
            (FILE_ID, fixed_slot(slot_id=b"J" * 16)),
            (FILE_ID, fixed_slot(salt=b"T" * 16)),
            (FILE_ID, fixed_slot(time_cost=3)),
            (FILE_ID, fixed_slot(memory_kib=128 * 1024)),
            (FILE_ID, fixed_slot(parallelism=2)),
            (FILE_ID, fixed_slot(wrap_nonce=b"O" * 12)),
        )
        for file_id, slot in variants:
            with self.subTest(slot=slot):
                self.assertNotEqual(baseline, build_password_slot_aad(file_id, slot))

    def test_ciphertext_is_deliberately_excluded_from_aad(self):
        first = build_password_slot_aad(FILE_ID, fixed_slot(wrapped_dek=b"A" * 48))
        second = build_password_slot_aad(FILE_ID, fixed_slot(wrapped_dek=b"B" * 48))
        self.assertEqual(first, second)

    def test_file_id_length_is_exact(self):
        for value in (b"", b"F" * 15, b"F" * 17, "not-bytes"):
            with self.subTest(value=value):
                with self.assertRaises(PasswordInputError):
                    build_password_slot_aad(value, fixed_slot())


class PasswordSlotWrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slot = create_password_slot(
            PASSWORD, DEK, FILE_ID, time_cost=2,
            memory_kib=64 * 1024, parallelism=1,
        )

    def test_roundtrip_restores_exact_dek(self):
        self.assertEqual(unwrap_password_slot(self.slot, PASSWORD, FILE_ID), DEK)

    def test_created_slot_has_exact_random_and_ciphertext_lengths(self):
        self.assertEqual(len(self.slot.slot_id), 16)
        self.assertEqual(len(self.slot.salt), 16)
        self.assertEqual(len(self.slot.wrap_nonce), 12)
        self.assertEqual(len(self.slot.wrapped_dek), 48)

    def test_wrong_password_is_rejected_generically(self):
        with self.assertRaisesRegex(
            PasswordSlotAuthenticationError,
            "password or authenticated password-slot data is invalid",
        ):
            unwrap_password_slot(self.slot, "wrong password", FILE_ID)

    def test_wrong_file_id_is_rejected(self):
        with self.assertRaises(PasswordSlotAuthenticationError):
            unwrap_password_slot(self.slot, PASSWORD, b"F" * 16)

    def test_tampered_ciphertext_is_rejected(self):
        changed = bytearray(self.slot.wrapped_dek)
        changed[0] ^= 1
        with self.assertRaises(PasswordSlotAuthenticationError):
            unwrap_password_slot(
                replace(self.slot, wrapped_dek=bytes(changed)), PASSWORD, FILE_ID
            )

    def test_tampered_authenticated_metadata_is_rejected(self):
        variants = (
            replace(self.slot, slot_id=b"J" * 16),
            replace(self.slot, salt=b"T" * 16),
            replace(self.slot, wrap_nonce=b"O" * 12),
        )
        for slot in variants:
            with self.subTest(slot=slot):
                with self.assertRaises(PasswordSlotAuthenticationError):
                    unwrap_password_slot(slot, PASSWORD, FILE_ID)

    def test_invalid_dek_and_file_id_are_rejected_before_kdf(self):
        with patch("mokosh_v2_password_slots.Argon2id") as argon2:
            for dek, file_id in ((b"D" * 31, FILE_ID), (DEK, b"F" * 15)):
                with self.subTest(dek_len=len(dek), file_id_len=len(file_id)):
                    with self.assertRaises(PasswordInputError):
                        create_password_slot(PASSWORD, dek, file_id)
        argon2.assert_not_called()

    def test_invalid_random_source_is_rejected_before_kdf(self):
        with patch("mokosh_v2_password_slots.os.urandom", return_value=b"short"):
            with patch("mokosh_v2_password_slots.Argon2id") as argon2:
                with self.assertRaises(PasswordInputError):
                    create_password_slot(PASSWORD, DEK, FILE_ID)
        argon2.assert_not_called()

    def test_default_creation_parameters_fit_default_policy(self):
        self.assertGreaterEqual(DEFAULT_PASSWORD_KDF_POLICY.max_time_cost, 3)
        self.assertGreaterEqual(DEFAULT_PASSWORD_KDF_POLICY.max_memory_kib, 64 * 1024)
        self.assertGreaterEqual(DEFAULT_PASSWORD_KDF_POLICY.max_parallelism, 4)

    def test_each_creation_uses_fresh_random_values(self):
        second = create_password_slot(
            PASSWORD, DEK, FILE_ID, time_cost=2,
            memory_kib=64 * 1024, parallelism=1,
        )
        self.assertNotEqual(self.slot.slot_id, second.slot_id)
        self.assertNotEqual(self.slot.salt, second.salt)
        self.assertNotEqual(self.slot.wrap_nonce, second.wrap_nonce)
        self.assertNotEqual(self.slot.wrapped_dek, second.wrapped_dek)


if __name__ == "__main__":
    unittest.main()
