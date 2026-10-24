import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from mokosh_v2_key_slots import (
    KeySlotError,
    KeyVaultSlot,
    PasswordSlot,
    key_slot_to_mapping,
    parse_key_slot,
)
from mokosh_v2_vault_slots import (
    VAULT_SLOT_AAD_DOMAIN,
    VAULT_SLOT_HKDF_INFO_DOMAIN,
    VaultSlotAuthenticationError,
    VaultSlotCryptoError,
    VaultSlotInputError,
    build_vault_slot_aad,
    build_vault_slot_hkdf_info,
    create_vault_slot,
    derive_vault_slot_kek,
    unwrap_vault_slot,
)


ROOT_KEY = b"R" * 32
OTHER_ROOT_KEY = b"Q" * 32
FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))


def fixed_slot(**changes):
    slot = KeyVaultSlot(
        slot_id=b"I" * 16,
        vault_key_version=7,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )
    return replace(slot, **changes)


class VaultSlotDerivationTests(unittest.TestCase):
    def test_hkdf_sha256_known_answer(self):
        self.assertEqual(
            derive_vault_slot_kek(ROOT_KEY, FILE_ID, fixed_slot()).hex(),
            "7a201562a97fe8ce3a660a89780032a52f28106202bb55e2eb1f1299653b01c4",
        )

    def test_hkdf_info_is_exact_domain_separated_canonical_json(self):
        info = build_vault_slot_hkdf_info(FILE_ID, fixed_slot())
        self.assertTrue(info.startswith(VAULT_SLOT_HKDF_INFO_DOMAIN))
        body = info[len(VAULT_SLOT_HKDF_INFO_DOMAIN) :]
        metadata = json.loads(body)
        self.assertEqual(
            set(metadata),
            {"file_id", "slot_id", "suite", "type", "vault_key_version"},
        )
        self.assertEqual(
            body,
            json.dumps(
                metadata,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
        )

    def test_each_derivation_context_changes_kek(self):
        baseline = derive_vault_slot_kek(ROOT_KEY, FILE_ID, fixed_slot())
        variants = (
            (OTHER_ROOT_KEY, FILE_ID, fixed_slot()),
            (ROOT_KEY, b"F" * 16, fixed_slot()),
            (ROOT_KEY, FILE_ID, fixed_slot(slot_id=b"J" * 16)),
            (ROOT_KEY, FILE_ID, fixed_slot(vault_key_version=8)),
        )
        for root_key, file_id, slot in variants:
            with self.subTest(slot=slot):
                self.assertNotEqual(
                    baseline, derive_vault_slot_kek(root_key, file_id, slot)
                )

    def test_nonce_and_ciphertext_do_not_change_kek(self):
        baseline = derive_vault_slot_kek(ROOT_KEY, FILE_ID, fixed_slot())
        self.assertEqual(
            baseline,
            derive_vault_slot_kek(
                ROOT_KEY,
                FILE_ID,
                fixed_slot(wrap_nonce=b"O" * 12, wrapped_dek=b"X" * 48),
            ),
        )

    def test_root_key_and_file_id_lengths_are_exact(self):
        invalid = (
            (b"R" * 31, FILE_ID),
            (b"R" * 33, FILE_ID),
            (ROOT_KEY, b"F" * 15),
            (ROOT_KEY, b"F" * 17),
            ("not-bytes", FILE_ID),
        )
        for root_key, file_id in invalid:
            with self.subTest(root_key=root_key, file_id=file_id):
                with self.assertRaises(VaultSlotInputError):
                    derive_vault_slot_kek(root_key, file_id, fixed_slot())

    def test_non_vault_slot_is_rejected(self):
        slot = PasswordSlot(b"I" * 16, b"S" * 16, 2, 65536, 1, b"N" * 12, b"W" * 48)
        with self.assertRaises(VaultSlotCryptoError):
            derive_vault_slot_kek(ROOT_KEY, FILE_ID, slot)


class VaultSlotAADTests(unittest.TestCase):
    def test_pre_hkdf_vault_suite_name_is_rejected(self):
        mapping = key_slot_to_mapping(fixed_slot())
        mapping["suite"] = "KEY-VAULT-AES-256-GCM"
        with self.assertRaises(KeySlotError):
            parse_key_slot(mapping)

    def test_aad_is_exact_and_includes_nonce(self):
        aad = build_vault_slot_aad(FILE_ID, fixed_slot())
        self.assertTrue(aad.startswith(VAULT_SLOT_AAD_DOMAIN))
        metadata = json.loads(aad[len(VAULT_SLOT_AAD_DOMAIN) :])
        self.assertEqual(
            set(metadata),
            {
                "file_id", "slot_id", "suite", "type",
                "vault_key_version", "wrap_nonce",
            },
        )

    def test_ciphertext_is_deliberately_excluded_from_aad(self):
        first = build_vault_slot_aad(FILE_ID, fixed_slot(wrapped_dek=b"A" * 48))
        second = build_vault_slot_aad(FILE_ID, fixed_slot(wrapped_dek=b"B" * 48))
        self.assertEqual(first, second)

    def test_every_authenticated_context_field_changes_aad(self):
        baseline = build_vault_slot_aad(FILE_ID, fixed_slot())
        variants = (
            (b"F" * 16, fixed_slot()),
            (FILE_ID, fixed_slot(slot_id=b"J" * 16)),
            (FILE_ID, fixed_slot(vault_key_version=8)),
            (FILE_ID, fixed_slot(wrap_nonce=b"O" * 12)),
        )
        for file_id, slot in variants:
            with self.subTest(slot=slot):
                self.assertNotEqual(baseline, build_vault_slot_aad(file_id, slot))

    def test_invalid_slot_structure_is_rejected(self):
        for slot in (
            fixed_slot(slot_id=b"short"),
            fixed_slot(vault_key_version=0),
            fixed_slot(wrap_nonce=b"short"),
            fixed_slot(wrapped_dek=b"short"),
        ):
            with self.subTest(slot=slot):
                with self.assertRaises(VaultSlotCryptoError):
                    build_vault_slot_aad(FILE_ID, slot)


class VaultSlotWrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slot = create_vault_slot(ROOT_KEY, 7, DEK, FILE_ID)

    def test_roundtrip_restores_exact_dek(self):
        self.assertEqual(unwrap_vault_slot(self.slot, ROOT_KEY, FILE_ID), DEK)

    def test_created_slot_has_exact_lengths_and_version(self):
        self.assertEqual(len(self.slot.slot_id), 16)
        self.assertEqual(self.slot.vault_key_version, 7)
        self.assertEqual(len(self.slot.wrap_nonce), 12)
        self.assertEqual(len(self.slot.wrapped_dek), 48)

    def test_wrong_root_key_is_rejected_generically(self):
        with self.assertRaisesRegex(
            VaultSlotAuthenticationError,
            "Vault key or authenticated Key Vault slot data is invalid",
        ):
            unwrap_vault_slot(self.slot, OTHER_ROOT_KEY, FILE_ID)

    def test_wrong_file_id_is_rejected(self):
        with self.assertRaises(VaultSlotAuthenticationError):
            unwrap_vault_slot(self.slot, ROOT_KEY, b"F" * 16)

    def test_tampered_ciphertext_is_rejected(self):
        changed = bytearray(self.slot.wrapped_dek)
        changed[-1] ^= 1
        with self.assertRaises(VaultSlotAuthenticationError):
            unwrap_vault_slot(
                replace(self.slot, wrapped_dek=bytes(changed)), ROOT_KEY, FILE_ID
            )

    def test_tampered_bound_metadata_is_rejected(self):
        variants = (
            replace(self.slot, slot_id=b"J" * 16),
            replace(self.slot, vault_key_version=8),
            replace(self.slot, wrap_nonce=b"O" * 12),
        )
        for slot in variants:
            with self.subTest(slot=slot):
                with self.assertRaises(VaultSlotAuthenticationError):
                    unwrap_vault_slot(slot, ROOT_KEY, FILE_ID)

    def test_invalid_inputs_are_rejected_before_random_or_hkdf(self):
        invalid = (
            (b"R" * 31, 7, DEK, FILE_ID),
            (ROOT_KEY, 7, b"D" * 31, FILE_ID),
            (ROOT_KEY, 7, DEK, b"F" * 15),
            (ROOT_KEY, 0, DEK, FILE_ID),
            (ROOT_KEY, True, DEK, FILE_ID),
        )
        with patch("mokosh_v2_vault_slots.os.urandom") as random_source:
            with patch("mokosh_v2_vault_slots.HKDF") as hkdf:
                for args in invalid:
                    with self.subTest(args=args):
                        with self.assertRaises(VaultSlotCryptoError):
                            create_vault_slot(*args)
        random_source.assert_not_called()
        hkdf.assert_not_called()

    def test_invalid_random_source_is_rejected_before_hkdf(self):
        with patch("mokosh_v2_vault_slots.os.urandom", return_value=b"short"):
            with patch("mokosh_v2_vault_slots.HKDF") as hkdf:
                with self.assertRaises(VaultSlotInputError):
                    create_vault_slot(ROOT_KEY, 7, DEK, FILE_ID)
        hkdf.assert_not_called()

    def test_each_creation_uses_fresh_random_values(self):
        second = create_vault_slot(ROOT_KEY, 7, DEK, FILE_ID)
        self.assertNotEqual(self.slot.slot_id, second.slot_id)
        self.assertNotEqual(self.slot.wrap_nonce, second.wrap_nonce)
        self.assertNotEqual(self.slot.wrapped_dek, second.wrapped_dek)


if __name__ == "__main__":
    unittest.main()
