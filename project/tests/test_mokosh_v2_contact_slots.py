import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import x25519

from mokosh_v2_contact_slots import (
    CONTACT_SLOT_AAD_DOMAIN,
    CONTACT_SLOT_HKDF_INFO_DOMAIN,
    ContactSlotAuthenticationError,
    ContactSlotCryptoError,
    ContactSlotInputError,
    build_contact_slot_aad,
    build_contact_slot_hkdf_info,
    create_contact_slot,
    derive_contact_slot_kek,
    unwrap_contact_slot,
)
from mokosh_v2_key_slots import (
    ContactHybridSlot,
    KeySlotError,
    key_slot_to_mapping,
    parse_key_slot,
)


try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as real_mlkem
except ImportError:
    real_mlkem = None


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
X_SHARED = b"X" * 32
PQ_SHARED = b"P" * 32


def fixed_slot(**changes):
    slot = ContactHybridSlot(
        slot_id=b"I" * 16,
        recipient_key_version=7,
        ephemeral_x25519_public_key=b"E" * 32,
        mlkem_ciphertext=b"C" * 1088,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )
    return replace(slot, **changes)


def _expand(seed, length):
    result = bytearray()
    counter = 0
    while len(result) < length:
        result.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(result[:length])


def fake_public_from_seed(seed):
    return _expand(b"fake-mlkem-public\x00" + seed, 1184)


class FakeMLKEM768PublicKey:
    def __init__(self, raw):
        self.raw = raw

    @classmethod
    def from_public_bytes(cls, raw):
        if len(raw) != 1184:
            raise ValueError("invalid public key")
        return cls(bytes(raw))

    def encapsulate(self):
        shared = hashlib.sha256(b"fake-mlkem-shared\x00" + self.raw).digest()
        ciphertext = _expand(b"fake-mlkem-ciphertext\x00" + self.raw, 1088)
        return shared, ciphertext


class FakeMLKEM768PrivateKey:
    def __init__(self, seed):
        self.seed = seed

    @classmethod
    def from_seed_bytes(cls, seed):
        if len(seed) != 64:
            raise ValueError("invalid seed")
        return cls(bytes(seed))

    def decapsulate(self, ciphertext):
        public = fake_public_from_seed(self.seed)
        expected = _expand(b"fake-mlkem-ciphertext\x00" + public, 1088)
        if bytes(ciphertext) == expected:
            return hashlib.sha256(b"fake-mlkem-shared\x00" + public).digest()
        return hashlib.sha256(
            b"fake-mlkem-rejection\x00" + self.seed + bytes(ciphertext)
        ).digest()


class FakeMLKEMModule:
    MLKEM768PublicKey = FakeMLKEM768PublicKey
    MLKEM768PrivateKey = FakeMLKEM768PrivateKey


class ContactSlotDerivationTests(unittest.TestCase):
    def test_hybrid_hkdf_known_answer(self):
        self.assertEqual(
            derive_contact_slot_kek(X_SHARED, PQ_SHARED, FILE_ID, fixed_slot()).hex(),
            "75f42b2ca06f60d8bddf144bc0e944def54e2bdc4b3a4e608d4b82251da20978",
        )

    def test_hkdf_info_is_domain_separated_canonical_json(self):
        info = build_contact_slot_hkdf_info(FILE_ID, fixed_slot())
        self.assertTrue(info.startswith(CONTACT_SLOT_HKDF_INFO_DOMAIN))
        body = info[len(CONTACT_SLOT_HKDF_INFO_DOMAIN) :]
        metadata = json.loads(body)
        self.assertEqual(
            set(metadata),
            {
                "ephemeral_x25519_public_key", "file_id", "mlkem_ciphertext",
                "recipient_key_version", "slot_id", "suite", "type",
            },
        )
        self.assertEqual(
            body,
            json.dumps(
                metadata, ensure_ascii=True, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii"),
        )

    def test_each_secret_is_mandatory_and_changes_kek(self):
        baseline = derive_contact_slot_kek(X_SHARED, PQ_SHARED, FILE_ID, fixed_slot())
        self.assertNotEqual(
            baseline,
            derive_contact_slot_kek(b"Y" * 32, PQ_SHARED, FILE_ID, fixed_slot()),
        )
        self.assertNotEqual(
            baseline,
            derive_contact_slot_kek(X_SHARED, b"Q" * 32, FILE_ID, fixed_slot()),
        )
        for x_secret, pq_secret in ((b"", PQ_SHARED), (X_SHARED, b"")):
            with self.assertRaises(ContactSlotInputError):
                derive_contact_slot_kek(x_secret, pq_secret, FILE_ID, fixed_slot())

    def test_every_public_context_field_changes_kek(self):
        baseline = derive_contact_slot_kek(X_SHARED, PQ_SHARED, FILE_ID, fixed_slot())
        variants = (
            (b"F" * 16, fixed_slot()),
            (FILE_ID, fixed_slot(slot_id=b"J" * 16)),
            (FILE_ID, fixed_slot(recipient_key_version=8)),
            (FILE_ID, fixed_slot(ephemeral_x25519_public_key=b"G" * 32)),
            (FILE_ID, fixed_slot(mlkem_ciphertext=b"D" * 1088)),
        )
        for file_id, slot in variants:
            with self.subTest(slot=slot):
                self.assertNotEqual(
                    baseline,
                    derive_contact_slot_kek(X_SHARED, PQ_SHARED, file_id, slot),
                )

    def test_nonce_and_wrapped_dek_do_not_change_kek(self):
        baseline = derive_contact_slot_kek(X_SHARED, PQ_SHARED, FILE_ID, fixed_slot())
        changed = fixed_slot(wrap_nonce=b"O" * 12, wrapped_dek=b"Z" * 48)
        self.assertEqual(
            baseline, derive_contact_slot_kek(X_SHARED, PQ_SHARED, FILE_ID, changed)
        )

    def test_secret_and_file_identifier_lengths_are_exact(self):
        invalid = (
            (b"X" * 31, PQ_SHARED, FILE_ID),
            (X_SHARED, b"P" * 31, FILE_ID),
            (X_SHARED, PQ_SHARED, b"F" * 15),
            ("not-bytes", PQ_SHARED, FILE_ID),
        )
        for x_secret, pq_secret, file_id in invalid:
            with self.subTest(file_id=file_id):
                with self.assertRaises(ContactSlotInputError):
                    derive_contact_slot_kek(
                        x_secret, pq_secret, file_id, fixed_slot()
                    )


class ContactSlotAADTests(unittest.TestCase):
    def test_aad_is_exact_and_includes_nonce(self):
        aad = build_contact_slot_aad(FILE_ID, fixed_slot())
        self.assertTrue(aad.startswith(CONTACT_SLOT_AAD_DOMAIN))
        metadata = json.loads(aad[len(CONTACT_SLOT_AAD_DOMAIN) :])
        self.assertIn("wrap_nonce", metadata)
        self.assertNotIn("wrapped_dek", metadata)
        self.assertNotIn("recipient_fingerprint", metadata)
        self.assertNotIn("nickname", metadata)

    def test_ciphertext_wrap_is_excluded_but_kem_ciphertext_is_bound(self):
        baseline = build_contact_slot_aad(FILE_ID, fixed_slot())
        self.assertEqual(
            baseline,
            build_contact_slot_aad(FILE_ID, fixed_slot(wrapped_dek=b"Z" * 48)),
        )
        self.assertNotEqual(
            baseline,
            build_contact_slot_aad(FILE_ID, fixed_slot(mlkem_ciphertext=b"D" * 1088)),
        )

    def test_old_or_classic_only_suite_is_rejected(self):
        mapping = key_slot_to_mapping(fixed_slot())
        mapping["suite"] = "X25519-ONLY-AES-256-GCM"
        with self.assertRaises(KeySlotError):
            parse_key_slot(mapping)

    def test_invalid_or_non_contact_slot_is_rejected(self):
        invalid = (
            object(),
            fixed_slot(ephemeral_x25519_public_key=b"short"),
            fixed_slot(mlkem_ciphertext=b"short"),
            fixed_slot(recipient_key_version=0),
        )
        for slot in invalid:
            with self.subTest(slot=slot):
                with self.assertRaises(ContactSlotCryptoError):
                    build_contact_slot_aad(FILE_ID, slot)


class FakeHybridIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.x_private = x25519.X25519PrivateKey.generate()
        cls.x_public_raw = cls.x_private.public_key().public_bytes_raw()
        cls.x_private_raw = cls.x_private.private_bytes_raw()
        cls.pq_seed = b"S" * 64
        cls.pq_public_raw = fake_public_from_seed(cls.pq_seed)
        with patch(
            "mokosh_v2_contact_slots._mlkem_module",
            return_value=FakeMLKEMModule,
        ):
            cls.slot = create_contact_slot(
                cls.x_public_raw, cls.pq_public_raw, 7, DEK, FILE_ID
            )

    def unwrap(self, slot=None, x_private=None, pq_seed=None, file_id=None):
        with patch(
            "mokosh_v2_contact_slots._mlkem_module",
            return_value=FakeMLKEMModule,
        ):
            return unwrap_contact_slot(
                self.slot if slot is None else slot,
                self.x_private_raw if x_private is None else x_private,
                self.pq_seed if pq_seed is None else pq_seed,
                FILE_ID if file_id is None else file_id,
            )

    def test_hybrid_roundtrip_restores_exact_dek(self):
        self.assertEqual(self.unwrap(), DEK)

    def test_created_slot_has_exact_public_schema_and_no_identity(self):
        mapping = key_slot_to_mapping(self.slot)
        self.assertEqual(len(self.slot.ephemeral_x25519_public_key), 32)
        self.assertEqual(len(self.slot.mlkem_ciphertext), 1088)
        self.assertEqual(len(self.slot.wrapped_dek), 48)
        self.assertNotIn("recipient_fingerprint", mapping)
        self.assertNotIn("nickname", mapping)

    def test_wrong_x25519_private_key_is_rejected(self):
        wrong = x25519.X25519PrivateKey.generate().private_bytes_raw()
        with self.assertRaises(ContactSlotAuthenticationError):
            self.unwrap(x_private=wrong)

    def test_wrong_mlkem_private_seed_is_rejected(self):
        with self.assertRaises(ContactSlotAuthenticationError):
            self.unwrap(pq_seed=b"T" * 64)

    def test_wrong_file_identifier_is_rejected(self):
        with self.assertRaises(ContactSlotAuthenticationError):
            self.unwrap(file_id=b"F" * 16)

    def test_tampered_kem_or_wrapped_ciphertext_is_rejected(self):
        changed_kem = bytearray(self.slot.mlkem_ciphertext)
        changed_kem[0] ^= 1
        changed_wrap = bytearray(self.slot.wrapped_dek)
        changed_wrap[-1] ^= 1
        for slot in (
            replace(self.slot, mlkem_ciphertext=bytes(changed_kem)),
            replace(self.slot, wrapped_dek=bytes(changed_wrap)),
        ):
            with self.subTest(slot=slot):
                with self.assertRaises(ContactSlotAuthenticationError):
                    self.unwrap(slot=slot)

    def test_tampered_slot_version_nonce_or_ephemeral_key_is_rejected(self):
        other_ephemeral = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
        variants = (
            replace(self.slot, slot_id=b"J" * 16),
            replace(self.slot, recipient_key_version=8),
            replace(self.slot, wrap_nonce=b"O" * 12),
            replace(self.slot, ephemeral_x25519_public_key=other_ephemeral),
        )
        for slot in variants:
            with self.subTest(slot=slot):
                with self.assertRaises(ContactSlotAuthenticationError):
                    self.unwrap(slot=slot)

    def test_invalid_inputs_are_rejected_before_random_or_kem(self):
        invalid = (
            (b"X" * 31, self.pq_public_raw, 7, DEK, FILE_ID),
            (self.x_public_raw, b"P" * 1183, 7, DEK, FILE_ID),
            (self.x_public_raw, self.pq_public_raw, 0, DEK, FILE_ID),
            (self.x_public_raw, self.pq_public_raw, True, DEK, FILE_ID),
            (self.x_public_raw, self.pq_public_raw, 7, b"D" * 31, FILE_ID),
            (self.x_public_raw, self.pq_public_raw, 7, DEK, b"F" * 15),
        )
        with patch("mokosh_v2_contact_slots.os.urandom") as random_source:
            with patch("mokosh_v2_contact_slots._mlkem_module") as loader:
                for args in invalid:
                    with self.subTest(args=args):
                        with self.assertRaises(ContactSlotCryptoError):
                            create_contact_slot(*args)
        random_source.assert_not_called()
        loader.assert_not_called()

    def test_invalid_random_source_is_rejected_before_kem(self):
        with patch("mokosh_v2_contact_slots.os.urandom", return_value=b"short"):
            with patch("mokosh_v2_contact_slots._mlkem_module") as loader:
                with self.assertRaises(ContactSlotInputError):
                    create_contact_slot(
                        self.x_public_raw, self.pq_public_raw, 7, DEK, FILE_ID
                    )
        loader.assert_not_called()

    def test_each_creation_uses_fresh_ephemeral_and_random_values(self):
        with patch(
            "mokosh_v2_contact_slots._mlkem_module",
            return_value=FakeMLKEMModule,
        ):
            second = create_contact_slot(
                self.x_public_raw, self.pq_public_raw, 7, DEK, FILE_ID
            )
        self.assertNotEqual(self.slot.slot_id, second.slot_id)
        self.assertNotEqual(
            self.slot.ephemeral_x25519_public_key,
            second.ephemeral_x25519_public_key,
        )
        self.assertNotEqual(self.slot.wrap_nonce, second.wrap_nonce)
        self.assertNotEqual(self.slot.wrapped_dek, second.wrapped_dek)


@unittest.skipUnless(real_mlkem is not None, "ML-KEM requires cryptography >= 47")
class RealMLKEMIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.x_private = x25519.X25519PrivateKey.generate()
        cls.pq_private = real_mlkem.MLKEM768PrivateKey.generate()
        cls.slot = create_contact_slot(
            cls.x_private.public_key().public_bytes_raw(),
            cls.pq_private.public_key().public_bytes_raw(),
            9,
            DEK,
            FILE_ID,
        )

    def test_real_hybrid_roundtrip(self):
        self.assertEqual(
            unwrap_contact_slot(
                self.slot,
                self.x_private.private_bytes_raw(),
                self.pq_private.private_bytes_raw(),
                FILE_ID,
            ),
            DEK,
        )

    def test_real_mlkem_sizes_and_schema(self):
        self.assertEqual(len(self.pq_private.public_key().public_bytes_raw()), 1184)
        self.assertEqual(len(self.pq_private.private_bytes_raw()), 64)
        self.assertEqual(len(self.slot.mlkem_ciphertext), 1088)

    def test_real_modified_mlkem_ciphertext_is_rejected(self):
        changed = bytearray(self.slot.mlkem_ciphertext)
        changed[0] ^= 1
        with self.assertRaises(ContactSlotAuthenticationError):
            unwrap_contact_slot(
                replace(self.slot, mlkem_ciphertext=bytes(changed)),
                self.x_private.private_bytes_raw(),
                self.pq_private.private_bytes_raw(),
                FILE_ID,
            )

    def test_real_wrong_mlkem_private_key_is_rejected(self):
        wrong = real_mlkem.MLKEM768PrivateKey.generate()
        with self.assertRaises(ContactSlotAuthenticationError):
            unwrap_contact_slot(
                self.slot,
                self.x_private.private_bytes_raw(),
                wrong.private_bytes_raw(),
                FILE_ID,
            )


if __name__ == "__main__":
    unittest.main()
