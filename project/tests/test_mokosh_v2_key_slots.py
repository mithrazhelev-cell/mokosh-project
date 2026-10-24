import base64
import unittest

from mokosh_v2_format import (
    DEFAULT_CHUNK_SIZE,
    V2FormatError,
    build_envelope_prefix,
    parse_envelope_prefix,
)
from mokosh_v2_key_slots import (
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    CONTACT_HYBRID_SLOT_TYPE,
    CONTACT_HYBRID_SUITE,
    KEY_VAULT_SLOT_TYPE,
    KEY_VAULT_SUITE,
    MAX_KEY_SLOTS,
    PASSWORD_SLOT_TYPE,
    PASSWORD_SUITE,
    ContactHybridSlot,
    DuplicateKeySlotError,
    KeySlotError,
    KeyVaultSlot,
    PasswordSlot,
    UnknownKeySlotTypeError,
    key_slot_to_mapping,
    key_slots_to_list,
    parse_key_slot,
    parse_key_slots,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def password_slot(**updates):
    slot = {
        "type": PASSWORD_SLOT_TYPE,
        "suite": PASSWORD_SUITE,
        "slot_id": b64url(b"P" * 16),
        "salt": b64url(b"S" * 16),
        "time_cost": 3,
        "memory_kib": 64 * 1024,
        "parallelism": 4,
        "wrap_nonce": b64url(b"N" * 12),
        "wrapped_dek": b64url(b"W" * 48),
    }
    slot.update(updates)
    return slot


def vault_slot(**updates):
    slot = {
        "type": KEY_VAULT_SLOT_TYPE,
        "suite": KEY_VAULT_SUITE,
        "slot_id": b64url(b"V" * 16),
        "vault_key_version": 2,
        "wrap_nonce": b64url(b"N" * 12),
        "wrapped_dek": b64url(b"W" * 48),
    }
    slot.update(updates)
    return slot


def contact_slot(**updates):
    slot = {
        "type": CONTACT_HYBRID_SLOT_TYPE,
        "suite": CONTACT_HYBRID_SUITE,
        "slot_id": b64url(b"C" * 16),
        "recipient_key_version": 3,
        "ephemeral_x25519_public_key": b64url(b"X" * 32),
        "mlkem_ciphertext": b64url(b"K" * 1088),
        "wrap_nonce": b64url(b"N" * 12),
        "wrapped_dek": b64url(b"W" * 48),
    }
    slot.update(updates)
    return slot


def valid_header(key_slots):
    return {
        "format": "MOKOSH",
        "version": 2,
        "file_id": b64url(bytes(range(16))),
        "content_aead": "AES-256-GCM-CHUNKED",
        "nonce_prefix": b64url(bytes(range(8))),
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "key_slots": key_slots,
        "created_utc": "2026-08-08T12:00:00Z",
        "writer": "MOKOSH Agent",
    }


class SlotRoundtripTests(unittest.TestCase):
    def test_password_slot_roundtrip(self):
        parsed = parse_key_slot(password_slot())
        self.assertIsInstance(parsed, PasswordSlot)
        self.assertEqual(parsed.slot_id, b"P" * 16)
        self.assertEqual(parsed.salt, b"S" * 16)
        self.assertEqual(key_slot_to_mapping(parsed), password_slot())

    def test_key_vault_slot_roundtrip(self):
        parsed = parse_key_slot(vault_slot())
        self.assertIsInstance(parsed, KeyVaultSlot)
        self.assertEqual(parsed.vault_key_version, 2)
        self.assertEqual(key_slot_to_mapping(parsed), vault_slot())

    def test_contact_hybrid_slot_roundtrip(self):
        parsed = parse_key_slot(contact_slot())
        self.assertIsInstance(parsed, ContactHybridSlot)
        self.assertEqual(len(parsed.mlkem_ciphertext), 1088)
        self.assertEqual(key_slot_to_mapping(parsed), contact_slot())

    def test_slot_list_roundtrip_preserves_order(self):
        mappings = [password_slot(), vault_slot(), contact_slot()]
        parsed = parse_key_slots(mappings)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(key_slots_to_list(parsed), mappings)

    def test_empty_slot_list_is_structurally_valid(self):
        self.assertEqual(parse_key_slots([]), ())


class ExactSchemaTests(unittest.TestCase):
    def test_non_object_and_missing_type_are_rejected(self):
        for invalid in (None, [], "slot", {"suite": PASSWORD_SUITE}):
            with self.subTest(invalid=invalid), self.assertRaises(KeySlotError):
                parse_key_slot(invalid)

    def test_non_text_field_name_is_rejected(self):
        slot = password_slot()
        slot[7] = "invalid JSON-style field"
        with self.assertRaises(KeySlotError):
            parse_key_slot(slot)

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(UnknownKeySlotTypeError):
            parse_key_slot(password_slot(type="FUTURE_SLOT"))

    def test_wrong_suite_is_rejected_for_each_type(self):
        for slot in (
            password_slot(suite=KEY_VAULT_SUITE),
            vault_slot(suite=PASSWORD_SUITE),
            contact_slot(suite="X25519-ONLY"),
        ):
            with self.subTest(slot=slot["type"]), self.assertRaises(KeySlotError):
                parse_key_slot(slot)

    def test_missing_required_field_is_rejected(self):
        for factory, field in (
            (password_slot, "salt"),
            (vault_slot, "vault_key_version"),
            (contact_slot, "mlkem_ciphertext"),
        ):
            slot = factory()
            del slot[field]
            with self.subTest(field=field), self.assertRaises(KeySlotError):
                parse_key_slot(slot)

    def test_unknown_or_human_metadata_field_is_rejected(self):
        for field in (
            "unknown",
            "nickname",
            "contact_name",
            "path",
            "recipient_fingerprint",
        ):
            with self.subTest(field=field), self.assertRaises(KeySlotError):
                parse_key_slot(password_slot(**{field: "private metadata"}))

    def test_classic_only_contact_fallback_is_rejected(self):
        slot = contact_slot(suite="X25519-HKDF-SHA-256-AES-256-GCM")
        del slot["mlkem_ciphertext"]
        with self.assertRaises(KeySlotError):
            parse_key_slot(slot)


class BinaryFieldTests(unittest.TestCase):
    def test_slot_id_length_is_exact_for_all_types(self):
        for factory in (password_slot, vault_slot, contact_slot):
            for size in (15, 17):
                with self.subTest(factory=factory.__name__, size=size):
                    with self.assertRaises(KeySlotError):
                        parse_key_slot(factory(slot_id=b64url(b"I" * size)))

    def test_padding_and_non_url_alphabet_are_rejected(self):
        for invalid in (b64url(b"P" * 16) + "=", "+" * 22, "not valid"):
            with self.subTest(invalid=invalid), self.assertRaises(KeySlotError):
                parse_key_slot(password_slot(slot_id=invalid))

    def test_password_binary_lengths_are_exact(self):
        for field, size in (("salt", 15), ("wrap_nonce", 11), ("wrapped_dek", 47)):
            with self.subTest(field=field), self.assertRaises(KeySlotError):
                parse_key_slot(password_slot(**{field: b64url(b"B" * size)}))

    def test_contact_binary_lengths_are_exact(self):
        invalid_fields = (
            ("ephemeral_x25519_public_key", 31),
            ("mlkem_ciphertext", 1087),
            ("wrap_nonce", 13),
            ("wrapped_dek", 49),
        )
        for field, size in invalid_fields:
            with self.subTest(field=field), self.assertRaises(KeySlotError):
                parse_key_slot(contact_slot(**{field: b64url(b"B" * size)}))

    def test_manually_invalid_dataclass_cannot_be_encoded(self):
        invalid = PasswordSlot(
            slot_id=b"short",
            salt=b"S" * 16,
            time_cost=3,
            memory_kib=64 * 1024,
            parallelism=4,
            wrap_nonce=b"N" * 12,
            wrapped_dek=b"W" * 48,
        )
        with self.assertRaises(KeySlotError):
            key_slot_to_mapping(invalid)

    def test_manually_wrong_binary_type_is_rejected_cleanly(self):
        invalid = KeyVaultSlot(
            slot_id="not-bytes",
            vault_key_version=1,
            wrap_nonce=b"N" * 12,
            wrapped_dek=b"W" * 48,
        )
        with self.assertRaises(KeySlotError):
            key_slot_to_mapping(invalid)


class IntegerBoundsTests(unittest.TestCase):
    def test_argon2_bounds_are_inclusive(self):
        for field, minimum, maximum in (
            ("time_cost", ARGON2_MIN_TIME_COST, ARGON2_MAX_TIME_COST),
            ("memory_kib", ARGON2_MIN_MEMORY_KIB, ARGON2_MAX_MEMORY_KIB),
            ("parallelism", ARGON2_MIN_PARALLELISM, ARGON2_MAX_PARALLELISM),
        ):
            parse_key_slot(password_slot(**{field: minimum}))
            parse_key_slot(password_slot(**{field: maximum}))

    def test_argon2_out_of_bounds_and_boolean_are_rejected(self):
        invalid_values = (
            ("time_cost", ARGON2_MIN_TIME_COST - 1),
            ("time_cost", ARGON2_MAX_TIME_COST + 1),
            ("memory_kib", ARGON2_MIN_MEMORY_KIB - 1),
            ("memory_kib", ARGON2_MAX_MEMORY_KIB + 1),
            ("parallelism", 0),
            ("parallelism", ARGON2_MAX_PARALLELISM + 1),
            ("time_cost", True),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value), self.assertRaises(KeySlotError):
                parse_key_slot(password_slot(**{field: value}))

    def test_key_versions_must_be_positive_uint32(self):
        for factory, field in (
            (vault_slot, "vault_key_version"),
            (contact_slot, "recipient_key_version"),
        ):
            for invalid in (0, -1, 0x100000000, True):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(KeySlotError):
                        parse_key_slot(factory(**{field: invalid}))


class SlotCollectionTests(unittest.TestCase):
    def test_key_slots_must_be_json_array(self):
        for invalid in (None, {}, (), "slots"):
            with self.subTest(invalid=invalid), self.assertRaises(KeySlotError):
                parse_key_slots(invalid)

    def test_slot_count_limit_is_enforced_before_items(self):
        with self.assertRaises(KeySlotError):
            parse_key_slots([None] * (MAX_KEY_SLOTS + 1))

    def test_duplicate_slot_id_is_rejected_across_types(self):
        duplicate_id = b64url(b"D" * 16)
        with self.assertRaises(DuplicateKeySlotError):
            parse_key_slots(
                [
                    password_slot(slot_id=duplicate_id),
                    contact_slot(slot_id=duplicate_id),
                ]
            )

    def test_invalid_item_reports_its_array_index(self):
        with self.assertRaisesRegex(KeySlotError, r"key_slots\[1\]"):
            parse_key_slots([password_slot(), {"type": "UNKNOWN"}])

    def test_encoder_rejects_unsupported_objects(self):
        with self.assertRaises(KeySlotError):
            key_slot_to_mapping({"type": PASSWORD_SLOT_TYPE})

    def test_list_encoder_requires_a_real_sequence(self):
        for invalid in (None, 7, "slots", b"slots"):
            with self.subTest(invalid=invalid), self.assertRaises(KeySlotError):
                key_slots_to_list(invalid)

    def test_list_encoder_enforces_slot_count_before_encoding(self):
        with self.assertRaises(KeySlotError):
            key_slots_to_list([None] * (MAX_KEY_SLOTS + 1))


class HeaderIntegrationTests(unittest.TestCase):
    def test_header_accepts_all_three_strict_slot_types(self):
        slots = [password_slot(), vault_slot(), contact_slot()]
        encoded = build_envelope_prefix(valid_header(slots))
        parsed, remainder = parse_envelope_prefix(encoded)
        self.assertEqual(parsed.header["key_slots"], slots)
        self.assertEqual(remainder, b"")

    def test_header_rejects_unknown_slot_type(self):
        with self.assertRaises(V2FormatError):
            build_envelope_prefix(
                valid_header([password_slot(type="UNKNOWN")])
            )

    def test_header_rejects_duplicate_slot_ids(self):
        duplicate_id = b64url(b"D" * 16)
        with self.assertRaises(V2FormatError):
            build_envelope_prefix(
                valid_header(
                    [
                        password_slot(slot_id=duplicate_id),
                        vault_slot(slot_id=duplicate_id),
                    ]
                )
            )

    def test_header_encoding_with_slots_is_deterministic(self):
        header = valid_header([password_slot(), contact_slot()])
        self.assertEqual(
            build_envelope_prefix(header),
            build_envelope_prefix(header),
        )


if __name__ == "__main__":
    unittest.main()
