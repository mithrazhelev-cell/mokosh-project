import unittest
from dataclasses import replace
from unittest.mock import patch

from mokosh_v2_key_slots import (
    ContactHybridSlot,
    DuplicateKeySlotError,
    KeyVaultSlot,
    PasswordSlot,
)
from mokosh_v2_password_slots import PasswordSlotAuthenticationError
from mokosh_v2_slot_orchestration import (
    ContactCredential,
    EnvelopeKeyPlan,
    KeySlotPlanBuilder,
    PasswordCredential,
    SlotBuilderStateError,
    SlotCredentialMismatchError,
    SlotOrchestrationError,
    SlotSelectionError,
    VaultCredential,
    select_key_slot,
    unwrap_selected_slot,
)


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
PASSWORD = "correct horse battery staple"
VAULT_KEY = b"V" * 32


def fixed_password(slot_id=b"P" * 16):
    return PasswordSlot(
        slot_id=slot_id,
        salt=b"S" * 16,
        time_cost=2,
        memory_kib=64 * 1024,
        parallelism=1,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )


def fixed_vault(slot_id=b"V" * 16):
    return KeyVaultSlot(slot_id, 3, b"Q" * 12, b"R" * 48)


def fixed_contact(slot_id=b"C" * 16):
    return ContactHybridSlot(
        slot_id,
        7,
        b"E" * 32,
        b"K" * 1088,
        b"O" * 12,
        b"Z" * 48,
    )


class BuilderTests(unittest.TestCase):
    def test_generated_file_id_and_dek_are_exact_and_not_reused(self):
        first = KeySlotPlanBuilder()
        second = KeySlotPlanBuilder()
        self.assertEqual(len(first.file_id), 16)
        self.assertNotEqual(first.file_id, second.file_id)
        first.add_vault(VAULT_KEY, 1)
        second.add_vault(VAULT_KEY, 1)
        first_plan = first.finish()
        second_plan = second.finish()
        self.assertEqual(len(first_plan.dek), 32)
        self.assertNotEqual(first_plan.dek, second_plan.dek)

    def test_password_and_vault_slots_wrap_the_same_exact_dek(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        password_slot = builder.add_password(
            PASSWORD, time_cost=2, parallelism=1
        )
        vault_slot = builder.add_vault(VAULT_KEY, 4)
        plan = builder.finish()
        self.assertEqual(plan.dek, DEK)
        self.assertEqual(
            unwrap_selected_slot(
                plan.slots,
                plan.file_id,
                password_slot.slot_id,
                PasswordCredential(PASSWORD),
            ),
            DEK,
        )
        self.assertEqual(
            unwrap_selected_slot(
                plan.header_key_slots(),
                plan.file_id,
                vault_slot.slot_id,
                VaultCredential(VAULT_KEY),
            ),
            DEK,
        )

    def test_contact_add_receives_the_same_builder_dek_and_file_id(self):
        expected = fixed_contact()
        with patch(
            "mokosh_v2_slot_orchestration.create_contact_slot",
            return_value=expected,
        ) as create:
            builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
            result = builder.add_contact(b"X" * 32, b"M" * 1184, 7)
        self.assertIs(result, expected)
        create.assert_called_once_with(b"X" * 32, b"M" * 1184, 7, DEK, FILE_ID)

    def test_empty_plan_is_rejected(self):
        with self.assertRaises(SlotBuilderStateError):
            KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK).finish()

    def test_builder_is_single_use_after_finish(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        builder.add_vault(VAULT_KEY, 1)
        builder.finish()
        with self.assertRaises(SlotBuilderStateError):
            builder.finish()
        with self.assertRaises(SlotBuilderStateError):
            builder.add_vault(VAULT_KEY, 1)

    def test_duplicate_slot_identifier_is_rejected(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        with patch(
            "mokosh_v2_slot_orchestration.create_vault_slot",
            side_effect=(fixed_vault(), fixed_vault()),
        ):
            builder.add_vault(VAULT_KEY, 1)
            with self.assertRaises(DuplicateKeySlotError):
                builder.add_vault(VAULT_KEY, 2)

    def test_builder_limit_is_checked_before_cryptography(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        builder._slots = [fixed_vault(bytes([index]) * 16) for index in range(64)]
        with patch("mokosh_v2_slot_orchestration.create_vault_slot") as create:
            with self.assertRaises(SlotBuilderStateError):
                builder.add_vault(VAULT_KEY, 1)
        create.assert_not_called()

    def test_invalid_explicit_file_id_or_dek_is_rejected(self):
        for kwargs in ({"file_id": b"short"}, {"dek": b"short"}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(SlotOrchestrationError):
                    KeySlotPlanBuilder(**kwargs)

    def test_plan_cannot_bypass_builder_and_is_immutable(self):
        with self.assertRaises(SlotOrchestrationError):
            EnvelopeKeyPlan(FILE_ID, DEK, ())
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        builder.add_vault(VAULT_KEY, 3)
        plan = builder.finish()
        with self.assertRaises(AttributeError):
            plan.file_id = b"F" * 16

    def test_header_mapping_is_a_fresh_copy(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        builder.add_vault(VAULT_KEY, 3)
        plan = builder.finish()
        first = plan.header_key_slots()
        first[0]["vault_key_version"] = 99
        self.assertEqual(plan.header_key_slots()[0]["vault_key_version"], 3)

    def test_secret_fields_are_hidden_from_repr(self):
        self.assertNotIn(PASSWORD, repr(PasswordCredential(PASSWORD)))
        self.assertNotIn(VAULT_KEY.hex(), repr(VaultCredential(VAULT_KEY)))
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        builder.add_vault(VAULT_KEY, 3)
        self.assertNotIn(DEK.hex(), repr(builder.finish()))


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.slots = (fixed_password(), fixed_vault(), fixed_contact())

    def test_selects_only_the_exact_public_slot_identifier(self):
        self.assertEqual(select_key_slot(self.slots, b"V" * 16), fixed_vault())

    def test_mapping_form_is_strictly_parsed(self):
        from mokosh_v2_key_slots import key_slots_to_list

        self.assertEqual(
            select_key_slot(key_slots_to_list(self.slots), b"C" * 16),
            fixed_contact(),
        )

    def test_missing_invalid_and_empty_selection_is_rejected(self):
        for slots, slot_id in (
            (self.slots, b"missing"),
            (self.slots, b"X" * 16),
            ((), b"X" * 16),
        ):
            with self.subTest(slot_id=slot_id):
                with self.assertRaises((SlotSelectionError, SlotOrchestrationError)):
                    select_key_slot(slots, slot_id)

    def test_duplicate_mapping_identifiers_are_rejected(self):
        from mokosh_v2_key_slots import key_slots_to_list

        mappings = key_slots_to_list((fixed_password(), fixed_vault()))
        mappings[1]["slot_id"] = mappings[0]["slot_id"]
        with self.assertRaises(DuplicateKeySlotError):
            select_key_slot(mappings, b"P" * 16)


class ExplicitCredentialDispatchTests(unittest.TestCase):
    def test_password_slot_uses_password_path_once_without_fallback(self):
        slot = fixed_password()
        with patch(
            "mokosh_v2_slot_orchestration.unwrap_password_slot",
            return_value=DEK,
        ) as password_unwrap, patch(
            "mokosh_v2_slot_orchestration.unwrap_vault_slot"
        ) as vault_unwrap, patch(
            "mokosh_v2_slot_orchestration.unwrap_contact_slot"
        ) as contact_unwrap:
            result = unwrap_selected_slot(
                (slot,), FILE_ID, slot.slot_id, PasswordCredential(PASSWORD)
            )
        self.assertEqual(result, DEK)
        password_unwrap.assert_called_once()
        vault_unwrap.assert_not_called()
        contact_unwrap.assert_not_called()

    def test_each_slot_rejects_every_wrong_credential_type_before_crypto(self):
        cases = (
            (fixed_password(), VaultCredential(VAULT_KEY)),
            (fixed_password(), ContactCredential(b"X" * 32, b"M" * 64)),
            (fixed_vault(), PasswordCredential(PASSWORD)),
            (fixed_vault(), ContactCredential(b"X" * 32, b"M" * 64)),
            (fixed_contact(), PasswordCredential(PASSWORD)),
            (fixed_contact(), VaultCredential(VAULT_KEY)),
        )
        for slot, credential in cases:
            with self.subTest(slot=type(slot).__name__):
                with patch(
                    "mokosh_v2_slot_orchestration.unwrap_password_slot"
                ) as password_unwrap, patch(
                    "mokosh_v2_slot_orchestration.unwrap_vault_slot"
                ) as vault_unwrap, patch(
                    "mokosh_v2_slot_orchestration.unwrap_contact_slot"
                ) as contact_unwrap:
                    with self.assertRaises(SlotCredentialMismatchError):
                        unwrap_selected_slot(
                            (slot,), FILE_ID, slot.slot_id, credential
                        )
                password_unwrap.assert_not_called()
                vault_unwrap.assert_not_called()
                contact_unwrap.assert_not_called()

    def test_only_selected_slot_is_attempted(self):
        password_slot = fixed_password()
        vault_slot = fixed_vault()
        with patch(
            "mokosh_v2_slot_orchestration.unwrap_vault_slot",
            return_value=DEK,
        ) as vault_unwrap, patch(
            "mokosh_v2_slot_orchestration.unwrap_password_slot"
        ) as password_unwrap:
            result = unwrap_selected_slot(
                (password_slot, vault_slot),
                FILE_ID,
                vault_slot.slot_id,
                VaultCredential(VAULT_KEY),
            )
        self.assertEqual(result, DEK)
        vault_unwrap.assert_called_once()
        password_unwrap.assert_not_called()

    def test_authentication_failure_is_not_replaced_or_retried(self):
        slot = fixed_password()
        failure = PasswordSlotAuthenticationError("invalid")
        with patch(
            "mokosh_v2_slot_orchestration.unwrap_password_slot",
            side_effect=failure,
        ) as password_unwrap:
            with self.assertRaises(PasswordSlotAuthenticationError):
                unwrap_selected_slot(
                    (slot,), FILE_ID, slot.slot_id, PasswordCredential("wrong")
                )
        password_unwrap.assert_called_once()

    def test_unwrapped_key_must_be_exactly_32_bytes(self):
        slot = fixed_vault()
        with patch(
            "mokosh_v2_slot_orchestration.unwrap_vault_slot",
            return_value=b"short",
        ):
            with self.assertRaises(SlotOrchestrationError):
                unwrap_selected_slot(
                    (slot,), FILE_ID, slot.slot_id, VaultCredential(VAULT_KEY)
                )

    def test_real_password_and_vault_roundtrip_with_explicit_selection(self):
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        password_slot = builder.add_password(
            PASSWORD, time_cost=2, parallelism=1
        )
        vault_slot = builder.add_vault(VAULT_KEY, 9)
        plan = builder.finish()
        self.assertEqual(
            unwrap_selected_slot(
                plan.slots,
                FILE_ID,
                password_slot.slot_id,
                PasswordCredential(PASSWORD),
            ),
            DEK,
        )
        self.assertEqual(
            unwrap_selected_slot(
                plan.slots,
                FILE_ID,
                vault_slot.slot_id,
                VaultCredential(VAULT_KEY),
            ),
            DEK,
        )


if __name__ == "__main__":
    unittest.main()
