import json
import unittest
from dataclasses import replace

from mokosh_v2_operation_journal import (
    JOURNAL_FORMAT,
    JOURNAL_NAME_PREFIX,
    JOURNAL_NAME_SUFFIX,
    JOURNAL_VERSION,
    MAX_JOURNAL_SIZE,
    PRIVATE_FILE_MODE,
    TEMP_NAME_PREFIX,
    OperationJournalError,
    build_operation_journal,
    decode_operation_journal,
    encode_operation_journal,
    journal_name_for,
    operation_id_from_journal_name,
    operation_id_from_temporary_name,
    temporary_name_for,
)


OPERATION_ID = "00112233445566778899aabbccddeeff"


def valid_record():
    return build_operation_journal(
        operation_id=OPERATION_ID,
        parent_device=11,
        parent_inode=22,
        temp_device=11,
        temp_inode=33,
        owner_uid=1000,
        owner_gid=1000,
    )


class OperationJournalCodecTests(unittest.TestCase):
    def test_record_is_deterministic_canonical_and_roundtrips(self):
        record = valid_record()
        encoded = encode_operation_journal(record)
        self.assertEqual(decode_operation_journal(encoded), record)
        self.assertEqual(encode_operation_journal(record), encoded)
        self.assertEqual(encoded, json.dumps(
            json.loads(encoded),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii"))
        self.assertLessEqual(len(encoded), MAX_JOURNAL_SIZE)

    def test_record_has_exact_public_fields_and_no_sensitive_names(self):
        record = valid_record()
        encoded = encode_operation_journal(record)
        self.assertEqual(record.format, JOURNAL_FORMAT)
        self.assertEqual(record.version, JOURNAL_VERSION)
        self.assertEqual(record.mode, PRIVATE_FILE_MODE)
        self.assertEqual(record.initial_links, 1)
        for forbidden in (
            b"source",
            b"output",
            b"final",
            b"password",
            b"contact",
            b"key",
            b"content",
            b"size",
            b"path",
        ):
            self.assertNotIn(forbidden, encoded.lower())

    def test_names_are_exact_and_bidirectionally_bound(self):
        temporary = temporary_name_for(OPERATION_ID)
        journal = journal_name_for(OPERATION_ID)
        self.assertEqual(temporary, TEMP_NAME_PREFIX + OPERATION_ID)
        self.assertEqual(
            journal,
            JOURNAL_NAME_PREFIX + OPERATION_ID + JOURNAL_NAME_SUFFIX,
        )
        self.assertEqual(operation_id_from_temporary_name(temporary), OPERATION_ID)
        self.assertEqual(operation_id_from_journal_name(journal), OPERATION_ID)

    def test_invalid_operation_identifiers_and_names_are_rejected(self):
        values = (
            "",
            "0" * 31,
            "0" * 33,
            "A" * 32,
            "g" * 32,
            "../" + "0" * 32,
            True,
            b"0" * 32,
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(OperationJournalError):
                    temporary_name_for(value)
        for value in ("bad", JOURNAL_NAME_PREFIX + OPERATION_ID, True):
            with self.subTest(value=value):
                with self.assertRaises(OperationJournalError):
                    operation_id_from_journal_name(value)

    def test_duplicate_unknown_missing_and_noncanonical_json_are_rejected(self):
        encoded = encode_operation_journal(valid_record())
        decoded = json.loads(encoded)
        variants = []
        variants.append(b'{"format":"a","format":"b"}')
        changed = dict(decoded)
        changed["unknown"] = 1
        variants.append(json.dumps(changed, sort_keys=True, separators=(",", ":")).encode())
        changed = dict(decoded)
        changed.pop("temp_inode")
        variants.append(json.dumps(changed, sort_keys=True, separators=(",", ":")).encode())
        variants.append(b" " + encoded)
        variants.append(encoded + b"\n")
        variants.append(encoded.replace(b'"version":1', b'"version":NaN'))
        for value in variants:
            with self.subTest(value=value[:40]):
                with self.assertRaises(OperationJournalError):
                    decode_operation_journal(value)

    def test_boolean_negative_overflow_and_policy_changes_are_rejected(self):
        record = valid_record()
        variants = (
            replace(record, version=True),
            replace(record, parent_inode=-1),
            replace(record, temp_inode=1 << 64),
            replace(record, owner_uid=1 << 32),
            replace(record, mode=0o644),
            replace(record, initial_links=2),
            replace(record, temporary_name=TEMP_NAME_PREFIX + "f" * 32),
        )
        for value in variants:
            with self.subTest(field=value):
                with self.assertRaises(OperationJournalError):
                    encode_operation_journal(value)

    def test_non_bytes_empty_oversized_and_non_ascii_are_rejected(self):
        values = (
            "text",
            b"",
            b"{" + b"x" * MAX_JOURNAL_SIZE + b"}",
            "ж".encode("utf-8"),
        )
        for value in values:
            with self.subTest(kind=type(value).__name__, length=len(value)):
                with self.assertRaises(OperationJournalError):
                    decode_operation_journal(value)


if __name__ == "__main__":
    unittest.main()
