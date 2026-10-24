import base64
import json
import unittest

from mokosh_v2_format import DEFAULT_CHUNK_SIZE, MAX_FRAME_INDEX, FormatLimitError
from mokosh_v2_manifest import (
    MAX_FILENAME_UTF8_LEN,
    MAX_MANIFEST_LEN,
    DuplicateManifestKeyError,
    Manifest,
    ManifestError,
    build_manifest,
    encode_manifest,
    expected_data_frames,
    parse_manifest,
)


DIGEST = bytes(range(32))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_object(**updates):
    result = {
        "original_name": "документ-测试.txt",
        "original_size": 123,
        "data_frames": 1,
        "plaintext_sha256": b64url(DIGEST),
    }
    result.update(updates)
    return result


def encoded_object(**updates):
    return json.dumps(
        valid_object(**updates),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class ManifestRoundtripTests(unittest.TestCase):
    def test_unicode_manifest_roundtrip(self):
        manifest = build_manifest(
            original_name="документ-测试.txt",
            original_size=123,
            plaintext_sha256=DIGEST,
            chunk_size=DEFAULT_CHUNK_SIZE,
            content_type="text/plain",
        )
        decoded = parse_manifest(
            encode_manifest(manifest, chunk_size=DEFAULT_CHUNK_SIZE),
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self.assertEqual(decoded, manifest)

    def test_encoding_is_deterministic(self):
        manifest = build_manifest(
            original_name="report.txt",
            original_size=1,
            plaintext_sha256=DIGEST,
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self.assertEqual(
            encode_manifest(manifest, chunk_size=DEFAULT_CHUNK_SIZE),
            encode_manifest(manifest, chunk_size=DEFAULT_CHUNK_SIZE),
        )

    def test_empty_file_uses_one_data_frame(self):
        manifest = build_manifest(
            original_name="empty.txt",
            original_size=0,
            plaintext_sha256=DIGEST,
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self.assertEqual(manifest.data_frames, 1)

    def test_frame_count_at_chunk_boundaries(self):
        self.assertEqual(
            expected_data_frames(DEFAULT_CHUNK_SIZE, chunk_size=DEFAULT_CHUNK_SIZE),
            1,
        )
        self.assertEqual(
            expected_data_frames(
                DEFAULT_CHUNK_SIZE + 1,
                chunk_size=DEFAULT_CHUNK_SIZE,
            ),
            2,
        )

    def test_optional_content_type_is_omitted_when_absent(self):
        manifest = build_manifest(
            original_name="data.bin",
            original_size=4,
            plaintext_sha256=DIGEST,
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        encoded = encode_manifest(manifest, chunk_size=DEFAULT_CHUNK_SIZE)
        self.assertNotIn(b"content_type", encoded)


class ManifestJSONTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        raw = encoded_object().decode("utf-8")
        duplicate = raw[:-1] + ',"original_name":"second.txt"}'
        with self.assertRaises(DuplicateManifestKeyError):
            parse_manifest(duplicate.encode(), chunk_size=DEFAULT_CHUNK_SIZE)

    def test_missing_required_field_is_rejected(self):
        value = valid_object()
        del value["plaintext_sha256"]
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(value).encode(), chunk_size=DEFAULT_CHUNK_SIZE)

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(
                encoded_object(secret_note="must not be stored"),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_non_object_root_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"[]", chunk_size=DEFAULT_CHUNK_SIZE)

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"{\xff}", chunk_size=DEFAULT_CHUNK_SIZE)

    def test_non_standard_json_constant_is_rejected(self):
        raw = encoded_object()[:-1] + b',"extra":NaN}'
        with self.assertRaises(ManifestError):
            parse_manifest(raw, chunk_size=DEFAULT_CHUNK_SIZE)

    def test_empty_or_oversized_manifest_is_rejected_before_json(self):
        for raw in (b"", b"{" + b" " * MAX_MANIFEST_LEN + b"}"):
            with self.subTest(size=len(raw)), self.assertRaises(FormatLimitError):
                parse_manifest(raw, chunk_size=DEFAULT_CHUNK_SIZE)


class FilenameSafetyTests(unittest.TestCase):
    def test_path_separators_and_dot_names_are_rejected(self):
        for name in ("../secret", "folder/file", "folder\\file", ".", ".."):
            with self.subTest(name=name), self.assertRaises(ManifestError):
                parse_manifest(
                    encoded_object(original_name=name),
                    chunk_size=DEFAULT_CHUNK_SIZE,
                )

    def test_empty_filename_is_rejected(self):
        with self.assertRaises(FormatLimitError):
            parse_manifest(
                encoded_object(original_name=""),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_control_character_is_rejected(self):
        for name in ("bad\nname.txt", "report\u202etxt.exe"):
            with self.subTest(name=name), self.assertRaises(ManifestError):
                parse_manifest(
                    encoded_object(original_name=name),
                    chunk_size=DEFAULT_CHUNK_SIZE,
                )

    def test_filename_limit_is_measured_in_utf8_bytes(self):
        valid = "а" * (MAX_FILENAME_UTF8_LEN // 2)
        parse_manifest(
            encoded_object(original_name=valid),
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        invalid = "а" * (MAX_FILENAME_UTF8_LEN // 2 + 1)
        with self.assertRaises(FormatLimitError):
            parse_manifest(
                encoded_object(original_name=invalid),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )


class SizeAndDigestTests(unittest.TestCase):
    def test_negative_or_boolean_size_is_rejected(self):
        for size in (-1, True):
            with self.subTest(size=size), self.assertRaises(ManifestError):
                parse_manifest(
                    encoded_object(original_size=size),
                    chunk_size=DEFAULT_CHUNK_SIZE,
                )

    def test_size_beyond_frame_capacity_is_rejected(self):
        too_large = MAX_FRAME_INDEX * DEFAULT_CHUNK_SIZE + 1
        with self.assertRaises(FormatLimitError):
            parse_manifest(
                encoded_object(original_size=too_large),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_inconsistent_data_frame_count_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(
                encoded_object(
                    original_size=DEFAULT_CHUNK_SIZE + 1,
                    data_frames=1,
                ),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_boolean_data_frame_count_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(
                encoded_object(data_frames=True),
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_padded_or_wrong_length_digest_is_rejected(self):
        for digest in (b64url(DIGEST) + "=", b64url(b"short")):
            with self.subTest(digest=digest), self.assertRaises(ManifestError):
                parse_manifest(
                    encoded_object(plaintext_sha256=digest),
                    chunk_size=DEFAULT_CHUNK_SIZE,
                )

    def test_build_requires_exact_32_byte_digest(self):
        with self.assertRaises(ManifestError):
            build_manifest(
                original_name="file.txt",
                original_size=1,
                plaintext_sha256=b"short",
                chunk_size=DEFAULT_CHUNK_SIZE,
            )

    def test_invalid_chunk_size_is_rejected(self):
        with self.assertRaises(FormatLimitError):
            parse_manifest(encoded_object(), chunk_size=1)


class ContentTypeTests(unittest.TestCase):
    def test_simple_content_type_is_accepted(self):
        manifest = parse_manifest(
            encoded_object(content_type="application/octet-stream"),
            chunk_size=DEFAULT_CHUNK_SIZE,
        )
        self.assertEqual(manifest.content_type, "application/octet-stream")

    def test_parameters_controls_and_missing_slash_are_rejected(self):
        for value in ("text/plain; charset=utf-8", "text\n/plain", "textplain", 7):
            with self.subTest(value=value), self.assertRaises(ManifestError):
                parse_manifest(
                    encoded_object(content_type=value),
                    chunk_size=DEFAULT_CHUNK_SIZE,
                )

    def test_encode_requires_manifest_instance(self):
        with self.assertRaises(ManifestError):
            encode_manifest(valid_object(), chunk_size=DEFAULT_CHUNK_SIZE)

    def test_manually_inconsistent_manifest_is_rejected_on_encode(self):
        manifest = Manifest(
            original_name="file.txt",
            original_size=DEFAULT_CHUNK_SIZE + 1,
            data_frames=1,
            plaintext_sha256=DIGEST,
        )
        with self.assertRaises(ManifestError):
            encode_manifest(manifest, chunk_size=DEFAULT_CHUNK_SIZE)


if __name__ == "__main__":
    unittest.main()
