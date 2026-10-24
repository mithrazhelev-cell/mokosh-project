import ast
import hashlib
import unittest
from pathlib import Path

import mokosh_recovery_phrase as phrase


ROOT = Path(__file__).resolve().parents[1]
VECTOR_KEY = bytes(range(32))
VECTOR_WORDS = (
    "cactus absurd avoid scissors anxiety gather lottery category door army "
    "half long cage bachelor another expect people blade school educate "
    "curtain scrub monitor lab tiger"
).split()


class RecoveryPhraseTests(unittest.TestCase):
    def test_pinned_wordlist_is_exact_sorted_ascii_vocabulary(self):
        path = ROOT / "third_party" / "bip39" / "english.txt"
        encoded = path.read_bytes()
        self.assertEqual(len(encoded), 13116)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            phrase.RECOVERY_PHRASE_WORDLIST_SHA256,
        )
        self.assertEqual(len(phrase.RECOVERY_PHRASE_WORDLIST), 2048)
        self.assertEqual(
            phrase.RECOVERY_PHRASE_WORDLIST,
            tuple(sorted(phrase.RECOVERY_PHRASE_WORDLIST)),
        )

    def test_fixed_vector_and_exact_25_word_round_trip(self):
        words = phrase.encode_recovery_phrase(VECTOR_KEY)
        self.assertEqual(words, tuple(VECTOR_WORDS))
        self.assertEqual(len(words), 25)
        self.assertEqual(phrase.decode_recovery_phrase(words), VECTOR_KEY)
        self.assertEqual(
            phrase.decode_recovery_phrase(" \n ".join(words)), VECTOR_KEY
        )

    def test_every_recovery_root_bit_round_trips(self):
        for bit in range(256):
            key = (1 << bit).to_bytes(32, "big")
            with self.subTest(bit=bit):
                self.assertEqual(
                    phrase.decode_recovery_phrase(
                        phrase.encode_recovery_phrase(key)
                    ),
                    key,
                )

    def test_zero_and_all_one_roots_have_fixed_outputs(self):
        zero = phrase.encode_recovery_phrase(bytes(32))
        ones = phrase.encode_recovery_phrase(b"\xff" * 32)
        self.assertEqual(zero[0], "cactus")
        self.assertEqual(zero[-2:], ("act", "picture"))
        self.assertEqual(ones[0], "divide")
        self.assertEqual(ones[-2:], ("work", "enroll"))

    def test_wrong_length_type_and_word_are_rejected(self):
        for value in (b"", b"R" * 31, b"R" * 33, "not bytes", object()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(phrase.RecoveryPhraseFormatError):
                    phrase.encode_recovery_phrase(value)
        invalid = list(VECTOR_WORDS)
        invalid[7] = "notaword"
        for value in (
            VECTOR_WORDS[:-1],
            VECTOR_WORDS + ["zoo"],
            invalid,
            [word.upper() for word in VECTOR_WORDS],
            object(),
        ):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(phrase.RecoveryPhraseFormatError):
                    phrase.decode_recovery_phrase(value)

    def test_sequence_words_and_text_are_bounded_before_lookup(self):
        words = list(phrase.encode_recovery_phrase(bytes(32)))
        words[0] = "a" * (phrase.RECOVERY_PHRASE_MAX_WORD_CHARS + 1)
        with self.assertRaises(phrase.RecoveryPhraseFormatError):
            phrase.decode_recovery_phrase(words)
        with self.assertRaises(phrase.RecoveryPhraseFormatError):
            phrase.decode_recovery_phrase(
                "a" * (phrase.RECOVERY_PHRASE_MAX_TEXT_BYTES + 1)
            )

    def test_no_prefix_fuzzy_unicode_or_bip39_length_acceptance(self):
        shortened = [word[:4] for word in VECTOR_WORDS]
        homoglyph = list(VECTOR_WORDS)
        homoglyph[0] = "cactuѕ"  # final character is Cyrillic.
        for value in (shortened, homoglyph, VECTOR_WORDS[:24]):
            with self.subTest(value=value[0]):
                with self.assertRaises(phrase.RecoveryPhraseFormatError):
                    phrase.decode_recovery_phrase(value)

    def test_changed_word_fails_checksum_without_correction(self):
        changed = list(VECTOR_WORDS)
        index = phrase.RECOVERY_PHRASE_WORDLIST.index(changed[-1])
        changed[-1] = phrase.RECOVERY_PHRASE_WORDLIST[index ^ 1]
        with self.assertRaises(phrase.RecoveryPhraseChecksumError):
            phrase.decode_recovery_phrase(changed)

    def test_wrong_version_fails_before_use(self):
        changed = list(VECTOR_WORDS)
        first = phrase.RECOVERY_PHRASE_WORDLIST.index(changed[0])
        changed[0] = phrase.RECOVERY_PHRASE_WORDLIST[first ^ 1024]
        with self.assertRaises(phrase.RecoveryPhraseFormatError):
            phrase.decode_recovery_phrase(changed)

    def test_canonical_text_and_numbering_require_valid_checksum(self):
        self.assertEqual(
            phrase.recovery_phrase_text(VECTOR_WORDS), " ".join(VECTOR_WORDS)
        )
        numbered = phrase.numbered_recovery_words(VECTOR_WORDS)
        self.assertEqual(numbered[0], (1, "cactus"))
        self.assertEqual(numbered[-1], (25, "tiger"))

    def test_module_has_no_network_clipboard_wallet_or_kdf_import(self):
        tree = ast.parse((ROOT / "mokosh_recovery_phrase.py").read_text())
        imported = {
            alias.name.split(".", 1)[0]
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".", 1)[0]
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(
            imported.isdisjoint(
                {
                    "socket",
                    "urllib",
                    "requests",
                    "tkinter",
                    "logging",
                    "mnemonic",
                    "bip32",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
