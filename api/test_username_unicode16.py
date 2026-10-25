import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase

from api import username_unicode16 as identity


class FrozenUnicode16Tests(SimpleTestCase):
    def test_full_casefold_is_the_frozen_default_not_interpreter_or_turkic_mapping(self):
        self.assertEqual(identity.full_casefold("\u1c89\u1c8a"), "\u1c8a\u1c8a")
        self.assertEqual(identity.full_casefold("StraßeΣςİI"), "strasseσσi\u0307i")
        self.assertEqual(identity.canonical_username_key(" \u1c89 "), "\u1c8a".encode())
        self.assertEqual(identity.normalize_username("\x1cＡlice\u3000"), "Alice")
        self.assertEqual(len(identity.STRIP_CHARACTERS), 29)

    def test_character_validation_uses_unicode16_even_when_python_does_not_know_a_letter(self):
        self.assertTrue(identity.valid_character("\u1c89"))
        for value in ["_", ".", "@", "+", "-", "Ⅷ", "²"]:
            self.assertTrue(identity.valid_character(value))
        for value in ["!", "/", "\u0307", "\ud800", "\U0010ffff"]:
            self.assertFalse(identity.valid_character(value))
            with self.assertRaises(ValueError):
                identity.normalize_username("name1" + value)

    def test_bad_missing_or_oversized_casefold_data_fails_closed_without_echoing_contents(self):
        with TemporaryDirectory(prefix="unicode16-data-") as temporary:
            path = Path(temporary) / "data.txt"
            with patch.object(identity, "_CASEFOLD_SOURCE", path):
                with self.assertRaisesMessage(identity.Unicode16IdentityError, "unavailable"):
                    identity._load_casefold_table()
                for contents in [b"PRIVATE-CONTENTS", b"x" * (identity._MAX_DATA_BYTES + 1)]:
                    path.write_bytes(contents)
                    with self.assertRaisesMessage(identity.Unicode16IdentityError, "integrity mismatch"):
                        identity._load_casefold_table()

    def test_casefold_and_strip_are_identical_in_each_available_interpreter(self):
        interpreters = json.loads(os.environ.get("CAMELLIA_REMOTE_IDENTITY_TEST_PYTHONS", "[]")) or [sys.executable]
        self.assertIsInstance(interpreters, list)
        self.assertLessEqual(len(interpreters), 5)
        code = (
            "import hashlib, json; from api import username_unicode16 as u; "
            "text = ''.join(chr(n) for n in range(0x110000)); "
            "print(json.dumps([hashlib.sha256(u.full_casefold(text).encode('utf-8', 'surrogatepass')).hexdigest(), "
            "[ord(c) for c in u.STRIP_CHARACTERS]]))"
        )
        expected = None
        for interpreter in interpreters:
            self.assertIsInstance(interpreter, str)
            result = subprocess.run(  # noqa: S603 - explicit test-controlled executable, no shell.
                [interpreter, "-c", code],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            actual = json.loads(result.stdout)
            if expected is None:
                expected = actual
            self.assertEqual(actual, expected)
