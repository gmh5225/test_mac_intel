"""Check checkout normalization without weakening source authentication."""

import unittest
from unicorn_header_input import corrected_header


class HeaderInputTests(unittest.TestCase):
    original = b"/* retained license */\n#if defined(_WIN64)\nbody\n#endif\n"

    def test_lf_checkout_preserves_the_complete_body(self):
        expected = b"/* retained license */\n#if defined(_WIN64) && !defined(__aarch64__)\nbody\n#endif\n"
        self.assertEqual(corrected_header(self.original, self.original), expected)

    def test_crlf_checkout_has_the_same_compiler_input(self):
        self.assertEqual(
            corrected_header(self.original.replace(b"\n", b"\r\n"), self.original),
            corrected_header(self.original, self.original),
        )

    def test_changed_source_bytes_fail_authentication(self):
        with self.assertRaisesRegex(ValueError, "pinned Git input"):
            corrected_header(self.original.replace(b"body", b"other"), self.original)

    def test_missing_guard_fails_before_any_copy(self):
        changed = self.original.replace(b"_WIN64", b"_WIN32")
        with self.assertRaisesRegex(ValueError, "setjmp guard"):
            corrected_header(changed, changed)

    def test_duplicate_guard_is_ambiguous(self):
        changed = self.original + self.original
        with self.assertRaisesRegex(ValueError, "setjmp guard"):
            corrected_header(changed, changed)
