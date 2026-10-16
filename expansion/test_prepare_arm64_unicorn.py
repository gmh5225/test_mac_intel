"""Check checkout normalization without weakening source authentication."""

import unittest
from unicorn_header_input import corrected_handler, corrected_header, corrected_masks


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


class HandlerInputTests(unittest.TestCase):
    original = (
        b"/* retained license */\n#ifdef _WIN64\n    ptr = closure;\nretained body\n"
    )

    def test_native_handler_preserves_the_existing_x64_body(self):
        result = corrected_handler(self.original, self.original)
        self.assertTrue(
            result.startswith(b"/* retained license */\n#if defined(__aarch64__)\n")
        )
        self.assertTrue(
            result.endswith(
                b"#elif defined(_WIN64)\n    ptr = closure;\nretained body\n"
            )
        )
        self.assertIn(
            b"FlushInstructionCache(GetCurrentProcess(), closure, 32);", result
        )

    def test_crlf_handler_has_the_same_compiler_input(self):
        self.assertEqual(
            corrected_handler(self.original.replace(b"\n", b"\r\n"), self.original),
            corrected_handler(self.original, self.original),
        )

    def test_changed_or_ambiguous_handler_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned Git input"):
            corrected_handler(self.original + b"changed", self.original)
        with self.assertRaisesRegex(ValueError, "exception closure"):
            corrected_handler(
                self.original + self.original, self.original + self.original
            )


class ImmediateMaskTests(unittest.TestCase):
    original = (
        b"prefix\nt1 = t0 & ~(0xffffUL << s0);\nt2 = t1 & ~(0xffffUL << s1);\nsuffix\n"
    )

    def test_both_masks_are_wide_and_the_other_bytes_are_preserved(self):
        expected = self.original.replace(b"0xffffUL", b"0xffffULL")
        self.assertEqual(corrected_masks(self.original, self.original), expected)
        self.assertEqual(
            corrected_masks(self.original.replace(b"\n", b"\r\n"), self.original),
            expected,
        )

    def test_changed_or_missing_mask_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned Git input"):
            corrected_masks(self.original + b"changed", self.original)
        changed = self.original.replace(b"0xffffUL << s1", b"other")
        with self.assertRaisesRegex(ValueError, "immediate mask"):
            corrected_masks(changed, changed)
