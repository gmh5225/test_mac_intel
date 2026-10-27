"""Keep the musl CLI expectation correction limited to its observed case."""
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pcre2_test_fixture import adapt, OLD, NEW


class NativeLocaleFixture(unittest.TestCase):
    def test_requires_both_controls_and_preserves_surrounding_cases(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); path = root / 'expected'; delta = root / 'change.patch'
            raw = b'earlier cases\n' + OLD + b'later cases\n'; path.write_bytes(raw)
            for controlled in [dict(native_setlocale_accepts_name=False, actual_cli_no_match=True),
                               dict(native_setlocale_accepts_name=True, actual_cli_no_match=False)]:
                with self.assertRaises(AssertionError): adapt(path, delta, **controlled)
                self.assertEqual(path.read_bytes(), raw); self.assertFalse(delta.exists())
            with self.assertRaises(AssertionError): adapt(path, delta, native_setlocale_accepts_name=True, actual_cli_no_match=True)
            with patch('pcre2_test_fixture.ORIGINAL_SHA256', hashlib.sha256(raw).hexdigest()):
                receipt = adapt(path, delta, native_setlocale_accepts_name=True, actual_cli_no_match=True)
            self.assertEqual(path.read_bytes(), b'earlier cases\n' + NEW + b'later cases\n')
            self.assertEqual(receipt['test_cases_removed'], 0)
            self.assertFalse(receipt['PCRE2_runtime_source_changed'])
            self.assertTrue(receipt['actual_test_150_still_executed'])


if __name__ == '__main__': unittest.main()
