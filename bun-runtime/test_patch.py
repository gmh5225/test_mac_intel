from pathlib import Path
import tempfile
import unittest
from patch_bun import patch


class PatchBoundaryTests(unittest.TestCase):
    def test_unqualified_entry_fails_without_writing_any_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"; entry = source / "src/runtime/bin_entry/mod.rs"
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b"fn main() {}\n")
            with self.assertRaisesRegex(AssertionError, "unqualified Bun"):
                patch(source, root / "evidence")
            self.assertEqual(entry.read_bytes(), b"fn main() {}\n")
            self.assertEqual(list(entry.parent.iterdir()), [entry])
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
