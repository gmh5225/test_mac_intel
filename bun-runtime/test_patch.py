from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch as replace
import hashlib
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

    def test_unqualified_build_graph_refuses_before_entry_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"
            entry = source / "src/runtime/bin_entry/mod.rs"; entry.parent.mkdir(parents=True)
            original = b'mod c_abi_exports;\n    unsafe { bun_core::init_argv(argc, argv) };\n'
            entry.write_bytes(original)
            build = source / "scripts/build/bun.ts"; build.parent.mkdir(parents=True); build.write_bytes(b"unqualified")
            with replace("patch_bun.ENTRY_SHA256", hashlib.sha256(original).hexdigest()):
                with self.assertRaisesRegex(AssertionError, "unqualified Bun native build graph"):
                    patch(source, root / "evidence", root / "native")
            self.assertEqual(entry.read_bytes(), original)
            self.assertFalse((source / "recovery-native").exists())
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
