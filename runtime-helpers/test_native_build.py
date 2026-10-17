from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from build_native import native_machine, unpack_portable


class NativeBuildBoundaryTests(unittest.TestCase):
    def test_wrong_machine_is_rejected_even_with_valid_native_header(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture"
            path.write_bytes(struct.pack("<II", 0xfeedfacf, 0x1000007))
            self.assertEqual(native_machine(path, "Darwin", "x64"), 0x1000007)
            with self.assertRaises(AssertionError):
                native_machine(path, "Darwin", "arm64")
            data = bytearray(72)
            data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"; struct.pack_into("<H", data, 68, 0xaa64)
            path.write_bytes(data)
            self.assertEqual(native_machine(path, "Windows", "arm64"), 0xaa64)
            with self.assertRaises(AssertionError):
                native_machine(path, "Windows", "x64")

    def test_unexpected_windows_archive_alias_fails_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                member = tarfile.TarInfo("ripgrep-14.1.1/HomebrewFormula")
                member.type = tarfile.SYMTYPE; member.linkname = "../outside"
                stream.addfile(member)
            # Mock the platform decision only; constructing PosixPath still
            # uses the real host's pathlib implementation.
            with patch("build_native.os.name", "nt"):
                with self.assertRaises(AssertionError):
                    unpack_portable(archive, root / "target", "ripgrep-14.1.1/")
            self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
