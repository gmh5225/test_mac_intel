"""A mismatched module must never receive a best-effort provider edit."""
import unittest
from patch_descriptor import patch


class PatchBoundaryTests(unittest.TestCase):
    def test_refuses_unpinned_inputs(self):
        for arch in ["x64", "arm64"]:
            for data in [b"", b'return Pte("/proc/self/exe",Ute)', b"\xff", b"export {};\n"]:
                with self.subTest(arch=arch, data=data), self.assertRaises(AssertionError):
                    patch(data, arch)


if __name__ == "__main__":
    unittest.main()
