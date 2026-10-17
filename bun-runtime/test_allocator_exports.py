import unittest
from allocator_exports import patch_script, verify_symbols, versions


class AllocatorAbiTests(unittest.TestCase):
    def test_platform_versions_preserve_libc_abi(self):
        self.assertEqual(versions("x64")["free"], "GLIBC_2.2.5")
        self.assertEqual(versions("x64")["aligned_alloc"], "GLIBC_2.16")
        self.assertEqual(set(versions("arm64").values()), {"GLIBC_2.17"})
        with self.assertRaises(AssertionError):
            versions("unqualified")

    def test_exports_keep_existing_public_versions_and_local_boundary(self):
        before = "BUN_1.2 {\n    global:\n        napi*;\n    local: *;\n};\n"
        after = patch_script(before, "x64")
        self.assertTrue(after.endswith(before))
        self.assertEqual(after.count("local:"), 1)
        with self.assertRaises(AssertionError):
            patch_script(after, "x64")

    def test_elf_gate_rejects_the_observed_hidden_and_misversioned_exports(self):
        correct = "\n".join(f"{i}: 1234 24 FUNC GLOBAL DEFAULT 14 {name}@@{version}"
                            for i, (name, version) in enumerate(versions("arm64").items()))
        self.assertEqual(verify_symbols(correct, "arm64"), versions("arm64"))
        for invalid in ["", correct.replace("free@@GLIBC_2.17", "free@@BUN_1.2"),
                        correct.replace("free@@GLIBC_2.17", "free"),
                        correct.replace("GLOBAL DEFAULT", "LOCAL HIDDEN"),
                        correct.replace("DEFAULT 14 malloc", "DEFAULT UND malloc")]:
            with self.assertRaises(AssertionError):
                verify_symbols(invalid, "arm64")


if __name__ == "__main__":
    unittest.main()
