"""Keep the musl allocator ABI distinct from the GNU versioned ABI."""
import unittest
from musl_allocator import SYMBOLS, patch_script, verify_symbols


class AllocatorABI(unittest.TestCase):
    def test_weak_alias_and_version_counterexamples(self):
        table = '\n'.join(f'{i}: 0000000000001000 8 FUNC {"WEAK" if name == "reallocarr" else "GLOBAL"} DEFAULT 16 {name}@@BUN_1.2' for i, name in enumerate(SYMBOLS))
        self.assertEqual(len(verify_symbols(table)['symbols']), 29)
        for invalid in [table.replace(' WEAK ', ' GLOBAL '), table.replace(' DEFAULT ', ' HIDDEN ', 1),
                        table.replace(' malloc@@BUN_1.2', ' malloc@@GLIBC_2.17'), '\n'.join(table.splitlines()[1:])]:
            with self.subTest(value=invalid[:60]), self.assertRaises(AssertionError): verify_symbols(invalid)

    def test_legacy_exports_and_local_boundary_are_preserved(self):
        before = 'BUN_1.2 {\n    global:\n        napi*;\n    local:\n        *;\n};\n'
        after = patch_script(before)
        self.assertTrue(after.endswith(before.split('    global:\n', 1)[1]))
        self.assertNotIn('GLIBC_', after)
        self.assertEqual(after.count('local:'), 1)
        self.assertTrue(all(after.count('        ' + name + ';\n') == 1 for name in SYMBOLS))


if __name__ == '__main__': unittest.main()
