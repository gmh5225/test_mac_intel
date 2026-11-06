import unittest

import collect


class ImportedABIBoundaries(unittest.TestCase):
    def fixture(self):
        lines = ['target triple = "arm64-apple-ios18.0.0"',
                 'target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"']
        for label, symbol in collect.SYMBOLS.items():
            lines += ['declare swiftcc void @"' + symbol + '"(ptr sret(%T) noalias, i64, ptr swiftself) #7',
                      '  call swiftcc void @"' + symbol + '"(ptr sret(%T) %out, i64 %s, ptr swiftself %self)',
                      'define swiftcc void @"nd_sdk_network_' + label + '"() {']
        lines.append('attributes #7 = { nounwind "frame-pointer"="all" }')
        return "\n".join(lines)

    def test_preserves_imported_carriers_and_attributes(self):
        result = collect.client_ir(self.fixture())
        self.assertEqual(len(result['imports']), 3)
        row = result['imports']['port_setter']
        self.assertIn('ptr sret(%T) noalias, i64, ptr swiftself', row['declaration'])
        self.assertIn('nounwind', row['declaration_attribute_groups']['7'])
        self.assertIn('ptr swiftself %self', row['direct_calls'][0])

    def test_wrapper_abi_cannot_substitute_for_import(self):
        text = self.fixture().replace('declare ', 'define ')
        with self.assertRaises(ValueError):
            collect.client_ir(text)

    def test_missing_each_import_refuses(self):
        for symbol in collect.SYMBOLS.values():
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                collect.client_ir(self.fixture().replace(symbol, 'unrelated'))

    def test_prefix_match_cannot_substitute_for_exact_symbol(self):
        for symbol in collect.SYMBOLS.values():
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                collect.client_ir(self.fixture().replace(symbol, symbol + 'suffix'))

    def test_declaration_without_call_refuses(self):
        text = '\n'.join(line for line in self.fixture().splitlines() if '  call ' not in line)
        with self.assertRaises(ValueError):
            collect.client_ir(text)

    def test_duplicate_import_refuses(self):
        text = self.fixture()
        text += '\n' + next(line for line in text.splitlines() if line.startswith('declare '))
        with self.assertRaises(ValueError):
            collect.client_ir(text)

    def test_missing_or_duplicate_attribute_group_refuses(self):
        text = self.fixture()
        attribute = text.splitlines()[-1]
        for changed in [text.replace(attribute, ''), text + '\n' + attribute]:
            with self.assertRaises(ValueError):
                collect.client_ir(changed)

    def test_missing_or_duplicate_target_refuses(self):
        text = self.fixture()
        for changed in [text.replace('target triple', 'unrelated'),
                        text.replace('target datalayout', 'unrelated'),
                        text + '\ntarget triple = "x86_64-apple-macos15.0.0"']:
            with self.assertRaises(ValueError):
                collect.client_ir(changed)

    def test_missing_client_wrapper_refuses(self):
        text = self.fixture().replace('nd_sdk_network_port_setter', 'unrelated')
        with self.assertRaises(ValueError):
            collect.client_ir(text)

    def test_unquoted_llvm_identifiers_preserve_same_import(self):
        text = self.fixture()
        for symbol in collect.SYMBOLS.values():
            text = text.replace('@"' + symbol + '"', '@' + symbol)
        self.assertEqual(len(collect.client_ir(text)['imports']), 3)


if __name__ == '__main__':
    unittest.main()
