import struct
import unittest

import corpus
import run


class HarnessTests(unittest.TestCase):
    def test_value_mismatch_blocks_candidate(self):
        case = dict(name='fixture', consumer='decoder')
        row = dict(library_kind='capstone', instructions=3, rejected=1,
                   boundary_hash='abc', value_hash='def')
        with self.assertRaisesRegex(ValueError, 'Capstone output mismatch'):
            run.check_outputs([row, dict(row, value_hash='bad')], case)

    def test_cross_decoder_difference_is_not_hidden(self):
        case = dict(name='fixture', consumer='decoder')
        row = dict(library_kind='capstone', instructions=3, rejected=1,
                   boundary_hash='abc', value_hash='def')
        self.assertTrue(run.check_outputs([row, dict(row, library_kind='iced', value_hash='other')], case))
        self.assertFalse(run.check_outputs([row, dict(row, library_kind='iced', boundary_hash='bad')], case))

    def test_pe_uses_initialized_virtual_extent(self):
        data = bytearray(256)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 70, 1)
        data[88:96] = b'.text\0\0\0'
        struct.pack_into('<IIII', data, 96, 3, 4096, 8, 128)
        data[128:136] = b'abcPAD!!'
        self.assertEqual(corpus.pe_text(data), b'abc')
        with self.assertRaisesRegex(ValueError, 'truncated PE text'):
            corpus.pe_text(data[:130])

    def test_unsupported_elf_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, 'unsupported ELF header'):
            corpus.elf_text(b'invalid')


if __name__ == '__main__':
    unittest.main()
