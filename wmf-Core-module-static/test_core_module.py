import copy
import hashlib
import unittest

import core_module_collect as subject


class Image:
    def __init__(self):
        self.text = dict(addr=0x1000, size=64)
        self.function_starts = [0x1000, 0x1008, 0x1018, 0x1020, 0x1030]
        self.calls = []

    def function(self, start):
        assert start != 0x1018, 'closed body must not be read again'
        self.calls.append(start)
        index = self.function_starts.index(start)
        end = (self.function_starts[index + 1] if index + 1 < len(self.function_starts)
               else self.text['addr'] + self.text['size'])
        return dict(start=hex(start), end=hex(end), size=end - start)


def closed():
    return dict(start='0x1018', end='0x1020', size=8, code_sha256='1' * 64)


class NewCoreModule(unittest.TestCase):
    def test_full_new_domain_without_reading_closed_body_or_bytes(self):
        image = Image()
        domain = subject.module_remainder(image, [closed()], 24)
        self.assertEqual(image.calls, [0x1000, 0x1008, 0x1020, 0x1030])
        self.assertEqual(sum(r['size'] for r in domain['complete_new_functions']), 56)
        self.assertEqual(domain['old_body_function_reads_or_disassemblies'], 0)

    def test_short_closed_boundary_refuses_before_new_reads(self):
        image = Image()
        row = closed()
        row['end'] = '0x101c'
        with self.assertRaises(AssertionError):
            subject.module_remainder(image, [row], 24)
        self.assertEqual(image.calls, [])

    def test_duplicate_closed_refuses(self):
        with self.assertRaises(AssertionError):
            subject.closed_metadata_ranges(Image(), [closed(), closed()])

    def test_unowned_text_prefix_refuses(self):
        image = Image()
        image.function_starts.pop(0)
        with self.assertRaises(AssertionError):
            subject.module_remainder(image, [closed()], 24)

    def test_byte_target_chunks_only_at_whole_function_boundaries(self):
        domain = subject.module_remainder(Image(), [closed()], 24)
        self.assertEqual(domain['new_disassembly_ranges'],
            [dict(start='0x1000', end='0x1018'), dict(start='0x1020', end='0x1030'),
             dict(start='0x1030', end='0x1040')])

    def test_oversized_single_function_remains_complete(self):
        self.assertEqual(subject.disassembly_chunks(
            [dict(start='0x1000', end='0x1100')], 64), [(0x1000, 0x1100)])

    def test_changed_new_interval_refuses_complete_metadata_plan(self):
        domain = subject.module_remainder(Image(), [closed()], 24)
        pin = dict(new_function_count=4, new_bytes=56,
                   new_interval_u64le_pair_sha256=domain['new_interval_u64le_pair_sha256'])
        subject.verify_new_plan(domain, pin)
        bad = copy.deepcopy(domain)
        bad['complete_new_functions'][0]['end'] = '0x1004'
        with self.assertRaises(AssertionError):
            subject.verify_new_plan(bad, pin)

    def test_new_raw_data_avoids_old_overlap(self):
        image = Image()
        image.sections = [dict(name='__const', flags=0, offset=0, size=16)]
        image.data = bytes(range(16))
        old = [dict(slice_file_offset=4, bytes=8, sha256=hashlib.sha256(image.data[4:12]).hexdigest())]
        result = subject.noncode_remainder(image, old)
        raw = result['sections'][0]['new_raw_ranges']
        self.assertEqual([(r['slice_file_offset'], r['bytes']) for r in raw], [(0, 4), (12, 4)])

    def test_zero_fill_is_not_a_file_read_or_live_value(self):
        image = Image()
        image.sections = [dict(name='__common', flags=1, offset=0, size=4096)]
        result = subject.noncode_remainder(image, [])
        self.assertEqual(result['sections'],
            [dict(section=image.sections[0], zero_fill_declaration_only=True)])
        self.assertTrue(result['initial_file_bytes_are_not_live_runtime_values'])


if __name__ == '__main__':
    unittest.main()
