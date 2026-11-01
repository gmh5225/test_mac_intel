import copy
import hashlib
import unittest

import zone_collect as subject


class Image:
    def __init__(self):
        self.text = dict(addr=0x1000, size=0x40)
        self.text_bytes = bytes(range(0x40))
        self.function_starts = [0x1000, 0x1008, 0x1018, 0x1020, 0x1030]
        self.calls = []

    def function(self, start):
        self.calls.append(start)
        index = self.function_starts.index(start)
        end = (self.function_starts[index + 1] if index + 1 < len(self.function_starts)
               else self.text['addr'] + self.text['size'])
        data = self.text_bytes[start - 0x1000:end - 0x1000]
        return dict(start=hex(start), end=hex(end), size=len(data),
                    code_sha256=hashlib.sha256(data).hexdigest())


def closed_record(image):
    return dict(start='0x1018', end='0x1020', size=8,
                code_sha256=hashlib.sha256(image.text_bytes[24:32]).hexdigest())


class StaticRemainder(unittest.TestCase):
    def test_complete_union_without_calling_closed_function_reader(self):
        image = Image()
        result = subject.malloc_remainder(image, [closed_record(image)])
        self.assertEqual(image.calls, [0x1000, 0x1008, 0x1020, 0x1030])
        self.assertEqual(result['new_disassembly_ranges'],
                         [dict(start='0x1000', end='0x1018'),
                          dict(start='0x1020', end='0x1040')])
        self.assertEqual(sum(row['size'] for row in result['complete_new_functions']), 56)

    def test_changed_closed_bytes_refuse_before_new_function_reads(self):
        image = Image()
        closed = closed_record(image)
        image.text_bytes = image.text_bytes[:24] + b'changed!' + image.text_bytes[32:]
        with self.assertRaises(AssertionError):
            subject.malloc_remainder(image, [closed])
        self.assertEqual(image.calls, [])

    def test_short_closed_interval_refuses(self):
        image = Image()
        closed = closed_record(image)
        closed['end'] = '0x101c'
        with self.assertRaises(AssertionError):
            subject.closed_body_ranges(image, [closed])

    def test_duplicate_closed_interval_refuses(self):
        image = Image()
        closed = closed_record(image)
        with self.assertRaises(AssertionError):
            subject.closed_body_ranges(image, [closed, copy.deepcopy(closed)])

    def test_unowned_text_prefix_refuses_complete_module_claim(self):
        image = Image()
        image.function_starts.remove(0x1000)
        with self.assertRaises(AssertionError):
            subject.malloc_remainder(image, [closed_record(image)])

    def test_overlapping_disassembly_intervals_refuse(self):
        with self.assertRaises(AssertionError):
            subject.disassembly_ranges([dict(start='0x1000', end='0x1010'),
                                        dict(start='0x1008', end='0x1018')])

    def test_partial_and_overlapping_prior_sections(self):
        self.assertEqual(subject.subtract_intervals(10, 50,
            [(0, 12), (20, 25), (23, 30), (40, 60), (70, 80)]), [(12, 20), (30, 40)])

    def test_zero_fill_never_reads_file_offset_zero(self):
        image = Image()
        image.sections = [dict(name='__bss', flags=1, offset=0, size=4096)]
        image.data = b''
        result = subject.new_noncode_sections(image,
            dict(sections=[], linkedit_payloads=[], declared_fixup_pages=[]))
        self.assertEqual(result['sections'],
            [dict(section=image.sections[0], zero_fill_declaration_only=True)])

    def test_raw_section_reads_only_new_nonoverlapping_bytes(self):
        image = Image()
        image.sections = [dict(name='__data', flags=0, offset=0, size=16)]
        image.data = bytes(range(16))
        raw = dict(slice_file_offset=4, bytes=8, data_hex=image.data[4:12].hex(),
                   sha256=hashlib.sha256(image.data[4:12]).hexdigest())
        result = subject.new_noncode_sections(image,
            dict(sections=[dict(raw=raw)], linkedit_payloads=[], declared_fixup_pages=[]))
        ranges = result['sections'][0]['new_raw_ranges']
        self.assertEqual([(row['slice_file_offset'], row['bytes']) for row in ranges],
                         [(0, 4), (12, 4)])
        self.assertEqual([row['data_hex'] for row in ranges], ['00010203', '0c0d0e0f'])


if __name__ == '__main__':
    unittest.main()
