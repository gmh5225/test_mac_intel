"""New synthetic bytes exercise collection; no target instructions execute."""

import copy
import hashlib
import struct
import unittest
import uuid

import collect
from macho import MachO


def synthetic_image():
    text = struct.pack('<6I', 0x94000002, 0xd65f03c0, 0x94000002,
                       0xd65f03c0, 0xd61f0120, 0xd65f03c0)
    strings = bytearray(b'\0')
    symbols = bytearray()
    for number, name in enumerate(collect.SEEDS):
        string_index = len(strings)
        strings.extend(name.encode() + b'\0')
        symbols.extend(struct.pack('<IBBHQ', string_index, 0x0f, 1, 0,
                                   0x1400 + 8 * number))
    symoff = 0x500
    stroff = symoff + len(symbols)
    startoff = stroff + len(strings)
    starts = bytes((0x80, 0x08, 0x08, 0x08, 0))
    end = startoff + len(starts)
    section = struct.pack('<16s16sQQ8I', b'__text', b'__TEXT', 0x1400, len(text),
                          0x400, 2, 0, 0, 0x80000400, 0, 0, 0)
    commands = [
        struct.pack('<II16s4Q4I', 0x19, 152, b'__TEXT', 0x1000, 0x1000,
                    0, 0x400 + len(text), 7, 5, 1, 0) + section,
        struct.pack('<II16s4Q4I', 0x19, 72, b'__LINKEDIT', 0x2000, 0x1000,
                    symoff, end - symoff, 7, 1, 0, 0),
        struct.pack('<II', 0x1b, 24) + uuid.UUID(collect.EXPECTED_UUID).bytes,
        struct.pack('<6I', 0x32, 24, 7, 0x1a0500, 0x1a0500, 0),
        struct.pack('<6I', 0x2, 24, symoff, 3, stroff, len(strings)),
        struct.pack('<4I', 0x26, 16, startoff, len(starts)),
    ]
    raw_commands = b''.join(commands)
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, len(commands),
                         len(raw_commands), 0x80, 0)
    data = bytearray(end)
    data[:len(header + raw_commands)] = header + raw_commands
    data[0x400:0x400 + len(text)] = text
    data[symoff:stroff] = symbols
    data[stroff:startoff] = strings
    data[startoff:] = starts
    return bytes(data)


class StaticCollectionTests(unittest.TestCase):
    def setUp(self):
        self.raw = synthetic_image()
        self.image = MachO(self.raw)

    def test_complete_three_function_bytes_and_indirect_branch(self):
        result = collect.select_functions(self.image, (collect.SEEDS[0],))
        self.assertEqual([body['start'] for body in result['functions']],
                         ['0x1400', '0x1408', '0x1410'])
        self.assertEqual([body['collection_depth'] for body in result['functions']], [0, 1, 2])
        self.assertEqual(b''.join(bytes.fromhex(body['code_hex']) for body in result['functions']),
                         self.raw[0x400:0x418])
        self.assertEqual(result['indirect_branches'][0]['register'], 9)
        self.assertEqual(result['indirect_branches'][0]['kind'], 'BR')
        self.assertFalse(result['complete_call_closure_or_effect_or_lifetime_qualified'])

    def test_bounded_frontier_keeps_full_edge(self):
        result = collect.select_functions(self.image, (collect.SEEDS[0],), depth_limit=1)
        self.assertEqual(len(result['functions']), 2)
        edge = result['deferred_direct_edges'][0]
        self.assertEqual(edge['edge']['pc'], '0x1408')
        self.assertEqual(edge['edge']['target'], '0x1410')
        self.assertEqual(edge['reason'], 'outside_selected_direct_callee_layers')

    def test_missing_exact_seed_is_refused(self):
        with self.assertRaisesRegex(AssertionError, 'one exact N_SECT'):
            collect.select_functions(self.image, ('_not_a_seed',))

    def test_duplicate_exact_definition_is_refused(self):
        self.image.symbols.append(copy.deepcopy(self.image.symbols[0]))
        with self.assertRaisesRegex(AssertionError, 'one exact N_SECT'):
            collect.select_functions(self.image)

    def test_seed_inside_function_is_refused(self):
        self.image.symbols[0]['value'] += 4
        with self.assertRaisesRegex(AssertionError, 'exact function start'):
            collect.select_functions(self.image)

    def test_distinct_names_sharing_one_entry_are_retained(self):
        self.image.symbols[1]['value'] = self.image.symbols[0]['value']
        result = collect.select_functions(self.image)
        self.assertEqual(len(result['seeds']), 3)
        self.assertEqual(len(result['functions']), 3)
        self.assertEqual(result['seeds'][0]['complete_nlist_record']['value'],
                         result['seeds'][1]['complete_nlist_record']['value'])

    def test_collection_cap_fails_instead_of_truncating(self):
        with self.assertRaisesRegex(AssertionError, 'collection cap'):
            collect.select_functions(self.image, (collect.SEEDS[0],), function_limit=2)

    def test_current_candidate_identity_is_required(self):
        collect.validate_image(self.image, collect.EXPECTED_UUID)
        with self.assertRaisesRegex(AssertionError, 'UUID differs'):
            collect.validate_image(self.image, '00000000-0000-0000-0000-000000000000')
        self.image.versions[0]['platform'] = 1
        with self.assertRaises(AssertionError):
            collect.validate_image(self.image, collect.EXPECTED_UUID)

    def test_executable_is_not_a_provider_dylib(self):
        self.image.header['filetype'] = 2
        with self.assertRaisesRegex(AssertionError, 'MH_DYLIB'):
            collect.validate_image(self.image, collect.EXPECTED_UUID)

    def test_fat_container_and_selected_slice_hashes_are_distinct(self):
        fat = struct.pack('>7I', 0xcafebabe, 1, 0x100000c, 0, 0x1000, len(self.raw), 12)
        data = fat + b'\0' * (0x1000 - len(fat)) + self.raw
        image = MachO(data)
        collect.validate_image(image, collect.EXPECTED_UUID)
        self.assertEqual(image.slice_offset, 0x1000)
        self.assertEqual(image.slice_sha256, hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(image.whole_sha256, hashlib.sha256(data).hexdigest())
        self.assertNotEqual(image.slice_sha256, image.whole_sha256)

    def test_function_start_payload_is_complete(self):
        context = collect.raw_context(self.image)
        self.assertEqual(len(context['linkedit_payloads']), 1)
        payload = context['linkedit_payloads'][0]['raw']
        self.assertEqual(payload['data_hex'], '8008080800')
        self.assertEqual(payload['bytes'], 5)
        self.assertEqual(context['declared_fixup_pages'], [])

    def test_invalid_declared_context_range_is_refused(self):
        self.image.commands[-1]['bytes_hex'] = struct.pack(
            '<4I', 0x26, 16, len(self.raw) - 1, 5).hex()
        with self.assertRaises(AssertionError):
            collect.raw_context(self.image)

    def test_unresolved_external_branch_is_retained(self):
        data = bytearray(self.raw)
        struct.pack_into('<I', data, 0x400, 0x94000100)  # 0x1400 -> 0x1800.
        result = collect.select_functions(MachO(bytes(data)), (collect.SEEDS[0],))
        self.assertEqual(len(result['functions']), 1)
        edge = result['deferred_direct_edges'][0]
        self.assertEqual(edge['edge']['target_identity']['kind'], 'unresolved_external_address')
        self.assertEqual(edge['edge']['target'], '0x1800')

    def test_interior_callee_edge_retains_nonentry_identity(self):
        data = bytearray(self.raw)
        struct.pack_into('<I', data, 0x400, 0x94000003)  # 0x1400 -> 0x140c.
        result = collect.select_functions(MachO(bytes(data)), (collect.SEEDS[0],))
        edge = result['functions'][0]['direct_branches'][0]
        self.assertEqual(edge['target'], '0x140c')
        self.assertFalse(edge['target_identity']['exact_function_entry'])
        self.assertEqual(result['functions'][1]['start'], '0x1408')
        self.assertEqual(result['functions'][1]['end'], '0x1410')

    def test_callee_cycle_does_not_expand_or_self_certify(self):
        data = bytearray(self.raw)
        struct.pack_into('<I', data, 0x408, 0x97fffffe)  # 0x1408 -> 0x1400.
        result = collect.select_functions(MachO(bytes(data)), (collect.SEEDS[0],))
        self.assertEqual(len(result['functions']), 2)
        self.assertFalse(result['complete_call_closure_or_effect_or_lifetime_qualified'])


if __name__ == '__main__':
    unittest.main()
