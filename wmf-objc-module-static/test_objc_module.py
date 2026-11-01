import copy
import hashlib
import struct
import unittest

import objc_module_collect as subject


class Image:
    def __init__(self):
        self.uuid = 'selected-uuid'
        self.whole_sha256 = 'a' * 64
        self.slice_sha256 = 'b' * 64
        self.text = dict(addr=0x1000, size=24)
        self.function_starts = [0x1000, 0x1008, 0x1010]
        self.symbols = [dict(index=0, name='_objc_retain_x8', type=15, section=1, value=0x1008)]


def selected_pin(image):
    return dict(uuid=image.uuid, whole_file_sha256=image.whole_sha256,
        selected_slice_sha256=image.slice_sha256, text=copy.deepcopy(image.text),
        function_starts_count=3,
        function_starts_u64le_sha256=hashlib.sha256(b''.join(struct.pack('<Q', n) for n in image.function_starts)).hexdigest(),
        closed_functions=[dict(start='0x1000')], required_new_exact_nlist_records=copy.deepcopy(image.symbols))


class NewObjCModuleProfile(unittest.TestCase):
    def test_complete_new_provider_frontier_without_reading_old_or_new_body(self):
        image = Image()
        subject.verify_selected_module(image, selected_pin(image))

    def test_wrong_uuid_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.uuid = 'another-uuid'
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_same_uuid_changed_whole_file_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.whole_sha256 = 'c' * 64
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_same_whole_pin_changed_slice_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.slice_sha256 = 'c' * 64
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_changed_text_boundary_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.text['size'] -= 4
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_same_count_changed_function_interval_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.function_starts[-1] += 4
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_changed_current_frontier_nlist_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.symbols[0]['type'] = 1
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_ambiguous_current_frontier_name_refuses(self):
        image = Image()
        pin = selected_pin(image)
        image.symbols.append(copy.deepcopy(image.symbols[0]))
        image.symbols[-1]['index'] = 1
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)

    def test_closed_body_cannot_be_claimed_as_the_new_frontier(self):
        image = Image()
        pin = selected_pin(image)
        pin['closed_functions'].append(dict(start='0x1008'))
        with self.assertRaises(AssertionError): subject.verify_selected_module(image, pin)


if __name__ == '__main__':
    unittest.main()
