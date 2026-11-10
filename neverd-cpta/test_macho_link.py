"""Qualify declared linker changes independently of the copied call body."""

import json
from pathlib import Path
import struct
import unittest

import macho_text

CASES = json.loads(Path(__file__).with_name("CptaMachOLinkTestCases.def").read_text())


class MachOLinkTests(unittest.TestCase):
    def test_compiler_relocation_is_explicit_and_the_default_stays_strict(self):
        data = bytes.fromhex(CASES["macho_hex"])
        with self.assertRaises(ValueError):
            macho_text.extract(data, CASES["symbol"])
        text, entry, relocations = macho_text.read(
            data, CASES["symbol"], CASES["runtime_calls"])
        self.assertEqual(text.hex(), CASES["text_hex"])
        self.assertEqual(entry, CASES["entry"])
        self.assertEqual(relocations, CASES["relocations"])
        with self.assertRaises(ValueError):
            macho_text.read(data.replace(CASES["relocations"][0]["symbol"].encode(),
                                         CASES["invalid_symbol"].encode()),
                            CASES["symbol"], CASES["runtime_calls"])

    def test_relocation_shape_and_instruction_are_validated(self):
        data = bytes.fromhex(CASES["macho_hex"])
        config = macho_text.CONFIG
        start = struct.calcsize(config["header_format"]) + struct.calcsize(config["segment_format"])
        section = struct.unpack_from(config["section_format"], data, start)
        for position in (section[4], section[6], section[6] + config["alignment"]):
            changed = bytearray(data)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                macho_text.read(changed, CASES["symbol"], CASES["runtime_calls"])

    def test_linked_image_keeps_every_other_byte_and_the_exact_call_target(self):
        data = bytes.fromhex(CASES["elf_hex"])
        symbols = macho_text.linked_symbols(data)
        text = bytes.fromhex(CASES["text_hex"])
        args = (symbols, CASES["renamed"], text, CASES["entry"],
                CASES["relocations"], CASES["runtime_calls"])
        macho_text.verify_linked(data, *args)
        address, section = symbols[CASES["renamed"]]
        start = section[4] + address - section[3]
        for offset in range(len(text)):
            changed = bytearray(data)
            changed[start + offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                macho_text.verify_linked(changed, *args)
        with self.assertRaises(ValueError):
            macho_text.linked_symbols(data[:len(data) // 2])


if __name__ == "__main__":
    unittest.main()
