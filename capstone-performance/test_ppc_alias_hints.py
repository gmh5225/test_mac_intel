#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ppc_alias_hints", ROOT / "suite/synctools/ppc_alias_hints.py"
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class AliasHintGeneration(unittest.TestCase):
    @staticmethod
    def strings(values):
        offset = 0
        result = []
        for value in values:
            result.append((offset, value))
            offset += len(value)
        return result

    def test_first_row_unknown_dynamic_and_limit(self):
        strings = self.strings([
            b"move $\x01\0", b"move.w $\x01\0", b"absent\0",
            b"move$\x01\0", b"123456789abcdef r0\0",
            b"123456789abcdefg r0\0",
        ])
        entries = [b"move", b"move.w", b"move", b"123456789abcdef", b"123456789abcdefg"]
        shift, slots = GENERATOR.projection(strings, entries)
        self.assertEqual([slots[offset >> shift] for offset, _ in strings],
                         [1, 2, 0, 0, 4, 0])
        self.assertEqual(len({offset >> shift for offset, _ in strings}), len(strings))

    def test_bad_extent_and_width(self):
        cases = [[], [(1, b"move\0")], [(0, b"move")],
                 [(0, b"mo\0ve\0")], [(0, b"a\0"), (1, b"b\0")]]
        for strings in cases:
            with self.subTest(strings=strings), self.assertRaises(ValueError):
                GENERATOR.projection(strings, [b"move"])
        with self.assertRaises(ValueError):
            GENERATOR.projection([(0, b"move\0")], [b"move"] * 65536)

    def test_checkout_idempotence_and_regeneration(self):
        arch = ROOT / "arch/PowerPC"
        source = (arch / "PPCGenAsmWriter.inc").read_text()
        names = (arch / "PPCGenCSAliasMnemMap.inc").read_text()
        original = GENERATOR.original_writer(source)
        generated = GENERATOR.generate_writer(original, names)
        self.assertEqual(GENERATOR.original_writer(generated), original)
        self.assertEqual(GENERATOR.generate_writer(generated, names), generated)
        printer = (arch / "PPCInstPrinter.c").read_text()
        integrated = GENERATOR.integrate_printer(printer)
        self.assertEqual(GENERATOR.integrate_printer(integrated), integrated)

    def test_incomplete_projection_rejected(self):
        arch = ROOT / "arch/PowerPC"
        generated = GENERATOR.generate_writer(
            (arch / "PPCGenAsmWriter.inc").read_text(),
            (arch / "PPCGenCSAliasMnemMap.inc").read_text())
        with self.assertRaises(ValueError):
            GENERATOR.original_writer(generated.replace(GENERATOR.END, ""))
        with self.assertRaises(ValueError):
            GENERATOR.original_writer(generated.replace("*AliasHint =", "*ChangedHint ="))

    def test_unknown_pattern_offset_rejected(self):
        arch = ROOT / "arch/PowerPC"
        source = GENERATOR.original_writer((arch / "PPCGenAsmWriter.inc").read_text())
        names = (arch / "PPCGenCSAliasMnemMap.inc").read_text()
        at = source.index("static const AliasPattern Patterns[] = {")
        for offset in ["99999999", "0x10"]:
            changed, count = re.subn(r"\{\d+,", "{" + offset + ",", source[at:], count=1)
            self.assertEqual(count, 1)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                GENERATOR.generate_writer(source[:at] + changed, names)


if __name__ == "__main__":
    unittest.main()
