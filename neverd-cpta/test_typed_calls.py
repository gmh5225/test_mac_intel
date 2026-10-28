"""Keep Darwin ABI and unchanged-instruction qualification boundaries explicit."""

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import authenticated_calls as calls
import macho_text
import typed_calls as typed
import test_authenticated_calls as integer_tests


EXPECTED = json.loads((typed.ROOT / "CptaTypedCallTestCases.def").read_text())


class TypedCallTests(unittest.TestCase):
    def test_darwin_fixed_spills_and_variadic_tail_are_distinct(self):
        by_name = {shape["name"]: shape for shape in typed.POLICY["shapes"]}
        floats, stack = typed.placements(by_name["f32-ten"])
        self.assertEqual(stack, 8)
        self.assertEqual([item["offset"] for item in floats if item["bank"] == "stack"], [0, 4])
        doubles, stack = typed.placements(by_name["f64-ten"])
        self.assertEqual(stack, 16)
        self.assertEqual([item["offset"] for item in doubles if item["bank"] == "stack"], [0, 8])
        for name in ("variadic-double", "variadic-mixed"):
            locations, stack = typed.placements(by_name[name])
            self.assertEqual(stack, 72)
            self.assertEqual([item["bank"] for item in locations[1:]], ["stack"] * 9)
            self.assertEqual([item["offset"] for item in locations[1:]], list(range(0, 72, 8)))

    def test_narrow_register_extensions_and_packed_stack_bytes(self):
        shapes = {shape["name"]: shape for shape in typed.POLICY["shapes"]}
        for case in EXPECTED["layouts"]:
            with self.subTest(case=case):
                locations, stack = typed.placements(shapes[case["name"]])
                self.assertEqual(stack, case["stack"])
                self.assertEqual([location["offset"] for location in locations
                                  if location["bank"] == "stack"], case["offsets"])
        for case in EXPECTED["extensions"]:
            with self.subTest(case=case):
                scalar = typed.POLICY["kinds"][case["kind"]]
                self.assertEqual(typed.integer_bits(case["value"], scalar), case["register"])
                self.assertEqual(typed.integer_bits(case["value"], scalar, True), case["stack"])

    def test_composite_placement_preserves_whole_values(self):
        shapes = {shape["name"]: shape for shape in typed.POLICY["shapes"]}
        for case in EXPECTED["composite_layouts"]:
            with self.subTest(case=case):
                locations, stack = typed.placements(shapes[case["name"]])
                self.assertEqual(stack, case["stack"])
                self.assertEqual([location["bank"] for location in locations], case["banks"])
                self.assertEqual([location["reg"] for location in locations if location["bank"] != "stack"], case["registers"])
                self.assertEqual([location["offset"] for location in locations if location["bank"] == "stack"], case["offsets"])

    def test_typed_profile_does_not_weaken_the_integer_contract(self):
        integer = copy.deepcopy(calls.CONFIG)
        helper = integer_tests.AuthenticatedCallTests()
        for route in typed.CONFIG["routes"]:
            for feature in typed.CONFIG["features"]:
                for el0 in (False, True):
                    config = calls.configuration(route, feature, el0, typed.CONFIG)
                    self.assertEqual(config["gate_values"]["neverd-memory-samples"], EXPECTED["samples"])
                    self.assertEqual(config["gate_values"]["neverd-pauth-faults-on"], EXPECTED["faults_per_mode"])
                    self.assertFalse(calls.assess(helper.transcript(route, feature, el0),
                                                  0, route, feature, el0, typed.CONFIG)["passed"])
        self.assertEqual(calls.CONFIG, integer)
        report = {"tests": 1, "failures": 0, "errors": 0, "testsuites": [{
            "name": "AArch64AuthenticatedCall", "testsuite": [{
                "name": "ExplicitTypesKeepAuthenticationOnTheCall", "status": "RUN",
                "result": "COMPLETED", typed.CONFIG["artifact_property"]: self.id()}]}]}
        self.assertEqual(calls.validate_test_report(report, typed.CONFIG), self.id())
        report["testsuites"][0]["testsuite"][0]["result"] = "SKIPPED"
        with self.assertRaises(ValueError):
            calls.validate_test_report(report, typed.CONFIG)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            typed.prepare_fixtures(directory, typed.CONFIG)
            self.assertNotIn("@", (directory / typed.CONFIG["fixtures"][0]["file"]).read_text())


class MachOTextTests(unittest.TestCase):
    def fixture(self, entry=0, relocations=0, cpu=None, name=b"_authenticated_dispatch"):
        config = macho_text.CONFIG
        def pack(kind, *values):
            return struct.pack(config[kind + "_format"], *values)
        text = bytes.fromhex("1f2003d5c0035fd6")
        header_size = struct.calcsize(config["header_format"])
        segment_size = (struct.calcsize(config["segment_format"])
                        + struct.calcsize(config["section_format"]))
        commands = segment_size + struct.calcsize(config["symbols_format"])
        text_offset = header_size + commands
        symbol_offset = text_offset + len(text)
        strings_offset = symbol_offset + struct.calcsize(config["symbol_format"])
        strings = b"\0" + name + b"\0"
        return (pack("header", config["magic"], config["cpu"] if cpu is None else cpu,
                     config["subtypes"][1], config["object"], 2, commands, 0, 0)
                + pack("segment", config["segment_command"], segment_size, b"", 0, len(text),
                       text_offset, len(text), 7, 7, 1, 0)
                + pack("section", config["text_section"].encode(), config["text_segment"].encode(),
                       0, len(text), text_offset, 2, 0, relocations, 0, 0, 0, 0)
                + pack("symbols", config["symbols_command"], struct.calcsize(config["symbols_format"]),
                       symbol_offset, 1, strings_offset, len(strings))
                + text + pack("symbol", 1, config["symbol_section_type"] | 1, 1, 0, entry) + strings)

    def test_preserves_instruction_bytes_and_the_exact_entry(self):
        text, entry = macho_text.extract(self.fixture(entry=4), "_authenticated_dispatch")
        self.assertEqual(text, bytes.fromhex("1f2003d5c0035fd6"))
        self.assertEqual(entry, 4)

    def test_refuses_relocation_wrong_cpu_missing_entry_and_truncation(self):
        fixture = self.fixture()
        for data in (self.fixture(relocations=1), self.fixture(cpu=0), self.fixture(entry=1),
                     self.fixture(entry=8), self.fixture(name=b"other"),
                     fixture[:31], fixture[:-1]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                macho_text.extract(data, "_authenticated_dispatch")


if __name__ == "__main__":
    unittest.main()
