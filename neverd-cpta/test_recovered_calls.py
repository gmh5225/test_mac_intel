"""Recovered-call evidence must not inherit explicit-prototype qualification."""

import copy
import json
import tempfile
from pathlib import Path
import unittest

import authenticated_calls as calls
import recovered_calls as recovered
import recovered_result_storage_calls as recovered_storage
import result_storage_calls as storage
import test_authenticated_calls as integer_tests
import typed_calls as typed


class RecoveredCallTests(unittest.TestCase):
    def test_explicit_exports_cannot_qualify_recovered_calls(self):
        report = {"tests": len(typed.CONFIG["test_report_cases"]),
                  "failures": 0, "errors": 0, "testsuites": []}
        for identity in typed.CONFIG["test_report_cases"]:
            suite, name = identity.rsplit(".", 1)
            report["testsuites"].append({"name": suite, "testsuite": [{
                "name": name, "status": "RUN", "result": "COMPLETED",
                typed.CONFIG["artifact_property"]: self.id()}]})
        self.assertEqual(calls.validate_test_report(report, typed.CONFIG), self.id())
        with self.assertRaises(ValueError):
            calls.validate_test_report(report, recovered.CONFIG)
        self.assertTrue(set(recovered.CONFIG["test_report_cases"]).isdisjoint(
            typed.CONFIG["test_report_cases"]))

    def test_native_vectors_use_one_register_and_aligned_whole_stack_values(self):
        expected = json.loads((typed.ROOT / "CptaTypedCallTestCases.def").read_text())
        shapes = {shape["name"]: shape for shape in recovered.POLICY["native_shapes"]}
        for case in expected["native_vector_layouts"]:
            with self.subTest(case=case["name"]):
                locations, stack = typed.placements(shapes[case["name"]])
                self.assertEqual(stack, case["stack"])
                self.assertEqual([p["offset"] for p in locations if p["bank"] == "stack"],
                                 case["offsets"])
                self.assertEqual([p["reg"] for p in locations if p["bank"] == "vector"],
                                 case["vector_registers"])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            typed.prepare_fixtures(work, recovered.CONFIG)
            for fixture in recovered.CONFIG["fixtures"]:
                self.assertNotIn("@", (work / fixture["file"]).read_text())

    def test_recovered_storage_requires_its_own_passing_test(self):
        suites = []
        for identity in storage.CONFIG["test_report_cases"]:
            suite, name = identity.rsplit(".", 1)
            suites.append({"name": suite, "testsuite": [{
                "name": name, "status": "RUN", "result": "COMPLETED",
                storage.CONFIG["artifact_property"]: self.id()}]})
        report = {"tests": len(suites), "failures": 0, "errors": 0,
                  "testsuites": suites}
        self.assertEqual(calls.validate_test_report(report, storage.CONFIG), self.id())
        with self.assertRaises(ValueError):
            calls.validate_test_report(report, recovered_storage.CONFIG)
        for field in ("required_gates", "faults_per_mode", "modes", "routes"):
            self.assertEqual(recovered_storage.CONFIG[field], storage.CONFIG[field])
        self.assertNotEqual(recovered_storage.CONFIG["cases"], storage.CONFIG["cases"])

    def test_hva_whole_banks_nested_arrays_and_every_return_word(self):
        expected = json.loads((typed.ROOT / "CptaTypedCallTestCases.def").read_text())
        shapes = {shape["name"]: shape for shape in recovered.POLICY["native_shapes"]}
        for case in expected["hva_layouts"]:
            with self.subTest(case=case["name"]):
                locations, stack = typed.placements(shapes[case["name"]])
                self.assertEqual(stack, case["stack"])
                members = [p for p in locations if p["argument"] == case["hva_argument"]]
                self.assertEqual([p["reg"] for p in members if p["bank"] == "vector"], case["registers"])
                self.assertEqual([p["lane"] for p in members if p["bank"] == "vector"], case["lanes"])
                self.assertEqual([p["offset"] for p in members if p["bank"] == "stack"], case["offsets"])
        for kind in expected["non_hva_kinds"]:
            self.assertIsNone(typed.vector_shape(kind))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            typed.prepare_fixtures(work, recovered.CONFIG)
            source = "".join((work / item["file"]).read_text()
                             for item in recovered.CONFIG["fixtures"])
            for marker in expected["hva_observation_markers"]:
                self.assertIn(marker, source)

    def test_all_recovered_routes_require_original_exception_classes(self):
        original = copy.deepcopy(typed.CONFIG)
        helper = integer_tests.AuthenticatedCallTests()
        for route in recovered.CONFIG["routes"]:
            for feature in recovered.CONFIG["features"]:
                for el0 in (False, True):
                    config = calls.configuration(route, feature, el0,
                                                 recovered.CONFIG)
                    values = config["gate_values"]
                    transcript = helper.transcript(route, feature, el0,
                                                   changes=values)
                    result = calls.assess(transcript, 0, route, feature, el0,
                                          recovered.CONFIG)
                    self.assertTrue(result["original_exception_class_qualified"])
                    self.assertFalse(result["native_apple_cpta_qualified"])
                    for gate in values:
                        changed = {**values, gate: values[gate] ^ 1}
                        transcript = helper.transcript(route, feature, el0,
                                                       changes=changed)
                        self.assertFalse(calls.assess(
                            transcript, 0, route, feature, el0,
                            recovered.CONFIG)["passed"])
        self.assertEqual(typed.CONFIG, original)


if __name__ == "__main__":
    unittest.main()
