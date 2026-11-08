"""Recovered-call evidence must not inherit explicit-prototype qualification."""

import copy
import unittest

import authenticated_calls as calls
import recovered_calls as recovered
import test_authenticated_calls as integer_tests
import typed_calls as typed


class RecoveredCallTests(unittest.TestCase):
    def test_explicit_exports_cannot_qualify_recovered_calls(self):
        report = integer_tests.AuthenticatedCallTests().report()
        with self.assertRaises(ValueError):
            calls.validate_test_report(report, recovered.CONFIG)
        self.assertTrue(set(recovered.CONFIG["test_report_cases"]).isdisjoint(
            typed.CONFIG["test_report_cases"]))

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
