"""Reject old exports and weakened PAC evidence for original-x8 calls."""

import copy
import json
import unittest

import authenticated_calls as calls
import result_storage_calls as storage
import test_authenticated_calls as integer_tests


class ResultStorageCallTests(unittest.TestCase):
    def test_integer_exports_do_not_qualify_result_storage(self):
        with self.assertRaises(ValueError):
            calls.validate_test_report(integer_tests.AuthenticatedCallTests().report(),
                                       storage.CONFIG)

    def test_every_gate_is_required_without_syndrome_exceptions(self):
        previous = copy.deepcopy(calls.CONFIG)
        for route in storage.CONFIG["routes"]:
            for feature in storage.CONFIG["features"]:
                for el0 in (False, True):
                    config = calls.configuration(route, feature, el0, storage.CONFIG)
                    values = {**config["gate_values"], config["pfr_record"]: 0x11,
                              config["isar_record"]: config["cpa2_level"],
                              config["passed_record"]: config["expected_passed_cases"]}

                    def assess(records):
                        transcript = "\n".join(
                            json.dumps({"name": key, "value": hex(value)},
                                       separators=(",", ":"))
                            for key, value in records.items())
                        return calls.assess(transcript, 0, route, feature, el0,
                                            storage.CONFIG)

                    self.assertTrue(assess(values)["original_exception_class_qualified"])
                    self.assertFalse(assess(values)["native_apple_cpta_qualified"])
                    for gate in config["gate_values"]:
                        for remove in (False, True):
                            changed = dict(values)
                            if remove:
                                del changed[gate]
                            else:
                                changed[gate] ^= 1
                            with self.subTest(route=route, feature=feature,
                                              el0=el0, gate=gate, remove=remove):
                                self.assertFalse(assess(changed)["passed"])
        self.assertEqual(calls.CONFIG, previous)


if __name__ == "__main__":
    unittest.main()
