"""Reject incomplete call exports and incorrect PAC exception evidence."""

import copy
import json
import unittest

import authenticated_calls as calls
import run


class AuthenticatedCallTests(unittest.TestCase):
    def report(self):
        cases = []
        for identity in calls.CONFIG["test_report_cases"]:
            suite, name = identity.rsplit(".", 1)
            cases.append({"name": name, "status": "RUN", "result": "COMPLETED"})
        for case in cases[:calls.CONFIG["export_count"]]:
            case[calls.CONFIG["artifact_property"]] = self.id()
        return {"tests": len(cases), "failures": 0, "errors": 0,
                "testsuites": [{"name": suite, "testsuite": cases}]}

    def transcript(self, route, feature, el0, changes=None, omit=None):
        config = calls.configuration(route, feature, el0)
        values = {**config["gate_values"], config["pfr_record"]: 0x11,
                  config["isar_record"]: config["cpa2_level"],
                  config["passed_record"]: config["expected_passed_cases"]}
        values.update(changes or {})
        return "\n".join(json.dumps({"name": name, "value": f"0x{value:016x}"},
                                    separators=(",", ":"))
                         for name, value in values.items() if name != omit)

    def test_all_named_tests_and_two_consistent_exports_are_mandatory(self):
        self.assertEqual(calls.validate_test_report(self.report()), self.id())
        variants = []
        missing = self.report()
        missing["testsuites"][0]["testsuite"].pop()
        variants.append(missing)
        mismatched = self.report()
        mismatched["testsuites"][0]["testsuite"][0][calls.CONFIG["artifact_property"]] += "-other"
        variants.append(mismatched)
        skipped = self.report()
        skipped["testsuites"][0]["testsuite"][-1]["result"] = "SKIPPED"
        variants.append(skipped)
        duplicate = self.report()
        duplicate["testsuites"][0]["testsuite"][-1] = duplicate["testsuites"][0]["testsuite"][0]
        variants.append(duplicate)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(ValueError):
                calls.validate_test_report(report)

    def test_matrix_retains_its_exact_qualification_boundaries(self):
        snapshots = copy.deepcopy(run.CONFIG)
        exact = 0
        for route in calls.CONFIG["routes"]:
            for feature in calls.CONFIG["features"]:
                for el0 in (False, True):
                    result = calls.assess(self.transcript(route, feature, el0),
                                          0, route, feature, el0)
                    self.assertTrue(result[calls.CONFIG["qualification_key"]])
                    self.assertFalse(result["neverd_output_qualified"])
                    self.assertFalse(result["native_apple_cpta_qualified"])
                    exact += result["exact_original_fault_syndrome"]
        self.assertEqual(exact, 22)
        self.assertEqual(run.CONFIG, snapshots)

    def test_missing_wrong_keys_controls_counts_and_syndromes_fail(self):
        for route in ("native", "high-O0"):
            feature = calls.CONFIG["features"][0]
            config = calls.configuration(route, feature, True)
            for name in ("call-key-readback", "call-controls", "call-pauth-level",
                         "neverd-pauth-faults-on", "call-differences-both",
                         "neverd-memory-on-el0-origin"):
                for transcript in (
                    self.transcript(route, feature, True, omit=name),
                    self.transcript(route, feature, True,
                                    changes={name: config["gate_values"][name] ^ 1}),
                ):
                    with self.subTest(route=route, name=name):
                        self.assertFalse(calls.assess(transcript, 0, route, feature, True)["passed"])
        self.assertFalse(calls.assess(self.transcript(route, feature, True),
                                      1, route, feature, True)["passed"])


if __name__ == "__main__":
    unittest.main()
