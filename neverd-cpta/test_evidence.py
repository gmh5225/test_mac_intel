"""Negative controls for admitting a real, complete guest observation."""

import json
import unittest

import run


class EvidenceTests(unittest.TestCase):
    def transcript(self, changes=None, omit=None):
        values = dict(run.CONFIG["gate_values"])
        values[run.CONFIG["pfr_record"]] = 0x11
        values[run.CONFIG["isar_record"]] = run.CONFIG["cpa2_level"]
        values[run.CONFIG["passed_record"]] = run.CONFIG["expected_passed_cases"]
        values.update(changes or {})
        return "\n".join(
            json.dumps({"name": name, "value": f"0x{value:016x}"}, separators=(",", ":"))
            for name, value in values.items() if name != omit
        )

    def test_complete_model_control_preserves_qualification_limits(self):
        result = run.assess(self.transcript(), 0)
        self.assertTrue(result["passed"])
        self.assertTrue(result["model_only"])
        self.assertFalse(result["native_apple_cpta_qualified"])
        self.assertFalse(result["neverd_output_qualified"])

    def test_every_missing_record_fails(self):
        for name in run.CONFIG["required_records"]:
            with self.subTest(name=name):
                self.assertFalse(run.assess(self.transcript(omit=name), 0)["passed"])

    def test_unsupported_or_reserved_cpa_level_fails(self):
        for value in (0, 1, 3, 15):
            with self.subTest(value=value):
                self.assertFalse(run.assess(self.transcript({run.CONFIG["isar_record"]: value}), 0)["passed"])

    def test_unresolved_higher_el_gates_fail(self):
        for name in ("pfr_el2_shift", "pfr_el3_shift"):
            with self.subTest(name=name):
                value = 0x11 | (1 << run.CONFIG[name])
                self.assertFalse(run.assess(self.transcript({run.CONFIG["pfr_record"]: value}), 0)["passed"])

    def test_ineffective_cpta_or_failed_guest_fails(self):
        for name, value in (("sctlr2-el1-on", 0), ("sctlr2-el1-off", 512),
                            ("failed-cases", 1), ("guest-complete", 0),
                            ("passed-cases", run.CONFIG["expected_passed_cases"] - 1)):
            with self.subTest(name=name):
                self.assertFalse(run.assess(self.transcript({name: value}), 0)["passed"])
        self.assertFalse(run.assess(self.transcript(), 1)["passed"])

    def test_empty_truncated_duplicate_and_unexpected_exception_fail(self):
        self.assertFalse(run.assess("", 0)["passed"])
        with self.assertRaises(ValueError):
            run.assess(self.transcript() + '\n{"name":', 0)
        with self.assertRaises(ValueError):
            run.assess(self.transcript() + "\n" + self.transcript(), 0)
        self.assertFalse(run.assess(self.transcript() + "\n" + run.CONFIG["unexpected_marker"], 0)["passed"])


if __name__ == "__main__":
    unittest.main()
