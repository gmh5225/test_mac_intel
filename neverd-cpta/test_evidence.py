"""Negative controls for admitting a real, complete guest observation."""

import json
import unittest

import generated_memory
import run


class EvidenceTests(unittest.TestCase):
    def transcript(self, changes=None, omit=None, config=None):
        config = run.CONFIG if config is None else config
        values = dict(config["gate_values"])
        values[config["pfr_record"]] = 0x11
        values[config["isar_record"]] = config["cpa2_level"]
        values[config["passed_record"]] = config["expected_passed_cases"]
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
        for name, expected in run.CONFIG["gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(run.assess(self.transcript({name: expected ^ 1}), 0)["passed"])
        self.assertFalse(run.assess(self.transcript({
            run.CONFIG["passed_record"]: run.CONFIG["expected_passed_cases"] - 1
        }), 0)["passed"])
        self.assertFalse(run.assess(self.transcript(), 1)["passed"])

    def test_empty_truncated_duplicate_and_unexpected_exception_fail(self):
        self.assertFalse(run.assess("", 0)["passed"])
        with self.assertRaises(ValueError):
            run.assess(self.transcript() + '\n{"name":', 0)
        with self.assertRaises(ValueError):
            run.assess(self.transcript() + "\n" + self.transcript(), 0)
        self.assertFalse(run.assess(self.transcript() + "\n" + run.CONFIG["unexpected_marker"], 0)["passed"])

    def test_generated_output_retains_its_narrow_qualification(self):
        config = generated_memory.configuration()
        result = generated_memory.assess(self.transcript(config=config), 0)
        self.assertTrue(result["passed"])
        self.assertTrue(result["explicit_immediate_memory_output_qualified"])
        self.assertFalse(result["neverd_output_qualified"])
        self.assertFalse(result["native_apple_cpta_qualified"])

    def test_every_missing_or_wrong_generated_observation_fails(self):
        config = generated_memory.configuration()
        for name, expected in generated_memory.CONFIG["generated_gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=name, config=config), 0)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({name: expected ^ 1}, config=config), 0)["passed"])

    def test_input_report_requires_every_named_test_and_one_export(self):
        cases = []
        suite = None
        for identity in generated_memory.CONFIG["test_report_cases"]:
            suite, name = identity.rsplit(".", 1)
            cases.append({"name": name, "status": "RUN", "result": "COMPLETED"})
        cases[0][generated_memory.CONFIG["artifact_property"]] = self.id()
        report = {"tests": len(cases), "failures": 0, "errors": 0,
                  "testsuites": [{"name": suite, "testsuite": cases}]}
        self.assertEqual(generated_memory.validate_test_report(report), self.id())
        invalid = json.loads(json.dumps(report))
        invalid["testsuites"][0]["testsuite"].pop()
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(invalid)
        for key, value in (("status", "NOTRUN"), ("result", "SKIPPED"),
                           ("name", cases[0]["name"])):
            invalid = json.loads(json.dumps(report))
            invalid["testsuites"][0]["testsuite"][-1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                generated_memory.validate_test_report(invalid)
        del cases[0][generated_memory.CONFIG["artifact_property"]]
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(report)

    def test_stack_profile_requires_effective_alignment_in_every_mode(self):
        profile = generated_memory.select_profile("stack")
        config = generated_memory.configuration(profile)
        text = self.transcript(config=config)
        result = generated_memory.assess(text, 0, profile)
        self.assertTrue(result["explicit_raw_sp_memory_output_qualified"])
        self.assertFalse(result["neverd_output_qualified"])
        self.assertFalse(result["native_apple_cpta_qualified"])
        self.assertNotIn("explicit_immediate_memory_output_qualified", result)
        for name, expected in profile["generated_gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=name, config=config), 0, profile)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({name: expected ^ 1}, config=config),
                    0, profile)["passed"])
        self.assertFalse(generated_memory.assess(text, 1, profile)["passed"])
        self.assertFalse(generated_memory.assess(text, 0)["passed"])
        with self.assertRaises(ValueError):
            generated_memory.select_profile(self.id())

    def test_stack_profile_requires_its_actual_tests_and_export(self):
        profile = generated_memory.select_profile("stack")
        cases = [{"name": identity.rsplit(".", 1)[1], "status": "RUN",
                  "result": "COMPLETED"}
                 for identity in profile["test_report_cases"]]
        suite = profile["test_report_cases"][0].rsplit(".", 1)[0]
        cases[0][profile["artifact_property"]] = self.id()
        report = {"tests": len(cases), "failures": 0, "errors": 0,
                  "testsuites": [{"name": suite, "testsuite": cases}]}
        self.assertEqual(generated_memory.validate_test_report(report, profile),
                         self.id())
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(report)
        cases[0][generated_memory.CONFIG["artifact_property"]] = cases[0].pop(
            profile["artifact_property"])
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(report, profile)

    def test_register_stack_profile_keeps_its_own_inventory_and_alignment(self):
        profile = generated_memory.select_profile("stack-register")
        config = generated_memory.configuration(profile)
        text = self.transcript(config=config)
        result = generated_memory.assess(text, 0, profile)
        self.assertTrue(result[profile["qualification_key"]])
        self.assertFalse(result["neverd_output_qualified"])
        self.assertFalse(result["native_apple_cpta_qualified"])
        for other in ("immediate", "stack"):
            self.assertFalse(generated_memory.assess(
                text, 0, generated_memory.select_profile(other))["passed"])
        for name, expected in profile["generated_gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=name, config=config), 0, profile)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({name: expected ^ 1}, config=config),
                    0, profile)["passed"])
        self.assertFalse(generated_memory.assess(text, 1, profile)["passed"])

    def test_register_stack_profile_rejects_an_immediate_export(self):
        profile = generated_memory.select_profile("stack-register")
        immediate = generated_memory.select_profile("stack")
        cases = [{"name": identity.rsplit(".", 1)[1], "status": "RUN",
                  "result": "COMPLETED"}
                 for identity in profile["test_report_cases"]]
        suite = profile["test_report_cases"][0].rsplit(".", 1)[0]
        cases[0][immediate["artifact_property"]] = self.id()
        report = {"tests": len(cases), "failures": 0, "errors": 0,
                  "testsuites": [{"name": suite, "testsuite": cases}]}
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(report, profile)
        cases[0][profile["artifact_property"]] = self.id()
        self.assertEqual(generated_memory.validate_test_report(report, profile),
                         self.id())
        cases[-1][profile["artifact_property"]] = self.id()
        with self.assertRaises(ValueError):
            generated_memory.validate_test_report(report, profile)

    def test_register_profile_rejects_immediate_counts_and_stack_scope(self):
        profile = generated_memory.select_profile("register")
        config = generated_memory.configuration(profile)
        text = self.transcript(config=config)
        result = generated_memory.assess(text, 0, profile)
        self.assertTrue(result[profile["qualification_key"]])
        self.assertFalse(result["neverd_output_qualified"])
        self.assertFalse(result["native_apple_cpta_qualified"])
        for other in ("immediate", "stack", "stack-register"):
            self.assertFalse(generated_memory.assess(
                text, 0, generated_memory.select_profile(other))["passed"])
        for name, expected in profile["generated_gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(generated_memory.assess(
                    self.transcript({name: expected ^ 1}, config=config),
                    0, profile)["passed"])

    def test_el0_environment_requires_each_hardware_origin_and_result(self):
        config = run.el0_configuration()
        text = self.transcript(config=config)
        result = run.assess(text, 0, config)
        self.assertTrue(result["passed"])
        self.assertFalse(result["neverd_output_qualified"])
        self.assertFalse(result["native_apple_cpta_qualified"])
        self.assertFalse(run.assess(self.transcript(), 0, config)["passed"])
        self.assertFalse(run.assess(text, 1, config)["passed"])
        for name, expected in run.CONFIG["el0_control"]["gate_values"].items():
            with self.subTest(name=name):
                self.assertFalse(run.assess(
                    self.transcript(omit=name, config=config), 0, config)["passed"])
                self.assertFalse(run.assess(
                    self.transcript({name: expected ^ 1}, config=config),
                    0, config)["passed"])

    def test_el0_output_profiles_cannot_borrow_el1_or_other_sample_counts(self):
        for profile_name, el1_name in (("el0-immediate", "immediate"),
                                       ("el0-register", "register"),
                                       ("el0-image-relocated", "image-relocated")):
            profile = generated_memory.select_profile(profile_name)
            config = generated_memory.configuration(profile)
            text = self.transcript(config=config)
            result = generated_memory.assess(text, 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            self.assertFalse(generated_memory.assess(text, 1, profile)["passed"])
            el1 = generated_memory.select_profile(el1_name)
            self.assertFalse(generated_memory.assess(
                self.transcript(config=generated_memory.configuration(el1)),
                0, profile)["passed"])
            for name, expected in profile["generated_gate_values"].items():
                with self.subTest(profile=profile_name, name=name):
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=name, config=config),
                        0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({name: expected ^ 1}, config=config),
                        0, profile)["passed"])

    def test_distinct_output_profiles_require_their_own_export(self):
        for name in generated_memory.CONFIG["profiles"]:
            profile = generated_memory.select_profile(name)
            if profile["artifact_property"] == generated_memory.CONFIG["artifact_property"]:
                continue
            cases = [{"name": identity.rsplit(".", 1)[1], "status": "RUN",
                      "result": "COMPLETED"}
                     for identity in profile["test_report_cases"]]
            suite = profile["test_report_cases"][0].rsplit(".", 1)[0]
            cases[0][generated_memory.CONFIG["artifact_property"]] = self.id()
            report = {"tests": len(cases), "failures": 0, "errors": 0,
                      "testsuites": [{"name": suite, "testsuite": cases}]}
            with self.assertRaises(ValueError):
                generated_memory.validate_test_report(report, profile)
            cases[-1][profile["artifact_property"]] = self.id()
            self.assertEqual(generated_memory.validate_test_report(report, profile),
                             self.id())
            cases[0][profile["artifact_property"]] = self.id()
            with self.assertRaises(ValueError):
                generated_memory.validate_test_report(report, profile)


if __name__ == "__main__":
    unittest.main()
