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
                                       ("el0-image", "image"),
                                       ("el0-image-relocated", "image-relocated"),
                                       ("el0-writeback", "writeback"),
                                       ("el0-vector-writeback", "vector-writeback"),
                                       ("el0-pair", "pair"),
                                       ("el0-ordered", "ordered"),
                                       ("el0-ordered-image", "ordered-image"),
                                       ("el0-ordered-image-relocated", "ordered-image-relocated")):
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

    def test_writeback_profiles_require_their_own_count_and_controls(self):
        for name in ("writeback", "el0-writeback"):
            profile = generated_memory.select_profile(name)
            self.assertIn("-DCPA_GENERATED_WRITEBACK_MEMORY=1", profile["guest_flags"])
            config = generated_memory.configuration(profile)
            text = self.transcript(config=config)
            result = generated_memory.assess(text, 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            for key, value in profile["generated_gate_values"].items():
                with self.subTest(profile=name, gate=key):
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=key, config=config), 0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({key: value ^ 1}, config=config),
                        0, profile)["passed"])
            for other in ("immediate", "register", "image", "image-relocated"):
                self.assertFalse(generated_memory.assess(
                    self.transcript(config=generated_memory.configuration(
                        generated_memory.select_profile(other))), 0, profile)["passed"])

    def test_vector_writeback_profiles_require_their_own_count_and_controls(self):
        for name in ("vector-writeback", "el0-vector-writeback"):
            profile = generated_memory.select_profile(name)
            self.assertIn("-DCPA_GENERATED_VECTOR_WRITEBACK_MEMORY=1", profile["guest_flags"])
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"], 100)
            self.assertIn("sizeof(vwb_cases)", profile["count_function"])
            config = generated_memory.configuration(profile)
            text = self.transcript(config=config)
            result = generated_memory.assess(text, 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            for key, value in profile["generated_gate_values"].items():
                with self.subTest(profile=name, gate=key):
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=key, config=config), 0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({key: value ^ 1}, config=config),
                        0, profile)["passed"])
            for other in ("immediate", "register", "image", "image-relocated",
                          "writeback", "el0-writeback"):
                self.assertFalse(generated_memory.assess(
                    self.transcript(config=generated_memory.configuration(
                        generated_memory.select_profile(other))), 0, profile)["passed"])

    def test_structure_batches_require_their_count_context_and_all_controls(self):
        names = [name for name in generated_memory.CONFIG["profiles"]
                 if "structure" in name and "-group-" not in name]
        self.assertEqual(len(names), 8)
        for name in names:
            profile = generated_memory.select_profile(name)
            self.assertIn("-DCPA_GENERATED_STRUCTURE_MEMORY=1", profile["guest_flags"])
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"],
                             30 if name.endswith("tail") else 48)
            self.assertIn("sizeof(structure_cases)", profile["count_function"])
            self.assertEqual(len(profile["test_report_cases"]), 58)
            config = generated_memory.configuration(profile)
            result = generated_memory.assess(self.transcript(config=config), 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            for key, value in profile["generated_gate_values"].items():
                with self.subTest(profile=name, gate=key):
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=key, config=config), 0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])
            other = generated_memory.select_profile(
                name.removesuffix("-tail") if name.endswith("tail") else name + "-tail")
            self.assertFalse(generated_memory.assess(
                self.transcript(config=generated_memory.configuration(other)), 0,
                profile)["passed"])

    def test_structure_reports_keep_context_identity_and_all_named_tests(self):
        for name in generated_memory.CONFIG["profiles"]:
            if "structure" not in name:
                continue
            profile = generated_memory.select_profile(name)
            suites = {}
            for identity in profile["test_report_cases"]:
                suite, case = identity.rsplit(".", 1)
                suites.setdefault(suite, []).append(
                    {"name": case, "status": "RUN", "result": "COMPLETED"})
            cases = [case for values in suites.values() for case in values]
            cases[0][profile["artifact_property"]] = self.id()
            report = {"tests": len(cases), "failures": 0, "errors": 0,
                      "testsuites": [{"name": name, "testsuite": values}
                                     for name, values in suites.items()]}
            self.assertEqual(generated_memory.validate_test_report(report, profile),
                             self.id())
            cases[-1]["result"] = "SKIPPED"
            with self.assertRaises(ValueError):
                generated_memory.validate_test_report(report, profile)
            cases[-1]["result"] = "COMPLETED"
            opposite = generated_memory.select_profile(
                name.replace("structure-image", "structure")
                if "structure-image" in name
                else name.replace("structure", "structure-image"))
            with self.assertRaises(ValueError):
                generated_memory.validate_test_report(report, opposite)

    def test_structure_groups_preserve_all_batches_and_actual_counts(self):
        names = [name for name in generated_memory.CONFIG["profiles"]
                 if "structure" in name and "-group-" in name]
        self.assertEqual(len(names), 12)
        for name in names:
            profile = generated_memory.select_profile(name)
            group = int(name.rsplit("-", 1)[1])
            self.assertEqual(profile["artifact_batches"],
                             [f"batch-{index * 48}"
                              for index in range(group * 8, (group + 1) * 8)])
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"],
                             366 if group == 2 else 384)
            self.assertIn("-DCPA_GENERATED_STRUCTURE_GROUP_MEMORY=1", profile["guest_flags"])
            config = generated_memory.configuration(profile)
            result = generated_memory.assess(self.transcript(config=config), 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            for key, value in profile["generated_gate_values"].items():
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=key, config=config), 0, profile)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])
            batch = generated_memory.select_profile(name.rsplit("-group-", 1)[0])
            self.assertFalse(generated_memory.assess(
                self.transcript(config=generated_memory.configuration(batch)), 0,
                profile)["passed"])

    def test_group_entry_executes_every_batch_and_propagates_each_failure(self):
        import grouped_memory
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path
        grouped = generated_memory.CONFIG["grouped"]
        batch_count = len(generated_memory.select_profile(
            "structure-group-0")["artifact_batches"])
        source = grouped["probe_globals"]
        source += grouped_memory.render_entry(grouped, batch_count)
        for index in range(batch_count):
            source += grouped["probe_batch"].format(
                entry=grouped["entry_name"].format(index=index),
                count=grouped["count_name"].format(index=index),
                index=index, length=index + 1)
        source += grouped["probe_main"].format(
            samples=sum(range(1, batch_count + 1)), batches=batch_count)
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "probe.c"
            path.write_text(source)
            binary = directory / "probe"
            subprocess.run([compiler, "-std=c11", "-O2", str(path), "-o", str(binary)],
                           check=True, timeout=run.CONFIG["build_timeout_seconds"],
                           capture_output=True)
            for failure in range(-1, batch_count):
                with self.subTest(failure=failure):
                    subprocess.run([str(binary), str(failure + 1)], check=True,
                                   timeout=run.CONFIG["timeout_seconds"],
                                   capture_output=True)

    def test_freestanding_byte_runtime_preserves_bounds_and_return_values(self):
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path
        runtime = generated_memory.CONFIG["freestanding_runtime"]
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / runtime["source_file"]
            source.write_text(runtime["source"] + runtime["probe"])
            binary = directory / "runtime-probe"
            subprocess.run([compiler, "-std=c11", *runtime["flags"], str(source),
                            "-o", str(binary)], check=True,
                           timeout=run.CONFIG["build_timeout_seconds"],
                           capture_output=True)
            subprocess.run([str(binary)], check=True,
                           timeout=run.CONFIG["timeout_seconds"],
                           capture_output=True)

    def test_sp_pauth_requires_active_distinct_data_keys(self):
        for name in ("sp-pauth", "el0-sp-pauth"):
            profile = generated_memory.select_profile(name)
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"], 7)
            self.assertEqual(len(profile["test_report_cases"]), 5)
            self.assertIn("-DCPA_GENERATED_SP_PAUTH=1", profile["guest_flags"])
            self.assertIn("-DSP_PAUTH_REQUIRE_ACTIVE=1", profile["generated_flags"])
            self.assertIn("sizeof(pauth_cases)", profile["count_function"])
            config = generated_memory.configuration(profile)
            self.assertTrue(generated_memory.assess(
                self.transcript(config=config), 0, profile)[profile["qualification_key"]])
            for key, value in profile["generated_gate_values"].items():
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=key, config=config), 0, profile)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])

    def test_sp_flow_requires_every_definition_and_effective_control(self):
        for name in ("sp-flow", "el0-sp-flow"):
            profile = generated_memory.select_profile(name)
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"], 20)
            self.assertEqual(len(profile["test_report_cases"]), 8)
            self.assertIn("-DCPA_GENERATED_SP_FLOW=1", profile["guest_flags"])
            self.assertIn("sizeof(flow_cases)", profile["count_function"])
            config = generated_memory.configuration(profile)
            result = generated_memory.assess(self.transcript(config=config), 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            for key, value in profile["generated_gate_values"].items():
                self.assertFalse(generated_memory.assess(
                    self.transcript(omit=key, config=config), 0, profile)["passed"])
                self.assertFalse(generated_memory.assess(
                    self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])
            for other in ("sp-writeback", "el0-sp-writeback", "stack"):
                self.assertFalse(generated_memory.assess(
                    self.transcript(config=generated_memory.configuration(
                        generated_memory.select_profile(other))), 0, profile)["passed"])

    def test_pair_profiles_require_both_results_and_their_own_counts(self):
        for name in ("pair", "el0-pair"):
            profile = generated_memory.select_profile(name)
            self.assertIn("-DCPA_GENERATED_PAIR_MEMORY=1", profile["guest_flags"])
            self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"], 215)
            self.assertIn("sizeof(pair_cases)", profile["count_function"])
            config = generated_memory.configuration(profile)
            result = generated_memory.assess(self.transcript(config=config), 0, profile)
            self.assertTrue(result[profile["qualification_key"]])
            self.assertFalse(result["neverd_output_qualified"])
            self.assertFalse(result["native_apple_cpta_qualified"])
            for key, value in profile["generated_gate_values"].items():
                with self.subTest(profile=name, gate=key):
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=key, config=config), 0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])
            for other in ("immediate", "register", "writeback", "vector-writeback"):
                self.assertFalse(generated_memory.assess(
                    self.transcript(config=generated_memory.configuration(
                        generated_memory.select_profile(other))), 0, profile)["passed"])

    def test_ordered_profiles_require_their_own_report_and_feature(self):
        for context in ("ordered", "ordered-image", "ordered-image-relocated"):
            for prefix in ("", "el0-"):
                profile = generated_memory.select_profile(prefix + context)
                self.assertIn("-DCPA_GENERATED_ORDERED_MEMORY=1", profile["guest_flags"])
                self.assertEqual(profile["generated_gate_values"]["neverd-memory-samples"], 115)
                self.assertEqual(profile["generated_gate_values"]["ordered-lrcpc-level"], 3)
                self.assertEqual(len(profile["test_report_cases"]), 9)
                config = generated_memory.configuration(profile)
                result = generated_memory.assess(self.transcript(config=config), 0, profile)
                self.assertTrue(result[profile["qualification_key"]])
                self.assertFalse(result["neverd_output_qualified"])
                self.assertFalse(result["native_apple_cpta_qualified"])
                for key, value in profile["generated_gate_values"].items():
                    with self.subTest(profile=prefix + context, gate=key):
                        self.assertFalse(generated_memory.assess(
                            self.transcript(omit=key, config=config), 0, profile)["passed"])
                        self.assertFalse(generated_memory.assess(
                            self.transcript({key: value ^ 1}, config=config), 0, profile)["passed"])

    def test_ordered_profiles_configure_the_real_optional_model_feature(self):
        default_parameters = dict(run.CONFIG["model_parameters"])
        for context in ("ordered", "ordered-image", "ordered-image-relocated"):
            for prefix in ("", "el0-"):
                profile = generated_memory.select_profile(prefix + context)
                config = generated_memory.configuration(profile)
                self.assertEqual(config["model_parameters"]["cluster0.has_lrcpc3"], "1")
                self.assertIn("cluster0.has_lrcpc3=1", run.model_command("model", "guest", config))
                for key, value in default_parameters.items():
                    self.assertEqual(config["model_parameters"][key], value)
        self.assertEqual(run.CONFIG["model_parameters"], default_parameters)
        self.assertNotIn("cluster0.has_lrcpc3=1", run.model_command("model", "guest"))

    def test_raw_sp_profiles_require_alignment_origin_and_complete_results(self):
        names = [name for name in generated_memory.CONFIG["profiles"]
                 if name.startswith(("sp-", "el0-sp-"))]
        self.assertEqual(len(names), 16)
        for name in names:
            with self.subTest(profile=name):
                profile = generated_memory.select_profile(name)
                self.assertIn("-DCPA_GENERATED_STACK_MEMORY=1", profile["guest_flags"])
                self.assertTrue(profile["artifact_property"].startswith("sp_"))
                config = generated_memory.configuration(profile)
                report = generated_memory.assess(self.transcript(config=config), 0, profile)
                self.assertTrue(report[profile["qualification_key"]])
                self.assertFalse(report["neverd_output_qualified"])
                self.assertFalse(report["native_apple_cpta_qualified"])
                for mode in ("off", "on", "cpta0-only", "both"):
                    self.assertEqual(profile["generated_gate_values"][
                        "neverd-memory-" + mode + "-sa"],
                        16 if name.startswith("el0-") else 8)
                for key, value in profile["generated_gate_values"].items():
                    self.assertFalse(generated_memory.assess(
                        self.transcript(omit=key, config=config), 0, profile)["passed"])
                    self.assertFalse(generated_memory.assess(
                        self.transcript({key: value ^ 1}, config=config), 0,
                        profile)["passed"])
                if "-neon-group-" in name:
                    group = int(name.rsplit("-", 1)[1])
                    self.assertEqual(len(profile["test_report_cases"]), 25)
                    self.assertEqual(profile["artifact_batches"], [
                        f"batch-{index * 48}" for index in
                        range(group * 8, (group + 1) * 8)])
                    self.assertEqual(profile["generated_gate_values"][
                        "neverd-memory-samples"], 366 if group == 2 else 384)

    def test_distinct_output_profiles_require_their_own_export(self):
        for name in generated_memory.CONFIG["profiles"]:
            profile = generated_memory.select_profile(name)
            if profile["artifact_property"] == generated_memory.CONFIG["artifact_property"]:
                continue
            suites = {}
            for identity in profile["test_report_cases"]:
                suite, case = identity.rsplit(".", 1)
                suites.setdefault(suite, []).append(
                    {"name": case, "status": "RUN", "result": "COMPLETED"})
            cases = [case for values in suites.values() for case in values]
            cases[0][generated_memory.CONFIG["artifact_property"]] = self.id()
            report = {"tests": len(cases), "failures": 0, "errors": 0,
                      "testsuites": [{"name": name, "testsuite": values}
                                     for name, values in suites.items()]}
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
