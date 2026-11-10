"""Exercise strict preflight ordering and owned build cleanup."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import run

CASES = json.loads(Path(__file__).with_name("TestCases.def").read_text())


class NativeEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / CASES["source_directory"]
        self.source.mkdir()
        self.output = self.root / CASES["output_directory"]
        self.policy = copy.deepcopy(run.POLICY)
        self.policy["source_revision"] = CASES["revision"]
        self.build = self.source / self.policy["build_directory"]
        patch = mock.patch.object(run.subprocess, "check_output", return_value=CASES["revision"])
        patch.start()
        self.addCleanup(patch.stop)

    def test_unavailable_preflight_stops_before_tools_dependencies_and_build(self):
        with mock.patch.object(run, "stage", return_value=CASES["stage_failure"]) as stage:
            self.assertEqual(run.execute(self.source, self.output, self.policy), CASES["stage_failure"])
        stage.assert_called_once()
        report = json.loads((self.output / self.policy["report_name"]).read_text())
        self.assertFalse(report[CASES["report_key"]])
        self.assertFalse(self.build.exists())

    def test_wrong_revision_stops_before_output_or_execution(self):
        self.policy["source_revision"] = CASES["wrong_revision"]
        with mock.patch.object(run, "stage") as stage, self.assertRaises(ValueError):
            run.execute(self.source, self.output, self.policy)
        stage.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_failed_startup_stops_before_tools_dependencies_and_build(self):
        with mock.patch.object(run, "stage", side_effect=[0, CASES["stage_failure"]]) as stage:
            self.assertEqual(run.execute(self.source, self.output, self.policy), CASES["stage_failure"])
        self.assertEqual(stage.call_count, 2)
        self.assertFalse(self.build.exists())

    def test_existing_build_is_never_reused_or_deleted(self):
        self.build.mkdir()
        product = self.build / CASES["partial_binary"]
        product.write_text(CASES["payload"])
        with self.assertRaises(ValueError):
            run.execute(self.source, self.output, self.policy)
        self.assertEqual(product.read_text(), CASES["payload"])

    def test_partial_owned_build_is_removed_after_failure(self):
        def fail(*args):
            self.build.mkdir()
            (self.build / CASES["partial_binary"]).write_text(CASES["payload"])
            (self.build / CASES["diagnostic"]).write_text(CASES["diagnostic_payload"])
            raise RuntimeError(CASES["exception"])

        with mock.patch.object(run, "stage", side_effect=fail), self.assertRaises(RuntimeError):
            run.execute(self.source, self.output, self.policy)
        self.assertFalse(self.build.exists())
        diagnostic = self.output / self.policy["build_diagnostics_directory"] / CASES["diagnostic"]
        self.assertEqual(diagnostic.read_text(), CASES["diagnostic_payload"])
        report = json.loads((self.output / self.policy["report_name"]).read_text())
        self.assertFalse(report[CASES["report_key"]])

    def test_successful_processes_cannot_replace_native_qualification(self):
        def complete(*args):
            startup = self.output / self.policy["startup_report"]
            startup.parent.mkdir(exist_ok=True)
            startup.write_text(json.dumps({self.policy["startup_qualification_key"]: True,
                                          "source_revision": CASES["revision"],
                                          "fixup_loader": self.policy["startup_fixup_loader"]}))
            report = self.output / self.policy["qualification_report"]
            report.parent.mkdir(exist_ok=True)
            report.write_text(json.dumps({CASES["report_key"]: False}))
            return 0

        with mock.patch.object(run, "stage", side_effect=complete), self.assertRaises(ValueError):
            run.execute(self.source, self.output, self.policy)
        result = json.loads((self.output / self.policy["report_name"]).read_text())
        self.assertFalse(result[CASES["report_key"]])

    def complete_reports(self, mutation=None, default_mutation=None, generated_mutation=None):
        def complete(*args):
            startup = self.output / self.policy["startup_report"]
            startup.parent.mkdir(exist_ok=True)
            startup.write_text(json.dumps({self.policy["startup_qualification_key"]: True,
                                          "source_revision": CASES["revision"],
                                          "fixup_loader": self.policy["startup_fixup_loader"]}))
            installed = self.output / self.policy["qualification_report"]
            installed.parent.mkdir(exist_ok=True)
            installed.write_text(json.dumps({CASES["report_key"]: True,
                                            self.policy["publication_qualification_key"]: True,
                                            "source_revision": CASES["revision"]}))
            executable = self.output / self.policy["executable_report"]
            executable.parent.mkdir(exist_ok=True)
            report = {self.policy["executable_qualification_key"]: True,
                      "source_revision": CASES["revision"],
                      "fixup_loader": self.policy["startup_fixup_loader"],
                      "probe_report_sha256": hashlib.sha256(startup.read_bytes()).hexdigest()}
            report.update(mutation or {})
            executable.write_text(json.dumps(report))
            probe = self.output / self.policy["probe_report"]
            probe.parent.mkdir(exist_ok=True)
            probe.write_text(json.dumps({"source_revision": CASES["revision"]}))
            default = self.output / self.policy["default_executable_report"]
            default.parent.mkdir(exist_ok=True)
            report = {self.policy["default_executable_qualification_key"]: True,
                      "source_revision": CASES["revision"],
                      "fixup_loader": self.policy["default_fixup_loader"],
                      "probe_report_sha256": hashlib.sha256(probe.read_bytes()).hexdigest()}
            report.update(default_mutation or {})
            default.write_text(json.dumps(report))
            for item in self.policy["generated_reports"]:
                path = self.output / item["path"]
                path.parent.mkdir(exist_ok=True)
                report = {item["key"]: True, "source_revision": CASES["revision"],
                          "fixup_loader": self.policy["default_fixup_loader"],
                          "probe_report_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
                          "ir_compiler": {"sha256": CASES["compiler_hash"]}}
                report.update(generated_mutation or {})
                path.write_text(json.dumps(report))
            return 0
        return complete

    def test_complete_reports_bind_startup_profile_and_native_publication(self):
        with mock.patch.object(run, "stage", side_effect=self.complete_reports()):
            self.assertEqual(run.execute(self.source, self.output, self.policy), 0)
        result = json.loads((self.output / self.policy["report_name"]).read_text())
        self.assertTrue(result[self.policy["startup_qualification_key"]])
        self.assertTrue(result[self.policy["publication_qualification_key"]])
        self.assertTrue(result[self.policy["executable_qualification_key"]])
        self.assertTrue(result[self.policy["default_executable_qualification_key"]])
        self.assertEqual(result[self.policy["startup_fixup_loader_key"]],
                         self.policy["startup_fixup_loader"])

    def test_executable_result_cannot_substitute_stale_or_wrong_profile_evidence(self):
        for mutation in CASES["executable_mutations"]:
            with self.subTest(mutation=mutation):
                self.output = self.root / str(CASES["executable_mutations"].index(mutation))
                with mock.patch.object(run, "stage", side_effect=self.complete_reports(mutation)), \
                        self.assertRaises(ValueError):
                    run.execute(self.source, self.output, self.policy)
                result = json.loads((self.output / self.policy["report_name"]).read_text())
                self.assertFalse(result[self.policy["executable_qualification_key"]])
                self.assertFalse(result["passed"])

    def test_default_startup_cannot_substitute_userspace_or_stale_evidence(self):
        for index, mutation in enumerate(CASES["default_executable_mutations"]):
            with self.subTest(mutation=mutation):
                self.output = self.root / str(index)
                with mock.patch.object(run, "stage", side_effect=self.complete_reports(
                        default_mutation=mutation)), self.assertRaises(ValueError):
                    run.execute(self.source, self.output, self.policy)
                result = json.loads((self.output / self.policy["report_name"]).read_text())
                self.assertFalse(result[self.policy["default_executable_qualification_key"]])
                self.assertFalse(result["passed"])

    def test_generated_publication_requires_current_system_probe_and_frontend(self):
        for index, mutation in enumerate(CASES["generated_mutations"]):
            with self.subTest(mutation=mutation):
                self.output = self.root / str(index)
                with mock.patch.object(run, "stage", side_effect=self.complete_reports(
                        generated_mutation=mutation)), self.assertRaises(ValueError):
                    run.execute(self.source, self.output, self.policy)
                result = json.loads((self.output / self.policy["report_name"]).read_text())
                self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
