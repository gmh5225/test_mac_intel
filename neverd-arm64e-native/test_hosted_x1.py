"""Check that partial host capability survives aggregation and stale records fail."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import hosted_x1 as hosted


CASES = json.loads(Path(__file__).with_name("TestCases.def").read_text())


class HostedFeatureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name)
        self.report = {"source_revision": CASES["revision"], "probes": {}}
        self.policy = copy.deepcopy(CASES["hosted_report_policy"])
        self.features = {}
        for section, key, _ in hosted.CONFIG["feature_rows"]:
            probe = self.policy.setdefault(section, {"mode": section})
            probe[key] = section + "." + key
            self.features.setdefault(section, {})[probe[key]] = False
        self.report[self.policy["x1_qualification"]["qualified_key"]] = False
        self.report.update(status=self.policy["unavailable"], missing=[])
        for mode in self.features:
            (self.output / mode).mkdir()
            self.save(mode)

    def save(self, mode, status=None):
        status = status or self.policy["unavailable"]
        path = self.output / mode / self.policy["report_name"]
        path.write_text(json.dumps({"source_revision": self.report["source_revision"], "status": status,
                                    **self.features[mode]}))
        self.report["probes"][mode] = {"status": status, "report": path.relative_to(self.output).as_posix(),
                                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_partial_and_older_observations(self):
        for section, key, label in hosted.CONFIG["feature_rows"]:
            probe = self.policy[section]
            field = probe[key]
            self.features[section][field] = True
            self.save(section)
            with self.subTest(key=field):
                summary = hosted.summarize(self.policy, self.report, self.report["source_revision"],
                                           self.policy["exit_codes"][self.report["status"]],
                                           section, self.output)
                self.assertIn(hosted.CONFIG["feature_row"].format(feature=label, result=self.policy["passed"]), summary)
                del probe[key]
                row = hosted.feature_summary(self.policy, self.report, self.output)
                self.assertIn(hosted.CONFIG["feature_row"].format(feature=label, result=hosted.CONFIG["unmeasured"]), row)
                probe[key] = field
            self.features[section][field] = False
            self.save(section)

    def test_absent_probe_in_older_policy_is_unmeasured(self):
        section, _, _ = hosted.CONFIG["feature_rows"][0]
        del self.policy[section]
        del self.report["probes"][section]
        summary = hosted.feature_summary(self.policy, self.report, self.output)
        for name, _, label in hosted.CONFIG["feature_rows"]:
            if name == section:
                row = hosted.CONFIG["feature_row"].format(feature=label, result=hosted.CONFIG["unmeasured"])
                self.assertIn(row, summary)

    def test_complete_result_requires_the_environment_and_q_on_the_same_host(self):
        gate = self.policy["x1_qualification"]
        gate.update(CASES["full_hosted_gate"])
        ordered = self.policy["ordered_probe"]
        q_key = ordered["qualified_key"]
        for environment in (False, True):
            for q in (False, True):
                with self.subTest(environment=environment, q=q):
                    complete = environment and q
                    status = self.policy["passed" if complete else "unavailable"]
                    self.features[ordered["mode"]][q_key] = q
                    self.save(ordered["mode"], self.policy["passed" if q else "unavailable"])
                    self.report.update({
                        "status": status,
                        "missing": [] if q else [{"feature": q_key}],
                        gate["qualified_key"]: environment,
                        gate["complete_key"]: complete,
                        q_key: q,
                    })
                    args = (self.policy, self.report, self.report["source_revision"],
                            self.policy["exit_codes"][status], ordered["mode"], self.output)
                    summary = hosted.summarize(*args)
                    self.assertIn(hosted.CONFIG["complete_summary"].format(
                        environment=json.dumps(environment), complete=status), summary)
                    self.report[gate["complete_key"]] = not complete
                    with self.assertRaises(ValueError):
                        hosted.summarize(*args)

    def test_measure_records_the_selected_mode_cpu_and_report_digest(self):
        source = self.output / CASES["source_directory"]
        policy_path = source / hosted.CONFIG["policy"]
        policy_path.parent.mkdir(parents=True)
        gate = self.policy["x1_qualification"]
        report_path = self.output / self.policy["report_name"]
        revision = self.report["source_revision"]
        env = {"SOURCE_REVISION": revision, "GITHUB_STEP_SUMMARY": str(source / hosted.CONFIG["host_record"])}
        for full in (False, True):
            if full:
                gate.update(CASES["full_hosted_gate"])
                self.report[gate["complete_key"]] = False
                self.report[self.policy["ordered_probe"]["qualified_key"]] = False
            policy_path.write_text(json.dumps(self.policy))
            report_path.write_text(json.dumps(self.report))
            mode = gate["complete_mode" if full else "mode"]
            with self.subTest(mode=mode), mock.patch.dict(hosted.os.environ, env), \
                    mock.patch.object(hosted.subprocess, "check_output", return_value=CASES["host_cpu"]), \
                    mock.patch.object(hosted.subprocess, "run") as run:
                run.return_value.returncode = self.policy["exit_codes"][self.report["status"]]
                hosted.measure(source, self.output)
                self.assertIn(mode, run.call_args_list[0].args[0])
                identity = json.loads((self.output / hosted.CONFIG["host_record"]).read_text())
                self.assertEqual(identity, {
                    "hardware": CASES["host_cpu"], "source_revision": revision, "mode": mode,
                    "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                })

    def test_failed_measurement_and_invalid_receipts(self):
        section, key, label = hosted.CONFIG["feature_rows"][0]
        self.save(section, self.policy["failed"])
        self.assertIn(hosted.CONFIG["feature_row"].format(feature=label, result=self.policy["failed"]),
                      hosted.feature_summary(self.policy, self.report, self.output))
        for field in ("sha256", "report", "status"):
            self.save(section)
            self.report["probes"][section][field] = self.report["source_revision"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.feature_summary(self.policy, self.report, self.output)
        self.save(section)
        self.report[self.policy[section][key]] = True
        with self.assertRaises(ValueError):
            hosted.feature_summary(self.policy, self.report, self.output)
        del self.report[self.policy[section][key]]
        self.report["source_revision"] += self.report["source_revision"]
        with self.assertRaises(ValueError):
            hosted.feature_summary(self.policy, self.report, self.output)
