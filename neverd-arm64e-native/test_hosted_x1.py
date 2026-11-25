"""Check that partial host capability survives aggregation and stale records fail."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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
