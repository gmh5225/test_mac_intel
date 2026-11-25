"""Check the source and r6 build contract before dispatching to Xcode."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import projections

CASES = json.loads(Path(__file__).with_name("TestCases.def").read_text())


class ProjectionWorkflowTests(unittest.TestCase):
    def test_both_jobs_require_the_resolved_revision(self):
        p = projections.CONFIG
        for stage in (p["build"], p["check"]):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.dict(os.environ, {p["revision_env"]: p["source_branch"]}), \
                    mock.patch.object(projections.subprocess, "check_output", return_value=p["target"]), \
                    mock.patch.object(projections.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    projections.run(stage, Path(tmp), Path(tmp))
                run.assert_not_called()

    def test_real_build_recipe_pins_r6_and_cleans_failed_exports(self):
        p = projections.CONFIG
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {p["revision_env"]: p["source_branch"]}), \
                mock.patch.object(projections.subprocess, "check_output", return_value=p["source_branch"]), \
                mock.patch.object(projections.subprocess, "run", side_effect=[
                    None, None, None, subprocess.CalledProcessError(1, p["verifier"])]) as runs:
            work = Path(tmp)
            policy = (work / p["verifier"]).with_suffix(".def")
            policy.parent.mkdir()
            policy.write_text(json.dumps({}))
            with self.assertRaises(subprocess.CalledProcessError):
                projections.run(p["build"], work, work)
            arguments = [call.args[0] for call in runs.call_args_list]
            self.assertTrue(any(p["package"] in value for value in arguments[1]))
            self.assertTrue(any(p["package_sha256"] in value for value in arguments[1]))
            self.assertIn(p["target"], arguments[2])
            self.assertIn(p["verifier"], arguments[3])
            self.assertFalse((work / p["build_dir"]).exists())

    def test_canonical_source_owns_the_r6_export(self):
        p = projections.CONFIG
        policy = CASES["projection_policy"]
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {p["revision_env"]: CASES["revision"]}), \
                mock.patch.object(projections.subprocess, "check_output", return_value=CASES["revision"]), \
                mock.patch.object(projections.subprocess, "run") as run:
            root = Path(tmp)
            path = (root / p["verifier"]).with_suffix(".def")
            path.parent.mkdir()
            path.write_text(json.dumps(policy))
            projections.run(p["build"], root, root)
            run.assert_called_once_with([projections.sys.executable, p["verifier"], policy["build"], policy["output"],
                                         root / p["inputs_dir"]], cwd=root, check=True)

    def test_hosted_observation_checks_the_same_run_reports_and_exit_code(self):
        p = projections.CONFIG
        policy = CASES["projection_policy"]
        native = {**CASES["hosted_report_policy"],
                  "x1_qualification": {**CASES["hosted_report_policy"]["x1_qualification"], **CASES["full_hosted_gate"]}}
        gate = native["x1_qualification"]
        model = CASES["projection_model"]
        labels = ["-".join((family, route, opt)) for family in model["cases"]
                  for route in (*model["routes"], *model["backend_objects"]) for opt in model["optimizations"]]
        for qualified, count, damage in ((True, len(labels), None), (False, len(labels), None),
                                         (False, len(labels) // 2, None), (False, 0, None),
                                         (True, len(labels), "sha256"), (True, len(labels), "status"),
                                         (True, len(labels), "source_revision"), (True, len(labels), "images"),
                                         (False, 0, "code"), (True, 0, "all_executed")):
            with self.subTest(qualified=qualified, count=count, damage=damage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / p["report_dir"]
                summary = root / p["resolve"]
                control = output / gate["complete_mode"] / native["report_name"]
                control.parent.mkdir(parents=True)
                path = (root / p["verifier"]).with_suffix(".def")
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(policy))
                (root / p["native_policy"]).write_text(json.dumps(native))
                (root / p["model_policy"]).write_text(json.dumps(model))
                controls = {"source_revision": CASES["wrong_revision"] if damage == "source_revision" else CASES["revision"],
                            "status": native["passed" if qualified else "unavailable"], gate["complete_key"]: qualified}
                control.write_text(json.dumps(controls))
                passed = qualified and count == len(labels)
                status = native["passed" if passed else "unavailable"]
                code = native["exit_codes"][native["failed"] if damage == "code" else status]
                images = {label: {"execution": p["compared"] if index < count else None}
                          for index, label in enumerate(labels)}
                if damage == "images":
                    images.pop(labels[-1])
                digest = hashlib.sha256(control.read_bytes()).hexdigest()
                report = {"status": native["failed"] if damage == "status" else status, "source_revision": CASES["revision"],
                          "all_linked": True, "all_executed": count == len(labels) or damage == "all_executed",
                          "images": images, policy["qualified_key"]: passed, gate["complete_key"]: qualified,
                          policy["control_receipt"]: {"report": control.relative_to(output).as_posix(),
                                                      "sha256": digest if damage != "sha256" else CASES["wrong_revision"]}}
                top = output / p["report"]
                top.write_text(json.dumps(report))
                with mock.patch.dict(os.environ, {p["revision_env"]: CASES["revision"], "GITHUB_STEP_SUMMARY": str(summary)}), \
                        mock.patch.object(projections.subprocess, "check_output", side_effect=[CASES["revision"], CASES["host_cpu"]]), \
                        mock.patch.object(projections.subprocess, "run", return_value=subprocess.CompletedProcess([], code)) as run:
                    if damage:
                        with self.assertRaises(ValueError):
                            projections.run(p["check"], root, root)
                        self.assertFalse((output / p["host_report"]).exists())
                    else:
                        projections.run(p["check"], root, root)
                        host = json.loads((output / p["host_report"]).read_text())
                        self.assertEqual((host["status"], host["executed"], host["controls"]), (status, count, qualified))
                        self.assertEqual(host["report_sha256"], hashlib.sha256(top.read_bytes()).hexdigest())
                        self.assertIn(status, summary.read_text())
                    self.assertIn(policy["require_native"], run.call_args.args[0])
