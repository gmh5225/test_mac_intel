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

    def test_ordered_receipt_requires_six_consistent_processes_and_the_transferred_objects(self):
        p = projections.CONFIG
        ordered = CASES["ordered_export"]
        routes = CASES["ordered_model"]
        target = routes["native"]
        policy = {"ordered": ordered, "manifest": CASES["export_manifest"]}
        model = {**CASES["projection_model"], "ordered": routes, "manifest": CASES["guest_manifest"], "report": p["report"]}
        labels = [f"{route}-{opt}" for route in routes["sources"] for opt in model["optimizations"]]
        labels += [routes["object_route"], routes["raw_object_route"]]
        for scope, damage in (("simd", None), ("gpr", None), ("unavailable", None), ("simd", "control"),
                              ("simd", "sha256"), ("simd", "exporter_sha256"), ("simd", "object_sha256"),
                              ("simd", "records"), ("gpr", "observations"), ("unavailable", "exit_code")):
            with self.subTest(scope=scope, damage=damage), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                directory = work / ordered["directory"]
                directory.mkdir()
                export_path = work / policy["manifest"]
                files = {name: name for name in (*routes["sources"].values(), target["object_file"], target["raw_object_file"])}
                identity = {"files": files, "fixtures": {CASES["payload"]: CASES["revision"]}}
                export = {"source_revision": CASES["revision"], "exporter_sha256": CASES["revision"], ordered["inputs"]: identity}
                export_path.write_text(json.dumps(export))
                guests = dict.fromkeys(labels, {})
                for route, filename in (("object_route", "object_file"), ("raw_object_route", "raw_object_file")):
                    guests[routes[route]] = {"object_sha256": CASES["wrong_revision"] if damage == "object_sha256" else files[target[filename]]}
                guest_path = directory / model["manifest"]
                guest_path.write_text(json.dumps({"guests": guests, "exports": files, "fixtures": identity["fixtures"],
                                                  "ordered_profile": target["profile"], "test_binary_sha256": CASES["revision"]}))
                gpr = scope != "unavailable"
                flags = {target["gpr_key"]: gpr, target["simd_key"]: scope == "simd"}
                records = [target[scope], target["rules"][0]] if gpr else [target[scope]]
                row = {"exit_code": 0 if gpr or damage == "exit_code" else target["skip_exit"], "records": records}
                observations = dict.fromkeys(labels, row)
                if damage == "records":
                    observations[labels[-1]] = {**row, "records": [target["gpr"], target["rules"][0]]}
                if damage == "observations":
                    del observations[labels[-1]]
                path = directory / model["report"]
                path.write_text(json.dumps({**flags, "manifest_sha256": projections.digest(guest_path), "observations": observations}))
                receipt = {**flags, "report": path.relative_to(work).as_posix(),
                           "sha256": CASES["wrong_revision"] if damage == "sha256" else projections.digest(path)}
                report = {**export, ordered["receipt"]: receipt, "input_manifest_sha256": projections.digest(export_path)}
                if damage == "exporter_sha256":
                    report["exporter_sha256"] = CASES["wrong_revision"]
                original_q = scope == "simd" and damage != "control"
                if damage:
                    with self.assertRaisesRegex(ValueError, p["ordered_error"]):
                        projections.check_ordered(work, work, policy, model, report, original_q)
                else:
                    self.assertEqual(projections.check_ordered(work, work, policy, model, report, original_q),
                                     {p["ordered_count"]: len(labels), **flags})

    def test_only_ordered_exports_use_all_hosted_profiles(self):
        p = projections.CONFIG
        base = CASES["projection_policy"]
        self.assertEqual(projections.host_profiles(base), [{"runner": p["x1_runner"], "artifact": p["x1_artifact"]}])
        profiles = projections.host_profiles({**base, "ordered": CASES["ordered_export"]})
        catalog = json.loads(Path(projections.__file__).with_name(p["host_catalog"]).read_bytes())
        self.assertEqual([profile["runner"] for profile in profiles], catalog["runners"])
        self.assertEqual(len({profile["artifact"] for profile in profiles}), len(profiles))

    def test_unlinked_images_require_every_cursor_profile_to_reject_the_x1_slice(self):
        native = {**CASES["hosted_report_policy"], **CASES["slice_control"]}
        cursor = native["cursor_probe"]
        labels = [cursor["profile_label"].format(optimization=o, recipe=r) for o in cursor["optimizations"] for r in cursor["recipes"]]
        mode = native["x1_cursor_probe"]["mode"]
        for damage in (None, "source_revision", "profiles", "sha256", "outcome", "cursor_sha256"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / mode / native["report_name"]
                path.parent.mkdir()
                row = {"status": native["unavailable"], "outcome": native["cpta_probe"]["slice_unavailable"]}
                rows = {label: dict(row) for label in labels}
                if damage == "profiles":
                    del rows[labels[0]]
                elif damage in ("sha256", "outcome"):
                    rows[labels[0]][damage] = CASES["wrong_revision"]
                path.write_text(json.dumps({"source_revision": CASES["wrong_revision"] if damage == "source_revision" else CASES["revision"],
                                            "status": native["unavailable"], "profiles": rows}))
                sha = projections.digest(path)
                controls = {"source_revision": CASES["revision"], "probes": {mode: {"sha256": sha}}}
                report = {"cursor_sha256": CASES["wrong_revision"] if damage == "cursor_sha256" else sha}
                if damage:
                    with self.assertRaisesRegex(ValueError, projections.CONFIG["link_error"]):
                        projections.confirm_unavailable_compiler(native, root, controls, report)
                else:
                    projections.confirm_unavailable_compiler(native, root, controls, report)
