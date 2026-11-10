"""Successful runs remove only the disposable tools they installed."""

import copy
import json
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import run


CASES = json.loads(Path(__file__).with_name("CptaCleanupTestCases.def").read_text())


class CleanupTests(unittest.TestCase):
    measurements = {}

    def test_pending_consumer_keeps_the_lock_after_controller_strong_kill(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            scratch = root / run.LIFECYCLE["scratch"]
            release = scratch / CASES["consumer_release"]
            with subprocess.Popen([sys.executable, "-c", CASES["producer"],
                                   str(root), CASES["consumer"]],
                                  env=dict(os.environ, PYTHONPATH=str(run.ROOT))) as child:
                try:
                    end = time.monotonic() + CASES["consumer_wait_seconds"]
                    while not (scratch / CASES["consumer_ready"]).exists() and time.monotonic() < end:
                        time.sleep(0.01)
                    self.assertTrue((scratch / CASES["consumer_ready"]).exists())
                    child.kill()
                    child.wait(timeout=CASES["child_timeout"])
                    with (root / run.LIFECYCLE["lock"]).open("a+") as lock:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    release.touch()
                    with run.artifact_session(root) as recovered:
                        self.assertFalse(any(recovered.iterdir()))
                finally:
                    if scratch.exists():
                        release.touch()
                    if child.poll() is None:
                        child.kill()
                        child.wait()

    def test_repeated_success_failure_and_abandonment_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            counts = []
            for error in (None, RuntimeError, KeyboardInterrupt, SystemExit):
                for _ in range(CASES["iterations"]):
                    try:
                        with run.artifact_session(root) as scratch:
                            (scratch / CASES["scratch_file"]).write_text(CASES["payload"])
                            (root / CASES["input_file"]).write_text(CASES["payload"])
                            (root / CASES["diagnostic_file"]).write_text(CASES["payload"])
                            if error:
                                raise error()
                    except (RuntimeError, KeyboardInterrupt, SystemExit):
                        pass
                    self.assertFalse((root / run.LIFECYCLE["scratch"]).exists())
                    files = [p for p in root.rglob("*") if p.is_file()]
                    counts.append((len(files), sum(p.stat().st_size for p in files)))
            self.assertEqual(len({row[0] for row in counts}), 1)
            self.assertLessEqual(max(row[1] for row in counts) - min(row[1] for row in counts), 1)
            self.measurements["sessions"] = counts

    def test_actual_driver_entry_points_clean_failed_installations_and_reuse_inputs(self):
        import authenticated_calls as calls
        import generated_memory as generated
        import grouped_memory as grouped

        for entry in ("primitive", "authenticated", "generated", "grouped"):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, artifacts = root / "output", root / "artifacts"
                artifacts.mkdir()
                report = root / "tests.json"
                report.write_text("{}\n")
                args = SimpleNamespace(output=output, artifacts=artifacts,
                                       test_report=report, neverd_revision="0" * 40,
                                       profile=generated.CONFIG["default_profile"],
                                       compiler=generated.CONFIG["compiler"],
                                       linker=generated.CONFIG["linker"])
                config = copy.deepcopy(calls.CONFIG)
                config["cases"] = config["cases"][:1]
                profile = generated.select_profile(args.profile)
                profile["artifact_batches"] = ["batch"]
                files = {route["file"] for route in generated.CONFIG["routes"]}
                files.add(generated.CONFIG["harness_file"])
                for directory in (artifacts, artifacts / "batch"):
                    directory.mkdir(exist_ok=True)
                    for name in files:
                        (directory / name).write_text(CASES["payload"])
                for case in config["cases"]:
                    directory = artifacts / case["directory"]
                    directory.mkdir()
                    for name in config["source_files"] + [r + ".o" for r in config["routes"]]:
                        (directory / name).write_text(CASES["payload"])

                def fail_install(work, evidence):
                    partial = work / run.CONFIG["model_install_directory"]
                    partial.mkdir()
                    (partial / CASES["scratch_file"]).write_text(CASES["payload"])
                    (evidence / CASES["diagnostic_file"]).write_text(CASES["payload"])
                    raise RuntimeError(CASES["payload"])

                def build(compiler, linker, work, evidence, *args):
                    (work / CASES["scratch_file"]).write_text(CASES["payload"])
                    guest = evidence / run.CONFIG["guest_elf"]
                    guest.write_text(CASES["payload"])
                    return guest

                arguments = [str(run.ROOT), "--artifacts", str(artifacts),
                             "--test-report", str(report), "--neverd-revision",
                             args.neverd_revision, "--output", str(output)]
                counts = []
                for _ in range(CASES["iterations"]):
                    with mock.patch.object(run, "prepare", side_effect=fail_install), \
                         mock.patch.object(run, "build", side_effect=build), \
                         mock.patch.object(calls, "validate_test_report", return_value=str(artifacts)), \
                         mock.patch.object(generated, "validate_test_report", return_value=str(artifacts)), \
                         mock.patch.object(sys, "argv", [str(run.ROOT)] if entry == "primitive" else arguments), \
                         mock.patch.dict(run.CONFIG, {"workspace_directory": str(output),
                                                     "evidence_directory": str(root / "evidence")}), \
                         self.assertRaises(RuntimeError):
                        if entry == "primitive":
                            run.main()
                        elif entry == "authenticated":
                            calls.main(config)
                        elif entry == "generated":
                            generated.main()
                        else:
                            grouped.execute(args, profile, generated.configuration(profile),
                                            str(artifacts), generated.CONFIG, generated.assess,
                                            generated.compile_freestanding_runtime)
                    self.assertFalse((output / run.LIFECYCLE["scratch"]).exists())
                    self.assertFalse((root / run.LIFECYCLE["cache_directory"] /
                                      run.LIFECYCLE["scratch"]).exists())
                    files = [p for p in root.rglob("*") if p.is_file()]
                    counts.append((len(files), sum(p.stat().st_size for p in files)))
                self.assertEqual(len(set(counts)), 1)
                self.measurements[entry] = counts

    def test_signals_release_the_owner_and_strong_kill_recovers_next_start(self):
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGKILL):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "output"
                env = dict(os.environ, PYTHONPATH=str(run.ROOT))
                with subprocess.Popen([sys.executable, "-c", CASES["child"], str(root)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, env=env) as child:
                    try:
                        self.assertEqual(child.stdout.readline().strip(), CASES["ready"])
                        with (root / run.LIFECYCLE["lock"]).open("a+") as lock:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        child.send_signal(sig)
                        child.communicate(timeout=CASES["child_timeout"])
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.communicate()
                self.assertEqual((root / run.LIFECYCLE["scratch"]).exists(),
                                 sig == signal.SIGKILL)
                diagnostic = (root / CASES["diagnostic_file"]).read_bytes()
                with run.artifact_session(root) as scratch:
                    self.assertFalse(any(scratch.iterdir()))
                    self.assertEqual((root / CASES["diagnostic_file"]).read_bytes(), diagnostic)
                receipt = json.loads((root / run.LIFECYCLE["lifecycle_receipt"]).read_text())
                self.assertEqual(receipt["recovered_interrupted_scratch"], sig == signal.SIGKILL)

    def test_model_cache_reuses_one_installation_and_preserves_supplied_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()

            def prepare(work, logs):
                model = work / run.CONFIG["model_install_directory"] / run.CONFIG["model_binary"]
                model.parent.mkdir(parents=True)
                model.write_text(CASES["payload"])
                return model

            with mock.patch.object(run, "prepare", side_effect=prepare) as install:
                for _ in range(CASES["iterations"]):
                    with run.model_session(root, evidence) as model:
                        self.assertEqual(model.read_text(), CASES["payload"])
                self.assertEqual(install.call_count, 1)
                supplied = root / CASES["input_file"]
                supplied.write_text(CASES["payload"])
                with run.model_session(root, evidence, supplied) as selected:
                    self.assertEqual(selected, supplied.resolve())
                self.assertEqual(supplied.read_text(), CASES["payload"])
                self.assertEqual(install.call_count, 1)

    def test_owned_inputs_are_atomic_and_unrelated_directories_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / CASES["input_file"]
            source.write_text(CASES["payload"])
            with self.assertRaises(ValueError):
                with run.artifact_session(root):
                    self.fail()
            self.assertEqual(source.read_text(), CASES["payload"])
            output = root / "output"
            with run.artifact_session(output) as scratch:
                target = output / CASES["input_file"]
                run.copy_input(source, target, scratch)
                run.copy_input(source, target, scratch)
                source.write_text(CASES["payload"] * 2)
                with self.assertRaises(ValueError):
                    run.copy_input(source, target, scratch)
                self.assertEqual(target.read_text(), CASES["payload"])

    def test_cleanup_preserves_guests_inputs_reports_and_supplied_models(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = CASES["payload"].encode()
            for name in CASES["preserved"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for key in ("model_archive", "model_installer"):
                (root / run.CONFIG[key]).write_bytes(data)
            model = root / run.CONFIG["model_install_directory"] / run.CONFIG["model_binary"]
            model.parent.mkdir(parents=True)
            model.write_bytes(data)
            run.remove_model_tools(root)
            for key in ("model_archive", "model_installer", "model_install_directory"):
                self.assertFalse((root / run.CONFIG[key]).exists())
            for name in CASES["preserved"]:
                self.assertEqual((root / name).read_bytes(), data)

    def test_an_installation_symlink_does_not_delete_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / CASES["preserved"][-1]
            external.parent.mkdir(parents=True)
            external.write_text(CASES["payload"])
            (root / run.CONFIG["model_install_directory"]).symlink_to(
                external.parent, target_is_directory=True)
            run.remove_model_tools(root)
            self.assertEqual(external.read_text(), CASES["payload"])


if __name__ == "__main__":
    unittest.main()
