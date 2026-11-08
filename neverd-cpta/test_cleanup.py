"""Successful runs remove only the disposable tools they installed."""

import json
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import run


CASES = json.loads(Path(__file__).with_name("CptaCleanupTestCases.def").read_text())


class CleanupTests(unittest.TestCase):
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
