import importlib.util
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from upstream_hvf_control import collect, witnesses

# The real runner imports the pinned checkout. Supply that checkout explicitly
# for local process tests too, without copying the retirement implementation.
DIAGNOSTICS = Path(os.environ["HVF_TEST_DIAGNOSTICS"]).resolve()
spec = importlib.util.spec_from_file_location("hvf_diagnostic", DIAGNOSTICS / "scripts/diagnose_hvf_methods.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


def complete_log():
    return ("Starting long loop...\nStarting random interrupts\n"
        + "".join(f"VM interrupt {n}/100000…\n" for n in range(0, 100000, 10000))
        + "interrupts finished\nDone\nSent 100000 randomly spaced interrupts, with 100003 interrupt VM exits, max exit delay 65000 ns\n")


class UpstreamControlTests(unittest.TestCase):
    def test_partial_repeated_and_wrong_workloads_are_not_successes(self):
        log = complete_log()
        self.assertTrue(witnesses(log)["passed"])
        for invalid in ("", log.replace("Done\n", ""), log.replace("Done\n", "Done\nDone\n"),
                        log.replace("VM interrupt 10000/100000…\n", ""),
                        log.replace("Sent 100000", "Sent 10000"), log + log,
                        log + "unhandled VMEXIT (32)\n", log.replace("100003 interrupt", "0 interrupt"),
                        log + "HLT\n", log + "EXIT_REASON_EXT_INTR in unexpected state 1\n",
                        log + "vm_vcpu_interrupt -> 0xfae94001\n",
                        "Done\n" + log.replace("Done\n", ""),
                        log.replace("Starting random interrupts\n", "") + "Starting random interrupts\n",
                        "\n".join(log.splitlines()[-1:] + log.splitlines()[:-1]) + "\n"):
            with self.subTest(invalid=invalid[-80:]):
                self.assertFalse(witnesses(invalid)["passed"])
        self.assertTrue(witnesses(log + "Status: STOP/UNSUPPORTED\n")["passed"])
        self.assertTrue(witnesses(log.replace("interrupts finished\nDone\n", "Done\ninterrupts finished\n"))["passed"])

    def run_child(self, code, timeout=2):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        status = collect([sys.executable, "-c", code], directory, directory,
                         shared.test_environment(os.environ), timeout, shared.NativeChildren)
        return directory, status

    def test_pty_preserves_output_and_reaps_success(self):
        log = complete_log()
        directory, status = self.run_child(f"import os; assert os.isatty(1); print({log!r}, end='')")
        self.assertEqual(status["status"], 0)
        self.assertFalse(status["timed_out"])
        self.assertTrue(status["child_retired"])
        self.assertEqual((directory / "output.log").read_text(), log)
        self.assertTrue(witnesses((directory / "output.log").read_text())["passed"])
        retired = json.loads((directory / "retirement.json").read_text())
        self.assertEqual(retired, [{"pid": status["pid"], "status": 0, "retired": True}])

    def test_timeout_preserves_prefix_and_retires_child(self):
        directory, status = self.run_child("import time; print('prefix', flush=True); time.sleep(30)", 0.2)
        self.assertTrue(status["timed_out"])
        self.assertTrue(status["child_retired"])
        self.assertEqual(status["status"], -signal.SIGKILL)
        self.assertIn("prefix", (directory / "output.log").read_text())

    def test_native_signal_is_not_a_success(self):
        _, status = self.run_child("import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(status["status"], -signal.SIGTERM)
        self.assertTrue(status["child_retired"])
        self.assertFalse(status["timed_out"])

    def test_exit_zero_observed_after_deadline_is_still_a_timeout(self):
        original = subprocess.Popen
        def delayed_spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            child.wait(timeout=2)
            time.sleep(0.1)
            return child
        with mock.patch.object(subprocess, "Popen", side_effect=delayed_spawn):
            _, status = self.run_child("print('complete')", timeout=0.05)
        self.assertEqual(status["status"], 0)
        self.assertTrue(status["timed_out"])
        self.assertTrue(status["child_retired"])

    def test_exit_between_empty_select_and_poll_does_not_drop_tail(self):
        original_spawn, original_select = subprocess.Popen, select.select
        children = []
        def spawn(*args, **kwargs):
            child = original_spawn(*args, **kwargs)
            children.append(child)
            return child
        first = True
        def empty_then_exit(*args):
            nonlocal first
            if first:
                first = False
                children[0].wait(timeout=2)
                return [], [], []
            return original_select(*args)
        log = complete_log()
        with mock.patch.object(subprocess, "Popen", side_effect=spawn), mock.patch.object(select, "select", side_effect=empty_then_exit):
            directory, status = self.run_child(f"print({log!r}, end='')")
        self.assertEqual(status["status"], 0)
        self.assertFalse(status["timed_out"])
        self.assertEqual((directory / "output.log").read_text(), log)

    def test_controller_cancellation_retires_independent_native_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp)
            code = ("import sys; from pathlib import Path; from upstream_hvf_control import collect; "
                f"sys.path.insert(0, {str(DIAGNOSTICS)!r}); "
                "from scripts.diagnose_hvf_methods import NativeChildren; "
                f"collect([sys.executable, '-c', 'import time; time.sleep(30)'], {tmp!r}, Path({tmp!r}), {{}}, 20, NativeChildren)")
            child = subprocess.Popen([sys.executable, "-c", code], cwd=Path(__file__).parent)
            try:
                deadline = time.monotonic() + 5
                while not (destination / "children.json").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((destination / "children.json").exists())
                child.terminate()
                self.assertEqual(child.wait(timeout=5), 128 + signal.SIGTERM)
                retirement = json.loads((destination / "retirement.json").read_text())
                self.assertEqual(len(retirement), 1)
                self.assertTrue(retirement[0]["retired"])
                self.assertEqual(retirement[0]["status"], -signal.SIGKILL)
                status = json.loads((destination / "native-status.json").read_text())
                self.assertTrue(status["controller_interrupted"])
                self.assertTrue(status["child_retired"])
                self.assertEqual(status["status"], -signal.SIGKILL)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    unittest.main()
