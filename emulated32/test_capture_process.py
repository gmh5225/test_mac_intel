"""Check daemon output inheritance and real process deadlines independently."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from capture_process import run_capture


class ProcessCaptureTests(unittest.TestCase):
    def test_daemon_inheriting_output_does_not_change_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'daemon.pid'
            code = """import os, sys, time
pid = os.fork()
if pid == 0:
    open(sys.argv[1], 'w').write(str(os.getpid()))
    time.sleep(10)
    os._exit(0)
while not os.path.exists(sys.argv[1]):
    time.sleep(0.01)
print('measured-parent', flush=True)
os._exit(93)
"""
            try:
                result = run_capture([sys.executable, '-c', code, str(pidfile)], timeout=2)
                self.assertEqual(result.returncode, 93)
                self.assertEqual(result.stdout, b'measured-parent\n')
            finally:
                if pidfile.exists():
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)

    def test_real_process_deadline_retains_output_and_fails(self):
        code = "import time; print('started', flush=True); time.sleep(10)"
        with self.assertRaises(subprocess.TimeoutExpired) as failure:
            run_capture([sys.executable, '-c', code], timeout=0.25)
        self.assertEqual(failure.exception.output, b'started\n')


if __name__ == '__main__':
    unittest.main()
