"""Exercise real child lifetime, closed pipes and Darwin zombie-only groups."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'macos-native-components'))
from client_protocol import run, group_members


@unittest.skipUnless(platform.system() == 'Darwin', 'Native Darwin process supervision is required')
class Retirement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='neverd-owned-retirement-')
        cls.root = Path(cls.temporary.name)
        cls.fixture = cls.root / 'retirement-control'
        cls.records = []
        subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            str(ROOT / 'retirement-control.c'), '-o', str(cls.fixture)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def execute(self, mode, wall=3):
        before = time.monotonic()
        record, stdout, stderr = run([self.fixture, mode], self.root,
            dict(HOME=str(self.root), TMPDIR=str(self.root), PATH='/unavailable'), self.root / self._testMethodName, wall=wall)
        self.assertEqual(stderr, b'')
        self.assertEqual(record['kill_errors'], [])
        self.assertEqual(record['group_retirement']['remaining_live_processes'], 0)
        self.assertFalse([m for m in group_members(record['leader_pid']) if not m['state'].startswith('Z')])
        self.records.append(dict(case=self._testMethodName, execution=record,
            stdout_sha256=hashlib.sha256(stdout).hexdigest()))
        return record, stdout, time.monotonic() - before

    def test_fast_normal_exit_is_not_a_permission_failure(self):
        record, stdout, _ = self.execute('--quick-exit')
        self.assertIsNone(record['failure']); self.assertEqual(record['exit_code'], 0); self.assertEqual(stdout, b'')

    def test_closed_streams_do_not_kill_a_still_running_leader(self):
        record, _, elapsed = self.execute('--close-streams-then-exit')
        self.assertIsNone(record['failure']); self.assertEqual(record['exit_code'], 0)
        self.assertGreaterEqual(elapsed, .14)

    def test_leader_exit_retires_child_without_inherited_pipes(self):
        record, stdout, _ = self.execute('--child-without-pipes')
        self.assertIsNone(record['failure']); self.assertEqual(record['exit_code'], 0)
        child = json.loads(stdout)['authored_child_pid']
        state = subprocess.run(['/bin/ps', '-p', str(child), '-o', 'stat='], capture_output=True, text=True, timeout=2)
        self.assertTrue(state.returncode == 1 or state.stdout.strip().startswith('Z'))

    def test_descendant_held_pipes_reach_the_deadline_and_are_retired(self):
        record, stdout, _ = self.execute('--child-holds-pipes', wall=.3)
        self.assertEqual(record['failure'], 'wall timeout')
        self.assertGreater(json.loads(stdout)['authored_child_pid'], 0)


if __name__ == '__main__':
    receipt = None
    if '--receipt' in sys.argv:
        index = sys.argv.index('--receipt'); receipt = Path(sys.argv[index + 1]).resolve()
        assert not receipt.exists(); del sys.argv[index:index + 2]
    tested = unittest.main(exit=False).result
    passed = tested.wasSuccessful() and tested.testsRun == 4 and not tested.skipped
    if receipt is not None:
        def sha(file): return hashlib.sha256(file.read_bytes()).hexdigest()
        receipt.write_text(json.dumps(dict(status='four_native_Darwin_process_retirement_controls_passed' if passed else 'not_qualified',
            platform=platform.system(), native_architecture=platform.machine(), cases=getattr(Retirement, 'records', []),
            source_script_sha256=sha(Path(__file__)), source_fixture_sha256=sha(ROOT / 'retirement-control.c'),
            protocol_sha256=sha(ROOT.parent / 'macos-native-components/client_protocol.py'), captured_inputs_executed=False), indent=2) + '\n')
    raise SystemExit(0 if passed else 1)
