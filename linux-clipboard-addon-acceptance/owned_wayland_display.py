"""Bounded private wlr-data-control compositor and independent public caller."""
from pathlib import Path
import json
import os
import signal
import subprocess
import time


class OwnedWayland:
    def __init__(self, folder, temporary, arch, mode, environment):
        self.folder = folder
        self.ready = temporary / 'wayland-ready.json'
        self.stop = temporary / 'wayland-stop'
        self.report = folder / 'wayland-state.json'
        self.ready.unlink(missing_ok=True); self.stop.unlink(missing_ok=True)
        inputs = Path('/inputs')
        with (folder / 'wayland-server.stdout').open('xb') as so, (folder / 'wayland-server.stderr').open('xb') as se:
            self.process = subprocess.Popen([str(inputs / ('owned-wayland-server-' + arch)), mode,
                                             str(self.ready), str(self.stop), str(self.report)],
                                            stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                            env=environment, start_new_session=True)
        try:
            self.qualify(inputs, arch, mode, environment)
        except BaseException:
            self.stop.write_text('owned fixture constructor failure\n')
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=3)
            (folder / 'wayland-constructor-retirement.json').write_text(json.dumps(dict(exit_code=self.process.returncode, reaped=True)) + '\n')
            raise

    def qualify(self, inputs, arch, mode, environment):
        deadline = time.monotonic() + 5
        while not self.ready.exists():
            assert self.process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        ready = json.loads(self.ready.read_bytes())
        assert ready['ready'] and Path(ready['socket']).name == ready['socket']
        environment['WAYLAND_DISPLAY'] = ready['socket']
        assert 'DISPLAY' not in environment
        for selection in ['regular', 'primary']:
            result = subprocess.run([str(inputs / ('owned-wayland-client-' + arch)), selection],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=environment)
            (self.folder / ('owned-wayland-' + selection + '.stdout')).write_bytes(result.stdout)
            (self.folder / ('owned-wayland-' + selection + '.stderr')).write_bytes(result.stderr)
            absent = mode == 'empty' or (mode == 'v1' and selection == 'primary')
            if absent:
                assert result.returncode == 1 and not result.stdout and result.stderr
            else:
                expected = 'owned clipboard fixture\n' if selection == 'regular' else '自有 primary 🧪\n'
                assert result.returncode == 0 and result.stdout == expected.encode() and not result.stderr
        (self.folder / 'wayland-ready.json').write_text(json.dumps(ready, indent=2) + '\n')

    def finish(self):
        self.stop.write_text('owned fixture stop\n')
        self.process.wait(timeout=5)
        assert self.process.returncode == 0
        state = json.loads(self.report.read_bytes())
        assert state['stopped'] and state['connections'] >= 2 and state['seats'] == 1
        assert not (self.folder / 'wayland-server.stderr').read_bytes()
        self.ready.unlink(missing_ok=True); self.stop.unlink(missing_ok=True)
