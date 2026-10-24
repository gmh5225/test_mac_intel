"""Own and validate the generated large-selection provider's lifecycle."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import sys
import time


class OwnedLargeX11:
    def __init__(self, folder, payload, environment, transport):
        self.folder = folder; self.stop = folder / 'provider-stop'
        self.report = folder / 'provider-report.json'
        ready = folder / 'provider-ready.json'
        self.size = payload.stat().st_size
        self.digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        self.transport = transport
        command = [sys.executable, '-B', '/inputs/owned_large_X11_provider.py', '--display', ':98',
            '--input', str(payload), '--ready', str(ready), '--stop', str(self.stop), '--report', str(self.report),
            '--transport', transport]
        with (folder / 'provider.stdout').open('xb') as out, (folder / 'provider.stderr').open('xb') as err:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=environment, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while not ready.exists():
                assert self.process.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            proof = json.loads(ready.read_bytes())
            assert proof['ready'] and proof['bytes'] == self.size and proof['sha256'] == self.digest
        except BaseException:
            self.retire()
            raise

    def retire(self):
        self.stop.write_text('owned provider stop\n')
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=3)
        (self.folder / 'provider-retirement.json').write_text(json.dumps(dict(exit_code=self.process.returncode, reaped=True)) + '\n')

    def finish(self):
        self.retire()
        assert self.process.returncode == 0
        assert not (self.folder / 'provider.stderr').read_bytes()
        report = json.loads(self.report.read_bytes())
        assert report['status'] == 'owned_X11_provider_stopped' and report['transport'] == self.transport
        assert report['bytes'] == self.size and report['sha256'] == self.digest and len(report['transfers']) == 1
        row = report['transfers'][0]
        assert row['data_bytes'] == self.size
        if self.transport == 'incr':
            assert row['marker_elements'] == 1 and row['terminal_sent'] and row['terminal_delete_received']
        else:
            assert row['direct_property']
