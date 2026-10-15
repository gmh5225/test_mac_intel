#!/usr/bin/env python3
"""Prepare the ARM32 Wine registry on the host's kernel compatibility layer.

This is tool installation, not a measured patch observation. All measured PE
processes still run later in the complete QEMU ARM32 guest.
"""
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import time
from capture_process import run_capture

root = Path('/work')
report = {'phase': 'wine-prefix-installation', 'execution_kind': 'arm64-kernel-compatibility',
          'counted_patch_observations': 0, 'kernel': platform.release(),
          'machine': platform.machine(), 'pointer_bits': struct.calcsize('P') * 8,
          'complete': False}
env = dict(os.environ, HOME='/root', DISPLAY=':99', WINEARCH='win32',
           WINEPREFIX='/root/wine32', WINEDEBUG='+timestamp,+setupapi')
with (root/'prefix-xvfb.log').open('wb') as log:
    display = subprocess.Popen(['Xvfb', ':99', '-screen', '0', '640x480x24', '-nolisten', 'tcp'],
                               stdout=log, stderr=subprocess.STDOUT)
    try:
        for attempt in range(10):
            if run_capture(['xdpyinfo'], timeout=2, env=env).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('prefix X server unavailable')
        try:
            result = run_capture(['/usr/lib/wine/wine', 'wineboot', '-u'], timeout=90, env=env)
            report['initialization'] = {'actual': result.returncode,
                                        'stdout': result.stdout.decode(errors='replace'),
                                        'stderr': result.stderr.decode(errors='replace')}
            assert result.returncode == 0
        except subprocess.TimeoutExpired as error:
            report['initialization'] = {'timeout_seconds': 90,
                                        'stdout': (error.output or b'').decode(errors='replace'),
                                        'stderr': (error.stderr or b'').decode(errors='replace')}
            raise
        stop = run_capture(['/usr/lib/wine/wineserver32', '-k'], timeout=20, env=env)
        wait = run_capture(['/usr/lib/wine/wineserver32', '-w'], timeout=20, env=env)
        assert stop.returncode == wait.returncode == 0
        report['complete'] = True
    finally:
        display.terminate()
        display.wait(timeout=5)
        (root/'prefix-installation.json').write_text(json.dumps(report, indent=2) + '\n')
