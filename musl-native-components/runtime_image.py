"""Reuse an exact cached runtime digest, or fetch and verify it once."""
import json
import subprocess
from sdk import ROOT


def select(arch, override=None):
    image = override or json.loads((ROOT.parent / 'seccomp-helper/pins.json').read_bytes())['profiles'][arch]['image']
    def inspect():
        result = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, timeout=30)
        return json.loads(result.stdout) if result.returncode == 0 else None
    rows = inspect()
    if rows is None:
        healthy = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True, timeout=30)
        assert healthy.returncode == 0, 'Container daemon is unavailable'
        assert not image.startswith('sha256:'), 'An explicit diagnostic image must already exist'
        last_error = b''
        for attempt in range(3):
            try:
                result = subprocess.run(['docker', 'pull', '--platform', 'linux/' + ('arm64' if arch == 'arm64' else 'amd64'), image], capture_output=True, timeout=240)
            except subprocess.TimeoutExpired:
                result = None; last_error = b'timeout'; continue
            if result.returncode == 0: break
            last_error = result.stderr[-2048:]
        assert result is not None and result.returncode == 0, 'Pinned runtime image download failed: ' + last_error.decode(errors='replace')
        rows = inspect()
    assert rows is not None and len(rows) == 1 and rows[0]['Architecture'] == {'arm64': 'arm64', 'x64': 'amd64'}[arch]
    if override is None: assert image in rows[0]['RepoDigests']
    return image
