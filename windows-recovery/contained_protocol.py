"""Bounded, interactive transport for the qualified AppContainer launcher."""
from pathlib import Path
import json
import subprocess
import time
import uuid

def matches(frame, fields):
    for name, expected in fields.items():
        value = frame
        for key in name.split("."):
            if not isinstance(value, dict) or key not in value: return False
            value = value[key]
        if value != expected: return False
    return True

class ContainedProtocol:
    def __init__(self, launcher, root, env, executable, argv, logs, name):
        self.root, self.logs, self.name = root, logs, name
        self.process = subprocess.Popen(list(map(str, [launcher, root, "NeverD.Protocol." + uuid.uuid4().hex,
            "45000", "--interactive", executable, *argv])), cwd=root / "work", env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.metadata = None

    def frames(self):
        path = self.root / "target.stdout"
        if not path.exists(): return []
        data = path.read_bytes(); assert len(data) < 2 * 1024 * 1024, "protocol output budget"
        # A multibyte character or JSON record may be split across writes.
        return [json.loads(line) for line in data.split(b"\n")[:-1] if line.strip()]

    def send(self, value):
        data = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False) + "\n").encode()
        self.process.stdin.write(data); self.process.stdin.flush()

    def wait(self, fields, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            for frame in self.frames():
                if matches(frame, fields): return frame
            if self.process.poll() is not None: raise RuntimeError("contained process ended before " + str(fields))
            time.sleep(.03)
        raise TimeoutError("protocol deadline: " + str(fields))

    def finish(self):
        self.process.stdin.close()
        self.process.wait(timeout=20)
        stdout = self.process.stdout.read(); stderr = self.process.stderr.read()
        (self.logs / (self.name + "-launcher.stdout")).write_bytes(stdout)
        (self.logs / (self.name + "-launcher.stderr")).write_bytes(stderr)
        assert self.process.returncode == 0, (self.name, self.process.returncode)
        self.metadata = json.loads(stdout)
        assert self.metadata["app_container"] and self.metadata["capability_count"] == 0, self.metadata
        assert not self.metadata["timeout"] and not self.metadata["output_limit"] and self.metadata["remaining_processes"] == 0, self.metadata
        return self.metadata

    def retain(self):
        if self.process.poll() is None:
            self.process.kill(); self.process.wait(timeout=10)
        for stream in ["stdout", "stderr"]:
            path = self.logs / (self.name + "-launcher." + stream)
            if not path.exists(): path.write_bytes(getattr(self.process, stream).read(65536))
        for stream in ["stdout", "stderr"]:
            path = self.root / ("target." + stream)
            if path.exists():
                with path.open("rb") as source:
                    (self.logs / (self.name + "." + stream)).write_bytes(source.read(2 * 1024 * 1024))
        for handle in [self.process.stdin, self.process.stdout, self.process.stderr]: handle.close()
