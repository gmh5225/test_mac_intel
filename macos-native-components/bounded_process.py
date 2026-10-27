"""Bounded local process execution; captured inputs require a qualified profile."""
from pathlib import Path
import hashlib
import json
import os
import resource
import selectors
import signal
import subprocess
import time


def run(label, command, cwd, environment, logs, *, wall=180, file_bytes=0, cpu=120, pass_fds=()):
    assert 0 <= file_bytes <= 512 * 1024 * 1024 and 0 < wall <= 300
    command = list(map(str, command)); logs = Path(logs)
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256)); resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=limits, pass_fds=pass_fds)
    selector = selectors.DefaultSelector(); streams = dict(stdout=bytearray(), stderr=bytearray()); failure = None; kill_errors = []
    for name, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
        os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + wall
    def stop():
        # Signal the owned group before poll() can reap its leader. Descendants
        # may still hold a pipe after the direct child has already exited.
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        except PermissionError as error: kill_errors.append(str(error))
        until = time.monotonic() + 2
        while process.poll() is None and time.monotonic() < until:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except PermissionError as error:
                if str(error) not in kill_errors: kill_errors.append(str(error))
                try: process.kill()
                except (PermissionError, ProcessLookupError): pass
            try: process.wait(timeout=.1)
            except subprocess.TimeoutExpired: pass
        assert process.poll() is not None, 'Could not reap bounded child'
    try:
        while selector.get_map():
            if time.monotonic() >= deadline: failure = 'wall timeout'; break
            for event, _ in selector.select(.1):
                raw = os.read(event.fileobj.fileno(), 65536)
                if not raw: selector.unregister(event.fileobj); continue
                target = streams[event.data]
                if len(target) + len(raw) > 262144:
                    target.extend(raw[:262144 - len(target)]); failure = 'output limit'; break
                target.extend(raw)
            if failure: break
        if failure: stop()
        code = process.wait(timeout=10)
    finally:
        selector.close()
        if process.poll() is None: stop()
    row = dict(label=label, command=command, exit_code=code, failure=failure, rlimit_fsize=file_bytes, kill_errors=kill_errors, streams={})
    for name, raw in streams.items():
        (logs / (label + '.' + name)).write_bytes(raw)
        row['streams'][name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    (logs / (label + '.result.json')).write_text(json.dumps(row, indent=2) + '\n')
    return row, bytes(streams['stdout']), bytes(streams['stderr'])
