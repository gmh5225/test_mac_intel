"""Bound streams and retire only the fresh owned native-role container."""
from pathlib import Path
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
import uuid


class RoleProcess:
    def __init__(self, arch, image, guard, sdk, loader_path, fixtures, private_logs, target_profile):
        self.arch, self.image, self.guard, self.sdk = arch, image, guard, sdk
        self.loader_path, self.fixtures, self.logs = loader_path, fixtures, private_logs
        self.target_profile = target_profile

    def execute(self, label, target, arguments, *, argv0=None, wall=60, expected_failure=None):
        assert re.fullmatch('[A-Za-z0-9-]+', label)
        name = 'neverd-musl-' + self.arch + '-' + label + '-' + uuid.uuid4().hex[:12]
        loader = self.target_profile['loader']
        command = ['docker', 'run', '--rm', '--name', name, '--log-driver', 'none', '--label', 'neverd-recovery-owned=musl-native-roles-v1',
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', '65534:65534', '--cpus', '2', '--memory', '2g', '--pids-limit', '128',
            '--ulimit', 'fsize=0:0', '--ulimit', 'core=0:0', '--ulimit', 'cpu=20:20', '--ulimit', 'nofile=256:256',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '--workdir', '/input',
            '--mount', f'type=bind,src={self.guard},dst=/runtime/guard,readonly',
            '--mount', f'type=bind,src={self.sdk},dst=/recovery-sdk,readonly',
            '--mount', f'type=bind,src={self.sdk / "lib" / loader},dst=/lib/{loader},readonly',
            '--mount', f'type=bind,src={self.loader_path},dst=/etc/{loader.replace(".so.1", ".path")},readonly',
            '--mount', f'type=bind,src={self.fixtures},dst=/input,readonly',
            '-e', 'HOME=/unavailable', '-e', 'PATH=/usr/bin:/bin', '-e', 'LANG=C', '-e', 'LC_ALL=C',
            '-e', 'NO_COLOR=1', '-e', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH=0']
        for directory in ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']:
            command += ['--tmpfs', directory + ':ro,nosuid,nodev,noexec,size=1m']
        if target is not None:
            command += ['--mount', f'type=bind,src={target},dst=/runtime/program,readonly']
            actual = ['/runtime/program', argv0, *map(str, arguments)]
            assert argv0 is not None
        else: actual = list(map(str, arguments))
        command += ['--entrypoint', '/runtime/guard', self.image, *actual]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector(); streams = dict(stdout=bytearray(), stderr=bytearray()); failure = None
        for key in streams:
            pipe = getattr(process, key); os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, key)
        deadline = time.monotonic() + wall; code = None; cleanup = []; retired = False
        try:
            while selector.get_map():
                if time.monotonic() > deadline: failure = 'wall timeout'; break
                for event, _ in selector.select(.1):
                    raw = os.read(event.fd, 65536)
                    if not raw: selector.unregister(event.fileobj); continue
                    buffer = streams[event.data]; keep = min(len(raw), 262144 - len(buffer)); buffer.extend(raw[:keep])
                    if keep < len(raw): failure = 'output limit'; break
                if failure: break
            if not failure:
                try: code = process.wait(timeout=10)
                except subprocess.TimeoutExpired: failure = 'retirement timeout'
        finally:
            selector.close()
            # Detach the client before asking the daemon to retire the container.
            # Otherwise an output flood can block attach teardown while nobody
            # drains the pipe. The container also has no persistent log driver.
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try: code = process.wait(timeout=5)
                except subprocess.TimeoutExpired: failure = failure or 'client retirement timeout'
            if code is None: code = process.poll()
            process.stdout.close(); process.stderr.close()
            for attempt in range(2):
                for action in [['rm', '--force', name], ['ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']]:
                    try:
                        result = subprocess.run(['docker', *action], capture_output=True, timeout=10)
                        cleanup.append(dict(argv=action, exit_code=result.returncode,
                            stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace')))
                        if action[0] == 'ps': retired = result.returncode == 0 and not result.stdout and not result.stderr
                    except subprocess.TimeoutExpired:
                        cleanup.append(dict(argv=action, timeout=True))
                if retired: break
        row = dict(label=label, command=command, container_name=name, exit_code=code, failure=failure, fsize_zero=True, cpu_limit_seconds=20,
            fresh_owned_container_retired=retired, retirement=cleanup, additive_socket_and_io_uring_refusal=True,
            streams={key: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for key, raw in streams.items()})
        for key, raw in streams.items(): (self.logs / (label + '.' + key)).write_bytes(raw)
        (self.logs / (label + '.result.json')).write_text(json.dumps(row, indent=2) + '\n')
        assert retired, 'Owned container retirement could not be confirmed; bounded streams and cleanup evidence were retained'
        assert failure == expected_failure, label + ': unexpected supervision result'
        return dict(row=row, stdout=bytes(streams['stdout']), stderr=bytes(streams['stderr']), exit_code=code)
