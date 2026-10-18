"""Bounded JSON protocol runner; callers separately qualify their Seatbelt profile."""
from pathlib import Path
import hashlib
import json
import os
import resource
import selectors
import signal
import subprocess
import time


def matches(value, fields):
    for path, expected in fields.items():
        current = value
        for part in path.split('.'):
            if not isinstance(current, dict) or part not in current: return False
            current = current[part]
        if current != expected: return False
    return True


def run(command, cwd, environment, logs, steps=None, *, wall=60, stream_cap=262144):
    assert 0 < wall <= 60 and 0 < stream_cap <= 262144
    logs = Path(logs); logs.mkdir()
    steps = steps if steps is not None else [dict(close_stdin=True)]
    assert 0 < len(steps) <= 64
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_CPU, (50, 50))
    command = list(map(str, command))
    process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=limits)
    selector = selectors.DefaultSelector(); data = dict(stdout=bytearray(), stderr=bytearray())
    for name in data:
        pipe = getattr(process, name); os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    os.set_blocking(process.stdin.fileno(), False)
    result = dict(command=command, failure=None, completed_steps=0, stdin_bytes=0, kill_errors=[])
    frames = []; buffer = b''; pending = b''; index = 0; cursor = 0
    start = step_started = time.monotonic(); killed = False
    def kill():
        nonlocal killed
        # Do this before poll/wait reaps the leader: a descendant may own its pipes.
        try: os.killpg(process.pid, signal.SIGKILL); killed = True
        except ProcessLookupError: killed = True
        except PermissionError as error:
            if str(error) not in result['kill_errors']: result['kill_errors'].append(str(error))
            try: process.kill()
            except (ProcessLookupError, PermissionError): pass
    def fail(reason):
        if result['failure'] is None: result['failure'] = reason
        kill()
    def advance():
        nonlocal index, cursor, pending, step_started
        while index < len(steps) and not pending and result['failure'] is None:
            step = steps[index]
            if 'wait_json' in step:
                found = next((i for i in range(cursor, len(frames)) if matches(frames[i], step['wait_json'])), None)
                if found is None:
                    if time.monotonic() - step_started > step.get('timeout_seconds', 20): fail('protocol deadline ' + str(index))
                    return
                cursor = found + 1
            elif 'close_stdin' in step:
                if not process.stdin.closed: process.stdin.close()
            else:
                if 'send_permission_response' in step:
                    assert cursor > 0
                    request = frames[cursor - 1]
                    assert matches(request, {'type':'control_request', 'request.subtype':'can_use_tool', 'request.tool_name':step['expected_tool']})
                    assert request['request']['input'] == step['expected_input'] and isinstance(request.get('request_id'), str)
                    reply = step['send_permission_response']; assert reply['behavior'] in ['allow', 'deny']
                    if reply['behavior'] == 'allow': assert reply['updatedInput'] == step['expected_input']
                    value = dict(type='control_response', response=dict(subtype='success', request_id=request['request_id'], response=reply))
                    pending = json.dumps(value, separators=(',', ':')).encode() + b'\n'
                elif 'send_json' in step:
                    pending = json.dumps(step['send_json'], ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
                else:
                    assert set(step) == {'send_bytes'}; pending = step['send_bytes']
                assert isinstance(pending, bytes) and len(pending) <= 65536 and not process.stdin.closed
                if pending:
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin'); return
            index += 1; result['completed_steps'] = index; step_started = time.monotonic()
    try:
        advance()
        while selector.get_map():
            elapsed = time.monotonic() - start
            if elapsed >= wall: fail('wall timeout')
            if result['failure'] is not None and not killed: kill()
            if elapsed >= wall + 2: break
            for event, _ in selector.select(.05):
                if event.data == 'stdin':
                    try: count = os.write(event.fd, pending)
                    except BlockingIOError: continue
                    except BrokenPipeError: fail('closed stdin'); count = len(pending)
                    result['stdin_bytes'] += count; pending = pending[count:]
                    if not pending:
                        selector.unregister(process.stdin); index += 1
                        result['completed_steps'] = index; step_started = time.monotonic()
                    continue
                raw = os.read(event.fd, 65536)
                if not raw: selector.unregister(event.fileobj); continue
                keep = min(len(raw), stream_cap - len(data[event.data]))
                data[event.data].extend(raw[:keep])
                if keep < len(raw): fail('output limit')
                if event.data == 'stdout':
                    buffer += raw[:keep]
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        try: frames.append(json.loads(line))
                        except (ValueError, UnicodeError): continue
                        if len(frames) > 1024: fail('JSON frame limit')
            advance()
        if index < len(steps) and result['failure'] is None: fail('incomplete protocol')
        try: process.wait(timeout=max(.01, wall - (time.monotonic() - start)))
        except subprocess.TimeoutExpired: fail('wall timeout'); process.wait(timeout=2)
    finally:
        kill()
        if process.poll() is None: process.wait(timeout=2)
        selector.close()
        for pipe in [process.stdin, process.stdout, process.stderr]:
            if not pipe.closed: pipe.close()
        result.update(exit_code=process.returncode, stream_limit_bytes=stream_cap, streams={})
        for name, raw in data.items():
            (logs / ('client.' + name)).write_bytes(raw)
            result['streams'][name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        (logs / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
    return result, bytes(data['stdout']), bytes(data['stderr'])
