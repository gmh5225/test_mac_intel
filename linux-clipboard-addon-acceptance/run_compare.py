"""Run inside an offline private container, against its own X11 display only."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from owned_blocked_display import BlockedDisplay
from owned_wayland_display import OwnedWayland
from owned_large_x11 import OwnedLargeX11

sys.path.insert(0, '/recipes/macos-native-components')
import bounded_process


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def retire(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3)


def selection_owner(display, selection):
    library = ctypes.CDLL('libX11.so.6')
    library.XOpenDisplay.argtypes = [ctypes.c_char_p]; library.XOpenDisplay.restype = ctypes.c_void_p
    library.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]; library.XInternAtom.restype = ctypes.c_ulong
    library.XGetSelectionOwner.argtypes = [ctypes.c_void_p, ctypes.c_ulong]; library.XGetSelectionOwner.restype = ctypes.c_ulong
    library.XCloseDisplay.argtypes = [ctypes.c_void_p]; library.XCloseDisplay.restype = ctypes.c_int
    connection = library.XOpenDisplay(display.encode()); assert connection
    try:
        atom = library.XInternAtom(connection, selection.encode(), 0)
        return library.XGetSelectionOwner(connection, atom)
    finally:
        library.XCloseDisplay(connection)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    parser.add_argument('--libc', choices=['gnu', 'musl'], required=True)
    parser.add_argument('--suite', choices=['basic', 'advanced', 'spawn', 'wayland', 'all'], default='basic')
    args = parser.parse_args()
    target = 'linux-' + args.arch + '-' + args.libc
    out = Path('/evidence'); inputs = Path('/inputs')
    receipt = dict(status='started', target=target, pairs=[], original_executed=False,
                   host_clipboard_connected=False, physical_device_access=False,
                   exception_stack_equivalence_claimed=False, goal_complete=False)
    receipt['suite'] = args.suite
    sources = out / 'source'; sources.mkdir()
    for source, name in [(Path(__file__), 'run_compare.py'), (inputs / 'compare-clipboard.mjs', 'compare-clipboard.mjs'),
                         (Path('/owned_blocked_display.py'), 'owned_blocked_display.py'),
                         (Path('/owned_wayland_display.py'), 'owned_wayland_display.py'),
                         (Path('/owned_large_x11.py'), 'owned_large_x11.py'),
                         (inputs / 'owned_large_X11_provider.py', 'owned_large_X11_provider.py'),
                         (Path('/recipes/macos-native-components/bounded_process.py'), 'bounded_process.py')]:
        shutil.copyfile(source, sources / name)
    receipt['program_sha256'] = sha(inputs / 'compare-clipboard.mjs')
    receipt['runner_sha256'] = sha(Path(__file__))
    temporary = Path('/tmp/private-clipboard'); temporary.mkdir(mode=0o700)
    for name in ['home', 'xdg', 'logs']:
        (temporary / name).mkdir(mode=0o700)
    env = dict(PATH='/usr/local/bin:/usr/bin:/bin', HOME=str(temporary / 'home'), TMPDIR='/tmp',
               LANG='C', LC_ALL='C', NO_COLOR='1', XDG_RUNTIME_DIR=str(temporary / 'xdg'),
               BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', BUN_INSTALL_CACHE_DIR=str(temporary / 'home/bun-cache'))
    engine = inputs / ('bun-' + target)
    engine_command = [str(engine)]
    if args.libc == 'musl':
        sys.path.insert(0, '/recipes/musl-native-components')
        from runtime_sdk import prepare
        runtime = temporary / 'musl-runtime'
        receipt['musl_runtime'] = prepare(args.arch, inputs / ('sdk-' + args.arch), runtime)
        sdk_loader = runtime / 'lib' / ('ld-musl-' + ('aarch64' if args.arch == 'arm64' else 'x86_64') + '.so.1')
        # The tmpfs remains noexec. Execute only the exact public loader from
        # the read-only inputs mount, with its library closure there as well.
        pinned_runtime = inputs / ('runtime-musl-' + args.arch)
        for path in runtime.rglob('*'):
            if path.is_file(): assert sha(path) == sha(pinned_runtime / path.relative_to(runtime))
        loader = inputs / ('owned-musl-loader-' + args.arch)
        assert sha(sdk_loader) == sha(loader)
        receipt['musl_loader_copy'] = dict(sha256=sha(loader), executable_mode=oct(loader.stat().st_mode & 0o777),
                                           SDK_bytes_modified=False)
        engine_command = [str(loader), '--library-path', str(pinned_runtime / 'lib') + ':' + str(pinned_runtime / 'usr/lib'), str(engine)]
    receipt['engine_sha256'] = sha(engine)
    receipt['inputs'] = {side: dict(sha256=sha(Path('/modules') / (side + '.node')),
                                  bytes=(Path('/modules') / (side + '.node')).stat().st_size)
                         for side in ['original', 'rebuilt']}
    fixture_names = ['compare-clipboard.mjs', 'owned-napi-probe.mjs', 'owned-' + target + '.node',
                     'owned-pthread-fault-' + target + '.so', 'owned-wayland-server-' + args.arch,
                     'owned-wayland-client-' + args.arch, 'owned_large_X11_provider.py']
    receipt['fixture_inputs'] = {name: dict(sha256=sha(inputs / name), bytes=(inputs / name).stat().st_size)
                               for name in fixture_names}

    def boundary(label):
        assert os.getuid() != 0 and not Path('/dev/snd').exists()
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        assert int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1'
        try:
            Path('/inputs/owned-readonly-canary').write_text('must not be written')
        except OSError as error:
            readonly_errno = error.errno
        else:
            raise AssertionError('Read-only input boundary failed')
        assert readonly_errno == 30
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(.2)
        try:
            network_errno = connection.connect_ex(('203.0.113.1', 9))
        finally:
            connection.close()
        assert network_errno == 101
        limits = {name: (Path('/sys/fs/cgroup') / name).read_text().strip()
                  for name in ['pids.current', 'pids.max', 'pids.peak', 'pids.events', 'memory.max', 'memory.events', 'cpu.stat']}
        assert limits['pids.max'] == '128' and limits['pids.events'] == 'max 0'
        assert 'oom_kill 0' in limits['memory.events']
        proof = dict(label=label, uid=os.getuid(), cap_effective=0, no_new_privileges=1,
                     readonly_errno=readonly_errno, external_network_errno=network_errno, audio_device_present=False,
                     host_display_socket_mounted=False, cgroup=limits)
        receipt.setdefault('boundary_controls', []).append(proof)

    def run(label, command, environment):
        row, stdout, stderr = bounded_process.run(label, command, temporary, environment, out,
                                                  wall=30, file_bytes=262144, cpu=20)
        receipt.setdefault('processes', []).append(row)
        assert row['failure'] is None and not row['kill_errors'], label + ': supervision failed'
        assert row['exit_code'] == 0 and not stderr, label + ': process failed'
        value = json.loads(stdout)
        return value

    try:
        boundary('before-owned-NAPI')
        control = run('owned-NAPI', [*engine_command, str(inputs / 'owned-napi-probe.mjs'),
                                     str(inputs / ('owned-' + target + '.node'))], env)
        assert control == dict(status='owned_native_NAPI_loading_pthread_TSFn_and_finalizer_pass', callbacks=3, finalizers=1)
        receipt['owned_NAPI'] = control
        fault_environment = dict(env, LD_PRELOAD=str(inputs / ('owned-pthread-fault-' + target + '.so')))
        control = run('owned-NAPI-fault-passthrough', [*engine_command, str(inputs / 'owned-napi-probe.mjs'),
                                                      str(inputs / ('owned-' + target + '.node'))], fault_environment)
        assert control == receipt['owned_NAPI']
        assert not (out / 'owned-pthread-failures.jsonl').exists()
        basic = ['disconnected', 'read-owned', 'read-empty', 'write-read']
        advanced = ['stranded-readers', 'exit-with-stranded-readers', 'spawn-error', 'incr-small',
                    'size-limit-low', 'size-limit-exact', 'size-limit-over']
        wayland_cases = ['wayland-read-owned', 'wayland-read-empty', 'wayland-write-read', 'wayland-write-v1']
        selected = {'basic': basic, 'advanced': advanced, 'spawn': ['spawn-error'], 'wayland': wayland_cases,
                    'all': basic + advanced + wayland_cases}[args.suite]
        for case in selected:
            observations = {}
            for side in ['original', 'rebuilt']:
                label = case + '-' + side
                folder = out / label; folder.mkdir()
                children = []
                blocked = None
                wayland = None
                owned_large = None
                environment = dict(env)
                try:
                    if case in ['read-owned', 'read-empty', 'write-read'] or (case.startswith('size-limit-') or case == 'incr-small'):
                        environment['DISPLAY'] = ':98'
                        with (folder / 'Xvfb.stdout').open('xb') as so, (folder / 'Xvfb.stderr').open('xb') as se:
                            display = subprocess.Popen(['Xvfb', ':98', '-screen', '0', '64x64x24', '-nolisten', 'tcp',
                                                        '-noreset', '-ac', '-extension', 'GLX'],
                                                       stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                                       env=environment, start_new_session=True)
                        children.append(display)
                        deadline = time.monotonic() + 5
                        while not Path('/tmp/.X11-unix/X98').exists():
                            assert display.poll() is None and time.monotonic() < deadline
                            time.sleep(0.01)
                        assert selection_owner(':98', 'CLIPBOARD') == 0 and selection_owner(':98', 'PRIMARY') == 0
                        if case == 'read-owned':
                            owners = {}
                            for selection, text in [('clipboard', 'owned clipboard fixture\n'), ('primary', '自有 primary 🧪\n')]:
                                with (folder / (selection + '.stdout')).open('xb') as so, (folder / (selection + '.stderr')).open('xb') as se:
                                    owner = subprocess.Popen(['xclip', '-quiet', '-selection', selection, '-in'], stdin=subprocess.PIPE,
                                                             stdout=so, stderr=se, env=environment, start_new_session=True)
                                children.append(owner)
                                owner.stdin.write(text.encode()); owner.stdin.close()
                                deadline = time.monotonic() + 5
                                while not (window := selection_owner(':98', selection.upper())):
                                    assert owner.poll() is None and time.monotonic() < deadline
                                    time.sleep(0.01)
                                owners[selection] = window
                                proof = subprocess.run(['xclip', '-selection', selection, '-out'], env=environment,
                                                       capture_output=True, timeout=5)
                                assert proof.returncode == 0 and proof.stdout == text.encode() and not proof.stderr
                            (folder / 'owned-selections.json').write_text(json.dumps(owners, indent=2) + '\n')
                        if (case.startswith('size-limit-') or case == 'incr-small'):
                            size = {'size-limit-low': 99999999, 'size-limit-exact': 100000000, 'size-limit-over': 100000001, 'incr-small': 65536}[case]
                            large = temporary / 'large-selection'
                            with large.open('wb') as stream:
                                chunk = b'Z' * 1048576
                                for _ in range(size // len(chunk)): stream.write(chunk)
                                stream.write(chunk[:size % len(chunk)])
                            (folder / 'large-fixture.json').write_text(json.dumps(dict(bytes=size, sha256=sha(large), fill_byte=90)) + '\n')
                            owned_large = OwnedLargeX11(folder, large, environment, 'incr' if case == 'incr-small' else 'direct')
                    if case in ['stranded-readers', 'exit-with-stranded-readers']:
                        blocked = BlockedDisplay(folder, temporary)
                        environment['DISPLAY'] = ':99'
                    if case == 'spawn-error': environment = dict(fault_environment)
                    mode = 'read' if case.startswith('read-') else 'size-limit' if (case.startswith('size-limit-') or case == 'incr-small') else case
                    if case.startswith('wayland-'):
                        fixture_mode = 'empty' if case == 'wayland-read-empty' else 'v1' if case == 'wayland-write-v1' else 'text'
                        wayland = OwnedWayland(folder, temporary, args.arch, fixture_mode, environment)
                        children.append(wayland.process)
                        mode = 'read' if case.startswith('wayland-read-') else 'write-read'
                    if side == 'original':
                        boundary('before-original-' + case)
                        receipt['original_executed'] = True
                    value = run(label, [*engine_command, str(inputs / 'compare-clipboard.mjs'), '/modules/' + side + '.node', mode], environment)
                    assert value['mode'] == mode and value['cacheIdentity']
                    assert [d['name'] for d in value['descriptors']] == ['getLinuxClipboardText', 'setLinuxClipboardText']
                    if case in ['read-owned', 'wayland-read-owned']:
                        assert [r['result']['text'] for r in value['rows']] == ['owned clipboard fixture\n', '自有 primary 🧪\n']
                    if case in ['read-empty', 'wayland-read-empty']:
                        assert all(r['phase'] == 'fulfilled' and r['result'] == dict(type='null', value=None) for r in value['rows'])
                    if case in ['write-read', 'wayland-write-read', 'wayland-write-v1']:
                        texts = ['', 'owned first text', '原生剪贴板 🧪\x00\n', 'owned replacement']
                        for ordinal, index in enumerate(range(0, len(value['rows']), 3)):
                            assert value['rows'][index]['result'] == dict(type='boolean', value=True)
                            assert value['rows'][index+1]['phase'] == 'fulfilled'
                            if case == 'wayland-write-v1':
                                assert value['rows'][index+2]['phase'] == 'rejected'
                                assert value['rows'][index+2]['error'] == dict(name='Error', code='GenericFailure', message=
                                    'arboard read failed: Unknown error while interacting with the clipboard: A required Wayland protocol (ext-data-control, or wlr-data-control version 2) is not supported by the compositor')
                            else:
                                assert value['rows'][index+2]['phase'] == 'fulfilled'
                                assert value['rows'][index+1]['result'] == value['rows'][index+2]['result']
                            text = texts[ordinal]; data = text.encode()
                            assert value['rows'][index+1]['result'] == dict(type='string', text=text, utf8Bytes=len(data),
                                                                          utf16Units=len(text.encode('utf-16-le')) // 2,
                                                                          sha256=hashlib.sha256(data).hexdigest())
                    if case in ['stranded-readers', 'exit-with-stranded-readers']:
                        assert all(r['phase'] == 'rejected' and r['error']['code'] == 'GenericFailure' and
                                   r['error']['message'] == 'no answer before the deadline' for r in value['rows'][:4])
                        if case == 'stranded-readers':
                            assert len(value['rows']) == 6
                            assert value['rows'][4]['error']['message'] == 'too many earlier reads still stuck in flight'
                            assert value['rows'][5]['error']['message'].startswith('no reachable display server: ')
                        else:
                            assert len(value['rows']) == 4
                        assert BlockedDisplay.reader_count() == 0, 'Reader threads survived the bounded process exit'
                    if case == 'spawn-error':
                        assert len(value['rows']) == 7
                        assert all(r['phase'] == 'rejected' and r['error']['code'] == 'GenericFailure' and
                                   r['error']['message'] == 'could not spawn the read thread: Resource temporarily unavailable (os error 11)'
                                   for r in value['rows'][:6])
                        assert value['rows'][6]['error']['message'].startswith('no reachable display server: ')
                    if (case.startswith('size-limit-') or case == 'incr-small'):
                        row = value['rows'][0]
                        if case == 'size-limit-over':
                            assert row['phase'] == 'rejected' and row['error']['message'] == 'selection text is over the size cap'
                        else:
                            expected = json.loads((folder / 'large-fixture.json').read_bytes())
                            assert row['phase'] == 'fulfilled' and row['result'] == dict(type='string', utf8Bytes=size,
                                                                                       utf16Units=size, sha256=expected['sha256'])
                    observations[side] = value
                    (folder / 'observation.json').write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
                finally:
                    if blocked is not None: blocked.finish()
                    if wayland is not None: wayland.finish()
                    if owned_large is not None: owned_large.finish()
                    for child in reversed(children): retire(child)
                    (temporary / 'large-selection').unlink(missing_ok=True)
                    (folder / 'retired.json').write_text(json.dumps(dict(child_exits=[p.poll() for p in children], all_reaped=True)) + '\n')
            equal = observations['original'] == observations['rebuilt']
            receipt['pairs'].append(dict(case=case, equal=equal, calls=len(observations['original']['rows'])))
            print(json.dumps(dict(target=target, case=case, equal=equal)), flush=True)
            assert equal, 'Raw structured observations differ: ' + case
            if case == 'spawn-error':
                events = [json.loads(line) for line in (out / 'owned-pthread-failures.jsonl').read_text().splitlines()]
                assert len(events) == 12 and all(row['pthread_create_return'] == 11 for row in events)
                assert [row['caller'] for row in events].count('/modules/original.node') == 6
                assert [row['caller'] for row in events].count('/modules/rebuilt.node') == 6
        for side, pin in receipt['inputs'].items():
            assert sha(Path('/modules') / (side + '.node')) == pin['sha256']
        for name, pin in receipt['fixture_inputs'].items():
            assert sha(inputs / name) == pin['sha256']
        boundary('final')
        receipt.update(status='clipboard_pair_cohorts_passed', admitted_pairs=len(receipt['pairs']),
                       function_observation_pairs=sum(r['calls'] for r in receipt['pairs']))
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
