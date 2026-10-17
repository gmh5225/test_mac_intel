"""Compare native macOS source-library roles after authored Seatbelt controls."""
from pathlib import Path
import argparse
import base64
import bz2
import errno
import gzip
import hashlib
import json
import os
import platform
import resource
import selectors
import shutil
import signal
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    p.add_argument('--role', choices=['ugrep', 'bfs'], default='ugrep')
    p.add_argument('--package', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--original-path', type=Path); a = p.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[a.arch]
    os_version = platform.mac_ver()[0]
    assert os.getuid() != 0
    package = a.package.resolve(); seen = set()
    assert not any(p.is_symlink() for p in package.rglob('*'))
    for row in json.loads((package / 'MANIFEST.json').read_bytes())['files']:
        rel = Path(row['file']); assert not rel.is_absolute() and '..' not in rel.parts and rel.as_posix() == row['file'] and row['file'] not in seen
        seen.add(row['file']); file = package / rel
        assert file.is_file() and file.stat().st_size == row['bytes'] and sha(file) == row['sha256']
    assert seen | {'MANIFEST.json'} == {p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    producer = json.loads((package / 'receipt.json').read_bytes())
    expected_status = 'macos_ugrep_source_library_and_upstream_host_checks_passed' if a.role == 'ugrep' else 'public_macos_bfs_cross_source_library_built_native_acceptance_pending'
    assert producer['arch'] == a.arch and producer['status'] == expected_status
    component = producer if a.role == 'ugrep' else producer['native_library']
    candidate = package / 'native-library' / (a.role + '-library-host'); assert sha(candidate) == component['host_sha256']
    candidate.chmod(0o500)
    pin = json.loads((ROOT / 'original-pins.json').read_bytes())[a.arch]
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    inputs = out / 'inputs'; inputs.mkdir(); fixtures = out / 'fixtures'; fixtures.mkdir()
    home = out / 'home'; home.mkdir(); work = out / 'work'; work.mkdir(); temp = out / 'tmp'; temp.mkdir()
    canary = out / 'outside-canary'; canary.write_bytes(b'owned outside fixture\n')
    text = b'first\nNEEDLE\npreneedle\n'; (fixtures / 'input.txt').write_bytes(text)
    (fixtures / '猫.txt').write_text('first\n🐈\n'); (fixtures / 'line\nbreak.txt').write_bytes(text)
    (fixtures / 'nested').mkdir(); (fixtures / 'nested/child.txt').write_bytes(b'nested NEEDLE\n')
    (fixtures / 'link.txt').symlink_to('input.txt')
    for suffix, raw in [('gz', gzip.compress(text, mtime=0)), ('bz2', bz2.compress(text)),
                        ('zst', bytes.fromhex('28b52ffd0458b9000066697273740a4e4545444c450a7072656e6565646c650a2c682895')),
                        ('br', bytes.fromhex('0f0b8066697273740a4e4545444c450a7072656e6565646c650a03'))]:
        (fixtures / ('input.' + suffix)).write_bytes(raw)
    transport = inputs / 'transport'; boundary = inputs / 'boundary'; original = inputs / 'original-copy'
    receipt = dict(status='started', arch=a.arch, component_role=a.role, native_host=True, runtime_os_version=os_version, candidate_manifest_sha256=sha(package / 'MANIFEST.json'),
        candidate_sha256=sha(candidate), captured_client_executed=False, captured_source_uploaded=False,
        boundary_qualified=False, controls=[], cases=[], normalization='none; exact exit/stdout/stderr bytes',
        whole_engine_integration=False, goal_complete=False)

    def build(name, source, destination):
        result = subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(destination)], capture_output=True, timeout=60)
        (logs / (name + '.stdout')).write_bytes(result.stdout); (logs / (name + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, name

    allowed = [transport, boundary, candidate, original]
    literal = lambda path: '(literal ' + json.dumps(str(path)) + ')'
    profile = '(version 1)\n(deny default)\n(allow sysctl-read)\n(allow file-read-metadata)\n'
    profile += '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (subpath "/System/Library") (subpath "/usr/lib") (subpath "/System/Volumes/Preboot/Cryptexes/OS") (subpath "/usr/share/locale") (subpath ' + json.dumps(str(fixtures)) + '))\n'
    profile += '(allow file-map-executable (subpath "/System/Library") (subpath "/usr/lib") (subpath "/System/Volumes/Preboot/Cryptexes/OS"))\n'
    for executable in allowed: profile += '(allow file-read* file-map-executable process-exec ' + literal(executable) + ')\n'
    profile += '(allow process-fork)\n(allow signal (target self))\n(deny network*)\n'
    profile_path = logs / 'profile.sb'; profile_path.write_text(profile)
    environment = dict(HOME=str(home), TMPDIR=str(temp), PATH='/unavailable', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                       BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256)); resource.setrlimit(resource.RLIMIT_CPU, (20, 20))

    def execute(label, target, argv0, args, stdin=b'', role=None, expected_failure=None):
        env = dict(environment)
        if role is not None: env['ARGV0'] = role
        command = ['/usr/bin/sandbox-exec', '-f', str(profile_path), str(transport), str(target), argv0, *map(str, args)]
        process = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, preexec_fn=limits)
        assert len(stdin) <= 4096; process.stdin.write(stdin); process.stdin.close()
        selector = selectors.DefaultSelector(); streams = dict(stdout=bytearray(), stderr=bytearray()); failure = None
        for key, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, key)
        deadline = time.monotonic() + 30; kill_errors = []
        def stop():
            # sandbox-exec can briefly reject a group signal around exec.
            # Reap an already exited child first, and retain any signal error.
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
            assert process.poll() is not None, 'Bounded child cleanup failed'
        try:
            while selector.get_map():
                if time.monotonic() > deadline: failure = 'wall timeout'; break
                for event, _ in selector.select(.1):
                    raw = os.read(event.fileobj.fileno(), 65536)
                    if not raw: selector.unregister(event.fileobj); continue
                    stream = streams[event.data]
                    if len(stream) + len(raw) > 262144:
                        stream.extend(raw[:262144 - len(stream)]); failure = 'output limit'; break
                    stream.extend(raw)
                if failure: break
            if failure: stop()
            code = process.wait(timeout=10)
        finally:
            selector.close()
            if process.poll() is None: stop()
        for key, raw in streams.items(): (logs / (label + '.' + key)).write_bytes(raw)
        result = dict(label=label, command=command, exit_code=code, failure=failure, fsize_zero=True, kill_errors=kill_errors,
            streams={key: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for key, raw in streams.items()})
        (logs / (label + '.result.json')).write_text(json.dumps(result, indent=2) + '\n')
        assert failure == expected_failure, label + ': ' + str(failure)
        return code, bytes(streams['stdout']), bytes(streams['stderr'])

    try:
        for name in ['compare_ugrep.py', 'role-transport.c', 'boundary-control.c', 'original-pins.json']:
            shutil.copyfile(ROOT / name, logs / name)
        build('transport-build', ROOT / 'role-transport.c', transport)
        build('boundary-build', ROOT / 'boundary-control.c', boundary)
        code, stdout, stderr = execute('boundary', boundary, 'owned-boundary', [canary, work / 'forbidden-write', fixtures / 'input.txt'])
        assert code == 0 and stdout and not stderr, 'Owned boundary control failed with exit ' + str(code)
        observed = json.loads(stdout); assert observed['readable'] == observed['shell_exec_denied'] == 1 and len(observed['network_errno']) == 4
        assert all(value in [errno.EPERM, errno.EACCES] for value in [observed['outside_errno'], observed['write_errno'], *observed['network_errno']])
        assert not (work / 'forbidden-write').exists() and canary.read_bytes() == b'owned outside fixture\n'
        receipt['controls'].append(dict(label='boundary', observed=observed))
        for index, (argv0, role) in enumerate([('owned-α 🐈', None), ('ugrep', 'unknown'), ('/path/ugrep', 'rg')]):
            args = ['a b', 'quote"slash\\', '🐈', '']
            code, stdout, stderr = execute('transport-' + str(index), transport, argv0, ['--capture', *args], role=role)
            assert code == 37 and not stderr and json.loads(stdout) == dict(argv0_hex=argv0.encode().hex(),
                env_hex=role.encode().hex() if role is not None else None, args=[arg.encode().hex() for arg in args])
            receipt['controls'].append(dict(label='transport-' + str(index), passed=True))
        execute('output-limit', transport, 'owned-flood', ['--flood'], expected_failure='output limit')
        receipt['controls'].append(dict(label='output-limit', passed=True))
        receipt['boundary_qualified'] = True
        (logs / 'qualified-before-original.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if a.original_path:
            assert a.original_path.is_file() and not a.original_path.is_symlink() and sha(a.original_path) == pin['sha256']
            shutil.copyfile(a.original_path, original)
        else:
            archive = inputs / 'published-input.tgz'
            result = subprocess.run(['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3',
                '--max-time', '300', '--max-filesize', '134217728', '--output', str(archive), pin['url']], capture_output=True, timeout=360)
            assert result.returncode == 0, 'Original input download failed'
            with archive.open('rb') as source: integrity = base64.b64encode(hashlib.file_digest(source, 'sha512').digest()).decode()
            assert pin['integrity'] == 'sha512-' + integrity
            with tarfile.open(archive, 'r:gz') as source:
                members = [m for m in source.getmembers() if m.name == 'package/claude' and m.isfile()]
                assert len(members) == 1 and members[0].size == pin['bytes']
                with source.extractfile(members[0]) as raw, original.open('xb') as destination: shutil.copyfileobj(raw, destination)
        assert original.stat().st_size == pin['bytes'] and sha(original) == pin['sha256']; original.chmod(0o500)
        cases = [('version', ['--version'], 0, b''), ('literal', ['--no-config', '-n', 'NEEDLE', fixtures / 'input.txt'], 0, b''),
                 ('absent', ['--no-config', 'absent-value', fixtures / 'input.txt'], 1, b''),
                 ('invalid', ['--no-config', '[', fixtures / 'input.txt'], 2, b''),
                 ('pcre', ['--no-config', '-P', '-o', '(?<=pre)needle', fixtures / 'input.txt'], 0, b''),
                 ('unicode', ['--no-config', '-n', '🐈', fixtures / '猫.txt'], 0, b''),
                 ('newline-filename', ['--no-config', '-n', 'NEEDLE', fixtures / 'line\nbreak.txt'], 0, b''),
                 ('count', ['--no-config', '-c', '-i', 'needle', fixtures / 'input.txt'], 0, b''),
                 ('stdin-pcre', ['--no-config', '-P', '-o', '(?<=pre)needle'], 0, text)]
        cases += [(suffix, ['--no-config', '-z', '-n', 'NEEDLE', fixtures / ('input.' + suffix)], 0, b'') for suffix in ['gz', 'bz2', 'zst', 'br']]
        if a.role == 'bfs':
            cases = [('version', ['--version'], 0, b''),
                ('name', ['-s', fixtures, '-maxdepth', '1', '-type', 'f', '-name', '*.txt', '-printf', '%f\n'], 0, b''),
                ('depth', ['-s', fixtures, '-mindepth', '2', '-maxdepth', '2', '-type', 'f', '-printf', '%P\n'], 0, b''),
                ('regex', ['-s', fixtures, '-maxdepth', '1', '-regex', '.*input[.]txt', '-printf', '%f\n'], 0, b''),
                ('link', ['-L', '-s', fixtures / 'link.txt', '-type', 'f', '-printf', '%f\n'], 0, b''),
                ('exec', [fixtures / 'input.txt', '-exec', transport, '--capture', ';'], 0, b''),
                ('absent', ['-s', fixtures, '-name', 'absent-value', '-print'], 0, b''),
                ('missing-user', [fixtures, '-maxdepth', '0', '-user', 'neverd_missing_public_fixture_user_21296'], 1, b'')]
            major = int(os_version.split('.')[0]); assert major == 15 or major >= 26
            expected_execdir = -signal.SIGSEGV if major == 15 else 0
            cases.append(('execdir', [fixtures / 'input.txt', '-execdir', transport, '--capture', ';'], expected_execdir, b''))
            receipt['execdir_runtime_boundary'] = dict(required_macos='26.0', expected_exit_code=expected_execdir,
                original_missing_API_fault_preserved=major == 15)
        for label, args, expected, stdin in cases:
            left = execute('original-' + label, original, a.role, args, stdin)
            receipt['captured_client_executed'] = True
            right = execute('candidate-' + label, candidate, a.role, args, stdin)
            matches = left == right and left[0] == expected
            receipt['cases'].append(dict(case=label, expected_exit_code=expected, original_exit_code=left[0], candidate_exit_code=right[0], matches=matches))
            assert matches, 'Exact ' + a.role + ' mismatch: ' + label
        assert sha(original) == pin['sha256'] and sha(candidate) == component['host_sha256']
        receipt.update(status='native_original_and_source_library_' + a.role + '_cases_match_exactly', differential_pairs=len(cases), original=pin,
            scope='Bounded standalone native source-library correspondence. Full Bun engine and recovered client integration remain open.')
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
