"""Native x64 comparison of private clipboard modules in owned displays.

Private source and complete clients are never inputs to this workflow. The
two reconstructed modules and previously built owned fixtures arrive through
repository secrets. Original modules are extracted as data from pinned public
packages. Only encrypted bounded records and aggregate status are exported.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import lzma
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
CONFIG = json.loads((ROOT / 'private-input-transport.json').read_bytes())
spec = importlib.util.spec_from_file_location('owned_audio_acceptance_common', REPO / 'linux-audio-client-acceptance/run.py')
common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def unpack(folder, destination):
    chunks = folder / 'chunks'
    assert {p.name for p in chunks.iterdir()} == {format(i, '03') for i in range(CONFIG['chunks'])}
    encoded = b''.join((chunks / format(i, '03')).read_bytes() for i in range(CONFIG['chunks']))
    assert len(encoded) == CONFIG['base64_bytes']
    raw = base64.b64decode(encoded, validate=True)
    assert len(raw) == CONFIG['archive_bytes'] and hashlib.sha256(raw).hexdigest() == CONFIG['archive_sha256']
    decoder = lzma.LZMADecompressor(memlimit=256 * 1024 * 1024)
    plain = decoder.decompress(raw, max_length=16 * 1024 * 1024)
    assert decoder.eof and not decoder.unused_data
    destination.mkdir(mode=0o700)
    expected = {'manifest.json', 'module-gnu.node', 'module-musl.node', 'owned-gnu.node', 'owned-musl.node',
                'fault-gnu.so', 'fault-musl.so', 'wayland-server', 'wayland-client'}
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        members = archive.getmembers()
        assert len(members) == len(expected) and {m.name for m in members} == expected
        for member in members:
            assert member.isreg() and 0 < member.size <= 4 * 1024 * 1024
            with archive.extractfile(member) as source, (destination / member.name).open('xb') as output:
                shutil.copyfileobj(source, output)
            (destination / member.name).chmod(0o500 if member.name.startswith('wayland-') else 0o400)
    manifest = json.loads((destination / 'manifest.json').read_bytes())
    assert manifest['schema'] == 'private.clipboard-x64-native-input.v11' and set(manifest['profiles']) == {'gnu', 'musl'}
    for relative, digest in manifest['owned_source_pins'].items():
        path = Path(relative)
        assert not path.is_absolute() and '..' not in path.parts and sha(ROOT / path) == digest
    for abi, row in manifest['profiles'].items():
        path = destination / ('module-' + abi + '.node')
        assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    for name, row in manifest['fixture_binaries'].items():
        assert name in expected and name != 'manifest.json'
        path = destination / name
        assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    for path in destination.iterdir():
        if path.name != 'manifest.json':
            header = path.read_bytes()[:64]
            assert header[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', header, 18)[0] == 62
    shutil.rmtree(chunks)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    for name in ['gnu-engine', 'musl-engine', 'sdk', 'input', 'private', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    private = args.private.resolve(); private.mkdir(mode=0o700)
    output = args.output.resolve(); output.mkdir()
    receipt = dict(status='started', function_pairs=0, cohort_pairs=0, original_execution_attempted=False,
        comparison_rules_modified=False, host_clipboard_connected=False, physical_device_access=False,
        private_source_uploaded=False, complete_client_uploaded=False, commands=[], profiles={}, goal_complete=False)
    environment = dict(PATH=os.environ['PATH'], HOME=os.environ['HOME'], LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')
    identity = uuid.uuid4().hex[:12]

    def run(label, command, timeout=180):
        assert re.fullmatch('[A-Za-z0-9-]+', label)
        command = list(map(str, command)); name = None
        if command[:2] == ['docker', 'run']:
            name = 'neverd-clipboard-' + identity + '-' + label
            command[2:2] = ['--name', name]
        row = dict(label=label, command=command); receipt['commands'].append(row)
        started = time.monotonic()
        with (private / (label + '.stdout')).open('xb') as stdout, (private / (label + '.stderr')).open('xb') as stderr:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment, timeout=timeout)
                row['exit_code'] = result.returncode
            except subprocess.TimeoutExpired:
                row['timeout'] = True
                if name:
                    cleanup = subprocess.run(['docker', 'rm', '--force', name], capture_output=True, timeout=30, env=environment)
                    row['retirement_exit'] = cleanup.returncode
                    check = subprocess.run(['docker', 'container', 'inspect', name], capture_output=True, timeout=20, env=environment)
                    row['container_absent_after_retirement'] = check.returncode == 1 and b'No such' in check.stderr
                    assert row['container_absent_after_retirement']
                raise
            finally:
                row['seconds'] = round(time.monotonic() - started, 3)
        assert result.returncode == 0, label + ': inspect encrypted diagnostics'
        return (private / (label + '.stdout')).read_bytes()

    failed = True
    try:
        assert platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0
        daemon = json.loads(run('daemon', ['docker', 'info', '--format', '{{json .}}'], 30))
        assert daemon['Architecture'] in ['amd64', 'x86_64'] and daemon['OSType'] == 'linux'
        receipt['host'] = dict(machine=platform.machine(), kernel=platform.release(),
            GitHub_head=os.environ.get('GITHUB_SHA'), GitHub_run_id=os.environ.get('GITHUB_RUN_ID'),
            GitHub_runner_arch=os.environ.get('RUNNER_ARCH'), docker_architecture=daemon['Architecture'])
        manifest = unpack(args.input.resolve(), private / 'replacements')
        recipes = private / 'recipes'
        receipt['retained_public_recipes'] = common.stage_recipes(recipes)
        pins = json.loads((REPO / 'linux-audio-client-acceptance/environment-pins.json').read_bytes())
        image = 'neverd-clipboard-x64:actions-v11'
        run('public-image', ['docker', 'build', '--platform', 'linux/amd64', '--build-arg',
            'UBUNTU_BASE=ubuntu@' + pins['ubuntu22']['amd64'], '--build-arg', 'PYTHON_BASE=' + pins['python']['x64'], '-t', image, ROOT], 600)
        info = json.loads(run('image', ['docker', 'image', 'inspect', image], 30))[0]
        assert info['Architecture'] == 'amd64'; image = info['Id']; receipt['runtime_image'] = image
        run('admit-gnu', [sys.executable, '-B', recipes / 'seccomp-helper/source_runtime.py', '--arch', 'x64',
            '--artifact', args.gnu_engine.resolve(), '--output', private / 'admitted-gnu'], 300)
        run('admit-musl', [sys.executable, '-B', '-c',
            'import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from source_engine import qualify;qualify("x64",Path(sys.argv[2]))',
            recipes / 'musl-native-components', args.musl_engine.resolve()], 180)
        inputs = private / 'inputs'; inputs.mkdir()
        for name in ['compare-clipboard.mjs', 'owned-napi-probe.mjs', 'owned_large_X11_provider.py']:
            shutil.copyfile(ROOT / name, inputs / name)
        for abi, engine in [('gnu', private / 'admitted-gnu/bun'), ('musl', args.musl_engine.resolve() / 'bun')]:
            shutil.copyfile(engine, inputs / ('bun-linux-x64-' + abi)); (inputs / ('bun-linux-x64-' + abi)).chmod(0o500)
            for source, name in [('owned-' + abi + '.node', 'owned-linux-x64-' + abi + '.node'),
                ('fault-' + abi + '.so', 'owned-pthread-fault-linux-x64-' + abi + '.so')]:
                shutil.copyfile(private / 'replacements' / source, inputs / name)
        for kind in ['server', 'client']:
            target = inputs / ('owned-wayland-' + kind + '-x64')
            shutil.copyfile(private / 'replacements' / ('wayland-' + kind), target); target.chmod(0o500)
        shutil.copytree(args.sdk.resolve(), inputs / 'sdk-x64')
        run('prepare-public-musl-runtime', [sys.executable, '-B', '-c',
            'import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from runtime_sdk import prepare;prepare("x64",Path(sys.argv[2]),Path(sys.argv[3]))',
            recipes / 'musl-native-components', args.sdk.resolve(), inputs / 'runtime-musl-x64'])
        loader = inputs / 'owned-musl-loader-x64'
        shutil.copyfile(inputs / 'runtime-musl-x64/lib/ld-musl-x86_64.so.1', loader); loader.chmod(0o500)
        tools = private / 'tools'; tools.mkdir()
        build = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2',
            '--memory', '2g', '--pids-limit', '64', '--ulimit', 'core=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--mount', f'type=bind,src={recipes},dst=/recipes,readonly', '--mount', f'type=bind,src={tools},dst=/tools']
        run('compile-owned-extractor', [*build, image, 'g++', '-std=c++20', '-static', '-O2', '-Wall', '-Wextra',
            '/recipes/seccomp-helper/extract-linux-graph.cpp', '-lcrypto', '-pthread', '-ldl', '-o', '/tools/extract'])
        for abi in ['gnu', 'musl']:
            target = private / ('target-' + abi); target.mkdir()
            original = common.prepare_original(abi, target / 'original-package', recipes)
            run('extract-' + abi, [*build, '--mount', f'type=bind,src={target},dst=/target', image, '/tools/extract',
                '/target/original-package/original', sha(original), '/target/extracted'], 90)
            rows = [line.split('\t') for line in (target / 'extracted/mapping.tsv').read_text().splitlines()]
            assert len(rows) == 2589 and len(rows[2346]) == 8
            file = rows[2346][5]; assert Path(file).name == file
            module = target / 'extracted/input' / file; profile = manifest['profiles'][abi]
            assert module.stat().st_size == profile['original_bytes'] and sha(module) == profile['original_sha256']
            original_module = target / 'original-clipboard.node'; shutil.copyfile(module, original_module)
            candidate = private / 'replacements' / ('module-' + abi + '.node')
            runtime = private / ('runtime-' + abi); runtime.mkdir()
            records = runtime / 'execution-records'; records.mkdir()
            command = ['docker', 'run', '--rm', '--init', '--platform', 'linux/amd64', '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}',
                '--cpus', '2', '--memory', '3g', '--pids-limit', '128', '--ulimit', 'core=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m']
            for source, destination in [(inputs, '/inputs'), (recipes, '/recipes'), (ROOT / 'run_compare.py', '/runner.py'),
                (ROOT / 'owned_blocked_display.py', '/owned_blocked_display.py'), (ROOT / 'owned_wayland_display.py', '/owned_wayland_display.py'),
                (ROOT / 'owned_large_x11.py', '/owned_large_x11.py'), (original_module, '/modules/original.node'), (candidate, '/modules/rebuilt.node')]:
                command += ['--mount', f'type=bind,src={source},dst={destination},readonly']
            command += ['--mount', f'type=bind,src={records},dst=/evidence', image, 'python3', '-B', '/runner.py', '--arch', 'x64', '--libc', abi, '--suite', 'all']
            receipt['original_execution_attempted'] = True
            run('full-' + abi, command, 300)
            result = json.loads((records / 'receipt.json').read_bytes())
            assert result['status'] == 'clipboard_pair_cohorts_passed' and result['original_executed']
            assert result['admitted_pairs'] == 15 and result['function_observation_pairs'] == 91
            assert result['inputs']['original']['sha256'] == profile['original_sha256']
            assert result['inputs']['rebuilt']['sha256'] == profile['sha256']
            receipt['profiles'][abi] = dict(module_sha256=profile['sha256'], original_sha256=profile['original_sha256'],
                source_sha256=profile['source_sha256'], cargo_lock_sha256=profile['cargo_lock_sha256'],
                pairs=91, cohorts=15, exact_raw_comparison=True, receipt_sha256=sha(records / 'receipt.json'))
            receipt['function_pairs'] += 91; receipt['cohort_pairs'] += 15
        receipt['status'] = 'native_x64_clipboard_182_function_pairs_and_30_cohorts_passed'
        failed = False
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, private_error=str(error), private_traceback=traceback.format_exc())
    finally:
        write(private / 'controller-receipt.json', receipt)
        public = {key: receipt[key] for key in ['status', 'function_pairs', 'cohort_pairs', 'original_execution_attempted',
            'comparison_rules_modified', 'host_clipboard_connected', 'physical_device_access', 'private_source_uploaded', 'complete_client_uploaded', 'goal_complete']}
        try:
            for path in private.glob('runtime-*/execution-records/**/*'):
                if path.is_file():
                    with path.open('rb') as stream:
                        signature = stream.read(4)
                        assert signature not in [b'\x7fELF'] and signature[:2] != b'MZ' and path.suffix not in ['.node', '.so', '.exe']
            public['encrypted_records'] = common.seal(private, output)
        except BaseException as error:
            public.update(status='private_records_encryption_failed_not_admitted', error_type=type(error).__name__)
            failed = True
        write(output / 'receipt.json', public)
        print(json.dumps(public), flush=True)
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
