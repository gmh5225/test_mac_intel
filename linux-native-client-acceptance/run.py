"""Rebuild complete clients containing both authored addons on native x64, then compare.

Only public recipes live here. Module replacements arrive through repository
secrets; captured sources and complete clients stay in the runner's temp tree.
All retained private streams are encrypted to the owner's public recipient.
"""
from pathlib import Path
import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
INPUT_CONFIG = json.loads((ROOT / 'private-input-transport.json').read_bytes())
RECIPIENT_SHA256 = 'dc19589992ec91dbb66f34435d302a4b14e47d9ccd789c60c75f1894a9a943de'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def unpack_input(folder, destination):
    chunks = folder / 'chunks'
    assert {p.name for p in chunks.iterdir()} == {format(i, '03') for i in range(INPUT_CONFIG['chunks'])}
    encoded = b''.join((chunks / format(i, '03')).read_bytes() for i in range(INPUT_CONFIG['chunks']))
    assert len(encoded) == INPUT_CONFIG['base64_bytes']
    raw = base64.b64decode(encoded, validate=True)
    assert len(raw) == INPUT_CONFIG['archive_bytes'] and hashlib.sha256(raw).hexdigest() == INPUT_CONFIG['archive_sha256']
    decompressor = lzma.LZMADecompressor(memlimit=256 * 1024 * 1024)
    plain = decompressor.decompress(raw, max_length=16 * 1024 * 1024)
    assert decompressor.eof and not decompressor.unused_data
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        members = archive.getmembers()
        assert len(members) == 5 and {m.name for m in members} == {'manifest.json', 'audio-gnu.node', 'audio-musl.node', 'clipboard-gnu.node', 'clipboard-musl.node'}
        for member in members:
            assert member.isreg() and 0 < member.size <= 6 * 1024 * 1024
            target = destination / member.name
            with archive.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            assert target.stat().st_size == member.size
            target.chmod(0o400)
    manifest = json.loads((destination / 'manifest.json').read_bytes())
    assert manifest['schema'] == 'private.native-Linux-x64-client-input.v12'
    assert manifest['sealed_audio_manifest_sha256'] == '71040598284241d900ae6da3c67716671bcb6b8b4583ef829ec85ee4cea81a67'
    assert manifest['sealed_clipboard_manifest_sha256'] == 'bafb56860cf220d03db28aceba01736176cb4ea7d80060462bc5e66af37df94e'
    assert set(manifest['profiles']) == {'gnu', 'musl'}
    for abi, row in manifest['profiles'].items():
        for kind in ['audio', 'clipboard']:
            module = destination / (kind + '-' + abi + '.node')
            assert module.stat().st_size == row[kind + '_bytes'] and sha(module) == row[kind + '_sha256']
        assert row['clipboard_source_sha256'] == 'a2ffcdbaf8568970e7c1aa50ae339038548f48076b999bb120861ac2c899e75b'
        assert set(row['clients']) == {'preserved', 'readable'}
        for client in row['clients'].values():
            assert 100 * 1024 * 1024 < client['bytes'] < 200 * 1024 * 1024
            assert re.fullmatch('[0-9a-f]{64}', client['sha256'])
    # No secret values enter any compiler, container or client environment.
    shutil.rmtree(chunks)
    return manifest


def download(url, target, limit):
    with urllib.request.urlopen(url, timeout=90) as source, target.open('xb') as out:
        total = 0
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            assert total <= limit
            out.write(block)


def prepare_original(abi, destination, recipes):
    destination.mkdir(mode=0o700)
    relative = 'seccomp-helper' if abi == 'gnu' else 'musl-native-components'
    pin = json.loads((recipes / relative / 'original-pins.json').read_bytes())['x64']
    archive = destination / 'original.tgz'
    download(pin['url'], archive, 128 * 1024 * 1024)
    digest = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    assert digest == pin['integrity'].removeprefix('sha512-')
    if abi == 'musl':
        assert archive.stat().st_size == pin['archive_bytes'] and sha(archive) == pin['archive_sha256']
    with tarfile.open(archive) as source:
        member = source.getmember('package/claude')
        assert member.isreg() and member.size == pin['bytes']
        with source.extractfile(member) as input_stream, (destination / 'original').open('xb') as output:
            shutil.copyfileobj(input_stream, output)
    original = destination / 'original'
    assert sha(original) == pin['sha256'] and original.stat().st_size == pin['bytes']
    original.chmod(0o500)
    header = destination / 'public-json.hpp'
    download('https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp', header, 1048576)
    assert sha(header) == '9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6'
    return original


def stage_recipes(destination):
    shutil.copytree(REPOSITORY, destination, ignore=shutil.ignore_patterns('.git', 'results', '__pycache__', 'retained-*'))
    # Same fixed public engine and unchanged schema-4 admission as sealed v7.
    shutil.copyfile(ROOT / 'fixed-gnu-source-runtime-pins.json', destination / 'seccomp-helper/source-runtime-pins.json')
    proof = ROOT / 'fixed-gnu-independent-qualification.json'
    pins = json.loads((ROOT / 'fixed-gnu-source-runtime-pins.json').read_bytes())
    assert all(row['independent_qualification_sha256'] == sha(proof) for row in pins['profiles'].values())
    for row in json.loads((ROOT / 'retained-comparison-pins.json').read_bytes())['files']:
        assert sha(ROOT / row['file']) == row['sha256']
    # The exact public header is downloaded before entering the offline root.
    # This is the sole retained v7 fixture transport adaptation, not an oracle.
    path = destination / 'musl-native-components/client_root.py'
    before = path.read_text()
    old = "        with urllib.request.urlopen('https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp', timeout=60) as stream:\n            raw = stream.read(1048576)\n"
    new = "        raw = Path('/inputs/public-json.hpp').read_bytes()\n"
    assert before.count(old) == 1
    path.write_text(before.replace(old, new))
    for row in json.loads((ROOT / 'retained-recipes-pins.json').read_bytes())['files']:
        retained = destination / row['file']
        assert retained.is_file() and not retained.is_symlink()
        assert retained.stat().st_size == row['bytes'] and sha(retained) == row['sha256'], row['file']
    return dict(public_header_transport_only=True, before_sha256=hashlib.sha256(before.encode()).hexdigest(), after_sha256=sha(path))


def seal(private, output):
    certificate = REPOSITORY / 'musl-native-components/private-diagnostics-recipient.pem'
    assert sha(certificate) == RECIPIENT_SHA256
    selected = []
    for path in private.rglob('*'):
        if not path.is_file():
            continue
        rel = path.relative_to(private)
        include = len(rel.parts) == 1 and path.suffix in {'.json', '.stdout', '.stderr'}
        include |= bool(rel.parts and rel.parts[0] == 'build-logs')
        include |= 'execution-records' in rel.parts and rel.parts[0].startswith('runtime-')
        include |= rel.parts[0].startswith('runtime-') and path.name in {'receipt.json', 'independent-readback.json'}
        include |= rel.parts[0] == 'owned' and path.suffix in {'.json', '.stdout', '.stderr'}
        if include:
            selected.append(path)
    assert selected and len(selected) <= 8192
    assert all(not p.is_symlink() and p.resolve().is_relative_to(private) and p.stat().st_size <= 16 * 1024 * 1024 for p in selected)
    assert sum(p.stat().st_size for p in selected) <= 256 * 1024 * 1024
    index = private / 'retained-record-index.json'
    write(index, dict(files=[dict(file=p.relative_to(private).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(selected)]))
    selected.append(index)
    archive = private / 'retained-records.tar.gz'
    with tarfile.open(archive, 'x:gz') as target:
        for path in sorted(selected):
            target.add(path, arcname=path.relative_to(private).as_posix(), recursive=False)
    assert archive.stat().st_size <= 64 * 1024 * 1024
    envelope = output / 'private-native-x64-records.cms'
    result = subprocess.run(['openssl', 'cms', '-encrypt', '-aes-256-gcm', '-binary', '-in', str(archive),
        '-outform', 'DER', '-out', str(envelope), '-recip', str(certificate), '-keyopt', 'rsa_padding_mode:oaep'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    if result.returncode:
        envelope.unlink(missing_ok=True)
        raise RuntimeError('Private diagnostic encryption failed; plaintext not exported')
    archive.unlink()
    return dict(algorithm='CMS AES-256-GCM / RSA-4096 OAEP', certificate_sha256=RECIPIENT_SHA256,
        files=len(selected), encrypted_bytes=envelope.stat().st_size, encrypted_sha256=sha(envelope),
        private_key_uploaded=False, plaintext_uploaded=False, source_or_client_binaries_uploaded=False)


def main():
    parser = argparse.ArgumentParser()
    for name in ['gnu-engine', 'musl-engine', 'sdk', 'private', 'output', 'input']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    private = args.private.resolve(); private.mkdir(mode=0o700)
    output = args.output.resolve(); output.mkdir()
    receipt = dict(status='started', expected_pairs=80, accepted_pairs=0,
        original_execution_attempted=False, normalizers_modified=False, goal_complete=False,
        input_transport='bounded_repository_secrets', physical_audio_access=False, commands=[])
    environment = dict(PATH=os.environ['PATH'], HOME=os.environ['HOME'], LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')
    run_id = uuid.uuid4().hex[:12]

    def run(label, command, timeout=180):
        assert re.fullmatch('[A-Za-z0-9-]+', label)
        command = list(map(str, command)); container = None
        if command[:2] == ['docker', 'run']:
            container = 'neverd-audio-x64-' + run_id + '-' + label
            command[2:2] = ['--name', container]
        row = dict(label=label, command=command); receipt['commands'].append(row)
        started = time.monotonic()
        with (private / (label + '.stdout')).open('xb') as out, (private / (label + '.stderr')).open('xb') as err:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=environment, timeout=timeout)
                row['exit_code'] = result.returncode
            except subprocess.TimeoutExpired:
                row['timeout'] = True
                if container:
                    cleanup = subprocess.run(['docker', 'rm', '--force', container], capture_output=True, timeout=30, env=environment)
                    row['retirement_exit'] = cleanup.returncode
                    check = subprocess.run(['docker', 'container', 'inspect', container], capture_output=True, timeout=20, env=environment)
                    row['container_absent_after_retirement'] = check.returncode == 1 and b'No such' in check.stderr
                    assert row['container_absent_after_retirement']
                raise
            finally:
                row['seconds'] = round(time.monotonic() - started, 3)
        assert result.returncode == 0, label + ': inspect encrypted private diagnostics'
        return (private / (label + '.stdout')).read_bytes()

    failed = True
    try:
        assert platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0
        daemon = json.loads(run('daemon', ['docker', 'info', '--format', '{{json .}}'], 30))
        assert daemon['Architecture'] in {'x86_64', 'amd64'} and daemon['OSType'] == 'linux'
        receipt['host'] = dict(kernel=platform.release(), machine=platform.machine(),
            docker={k: daemon.get(k) for k in ['Architecture', 'OSType', 'KernelVersion', 'ServerVersion']},
            GitHub_run_id=os.environ.get('GITHUB_RUN_ID'), GitHub_head=os.environ.get('GITHUB_SHA'),
            GitHub_runner_os=os.environ.get('RUNNER_OS'), GitHub_runner_arch=os.environ.get('RUNNER_ARCH'))
        pins = json.loads((ROOT / 'environment-pins.json').read_bytes())
        image = 'neverd-native-client-x64:actions-v12'
        run('public-image', ['docker', 'build', '--platform', 'linux/amd64', '--build-arg',
            'UBUNTU_BASE=ubuntu@' + pins['ubuntu22']['amd64'], '--build-arg', 'PYTHON_BASE=' + pins['python']['x64'],
            '-t', image, ROOT], 600)
        info = json.loads(run('image-inspect', ['docker', 'image', 'inspect', image], 30))[0]
        assert info['Architecture'] == 'amd64'
        image = info['Id']; receipt['runtime_image'] = image
        common = ['docker', 'run', '--rm', '--init', '--platform', 'linux/amd64', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=unconfined',
            '--security-opt', 'apparmor=unconfined', '--security-opt', 'systempaths=unconfined', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2',
            '--memory', '3g', '--pids-limit', '128', '--ulimit', 'core=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m']
        receipt['outer_namespace_adaptation'] = dict(Docker_AppArmor='unconfined',
            reason='docker-default denied mount propagation in the owned nested user namespace',
            product_Bash_sandbox_enabled=True, capabilities_dropped=True, non_root=True, network='none', read_only_root=True)
        owned = private / 'owned'; owned.mkdir()
        run('owned-kernel-gate', [*common, '--mount', f'type=bind,src={ROOT},dst=/gate,readonly',
            '--mount', f'type=bind,src={owned},dst=/evidence', image, 'python3', '-B', '/gate/owned_preflight.py',
            '--cpu', 'x86_64', '--output', '/evidence/control'], 120)
        gate = json.loads((owned / 'control/receipt.json').read_bytes())
        assert gate['status'] == 'owned_kernel_and_nested_namespace_controls_passed' and not gate['client_executed']
        receipt['owned_kernel_gate_passed'] = True
        inputs = unpack_input(args.input.resolve(), private / 'module-replacements')
        recipes = private / 'recipes'
        receipt['retained_header_transport'] = stage_recipes(recipes)
        logs = private / 'build-logs'; logs.mkdir()
        # Qualify public artifacts with the retained, unchanged engine verifiers.
        run('admit-gnu-engine', [sys.executable, '-B', recipes / 'seccomp-helper/source_runtime.py', '--arch', 'x64',
            '--artifact', args.gnu_engine.resolve(), '--output', private / 'admitted-gnu'], 300)
        run('admit-musl-engine', [sys.executable, '-B', '-c',
            'import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from source_engine import qualify;qualify("x64",Path(sys.argv[2]))',
            recipes / 'musl-native-components', args.musl_engine.resolve()], 180)
        args.musl_engine.resolve().joinpath('bun').chmod(0o500)
        base = json.loads((recipes / 'seccomp-helper/pins.json').read_bytes())['profiles']['x64']['image']
        run('pull-public-build-base', ['docker', 'pull', '--platform', 'linux/amd64', base], 300)
        tools = private / 'workspace-tools'; tools.mkdir()
        build_base = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2',
            '--memory', '2g', '--pids-limit', '64', '--ulimit', 'core=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--mount', f'type=bind,src={recipes},dst=/recipes,readonly', '--mount', f'type=bind,src={tools},dst=/tools']
        run('compile-owned-extractor', [*build_base, base, 'g++', '-std=c++20', '-static', '-O2', '-Wall', '-Wextra',
            '/recipes/seccomp-helper/extract-linux-graph.cpp', '-lcrypto', '-pthread', '-ldl', '-o', '/tools/extract'])
        spec = importlib.util.spec_from_file_location('retained_whitespace_recipe', recipes / 'seccomp-helper/format_recipe.py')
        formatter = importlib.util.module_from_spec(spec); spec.loader.exec_module(formatter)
        receipt['client_builds'] = {}
        for abi in ['gnu', 'musl']:
            profile = inputs['profiles'][abi]
            target = private / ('target-' + abi); target.mkdir()
            inbox = target / 'inputs'
            original = prepare_original(abi, inbox, recipes)
            extracted = target / 'extracted'
            run('extract-' + abi, [*build_base, '--mount', f'type=bind,src={target},dst=/target', base,
                '/tools/extract', '/target/inputs/original', sha(original), '/target/extracted'], 90)
            data = json.loads(gzip.decompress((recipes / ('seccomp-helper/linux-readable-recipes-v1.json.gz' if abi == 'gnu'
                else 'musl-native-components/musl-readable-recipes-v1.json.gz')).read_bytes()))
            expected = data['profiles']['x64']; rows = expected['rows']
            mapping = [line.split('\t') for line in (extracted / 'mapping.tsv').read_text().splitlines()]
            assert len(mapping) == len(rows) == 2589
            workspace = target / 'workspace'; workspace.mkdir()
            for layout in ['preserved', 'readable']:
                sources = workspace / layout / 'sources'; sources.mkdir(parents=True)
                for row, values in zip(rows, mapping):
                    index = row['module_index']; name, loader, encoding, form, side, file, size, digest = values
                    assert [name, int(loader), int(encoding), int(form), int(side), int(size), digest] == [
                        row[k] for k in ['virtual_name', 'loader_id', 'encoding_id', 'format_id', 'side_id', 'bytes', 'storage_sha256']]
                    assert Path(file).name == file
                    raw = (extracted / 'input' / file).read_bytes()
                    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == digest
                    if layout == 'readable' and row['loader_id'] == 1:
                        raw = formatter.formatted(raw, data['recipes'][digest])
                        assert hashlib.sha256(raw).hexdigest() == row['readable_sha256']
                    if index in [2346, 2364]:
                        kind = 'clipboard' if index == 2346 else 'audio'
                        raw = (private / 'module-replacements' / (kind + '-' + abi + '.node')).read_bytes()
                    (sources / ('m' + str(index))).write_bytes(raw)
            clients = target / 'clients'; build_logs = logs / abi; build_logs.mkdir()
            engine = private / 'admitted-gnu/bun' if abi == 'gnu' else args.musl_engine.resolve() / 'bun'
            assert sha(engine) == profile['engine_sha256']
            if abi == 'gnu':
                command = [sys.executable, '-B', recipes / 'seccomp-helper/native_client_build.py', '--arch', 'x64',
                    '--original', original, '--output', clients, '--logs', build_logs, '--source-bun', engine,
                    '--source-bun-sha256', sha(engine), '--source-workspace', workspace, '--containerized-tools']
            else:
                command = [sys.executable, '-B', recipes / 'musl-native-components/client_build.py', '--arch', 'x64',
                    '--original', original, '--engine', engine, '--sdk', args.sdk.resolve(), '--output', clients,
                    '--logs', build_logs, '--workspace', workspace]
            run('build-' + abi, command, 1200)
            built = json.loads((build_logs / 'native-client-build.json').read_bytes())
            for layout in ['preserved', 'readable']:
                client = clients / layout / 'client-final'
                assert dict(bytes=client.stat().st_size, sha256=sha(client)) == profile['clients'][layout]
                edits = built['intentional_edit_modules'][layout] if abi == 'gnu' else built['clients'][layout]['intentionally_edited_modules']
                assert edits == [2346, 2364] and built['original_descriptor_provider_preserved']
                shutil.copyfile(client, inbox / ('client-' + layout)); (inbox / ('client-' + layout)).chmod(0o500)
            receipt['client_builds'][abi] = dict(exact_locally_rebuilt_client_bytes=True, only_changed_modules=[2346, 2364],
                original_descriptor_provider_preserved=True, original_executed_during_build=False)
            write(inbox / 'inputs.json', [dict(name=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(inbox.iterdir())])
            runtime = private / ('runtime-' + abi); runtime.mkdir()
            label = 'native-x64-' + abi + '-full-v12'
            receipt['original_execution_attempted'] = True
            run('full-' + abi, [*common, '--mount', f'type=bind,src={recipes},dst=/recipes,readonly',
                '--mount', f'type=bind,src={args.sdk.resolve()},dst=/sdk,readonly',
                '--mount', f'type=bind,src={inbox},dst=/inputs,readonly', '--mount', f'type=bind,src={ROOT / ("runner-" + abi + ".py")},dst=/runner.py,readonly',
                '--mount', f'type=bind,src={runtime},dst=/work', image, 'python3', '-B', '/runner.py',
                '--arch', 'x64', '--scope', 'full', '--run-label', label], 2400)
            path = runtime / label / 'receipt.json'
            run('readback-' + abi, [sys.executable, '-B', ROOT / 'verify_client_records.py', '--recipes', recipes,
                '--receipt', path, '--output', runtime / 'independent-readback.json'], 60)
            value = json.loads((runtime / 'independent-readback.json').read_bytes())
            assert value['pairs'] == 40
            receipt['accepted_pairs'] += 40
        assert receipt['accepted_pairs'] == 80
        receipt['status'] = 'native_x64_audio_clipboard_four_clients_80_pairs_independently_recomputed'
        failed = False
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, private_error=str(error), private_traceback=traceback.format_exc())
    finally:
        write(private / 'controller-receipt.json', receipt)
        public = {k: receipt[k] for k in ['status', 'expected_pairs', 'accepted_pairs', 'original_execution_attempted', 'normalizers_modified', 'goal_complete']}
        try:
            public['encrypted_records'] = seal(private, output)
        except BaseException as error:
            public.update(status='private_records_encryption_failed_not_admitted', error_type=type(error).__name__)
            failed = True
        write(output / 'receipt.json', public)
        print(json.dumps(public), flush=True)
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
