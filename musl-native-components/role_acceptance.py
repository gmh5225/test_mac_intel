"""Compare native musl Ugrep/Bfs only after owned file/network/stream controls."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import tarfile
import urllib.request

from sdk import ROOT, profile, sha
from component_libraries import qualify
from runtime_sdk import prepare as prepare_runtime
from role_cases import prepare as prepare_fixtures, cases
from role_process import RoleProcess


def original_input(arch, output, supplied=None):
    pin = json.loads((ROOT / 'original-pins.json').read_bytes())[arch]
    destination = output / 'original'
    if supplied is not None: shutil.copyfile(supplied, destination)
    else:
        archive = output / 'original.tgz'; digest = hashlib.sha512(); size = 0
        with urllib.request.urlopen(pin['url'], timeout=90) as response, archive.open('xb') as target:
            while chunk := response.read(1048576):
                size += len(chunk); assert size <= pin['archive_bytes']; digest.update(chunk); target.write(chunk)
        assert size == pin['archive_bytes'] and sha(archive) == pin['archive_sha256']
        assert 'sha512-' + base64.b64encode(digest.digest()).decode() == pin['integrity']
        with tarfile.open(archive, 'r:gz') as tar:
            wanted = [m for m in tar.getmembers() if m.name == 'package/claude' and m.isfile()]
            assert len(wanted) == 1 and wanted[0].size == pin['bytes']
            with tar.extractfile(wanted[0]) as stream, destination.open('xb') as target: shutil.copyfileobj(stream, target)
    assert destination.stat().st_size == pin['bytes'] and sha(destination) == pin['sha256']
    destination.chmod(0o555)
    return destination, pin


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    for name in ['components', 'sdk', 'baseline', 'private', 'output']: p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--original-path', type=Path); p.add_argument('--runtime-image'); a = p.parse_args()
    assert platform.system() in ['Linux', 'Darwin'] and {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'x64'}[platform.machine()] == a.arch
    assert os.getuid() != 0
    architecture = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .Architecture}}']))
    assert architecture in {'arm64': ['aarch64', 'arm64'], 'x64': ['x86_64', 'amd64']}[a.arch], 'Native Docker CPU is required'
    components = a.components.resolve(); provenance = qualify(a.arch, components)
    private = a.private.resolve(); private.mkdir(); records = private / 'records'; records.mkdir()
    out = a.output.resolve(); out.mkdir(); assert not private.is_relative_to(out) and not out.is_relative_to(private)
    public_recipe_image = json.loads((ROOT.parent / 'seccomp-helper/pins.json').read_bytes())['profiles'][a.arch]['image']
    image = a.runtime_image or public_recipe_image
    if not image.startswith('sha256:'):
        subprocess.run(['docker', 'pull', '--platform', 'linux/' + ('arm64' if a.arch == 'arm64' else 'amd64'), image], check=True, stdout=subprocess.DEVNULL)
    inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image])); assert len(inspected) == 1
    assert inspected[0]['Architecture'] == {'arm64': 'arm64', 'x64': 'amd64'}[a.arch]
    if a.runtime_image is None: assert image in inspected[0]['RepoDigests']
    sdk = private / 'sdk'; sdk_proof = prepare_runtime(a.arch, a.sdk.resolve(), sdk)
    loader_path = private / 'musl-loader.path'; loader_path.write_text('/recovery-sdk/usr/lib:/recovery-sdk/lib\n')
    fixtures = private / 'fixtures'; prepare_fixtures(fixtures); (fixtures / 'owned.txt').write_bytes(b'owned role profile\n')
    sentinel = private / 'outside-sentinel'; sentinel.write_bytes(b'owned host file invisible to the role profile\n')
    source = private / 'guard.c'; shutil.copyfile(ROOT / 'native-role-guard.c', source)
    compiled = private / 'compiled'; compiled.mkdir(); guard = compiled / 'guard'
    compiler = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2', '--memory', '512m', '--pids-limit', '64',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '--mount', f'type=bind,src={source},dst=/source/guard.c,readonly',
        '--mount', f'type=bind,src={compiled},dst=/output', '--entrypoint', '/usr/bin/cc', image]
    cc = subprocess.run([*compiler, '--version'], capture_output=True, timeout=60); assert cc.returncode == 0
    build = subprocess.run([*compiler, '-std=c11', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '/source/guard.c', '-o', '/output/guard'], capture_output=True, timeout=60)
    (out / 'owned-guard-build.stdout').write_bytes(build.stdout); (out / 'owned-guard-build.stderr').write_bytes(build.stderr)
    assert build.returncode == 0; guard.chmod(0o555)
    raw = guard.read_bytes(); assert raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == {'arm64': 183, 'x64': 62}[a.arch]
    offset = struct.unpack_from('<Q', raw, 32)[0]; width, count = struct.unpack_from('<HH', raw, 54)
    assert width == 56 and 0 < count < 1024 and offset + width * count <= len(raw)
    assert all(struct.unpack_from('<I', raw, offset + width * i)[0] not in [2, 3] for i in range(count)), 'Guard must have no dynamic loader or library dependency'
    baseline_pin = json.loads((ROOT.parent / 'platform-runtime/musl-baseline-candidates.json').read_bytes())['profiles'][a.arch]
    baseline = private / 'public-baseline'; shutil.copyfile(a.baseline, baseline); baseline.chmod(0o555)
    assert sha(baseline) == baseline_pin['binary_sha256']
    process = RoleProcess(a.arch, image, guard, sdk, loader_path, fixtures, records, profile(a.arch))
    controls = []; comparisons = []; original = None
    receipt = dict(status='started', arch=a.arch, native_Docker_CPU=True, runtime_image=image, pinned_runtime_image=a.runtime_image is None,
        admitted_components=provenance, SDK=sdk_proof, guard_source_sha256=sha(source), guard_sha256=sha(guard),
        host_compiler=cc.stdout.decode(errors='replace'), host_sentinel_existed_before_probe=True, host_sentinel_sha256=sha(sentinel),
        original_executed=False, original_execution_attempted=False, captured_source_uploaded=False, original_binary_uploaded=False, client_binary_uploaded=False,
        normalization='none; exact native exit/stdout/stderr bytes', controls=controls, cases=comparisons, goal_complete=False)
    def owned(label):
        boundary = process.execute(label + '-boundary', None, ['--probe', str(sentinel)])
        assert boundary['exit_code'] == 0 and not boundary['stderr']
        expected = dict(readable=1, outside_errno=2, write_errno=30, network_errno=[1, 1, 1, 1], unix_errno=1, shell_exec_refused=True)
        assert json.loads(boundary['stdout']) == expected
        script = 'console.log(JSON.stringify({arch:process.arch,message:"owned musl loader",revision:Bun.revision.slice(0,9),text:require("node:fs").readFileSync("/input/owned.txt","utf8")}))'
        loader = process.execute(label + '-loader', baseline, ['-e', script], argv0='bun')
        assert loader['exit_code'] == 0 and not loader['stderr']
        assert json.loads(loader['stdout']) == dict(arch=a.arch, message='owned musl loader', revision='c6da4a4d3', text='owned role profile\n')
        controls.append(dict(case=label, boundary=boundary['row'], observed_boundary=expected, loader=loader['row']))
    try:
        owned('owned-initial')
        receiver = process.execute('owned-receiver', None, ['--receiver-probe', 'owned-control', '/input/nested/child.txt'])
        assert receiver['exit_code'] == 0 and not receiver['stderr']
        assert receiver['stdout'] == b'owned receiver cwd=/input\nmarker=owned-control\npath=/input/nested/child.txt\n'
        argv = ['odd 空格\nname', '--argv-probe', 'a b', 'quote"slash\\', 'λ猫', '']
        transported = process.execute('owned-argv', guard, argv[1:], argv0=argv[0])
        assert transported['exit_code'] == 0 and not transported['stderr'] and transported['stdout'] == ''.join(value.encode().hex() + '\n' for value in argv).encode()
        flood = process.execute('owned-flood', None, ['--flood-probe'], expected_failure='output limit')
        assert len(flood['stdout']) == 262144 and flood['row']['fresh_owned_container_retired']
        retired = process.execute('owned-descendant', None, ['--descendant-probe'], expected_failure='wall timeout', wall=3)
        assert retired['stdout'].startswith(b'owned child ') and retired['row']['fresh_owned_container_retired']
        receipt['transport_and_supervision_controls'] = dict(receiver=receiver['row'], argv=transported['row'], flood=flood['row'], descendant=retired['row'])
        (out / 'qualified-before-original.json').write_text(json.dumps(receipt, indent=2) + '\n')
        original, original_pin = original_input(a.arch, private, a.original_path)
        receipt['original_pin'] = original_pin
        candidates = {}
        for role in ['ugrep', 'bfs']:
            src = components / 'native-libraries' / role / (role + '-library-host')
            target = private / role; shutil.copyfile(src, target); target.chmod(0o555)
            assert sha(target) == sha(src); candidates[role] = target
        for label, role, args, code in cases():
            owned(label + '-before-original')
            receipt['original_execution_attempted'] = True
            left = process.execute(label + '-original', original, args, argv0=role); receipt['original_executed'] = True
            right = process.execute(label + '-candidate', candidates[role], args, argv0=role)
            mismatch = [name for name in ['exit_code', 'stdout', 'stderr'] if left[name] != right[name]]
            if left['exit_code'] != code or right['exit_code'] != code: mismatch.append('expected exit code')
            receivers = {'BF-exec': b'owned receiver cwd=/input\nmarker=owned-exec\npath=/input/nested/child.txt\n',
                'BF-execdir': b'owned receiver cwd=/input/nested\nmarker=owned-execdir\npath=./child.txt\n'}
            if label in receivers and left['stdout'] != receivers[label]: mismatch.append('owned receiver cwd/path contract')
            comparisons.append(dict(case=label, role=role, argv=args, expected_exit_code=code, original=left['row'], candidate=right['row'], matches=not mismatch, differences=mismatch))
            assert not mismatch, label + ': native component correspondence failed'
        assert len(comparisons) == 22 and sha(original) == original_pin['sha256']
        # Every original stream has now matched a qualified public native tool
        # on authored fixture inputs. Failures remain only in private storage.
        exported = out / 'validated-native-records'; exported.mkdir()
        for path in records.iterdir():
            assert path.is_file() and not path.is_symlink(); shutil.copyfile(path, exported / path.name)
        receipt.update(status='native_musl_Ugrep_Bfs_22_original_pairs_passed_after_each_owned_profile_control', differential_pairs=22,
            original_or_source_files_in_public_output=False, full_Bun_engine_accepted=False, recovered_client_accepted=False,
            exact_original_transitive_versions_proven=False, local_image_override_is_diagnostic_only=a.runtime_image is not None)
    except BaseException as error:
        receipt.update(status='musl_role_correspondence_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if receipt['status'] == 'native_musl_Ugrep_Bfs_22_original_pairs_passed_after_each_owned_profile_control':
            files = [dict(file=p.relative_to(out).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(out.rglob('*')) if p.is_file()]
            (out / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')


if __name__ == '__main__': main()
