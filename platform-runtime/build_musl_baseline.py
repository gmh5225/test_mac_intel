"""Build a public musl engine using an independently admitted SDK snapshot."""
from pathlib import Path
import argparse
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
from build_macos import COMMIT, sha

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from build_linux import PROFILES


def verify_package(root, pin):
    assert sha(root / 'MANIFEST.json') == pin['manifest_sha256']
    assert sha(root / 'receipt.json') == pin['receipt_sha256']
    manifest = json.loads((root / 'MANIFEST.json').read_bytes()); seen = set()
    for row in manifest['files']:
        rel = Path(row['file']); assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen
        seen.add(row['file']); path = root / rel
        assert not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    assert {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == seen | {'MANIFEST.json'}
    receipt = json.loads((root / 'receipt.json').read_bytes())
    assert receipt['status'] == 'public_musl_sdk_files_and_installed_index_versions_captured'
    assert not receipt['recovered_engine_qualified']
    assert sha(root / 'musl-sysroot.tar.gz') == pin['sysroot_archive_sha256']
    assert sha(root / 'sysroot-files.json') == pin['sysroot_file_manifest_sha256']
    return receipt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', choices=PROFILES, required=True)
    parser.add_argument('--sdk', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == {'x64': 'x86_64', 'arm64': 'aarch64'}[args.arch]
    pins = json.loads((ROOT / 'musl-sdk-runtime-pins.json').read_bytes()); pin = pins['profiles'][args.arch]
    sdk = args.sdk.resolve(); sdk_receipt = verify_package(sdk, pin)
    assert sdk_receipt['arch'] == args.arch
    profile = PROFILES[args.arch]; out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    source = out / 'bun-source'; sysroot = out / 'sysroot'; sysroot.mkdir()
    receipt = dict(status='started', arch=args.arch, public_bun_commit=COMMIT, compiler_profile=profile, sdk_pin=pin,
        sdk_qualification_sha256=pins['independent_qualification_sha256'], commands=[], controls=[],
        captured_client_executed=False, recovered_native_roles_integrated=False, original_prefix_reused=False, goal_complete=False)

    def run(label, argv, cwd=None, expected=None):
        argv = list(map(str, argv)); receipt['commands'].append(dict(label=label, argv=argv))
        print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            completed = subprocess.run(argv, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=6600)
        assert completed.returncode == 0, label + ' failed; inspect retained diagnostics'
        if expected is not None: assert (logs / (label + '.log')).read_bytes() == expected, label + ' output differs'

    try:
        with tarfile.open(sdk / 'musl-sysroot.tar.gz', 'r:gz') as archive:
            archive.extractall(sysroot, filter='data')
        wanted = json.loads((sdk / 'sysroot-files.json').read_bytes())
        for row in wanted:
            path = sysroot / row['file']
            if row['kind'] == 'symlink':
                assert path.is_symlink() and os.readlink(path) == row['target'] and path.resolve().is_relative_to(sysroot)
            else:
                assert path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
                assert stat.S_IMODE(path.stat().st_mode) == row['mode']
        assert {p.relative_to(sysroot).as_posix() for p in sysroot.rglob('*') if p.is_file() or p.is_symlink()} == {p['file'] for p in wanted}
        receipt['sdk_files_reverified_after_extraction'] = len(wanted)
        run('git-init', ['git', 'init', source]); run('git-remote', ['git', 'remote', 'add', 'origin', 'https://github.com/oven-sh/bun.git'], source)
        run('git-fetch', ['git', '-c', 'http.version=HTTP/1.1', 'fetch', '--depth', '1', 'origin', COMMIT], source)
        run('git-checkout', ['git', 'checkout', '--detach', COMMIT], source)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == COMMIT
        run('compiler-image-pull', ['docker', 'pull', '--platform', profile['docker_platform'], profile['image']])
        run('compiler-image-inspect', ['docker', 'image', 'inspect', profile['image']])
        target_arch = 'aarch64' if args.arch == 'arm64' else 'x64'
        target = ('aarch64' if args.arch == 'arm64' else 'x86_64') + '-alpine-linux-musl'
        run('public-bun-build', ['docker', 'run', '--rm', '--platform', profile['docker_platform'], '--cap-drop', 'ALL',
            '--cap-add', 'DAC_OVERRIDE', '--security-opt', 'no-new-privileges', '--cpus', '4', '--memory', '12g', '--pids-limit', '512',
            '--mount', f'type=bind,src={out},dst=/output', '--mount', f'type=bind,src={ROOT},dst=/recipes,readonly',
            '-e', 'BUN_TARGET_ARCH=' + target_arch, '-e', 'MUSL_TARGET=' + target,
            '--entrypoint', '/bin/bash', profile['image'], '/recipes/build-musl-baseline.sh'])
        binary = source / 'build/recovery/bun'; raw = binary.read_bytes()
        assert raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == profile['machine']
        run('elf-program-headers', ['readelf', '-W', '-l', binary]); headers = (logs / 'elf-program-headers.log').read_text()
        run('elf-dynamic', ['readelf', '-W', '-d', binary]); dynamic = (logs / 'elf-dynamic.log').read_text()
        run('elf-version-info', ['readelf', '-W', '--version-info', binary])
        assert not re.search(r'GLIBC_[0-9]', (logs / 'elf-version-info.log').read_text()), 'musl engine imported glibc symbol versions'
        loader_name = 'ld-musl-' + ('aarch64' if args.arch == 'arm64' else 'x86_64') + '.so.1'
        interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)', headers)
        assert interpreters in ([], ['/lib/' + loader_name]), 'Unexpected engine ELF interpreter'
        needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', dynamic)
        assert not any(name in ['libc.so.6', 'libpthread.so.0', 'libm.so.6'] for name in needed)
        assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source)
        run_binary = out / 'owned-engine'; shutil.copyfile(binary, run_binary); run_binary.chmod(0o555)
        fixture = out / 'owned-fixture.txt'; fixture.write_bytes(b'owned musl filesystem\n')
        cases = [
            ('version', ['--version'], b'1.4.3\n'),
            ('revision', ['--revision'], None),
            ('javascript-zlib-unicode', ['-e', 'const z=require("node:zlib");const s="owned λ 中文";console.log(JSON.stringify({arch:process.arch,message:z.gunzipSync(z.gzipSync(s)).toString(),regexp:/λ/u.test(s)}))'],
                json.dumps(dict(arch=args.arch, message='owned λ 中文', regexp=True), ensure_ascii=False, separators=(',', ':')).encode() + b'\n'),
            ('filesystem', ['-e', 'process.stdout.write(require("node:fs").readFileSync("/owned/owned-fixture.txt"))'], b'owned musl filesystem\n'),
        ]
        for label, arguments, expected in cases:
            command = ['docker', 'run', '--rm', '--platform', profile['docker_platform'], '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--cpus', '2', '--memory', '2g',
                '--pids-limit', '128', '--ulimit', 'fsize=0:0', '--ulimit', 'core=0:0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
                '--mount', f'type=bind,src={run_binary},dst=/runtime/bun,readonly',
                '--mount', f'type=bind,src={sysroot},dst=/recovery-sdk,readonly',
                '--mount', f'type=bind,src={fixture},dst=/owned/owned-fixture.txt,readonly',
                '--mount', f'type=bind,src={sysroot / "lib" / loader_name},dst=/lib/{loader_name},readonly',
                '-e', 'LD_LIBRARY_PATH=/recovery-sdk/usr/lib:/recovery-sdk/lib', '-e', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH=0',
                '--entrypoint', '/runtime/bun', profile['image'], *arguments]
            completed = subprocess.run(command, capture_output=True, timeout=120)
            (logs / (label + '.stdout')).write_bytes(completed.stdout); (logs / (label + '.stderr')).write_bytes(completed.stderr)
            receipt['controls'].append(dict(label=label, argv=command, exit_code=completed.returncode,
                stdout_hex=completed.stdout.hex(), stderr_hex=completed.stderr.hex(), fsize_zero=True, network='none'))
            assert completed.returncode == 0 and not completed.stderr and (expected is None or completed.stdout == expected), label
            if label == 'revision': assert COMMIT[:9].encode() in completed.stdout
        package = out / 'public-runtime'; package.mkdir(); shutil.copyfile(binary, package / 'bun'); (package / 'bun').chmod(0o555)
        recipes = package / 'recipes'; recipes.mkdir()
        shutil.copytree(ROOT.parent / 'bun-runtime', recipes / 'bun-runtime', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        platform_recipes = recipes / 'platform-runtime'; platform_recipes.mkdir()
        for name in ['build_musl_baseline.py', 'build-musl-baseline.sh', 'build_macos.py', 'musl-sdk-runtime-pins.json']:
            shutil.copyfile(ROOT / name, platform_recipes / name)
        shutil.copyfile(sdk / 'sysroot-files.json', package / 'sdk-files.json')
        receipt.update(status='unmodified_public_musl_source_baseline_and_bounded_owned_controls_passed',
            binary_sha256=sha(binary), binary_bytes=len(raw), interpreter=interpreters, needed_libraries=needed,
            source_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip(),
            runtime_dependency_mode='exact_admitted_sdk_loader_and_libraries_in_native_restricted_container')
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='musl_baseline_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        build = source / 'build/recovery'
        for name in ['build.ninja', 'bun-profile.rsp', 'bun.rsp', 'configure.json', 'rust-target/plan.json']:
            path = build / name
            if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
                shutil.copyfile(path, logs / name.replace('/', '-'))
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
