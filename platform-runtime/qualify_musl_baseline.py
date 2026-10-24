"""Exercise exact musl baselines and standalones in a native Linux container."""
from pathlib import Path
import argparse
import json
import os
import platform
import posixpath
import shutil
import stat
import struct
import subprocess
import tarfile
from build_macos import COMMIT, sha
from build_musl_baseline import verify_package

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    parser.add_argument('--runtime', required=True, type=Path); parser.add_argument('--sdk', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    pins = json.loads((ROOT / 'musl-baseline-candidates.json').read_bytes()); pin = pins['profiles'][args.arch]
    assert pins['public_bun_commit'] == COMMIT
    docker_arch = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .Architecture}}'], text=True))
    assert docker_arch in {'arm64': ['aarch64', 'arm64'], 'x64': ['x86_64', 'amd64']}[args.arch], 'Native runtime architecture is required'
    runtime = args.runtime.resolve(); sdk = args.sdk.resolve(); out = args.output.resolve(); out.mkdir()
    logs = out / 'diagnostics'; logs.mkdir(); sysroot = out / 'sysroot'; sysroot.mkdir()
    sdk_pins = json.loads((ROOT / 'musl-sdk-runtime-pins.json').read_bytes()); sdk_receipt = verify_package(sdk, sdk_pins['profiles'][args.arch])
    assert sdk_receipt['arch'] == args.arch
    seen = set()
    for row in json.loads((runtime / 'MANIFEST.json').read_bytes())['files']:
        rel = Path(row['file']); assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen
        seen.add(row['file']); path = runtime / rel
        assert not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    assert {p.relative_to(runtime).as_posix() for p in runtime.rglob('*') if p.is_file()} == seen | {'MANIFEST.json'}
    binary = runtime / 'bun'; assert sha(binary) == pin['binary_sha256']
    receipt = json.loads((runtime / 'receipt.json').read_bytes())
    assert receipt['public_bun_commit'] == COMMIT and receipt['arch'] == args.arch and not receipt['recovered_native_roles_integrated']
    sdk_files = {row['file']: row for row in json.loads((sdk / 'sysroot-files.json').read_bytes())}
    # Runtime controls need shared libraries, not Linux kernel headers whose
    # case-distinct names collide on a typical macOS host filesystem.
    runtime_names = {name for name in sdk_files if len(Path(name).parts) == (2 if name.startswith('lib/') else 3)
        and (name.startswith('lib/') or name.startswith('usr/lib/')) and ('.so' in Path(name).name or Path(name).name.startswith('ld-musl-'))}
    with tarfile.open(sdk / 'musl-sysroot.tar.gz', 'r:gz') as archive:
        members = {member.name: member for member in archive.getmembers()}
        pending = set(runtime_names)
        while pending:
            name = pending.pop(); row = sdk_files[name]; member = members[name]
            if row['kind'] == 'symlink':
                target = posixpath.normpath(posixpath.join(str(Path(name).parent), row['target']))
            elif member.islnk(): target = member.linkname
            else: continue
            assert target in sdk_files and not target.startswith('/') and not target.startswith('../')
            if target not in runtime_names: runtime_names.add(target); pending.add(target)
        assert len({name.casefold() for name in runtime_names}) == len(runtime_names), 'Runtime library names need a case-sensitive output filesystem'
        archive.extractall(sysroot, members=[members[name] for name in sorted(runtime_names)], filter='data')
    for row in [sdk_files[name] for name in sorted(runtime_names)]:
        path = sysroot / row['file']
        if row['kind'] == 'symlink':
            assert path.is_symlink() and os.readlink(path) == row['target'] and path.resolve().is_relative_to(sysroot)
        else:
            assert not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
            assert stat.S_IMODE(path.stat().st_mode) == row['mode']
    image_profile = json.loads((ROOT.parent / 'seccomp-helper/pins.json').read_bytes())['profiles'][args.arch]
    image = image_profile['image']; docker_platform = {'arm64': 'linux/arm64', 'x64': 'linux/amd64'}[args.arch]
    subprocess.run(['docker', 'pull', '--platform', docker_platform, image], check=True, stdout=subprocess.DEVNULL)
    inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image])); assert len(inspect) == 1
    assert inspect[0]['Architecture'] == {'arm64': 'arm64', 'x64': 'amd64'}[args.arch] and image in inspect[0]['RepoDigests']
    (logs / 'runtime-image.json').write_text(json.dumps(inspect, indent=2) + '\n')
    inputs = out / 'owned-input'; inputs.mkdir(); outputs = out / 'owned-output'; outputs.mkdir()
    engine = out / 'owned-engine'; shutil.copyfile(binary, engine); engine.chmod(0o555)
    loader = 'ld-musl-' + ('aarch64' if args.arch == 'arm64' else 'x86_64') + '.so.1'
    script = 'const z=require("node:zlib");const s="owned λ 中文";if(!["/runtime/bun","/output/owned-standalone"].includes(process.execPath))throw Error(process.execPath);console.log(JSON.stringify({arch:process.arch,revision:Bun.revision.slice(0,9),unicode:z.gunzipSync(z.gzipSync(Buffer.from(s))).toString(),regexp:/λ/u.test(s),bigint:String(2n**64n)}));'
    entry = inputs / 'owned-entry.js'; entry.write_text(script, encoding='utf-8')
    (inputs / 'owned 空格\nfixture.txt').write_bytes(b'owned filesystem\n')
    expected = json.dumps(dict(arch=args.arch, revision=COMMIT[:9], unicode='owned λ 中文', regexp=True,
                               bigint='18446744073709551616'), ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
    observations = []

    def run(label, arguments, expected=None, compile=False, executable='/runtime/bun'):
        argv = ['docker', 'run', '--rm', '--platform', docker_platform, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}' if compile else '65534:65534',
            '--cpus', '2', '--memory', '2g', '--pids-limit', '128', '--ulimit', 'core=0:0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--mount', f'type=bind,src={engine},dst=/runtime/bun,readonly',
            '--mount', f'type=bind,src={sysroot},dst=/recovery-sdk,readonly',
            '--mount', f'type=bind,src={sysroot / "lib" / loader},dst=/lib/{loader},readonly',
            '--mount', f'type=bind,src={inputs},dst=/input,readonly',
            '--mount', f'type=bind,src={outputs},dst=/output' + ('' if compile else ',readonly'),
            '--workdir', '/output', '-e', 'LD_LIBRARY_PATH=/recovery-sdk/usr/lib:/recovery-sdk/lib',
            '-e', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH=0', '-e', 'BUN_INSTALL_CACHE_DIR=/tmp/owned-cache']
        if not compile: argv += ['--ulimit', 'fsize=0:0']
        argv += ['--entrypoint', executable, image, *arguments]
        result = subprocess.run(argv, capture_output=True, timeout=180)
        (logs / (label + '.stdout')).write_bytes(result.stdout); (logs / (label + '.stderr')).write_bytes(result.stderr)
        observations.append(dict(label=label, argv=argv, exit_code=result.returncode, stdout_hex=result.stdout.hex(),
                                 stderr_hex=result.stderr.hex(), fsize_zero=not compile, network='none'))
        (logs / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        assert result.returncode == 0 and (expected is None or result.stdout == expected), label + ' failed'
        if expected is not None: assert not result.stderr, label + ' emitted diagnostics'
        return result

    run('version', ['--version'], b'1.4.3\n')
    revision = run('revision', ['--revision']); assert COMMIT[:9].encode() in revision.stdout and not revision.stderr
    run('javascript-zlib-unicode', ['-e', script], expected)
    run('filesystem-path', ['-e', 'process.stdout.write(require("node:fs").readFileSync(process.argv.at(-1)));', '/input/owned 空格\nfixture.txt'], b'owned filesystem\n')
    run('compile-owned-standalone', ['build', '--compile', '--compile-executable-path', '/runtime/bun', '--outfile', '/output/owned-standalone', '/input/owned-entry.js'], compile=True)
    compiled = outputs / 'owned-standalone'; raw = compiled.read_bytes()
    assert raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == {'arm64': 183, 'x64': 62}[args.arch]
    run('execute-owned-standalone', [], expected, executable='/output/owned-standalone')
    report = dict(status='public_musl_native_owned_controls_and_explicit_source_engine_standalone_passed', arch=args.arch,
        candidate=pin, binary_sha256=sha(engine), standalone_sha256=sha(compiled), observations=observations,
        orchestrator_platform=platform.platform(), docker_native_architecture=docker_arch, runtime_image=image,
        standalone_engine_explicitly_pinned=True, standalone_source_revision_checked=True, process_exec_path_checked=True,
        sdk_pin=sdk_pins['profiles'][args.arch], sdk_runtime_files_reverified=len(runtime_names),
        sdk_headers_used=False, captured_client_executed=False, native_roles_integrated=False, goal_complete=False)
    (logs / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    shutil.copyfile(entry, logs / 'owned-entry.js')


if __name__ == '__main__': main()
