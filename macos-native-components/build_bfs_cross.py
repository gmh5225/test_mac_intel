"""Cross-build public Bfs with the measured Darwin flags in a pinned image."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import unpack
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from build_linux import PROFILES
from prepare_sdk import prepare as prepare_sdk


def sha(path):
    with path.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    p.add_argument('--output', required=True, type=Path); p.add_argument('--source-inputs', type=Path); a = p.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); work = out / 'bun'; work.mkdir()
    for name in ['embedded', 'home', 'no-host-pkgconfig']: (work / name).mkdir()
    inputs = out / 'source-inputs'; inputs.mkdir()
    selected = [row for row in json.loads((ROOT.parent / 'extra-components/sources.json').read_bytes())['files'] if row['name'] in ['bfs', 'oniguruma']]
    assert {row['name'] for row in selected} == {'bfs', 'oniguruma'}
    profile = PROFILES['x64']; commands = []
    receipt = dict(status='started', arch=a.arch, build_host='Linux x86_64', source_inputs=selected,
        compiler_image=profile['image'], commands=commands, captured_client_executed=False, captured_source_uploaded=False,
        original_transitive_versions_proven=False, original_sdk_bytes_proven=False, native_qualified=False, goal_complete=False)

    def run(label, argv, timeout=1800):
        argv = list(map(str, argv)); commands.append(dict(label=label, argv=argv)); print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        assert result.returncode == 0, label + ' failed; inspect retained diagnostics'

    try:
        for row in selected:
            path = inputs / (row['name'] + '.tar.gz')
            if a.source_inputs: shutil.copyfile(a.source_inputs / path.name, path)
            else: run('download-' + row['name'], ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '180', '--output', path, row['url']])
            assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
            unpack(path, work / 'embedded' / row['name'], row['prefix'])
        run('compiler-pull', ['docker', 'pull', '--platform', 'linux/amd64', profile['image']], 1200)
        run('compiler-inspect', ['docker', 'image', 'inspect', profile['image']])
        sdk, receipt['sdk'] = prepare_sdk(out, profile['image'], run)
        run('source-build', ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', str(os.getuid()) + ':' + str(os.getgid()), '--cpus', '2', '--memory', '4g', '--pids-limit', '256',
            '--mount', 'type=bind,src=' + str(work) + ',dst=/tmpfs/bun', '--mount', 'type=bind,src=' + str(ROOT) + ',dst=/recipes,readonly',
            '--mount', 'type=bind,src=' + str(sdk) + ',dst=/opt/macos-sdk/MacOSX26.5.sdk,readonly',
            '--env', 'RECOVERY_ARCH=' + a.arch, '--entrypoint', '/bin/bash', profile['image'], '/recipes/build-bfs-cross.sh'])
        r = json.loads((work / 'native-library/receipt.json').read_bytes()); assert r['arch'] == a.arch
        host = work / 'native-library/bfs-library-host'; assert sha(host) == r['host_sha256']
        header = struct.unpack('<8I', host.read_bytes()[:32]); assert header[0] == 0xfeedfacf and header[1] == {'arm64': 0x100000c, 'x64': 0x1000007}[a.arch] and header[3] == 2
        package = out / 'public-library'; package.mkdir(); shutil.copytree(work / 'native-library', package / 'native-library')
        shutil.copytree(inputs, package / 'source-inputs')
        test_tree = package / 'upstream-test-tree'; test_tree.mkdir(); bfs = work / 'embedded/bfs'
        for name in ['tests', 'bin', 'build', 'gen']: shutil.copytree(bfs / name, test_tree / name, symlinks=True)
        for name in ['LICENSE', 'Makefile']: shutil.copyfile(bfs / name, test_tree / name)
        tests = package / 'oniguruma-tests'; tests.mkdir()
        for name in ['test_utf8', 'test_syntax', 'test_options', 'testc', 'testcu', 'test_regset', 'test_back']:
            shutil.copyfile(work / 'build/release/deps/oniguruma/test' / name, tests / name)
        shutil.copyfile(work / 'embedded/oniguruma/COPYING', package / 'ONIGURUMA-LICENSE')
        shutil.copyfile(ROOT / ('expected-bfs-version-' + a.arch + '.txt'), package / 'expected-original-version.txt')
        for name in ['build_bfs_cross.py', 'build-bfs-cross.sh', 'export_bfs_cross.py', 'prepare_sdk.py', 'macos-sdk-pins.json', 'macho_objects.py', 'private_symbols.py']:
            shutil.copyfile(ROOT / name, package / name)
        receipt.update(status='public_macos_bfs_cross_source_library_built_native_acceptance_pending', native_library=r)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        assert not any(p.is_symlink() for p in package.rglob('*')), 'Exported test fixture contains unaccounted symbolic links'
        rows = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=rows), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        for name in ['export-diagnostics', 'embedded/bfs/gen']:
            path = work / name
            if path.is_dir(): shutil.copytree(path, logs / Path(name).name)
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
