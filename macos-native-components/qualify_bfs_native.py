"""Run the cross-built Bfs/Oniguruma suites on a matching native macOS host."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess


def sha(path):
    with path.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    p.add_argument('--package', type=Path, required=True); p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[a.arch] and os.getuid() != 0
    package = a.package.resolve(); names = set(); assert not any(p.is_symlink() for p in package.rglob('*'))
    for row in json.loads((package / 'MANIFEST.json').read_bytes())['files']:
        rel = Path(row['file']); assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in names
        names.add(row['file']); path = package / rel
        assert path.is_file() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
    assert names | {'MANIFEST.json'} == {p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    producer = json.loads((package / 'receipt.json').read_bytes())
    assert producer['status'] == 'public_macos_bfs_cross_source_library_built_native_acceptance_pending' and producer['arch'] == a.arch
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); tree = out / 'test-tree'
    shutil.copytree(package / 'upstream-test-tree', tree)
    tests = out / 'oniguruma-tests'; shutil.copytree(package / 'oniguruma-tests', tests)
    binaries = [tree / 'bin/bfs', *[p for p in (tree / 'bin/tests').iterdir() if p.is_file()], *[p for p in tests.iterdir() if p.is_file()]]
    for path in binaries:
        assert struct.unpack('<II', path.read_bytes()[:8]) == (0xfeedfacf, {'arm64': 0x100000c, 'x64': 0x1000007}[a.arch]); path.chmod(0o500)
    for path in tree.rglob('*.sh'): path.chmod(0o500)
    commands = []; receipt = dict(status='started', arch=a.arch, native_host=True, commands=commands,
        package_manifest_sha256=sha(package / 'MANIFEST.json'), captured_client_executed=False, whole_engine_integration=False, goal_complete=False)
    environment = {k: v for k, v in os.environ.items() if not k.startswith('ACTIONS_') and not any(w in k.upper() for w in ['TOKEN', 'SECRET', 'PASSWORD'])}
    environment.update(HOME=str(out / 'home'), TMPDIR=str(out / 'tmp'), LANG='C', LC_ALL='C')
    (out / 'home').mkdir(); (out / 'tmp').mkdir()
    def run(label, argv, cwd=tree, timeout=900):
        argv = list(map(str, argv)); commands.append(dict(label=label, argv=argv, cwd=str(cwd))); print('Starting ' + label, flush=True)
        with (logs / (label + '.stdout')).open('xb') as stdout, (logs / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(argv, cwd=cwd, env=environment, stdout=stdout, stderr=stderr, timeout=timeout)
        commands[-1]['exit_code'] = result.returncode; assert result.returncode == 0, label
        return (logs / (label + '.stdout')).read_bytes()
    try:
        bash_version = run('bash-version', ['bash', '--version'])
        assert int(bash_version.decode().split('version ', 1)[1].split('.', 1)[0]) >= 4
        expected = (package / 'expected-original-version.txt').read_bytes()
        assert run('upstream-version', [tree / 'bin/bfs', '--version']) == expected
        for binary in sorted(tests.iterdir()): run('oniguruma-' + binary.name, [binary], tests)
        run('bfs-unit-tests', [tree / 'bin/tests/units'])
        variants = [[], ['-S', 'dfs'], ['-S', 'ids'], ['-S', 'eds'], ['-j1'], ['-j2'], ['-j3'], ['-s']]
        for phase in ['upstream', 'library-host']:
            if phase == 'library-host':
                source = package / 'native-library/bfs-library-host'; assert sha(source) == producer['native_library']['host_sha256']
                (tree / 'bin/bfs').chmod(0o700)
                shutil.copyfile(source, tree / 'bin/bfs'); (tree / 'bin/bfs').chmod(0o500)
                assert run('library-host-version', [tree / 'bin/bfs', '--version']) == expected
            for index, flags in enumerate(variants):
                run(phase + '-integration-' + str(index), ['bash', 'tests/tests.sh', '--bfs=' + ' '.join(['bin/bfs', *flags]), '-j2', '--verbose=skipped'])
        assert sha(tree / 'bin/bfs') == producer['native_library']['host_sha256']
        receipt.update(status='native_macos_bfs_and_oniguruma_upstream_suites_passed_with_fresh_library_host',
            oniguruma_tests=len(list(tests.iterdir())), bfs_integration_runs=2 * len(variants),
            host_sha256=producer['native_library']['host_sha256'], original_version_bytes_reproduced=True,
            scope='Native component suite controls; original-role and full engine acceptance are separate gates.')
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
