"""Build fresh musl C component graphs in the admitted native compiler image."""
from pathlib import Path
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
from sdk import prepare, profile, sha
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from build_linux import PROFILES
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import unpack


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', required=True, choices=PROFILES)
    parser.add_argument('--sdk', required=True, type=Path); parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-inputs', type=Path); args = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == {'x64': 'x86_64', 'arm64': 'aarch64'}[args.arch]
    assert os.getuid() != 0, 'Use an owned unprivileged runner checkout'
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    work = out / 'bun'; work.mkdir(); sources = work / 'embedded'; sources.mkdir()
    inputs = out / 'source-inputs'; inputs.mkdir(); (work / 'home').mkdir(); (work / 'no-host-pkgconfig').mkdir()
    cp = PROFILES[args.arch]; target = profile(args.arch)
    receipt = dict(status='started', arch=args.arch, compiler_profile=cp, target_profile=target, commands=[],
        captured_client_executed=False, original_prefix_reused=False, exact_original_transitive_versions_proven=False,
        core_engine_integrated=False, goal_complete=False)
    def run(label, argv, timeout=3600):
        argv = list(map(str, argv)); print('Starting ' + label, flush=True)
        receipt['commands'].append(dict(label=label, argv=argv))
        with (logs / (label + '.log')).open('xb') as stream:
            result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        assert result.returncode == 0, label + ' failed; inspect retained public diagnostics'
    try:
        receipt['SDK'] = prepare(args.arch, args.sdk.resolve(), out / 'sysroot')
        selected = json.loads((ROOT.parent / 'extra-components/sources.json').read_bytes())['files']
        assert {row['name'] for row in selected} == {'ugrep', 'bfs', 'oniguruma', 'pcre2', 'zlib', 'bzip2', 'zstd', 'brotli'}
        receipt['sources'] = selected
        for row in selected:
            archive = inputs / (row['name'] + '.tar.gz')
            if args.source_inputs: shutil.copyfile(args.source_inputs / archive.name, archive)
            else: run('download-' + row['name'], ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', archive, row['url']])
            assert archive.stat().st_size <= 16777216 and sha(archive) == row['sha256']
            if 'bytes' in row: assert archive.stat().st_size == row['bytes']
            unpack(archive, sources / row['name'], row['prefix'])
            with tarfile.open(archive) as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        assert 0 <= member.mtime < 4102444800
                        os.utime(sources / row['name'] / member.name[len(row['prefix']):], (member.mtime, member.mtime), follow_symlinks=False)
        run('compiler-pull', ['docker', 'pull', '--platform', cp['docker_platform'], cp['image']], 1800)
        run('compiler-inspect', ['docker', 'image', 'inspect', cp['image']])
        identity = out / 'identity'; identity.mkdir()
        for kind, value, entry in [('passwd', os.getuid(), f'recovery:x:{os.getuid()}:{os.getgid()}::/tmpfs/bun/home:/bin/bash'),
                                    ('group', os.getgid(), f'recovery:x:{os.getgid()}:')]:
            run('compiler-' + kind, ['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--entrypoint', '/bin/cat', cp['image'], '/etc/' + kind])
            raw = (logs / ('compiler-' + kind + '.log')).read_text(); rows = [line.split(':') for line in raw.splitlines() if line]
            assert all(len(row) == (7 if kind == 'passwd' else 4) and row[2].isdigit() for row in rows)
            assert sum(int(row[2]) == value for row in rows) <= 1
            if not any(int(row[2]) == value for row in rows):
                assert all(row[0] != 'recovery' for row in rows); raw = raw.rstrip('\n') + '\n' + entry + '\n'
            (identity / kind).write_text(raw)
        # Only musl's own loader reads this path file. GNU compiler/build
        # programs retain their normal loader search path and C++ runtime.
        loader_path = out / 'musl-loader.path'; loader_path.write_text(target['sysroot'] + '/usr/lib:' + target['sysroot'] + '/lib\n')
        mounts = [str(work) + ',dst=/tmpfs/bun', str(out / 'sysroot') + ',dst=' + target['sysroot'] + ',readonly',
            str(out / 'sysroot/lib' / target['loader']) + ',dst=/lib/' + target['loader'] + ',readonly',
            str(loader_path) + ',dst=/etc/' + target['loader'].replace('.so.1', '.path') + ',readonly',
            str(ROOT.parent) + ',dst=/repo,readonly', str(logs) + ',dst=/diagnostics']
        mounts += [str(identity / name) + ',dst=/etc/' + name + ',readonly' for name in ['passwd', 'group']]
        argv = ['docker', 'run', '--rm', '--platform', cp['docker_platform'], '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2', '--memory', '5g', '--pids-limit', '256']
        for mount in mounts: argv += ['--mount', 'type=bind,src=' + mount]
        run('components-build', [*argv, '--entrypoint', '/usr/bin/python3', cp['image'], '/repo/musl-native-components/build_components.py', '--arch', args.arch], 5400)
        inner = json.loads((work / 'native-libraries/receipt.json').read_bytes())
        assert inner['status'] == 'musl_source_component_graphs_hosts_and_upstream_checks_passed'
        receipt.update(status=inner['status'], components=inner['components'], source_graph=inner,
            dynamic_dependency_contract='only_target_musl_libc', private_symbol_proofs_required=True)
        package = out / 'public-components'; package.mkdir()
        shutil.copytree(work / 'native-libraries', package / 'native-libraries'); shutil.copytree(inputs, package / 'source-inputs')
        shutil.copyfile(args.sdk / 'sysroot-files.json', package / 'sdk-files.json')
        recipes = package / 'recipes'; recipes.mkdir()
        for folder in ['musl-native-components', 'runtime-helpers', 'platform-runtime', 'bun-runtime']:
            shutil.copytree(ROOT.parent / folder, recipes / folder, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for role, name in [('ugrep', 'LICENSE.txt'), ('bfs', 'LICENSE'), ('oniguruma', 'COPYING')]:
            shutil.copyfile(sources / role / name, package / (role.upper() + '-LICENSE.txt'))
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        rows = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=rows), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='musl_components_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
