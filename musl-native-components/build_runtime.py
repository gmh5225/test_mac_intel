"""Build public Bun with admitted musl C graphs and freshly compiled rg/std."""
from pathlib import Path
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
from sdk import prepare, profile, sha
from component_libraries import qualify
from prepare_sources import prepare as prepare_sources
from patch_musl import patch
from musl_allocator import verify_symbols
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from build_linux import PROFILES, COMMIT
from verify_musl_graph import verify as verify_plan


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', choices=PROFILES, required=True)
    parser.add_argument('--sdk', required=True, type=Path); parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == {'arm64': 'aarch64', 'x64': 'x86_64'}[args.arch]
    components = args.components.resolve(); provenance = qualify(args.arch, components)
    cp = PROFILES[args.arch]; target = profile(args.arch)
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); source = out / 'bun-source'
    receipt = dict(status='started', arch=args.arch, compiler_profile=cp, target_profile=target, public_bun_commit=COMMIT,
        components=provenance, commands=[], captured_client_executed=False, compiled_rust_archive_used=False,
        original_prefix_reused=False, private_producer_revision_recovered=False, erased_types_restored=False, goal_complete=False)
    def run(label, argv, cwd=None, timeout=6600):
        argv = list(map(str, argv)); print('Starting ' + label, flush=True)
        receipt['commands'].append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None))
        with (logs / (label + '.log')).open('xb') as stream:
            result = subprocess.run(argv, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        assert result.returncode == 0, label + ' failed; inspect retained public diagnostics'
    try:
        receipt['SDK'] = prepare(args.arch, args.sdk.resolve(), out / 'sysroot')
        receipt['native_sources'] = prepare_sources(out / 'native-source-inputs', run)
        run('git-init', ['git', 'init', source]); run('git-remote', ['git', 'remote', 'add', 'origin', 'https://github.com/oven-sh/bun.git'], source)
        run('git-fetch', ['git', '-c', 'http.version=HTTP/1.1', 'fetch', '--depth', '1', 'origin', COMMIT], source)
        run('git-checkout', ['git', 'checkout', '--detach', COMMIT], source)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == COMMIT
        receipt['source_patch'] = patch(source, logs / 'source-patch', out / 'native-source-inputs', components)
        run('compiler-pull', ['docker', 'pull', '--platform', cp['docker_platform'], cp['image']], timeout=1800)
        run('compiler-inspect', ['docker', 'image', 'inspect', cp['image']])
        loader_path = out / 'musl-loader.path'; loader_path.write_text(target['sysroot'] + '/usr/lib:' + target['sysroot'] + '/lib\n')
        mounts = [str(out) + ',dst=/output', str(ROOT.parent) + ',dst=/repo,readonly',
            str(out / 'sysroot') + ',dst=' + target['sysroot'] + ',readonly',
            str(out / 'sysroot/lib' / target['loader']) + ',dst=/lib/' + target['loader'] + ',readonly',
            str(loader_path) + ',dst=/etc/' + target['loader'].replace('.so.1', '.path') + ',readonly']
        base = ['docker', 'run', '--rm', '--platform', cp['docker_platform'], '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '512']
        for mount in mounts: base += ['--mount', 'type=bind,src=' + mount]
        run('source-engine-build', [*base, '--cap-add', 'DAC_OVERRIDE', '--cpus', '4', '--memory', '12g',
            '-e', 'RECOVERY_MUSL_SYSROOT=' + target['sysroot'], '-e', 'BUN_TARGET_ARCH=' + ('aarch64' if args.arch == 'arm64' else 'x64'),
            '--entrypoint', '/bin/bash', cp['image'], '/repo/musl-native-components/build-runtime.sh'])
        checks = re.findall(r'\[check\] bun-profile ([0-9]+) duplicate strong symbols', (logs / 'source-engine-build.log').read_text())
        assert checks == ['0'], 'Ambiguous strong symbol ownership in the complete musl source graph'
        binary = source / 'build/recovery/bun'
        receipt['single_rust_graph'] = verify_plan(source / 'build/recovery/rust-target/plan.json')
        assert receipt['single_rust_graph']['triple'] == ('aarch64' if args.arch == 'arm64' else 'x86_64') + '-unknown-linux-musl'
        run('engine-dynamic', ['readelf', '-d', binary]); needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', (logs / 'engine-dynamic.log').read_text())
        assert needed == [target['libc']], 'Complete musl engine imported an extra runtime library'
        run('engine-version-info', ['readelf', '--version-info', binary]); assert not re.search(r'(?:GLIBC|GLIBCXX|CXXABI)_\d', (logs / 'engine-version-info.log').read_text())
        run('engine-dynsyms', ['readelf', '--dyn-syms', '--wide', binary]); receipt['allocator_exports'] = verify_symbols((logs / 'engine-dynsyms.log').read_text())
        run('engine-sections', ['readelf', '-S', '--wide', binary]); sections = (logs / 'engine-sections.log').read_text()
        assert all(re.search(r'\s' + re.escape(name) + r'\s', sections) for name in ['.eh_frame', '.eh_frame_hdr', '.gcc_except_table'])
        run('engine-headers', ['readelf', '-l', '--wide', binary]); headers = (logs / 'engine-headers.log').read_text()
        assert 'GNU_EH_FRAME' in headers and re.findall(r'Requesting program interpreter: ([^\]]+)\]', headers) == ['/lib/' + target['loader']]
        # The compiler process is the only root process; native controls run
        # without capabilities/network under the runner UID and zero file budgets.
        controls = logs / 'native-controls'
        owned_base = ['docker', 'run', '--rm', '--platform', cp['docker_platform'], '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '2', '--memory', '3g', '--pids-limit', '128', '--ulimit', 'core=0:0']
        for mount in mounts: owned_base += ['--mount', 'type=bind,src=' + mount]
        owned_base += ['--mount', 'type=bind,src=' + str(components) + ',dst=/components,readonly']
        run('native-controls', [*owned_base, '--entrypoint', '/usr/bin/python3', cp['image'], '/repo/musl-native-components/qualify_runtime.py',
            '--arch', args.arch, '--runtime', '/output/bun-source/build/recovery/bun', '--components', '/components', '--output', '/output/diagnostics/native-controls'], timeout=900)
        owned = json.loads((controls / 'receipt.json').read_bytes())
        assert owned['status'] == 'native_musl_source_roles_and_768_filename_controls_passed' and owned['native_rg_filename_controls']['cases'] == 768
        package = out / 'public-runtime'; package.mkdir(); shutil.copyfile(binary, package / 'bun'); (package / 'bun').chmod(0o555)
        shutil.copytree(out / 'native-source-inputs', package / 'native-source-inputs')
        shutil.copytree(components, package / 'C-source-component-inputs')
        shutil.copytree(logs / 'source-patch', package / 'source-patch')
        recipes = package / 'recipes'; recipes.mkdir()
        for directory in ['musl-native-components', 'bun-runtime', 'runtime-helpers', 'platform-runtime', 'seccomp-helper']:
            shutil.copytree(ROOT.parent / directory, recipes / directory, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(source / 'Cargo.lock', package / 'Cargo.lock'); shutil.copyfile(source / 'build/recovery/rust-target/plan.json', package / 'rust-plan.json')
        receipt.update(status='public_musl_complete_native_source_engine_and_owned_controls_passed', binary_sha256=sha(binary),
            binary_bytes=binary.stat().st_size, needed_libraries=needed, duplicate_strong_symbols=0, native_controls=owned,
            recovered_native_roles_integrated=True, original_client_acceptance_pending=True)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='musl_source_engine_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        for name in ['build.ninja', 'bun-profile.rsp', 'bun.rsp', 'configure.json', 'rust-target/plan.json']:
            path = source / 'build/recovery' / name
            if path.is_file() and path.stat().st_size <= 16 * 1024 * 1024: shutil.copyfile(path, logs / name.replace('/', '-'))
        binary = source / 'build/recovery/bun'
        if receipt['status'] == 'musl_source_engine_failed_not_admitted':
            if binary.is_file(): shutil.copyfile(binary, logs / 'public-unqualified-bun')
            total = 0
            for config in sorted((source / 'build/recovery/rust-target').rglob('config.log')):
                assert config.is_file() and not config.is_symlink() and config.stat().st_size <= 8 * 1024 * 1024
                total += config.stat().st_size; assert total <= 32 * 1024 * 1024
                target = logs / 'public-build-script-configs' / config.relative_to(source / 'build/recovery/rust-target')
                target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(config, target)
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
