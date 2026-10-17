"""Reuse the public Mac toolchain builder with admitted native source graphs."""
from pathlib import Path
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'platform-runtime'))
import build_macos
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from prepare_native_sources import prepare as prepare_sources
from native_rg_controls import verify as verify_rg
from verify_rust_plan import verify as verify_plan
from component_libraries import qualify as qualify_component
from macho_runtime import qualify as qualify_macho
from patch_macos import patch, sha
from prepare_sdk import prepare as prepare_sdk


class NativeProfile:
    CPP_CONTROL = '''#include <unordered_map>
#include <string>
#include <stdexcept>
int main() {
    std::unordered_map<std::string, int> values; values["owned"] = 7;
    try { throw std::runtime_error("owned exception"); }
    catch (const std::runtime_error& error) { return values.at("owned") == 7 && std::string(error.what()) == "owned exception" ? 0 : 1; }
    return 2;
}
'''

    def add_arguments(self, parser):
        parser.add_argument('--bfs-libraries', type=Path, required=True)
        parser.add_argument('--ugrep-libraries', type=Path, required=True)

    def preflight(self, args, record):
        self.bfs = args.bfs_libraries.resolve(); self.ugrep = args.ugrep_libraries.resolve()
        record['native_components'] = {role: qualify_component(role, args.arch, package) for role, package in [('bfs', self.bfs), ('ugrep', self.ugrep)]}
        record.update(build_profile='macos-native-source-roles', one_rust_std_graph_required=True,
            compiled_rust_archive_used=False, C_source_libraries_used=True,
            private_producer_revision_recovered=False, erased_producer_types_restored=False)

    def prepare_sdk(self, args, out, bun, run, record):
        sdk, receipt = prepare_sdk(out, None, run, native_bun=bun)
        record['native_component_SDK'] = receipt
        return sdk

    def prepare_build(self, args, out, source, bun, toolbin, env, run, record, extra_flags):
        inputs = out / 'native-source-inputs'; record['native_source_preparation'] = prepare_sources(inputs, run)
        record['native_source_patch'] = patch(source, out / 'diagnostics/native-source-patch', inputs, self.bfs, self.ugrep, args.arch)
        native = source / 'recovery-native'; install = native / 'pcre2-install'; (install / 'lib/pkgconfig').mkdir(parents=True)
        # The accepted Ugrep package retains its complete pre-namespace PCRE2
        # graph. rg needs those C names; its Rust/std are compiled here afresh.
        raw = self.ugrep / 'native-library/raw-dependency-archives/libpcre2-8.a'
        shutil.copyfile(raw, install / 'lib/libpcre2-8.a')
        pc = install / 'lib/pkgconfig/libpcre2-8.pc'
        pc.write_text('prefix=' + str(install) + '\nlibdir=${prefix}/lib\nincludedir=' + str(native / 'pcre2-source/src') +
            '\nName: libpcre2-8\nDescription: Accepted source-built PCRE2 8-bit graph\nVersion: 10.45\nLibs: -L${libdir} -lpcre2-8\nLibs.private: -lpthread\nCflags: -I${includedir}\n')
        record['rg_PCRE2_C_library'] = dict(source_component='accepted Ugrep pre-namespace PCRE2 graph',
            archive_sha256=sha(raw), staged_archive_sha256=sha(install / 'lib/libpcre2-8.a'), pkg_config_sha256=sha(pc))
        env.update(PCRE2_SYS_STATIC='0', PKG_CONFIG_ALL_STATIC='1', PKG_CONFIG_ALLOW_CROSS='1',
            PKG_CONFIG_PATH=str(pc.parent), PKG_CONFIG_LIBDIR=str(pc.parent),
            GIT_CEILING_DIRECTORIES=str(native))
        env.pop('PKG_CONFIG_SYSROOT_DIR', None)
        run('native-pcre2-pkg-config-version', ['pkg-config', '--modversion', 'libpcre2-8'])
        assert (out / 'diagnostics/native-pcre2-pkg-config-version.log').read_bytes() == b'10.45\n'
        run('native-pcre2-pkg-config-static-link', ['pkg-config', '--static', '--cflags', '--libs', 'libpcre2-8'])
        build_arch = 'aarch64' if args.arch == 'arm64' else 'x64'
        run('native-single-rust-plan', [bun, 'scripts/build.ts', '--profile=release', '--arch=' + build_arch,
            '--os=darwin', '--osx-deployment-target=13.0', '--build-dir=' + str(source / 'build/recovery'), '--target=rust-plan', '-j2', *extra_flags], source, direct_log=True)
        plan = source / 'build/recovery/rust-target/plan.json'; graph = verify_plan(plan)
        assert graph['triple'] == {'arm64': 'aarch64-apple-darwin', 'x64': 'x86_64-apple-darwin'}[args.arch]
        record['single_rust_graph'] = graph
        (out / 'diagnostics/single-rust-graph.json').write_text(json.dumps(graph, indent=2) + '\n')
        shutil.copyfile(plan, out / 'diagnostics/rust-plan.json')

    def expected_changes(self, record):
        return [' M ' + p['file'] for p in record['native_source_patch']['patches']] + ['?? recovery-native/',
            '?? src/runtime/bin_entry/recovered_multicall.rs', '?? src/runtime/bin_entry/darwin_role_contract.rs']

    def qualify_and_export(self, args, out, source, bun, toolbin, env, run, record):
        logs = out / 'diagnostics'; binary = source / 'build/recovery/bun'
        check = qualify_macho(binary, args.arch); record['final_macho'] = check
        (logs / 'final-macho.json').write_text(json.dumps(check, indent=2) + '\n')
        checks = re.findall(r'\[check\] bun-profile ([0-9]+) duplicate strong symbols', (logs / 'public-bun-build.log').read_text())
        assert checks == ['0'], 'Source-role graph introduced ambiguous duplicate strong symbol ownership'
        record['duplicate_strong_symbols'] = 0
        if args.arch == 'arm64':
            record['native_rg_filename_controls'] = verify_rg(binary, logs / 'native-rg-filename-controls')
            record['native_role_controls'] = owned_controls(binary, args.arch, logs / 'native-role-controls', self.bfs, self.ugrep)
        package = out / 'public-runtime'; package.mkdir(); shutil.copyfile(binary, package / 'bun'); (package / 'bun').chmod(0o500)
        shutil.copytree(out / 'native-source-inputs', package / 'native-source-inputs')
        shutil.copytree(self.bfs, package / 'bfs-source-library-inputs'); shutil.copytree(self.ugrep, package / 'ugrep-source-library-inputs')
        shutil.copytree(logs / 'native-source-patch', package / 'native-source-patch')
        recipes = package / 'recipes'; recipes.mkdir(); mac_recipes = recipes / 'macos-native-components'; mac_recipes.mkdir()
        for name in ['build_runtime.py', 'patch_macos.py', 'component_libraries.py', 'macho_runtime.py', 'prepare_sdk.py',
                     'macos-sdk-pins.json', 'bfs-library-pins.json', 'ugrep-library-pins.json', 'recovered_multicall.rs', 'qualify_runtime.py']:
            shutil.copyfile(ROOT / name, mac_recipes / name)
        for directory, names in [('bun-runtime', ['prepare_native_sources.py', 'rust_source_graph.py', 'stage_native_sources.py', 'verify_rust_plan.py', 'native_rg_controls.py', 'native_libraries.py', 'resolved-Cargo.lock']),
            ('platform-runtime', ['build_macos.py']), ('runtime-helpers', ['build.py', 'prepare_pcre2.py']), ('native-role-contracts', ['darwin.rs'])]:
            folder = recipes / directory; folder.mkdir()
            for name in names: shutil.copyfile(ROOT.parent / directory / name, folder / name)
        for name in ['rust-plan.json', 'single-rust-graph.json', 'final-macho.json']: shutil.copyfile(logs / name, package / name)
        for name in ['Cargo.lock', 'Cargo.toml']: shutil.copyfile(source / name, package / name)
        record.update(status='public_macos_source_native_engine_built', binary_sha256=sha(binary), binary_bytes=binary.stat().st_size,
            recovered_native_roles_integrated=True, native_arm64_roles_controlled=args.arch == 'arm64',
            native_intel_execution_pending=args.arch == 'x64', captured_source_uploaded=False,
            complete_Bfs_runtime_requires_macos='26.0', original_macos15_execdir_SIGSEGV_preserved=True,
            scope='Source engine with rg/std compiled together and admitted Ugrep/Bfs C libraries. Native Intel and actual recovered-client correspondence are separate gates.')
        (package / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        rows = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=rows), indent=2) + '\n')


def owned_controls(runtime, arch, output, bfs_package, ugrep_package):
    output.mkdir(); fixture = output / 'owned-input.txt'; fixture.write_bytes(b'first\nNEEDLE\npreneedle\n')
    cases = [('runtime', None, ['--version'], 0, b'1.4.3\n'),
        ('runtime-env-consumed', 'unknown', ['-e', 'console.log(process.env.ARGV0 === undefined)'], 0, b'true\n'),
        ('rg-version', 'rg', ['--version'], 0, None),
        ('rg-pcre', 'rg', ['--no-config', '-P', '-o', '(?<=pre)needle', str(fixture)], 0, b'needle\n'),
        ('rg-absent', 'rg', ['--no-config', 'absent-owned', str(fixture)], 1, b''),
        ('ugrep-version', 'ugrep', ['--version'], 0, bytes.fromhex(json.loads((ugrep_package / 'receipt.json').read_bytes())['expected_native_version_hex'])),
        ('ugrep-pcre', 'ug', ['--no-config', '-P', '-o', '(?<=pre)needle', str(fixture)], 0, b'needle\n'),
        ('ugrep-invalid-regex', 'ugrep', ['--no-config', '-P', '(', str(fixture)], 2, None),
        ('bfs-version', 'bfs', ['--version'], 0, (bfs_package / 'expected-original-version.txt').read_bytes()),
        ('bfs-name', 'bfs', [str(fixture), '-maxdepth', '0', '-name', 'owned-input.txt', '-print'], 0, os.fsencode(fixture) + b'\n'),
        ('bfs-execdir-OS-boundary', 'bfs', [str(fixture), '-execdir', '/usr/bin/true', ';'], -11 if int(platform.mac_ver()[0].split('.')[0]) == 15 else 0, b'')]
    rows = []; (output / 'home').mkdir(); (output / 'tmp').mkdir()
    environment = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), HOME=str(output / 'home'), TMPDIR=str(output / 'tmp'), LANG='C', LC_ALL='C', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    for key in list(environment):
        if key.startswith('ACTIONS_') or any(w in key.upper() for w in ['TOKEN', 'SECRET', 'PASSWORD']): environment.pop(key)
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for label, role, args, code, expected in cases:
        env = dict(environment)
        if role is not None: env['ARGV0'] = role
        result = subprocess.run([str(runtime), *args], env=env, capture_output=True, timeout=30, preexec_fn=limits)
        (output / (label + '.stdout')).write_bytes(result.stdout); (output / (label + '.stderr')).write_bytes(result.stderr)
        row = dict(case=label, exit_code=result.returncode, expected_exit_code=code, stdout_sha256=__import__('hashlib').sha256(result.stdout).hexdigest(), stderr_sha256=__import__('hashlib').sha256(result.stderr).hexdigest(), rlimit_fsize=0); rows.append(row)
        (output / 'receipt.json').write_text(json.dumps(dict(status='started', rows=rows), indent=2) + '\n')
        assert result.returncode == code and (expected is None or result.stdout == expected), label
        if code != 2: assert not result.stderr, label
        if label == 'rg-version': assert result.stdout.startswith(b'ripgrep 14.1.1\n') and b'PCRE2 10.45 is available (JIT is available)' in result.stdout and b'(rev ' not in result.stdout
    receipt = dict(status='owned_native_runtime_and_three_source_roles_passed', arch=arch, binary_sha256=sha(runtime), rows=rows, captured_client_executed=False)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return dict(status=receipt['status'], cases=len(rows), rlimit_fsize=0)


if __name__ == '__main__': build_macos.main(native_profile=NativeProfile())
