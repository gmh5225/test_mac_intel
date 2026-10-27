"""Build the Windows public engine with one rg/std graph and private Ugrep C."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'platform-runtime'))
import build_windows
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from prepare_native_sources import prepare as prepare_sources
from verify_rust_plan import verify as verify_plan
from component_libraries import qualify_library
from patch_windows import patch
from pe_runtime import qualify as qualify_pe
from coff_admission import sha
from cxx_abi_control import qualify as qualify_Cxx_ABI
from string_sort_controls import qualify as qualify_string_sort
from prepare_arm64_sdk import prepare as prepare_ARM64_SDK


class NativeProfile:
    def add_arguments(self, parser):
        parser.add_argument('--ugrep-libraries', type=Path, required=True)

    def preflight(self, args, receipt):
        self.ugrep = args.ugrep_libraries.resolve()
        receipt['native_ugrep_component'] = qualify_library(args.arch, self.ugrep)
        pins = json.loads((ROOT / 'role-boundary-pins.json').read_bytes())
        assert set(pins['profiles']) == {'arm64', 'x64'}
        for name, file in [('role_boundary.rs', ROOT / 'role_boundary.rs'),
            ('windows_role_contract.rs', ROOT.parent / 'native-role-contracts/windows.rs')]:
            assert sha(file) in [pins['canonical_source_hashes'][name], pins['native_checkout_source_hashes'][name]]
        receipt.update(build_profile='Windows_complete_native_source_roles', target_std_libraries_required=1,
            compiled_Rust_archive_used=False, native_role_boundary_qualification=pins['independent_qualification_sha256'])

    def prepare_build(self, args, out, source, bun, toolbin, env, run, receipt):
        if args.arch == 'arm64': receipt['ARM64_SDK_setup'] = prepare_ARM64_SDK(out / 'diagnostics', env)
        receipt['Cxx_return_ABI_control'] = qualify_Cxx_ABI(args.arch, out / 'diagnostics', toolbin, env, run, self.ugrep)
        inputs = out / 'native-source-inputs'; receipt['native_source_preparation'] = prepare_sources(inputs, run, target_os='windows')
        receipt['native_source_patch'] = patch(source, out / 'diagnostics/native-source-patch', inputs, self.ugrep, args.arch)
        install = source / 'recovery-native/pcre2-install'; install.mkdir()
        raw = self.ugrep / 'native-library/raw-dependency-archives/pcre2-8-static.lib'
        shutil.copyfile(raw, install / raw.name)
        env.update(RECOVERY_PCRE2_LIBDIR=install.as_posix(), RECOVERY_PCRE2_LIBNAME='pcre2-8-static',
            GIT_CEILING_DIRECTORIES=str(source / 'recovery-native'))
        env.pop('ARGV0', None)
        receipt['rg_unprefixed_PCRE2_C_graph'] = dict(source='admitted Ugrep pre-namespace archive',
            archive_sha256=sha(raw), staged_sha256=sha(install / raw.name), linked_version='10.45')
        run('native-single-rust-plan', [bun, 'scripts/build.ts', '--profile=release', '--os=windows',
            '--arch=' + build_windows.PROFILES[args.arch]['build_arch'], '--build-dir=' + str(source / 'build/recovery'),
            '--target=rust-plan', '-j2'], source)
        plan = source / 'build/recovery/rust-target/plan.json'; graph = verify_plan(plan)
        assert graph['triple'] == build_windows.PROFILES[args.arch]['target']
        parsed = json.loads(plan.read_bytes())
        pcre_sys = [u for u in parsed['unitGraph']['units'] if u['platform'] == graph['triple'] and u['target']['name'] == 'pcre2_sys']
        assert len(pcre_sys) == 1 and '/recovery-native/pcre2-sys-overlay/' in pcre_sys[0]['target']['src_path'].replace('\\', '/')
        receipt['single_Rust_graph'] = graph
        (out / 'diagnostics/single-rust-graph.json').write_text(json.dumps(graph, indent=2) + '\n')
        shutil.copyfile(plan, out / 'diagnostics/rust-plan.json')

    def expected_changes(self, receipt):
        return [' M ' + row['file'] for row in receipt['native_source_patch']['patches']] + ['?? recovery-native/',
            '?? src/runtime/bin_entry/recovered_multicall.rs', '?? src/runtime/bin_entry/role_boundary.rs',
            '?? src/runtime/bin_entry/windows_role_contract.rs']

    def qualify_and_export(self, args, out, source, bun, toolbin, env, run, receipt):
        binary = source / 'build/recovery/bun.exe'; logs = out / 'diagnostics'
        receipt['final_PE'] = qualify_pe(binary, args.arch)
        (logs / 'final-PE.json').write_text(json.dumps(receipt['final_PE'], indent=2) + '\n')
        checks = re.findall(r'\[check\] bun-profile ([0-9]+) duplicate strong symbols', (logs / 'public-bun-build.log').read_text(encoding='utf-8'))
        assert checks == ['0'], 'Ambiguous strong symbol ownership in Windows source graph'
        receipt['duplicate_strong_symbols'] = 0
        receipt['owned_native_controls'] = owned_controls(binary, args.arch, logs / 'native-role-controls', self.ugrep)
        receipt['authored_string_sort_controls'] = qualify_string_sort(binary, args.arch, logs / 'string-sort-controls')
        run('final-PE-imports-exports', [toolbin / 'llvm-readobj.exe', '--file-headers', '--sections', '--coff-imports', '--coff-exports', binary])
        package = out / 'public-runtime'; package.mkdir(); shutil.copyfile(binary, package / 'bun.exe')
        shutil.copytree(inputs := out / 'native-source-inputs', package / inputs.name)
        shutil.copytree(self.ugrep, package / 'ugrep-source-library-inputs')
        shutil.copytree(logs / 'native-source-patch', package / 'native-source-patch')
        recipes = package / 'recipes'; recipes.mkdir()
        names = ['build_runtime.py', 'cxx_abi_control.py', 'string_sort_controls.py', 'prepare_arm64_sdk.py', 'patch_windows.py', 'pcre2_sys_overlay.py', 'pe_runtime.py', 'component_libraries.py',
            'coff_admission.py', 'ugrep-library-pins.json', 'source-component-pins.json', 'role-boundary-pins.json',
            'role_boundary.rs', 'recovered_multicall.rs', 'resolved-Cargo.lock']
        folder = recipes / 'windows-native-components'; folder.mkdir()
        for name in names: shutil.copyfile(ROOT / name, folder / name)
        for directory, names in [('platform-runtime', ['build_windows.py', 'build_macos.py']),
            ('bun-runtime', ['prepare_native_sources.py', 'rust_source_graph.py', 'stage_native_sources.py', 'verify_rust_plan.py', 'resolved-Cargo.lock', 'native_libraries.py']),
            ('runtime-helpers', ['build.py', 'build_native.py', 'prepare_pcre2.py']), ('native-role-contracts', ['windows.rs'])]:
            folder = recipes / directory; folder.mkdir()
            for name in names: shutil.copyfile(ROOT.parent / directory / name, folder / name)
        for name in ['Cargo.lock', 'Cargo.toml']: shutil.copyfile(source / name, package / name)
        for name in ['rust-plan.json', 'single-rust-graph.json', 'final-PE.json']: shutil.copyfile(logs / name, package / name)
        if args.arch == 'arm64':
            for name in ['Cxx-return-ABI.json', 'ARM64-SDK-setup.json']: shutil.copyfile(logs / name, package / name)
        shutil.copytree(logs / 'string-sort-controls', package / 'string-sort-controls')
        receipt.update(status='public_Windows_complete_native_source_engine_and_owned_controls_passed',
            binary_sha256=sha(binary), binary_bytes=binary.stat().st_size, recovered_native_roles_integrated=True,
            source_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip(),
            captured_source_uploaded=False, original_private_revision_recovered=False,
            original_process_role_pairs_qualified=False, recovered_actual_client_qualified=False, goal_complete=False)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        rows = [dict(file=f.relative_to(package).as_posix(), bytes=f.stat().st_size, sha256=sha(f)) for f in sorted(package.rglob('*')) if f.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=rows), indent=2) + '\n')


def owned_controls(binary, arch, output, ugrep):
    output.mkdir(); env = dict(os.environ)
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    env.pop('ARGV0', None); env.update(NO_COLOR='1', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    fixture = output / 'owned 空格 猫.txt'; fixture.write_bytes(b'first\nNEEDLE\npreneedle\n')
    version = bytes.fromhex(json.loads((ugrep / 'receipt.json').read_bytes())['expected_native_version_hex'])
    cases = [('runtime', None, ['--version'], 0, b'1.4.3\n'),
        ('unknown-env-consumed', 'unknown', ['-e', 'console.log(process.env.ARGV0===undefined)'], 0, b'true\n'),
        ('bfs-is-runtime', 'bfs', ['--version'], 0, b'1.4.3\n'),
        ('seccomp-is-runtime', 'apply-seccomp', ['--version'], 0, b'1.4.3\n'),
        ('rg-version', 'rg', ['--version'], 0, None),
        ('rg-pcre', 'rg', ['--no-config', '-P', '-o', '(?<=pre)needle', fixture], 0, b'needle\n'),
        ('rg-absent', 'rg', ['--no-config', 'owned-absent', fixture], 1, b''),
        ('ug-version', 'ugrep', ['--version'], 0, version),
        ('ug-pcre', 'ug', ['--no-config', '-P', '-o', '(?<=pre)needle', fixture], 0, b'needle\r\n'),
        ('ug-literal', 'ugrep', ['--no-config', '-n', 'NEEDLE', fixture], 0, b'2:NEEDLE\n'),
        ('ug-invalid-regex', 'ugrep', ['--no-config', '-P', '(', fixture], 2, b'')]
    rows = []
    def observe(label, argv, environment, code, wanted):
        r = subprocess.run(list(map(str, argv)), executable=binary, cwd=output, env=environment, capture_output=True, timeout=30)
        assert len(r.stdout) + len(r.stderr) <= 262144
        (output / (label + '.stdout')).write_bytes(r.stdout); (output / (label + '.stderr')).write_bytes(r.stderr)
        row = dict(case=label, exit_code=r.returncode, stdout_sha256=sha(output / (label + '.stdout')), stderr_sha256=sha(output / (label + '.stderr')))
        rows.append(row); (output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')
        assert r.returncode == code and (wanted is None or r.stdout == wanted), label
        if code != 2: assert not r.stderr, label
        return r.stdout
    for label, role, arguments, code, wanted in cases:
        current = dict(env)
        if role is not None: current['ARGV0'] = role
        raw = observe(label, [binary, *arguments], current, code, wanted)
        if label == 'rg-version': assert raw.startswith(b'ripgrep 14.1.1\n') and b'PCRE2 10.45 is available (JIT is available)' in raw and b'(rev ' not in raw
    # Windows has no /dev/fd pathname contract. Exercise its own valid UTF-16
    # filename paths through the real Rust caller, including raw NUL framing.
    filename_checks = 0
    for i, name in enumerate(['owned-input.txt', 'owned space 雪猫.txt']):
        file = output / name; file.write_bytes(b'target\nother\ntarget\n'); encoded = str(file).encode()
        variants = [('plain', ['-c'], b'2\n'), ('filename', ['-c', '-H'], encoded + b':2\n'),
            ('nul', ['-c', '-H', '--null'], encoded + b'\0' + b'2\n'), ('files', ['-l', '--null'], encoded + b'\0'),
            ('hidden-nul', ['--hidden', '--max-columns', '500', '-c', '-H', '--null'], encoded + b'\0' + b'2\n'),
            ('json', ['--json'], None)]
        for label, flags, wanted in variants:
            for repeat in range(32):
                raw = observe(f'filename-{i}-{label}-{repeat}', ['rg.exe', '--no-config', *flags, 'target', file], env, 0, wanted)
                if label == 'json':
                    records = [json.loads(line) for line in raw.splitlines()]
                    assert records[0]['data']['path']['text'] == str(file)
                    assert records[-1]['type'] == 'summary' and records[-1]['data']['stats']['matches'] == 2
                filename_checks += 1
    receipt = dict(status='native_Windows_source_roles_and_repeated_filename_controls_passed', arch=arch,
        role_controls=len(cases), filename_controls=filename_checks, rows=rows, captured_input_used=False)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n'); return receipt


if __name__ == '__main__': build_windows.main(native_profile=NativeProfile())
