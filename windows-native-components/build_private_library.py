"""Namespace admitted native source objects and link their own wide-entry host."""
from pathlib import Path
import argparse
import bz2
import gzip
import json
import os
import shutil
import subprocess
import zipfile
from component_libraries import qualify_candidate
from private_symbols import ENTRY, isolate
from toolchain import ROOT, prepare, sha


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['x64', 'arm64'])
    p.add_argument('--candidate', required=True, type=Path); p.add_argument('--output', required=True, type=Path); a = p.parse_args()
    candidate = a.candidate.resolve(); provenance = qualify_candidate(a.arch, candidate)
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    env = dict(os.environ); token = env.get('GH_TOKEN')
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    env.pop('ARGV0', None); env.update(NO_COLOR='1', TERM='dumb', LC_ALL='C', LANG='C')
    receipt = dict(status='started', arch=a.arch, candidate_provenance=provenance, commands=[],
        original_executed=False, full_engine_integrated=False, goal_complete=False)
    def run(label, command, *, cwd=None, data=None, expected=0):
        command = list(map(str, command)); print('Starting ' + label, flush=True)
        row = dict(label=label, argv=command); receipt['commands'].append(row)
        with (logs / (label + '.stdout')).open('xb') as stdout, (logs / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(command, cwd=cwd, env=env, input=data, stdout=stdout, stderr=stderr, timeout=1200)
        row['exit_code'] = result.returncode; assert result.returncode == expected, label
        assert max((logs / (label + '.' + suffix)).stat().st_size for suffix in ['stdout', 'stderr']) <= 32 * 1024 * 1024
        return (logs / (label + '.stdout')).read_bytes()
    try:
        toolbin, cmake, receipt['toolchain'] = prepare(a.arch, out, env, run, token)
        package = out / 'public-library'; package.mkdir(); library = package / 'native-library'; library.mkdir()
        objects = []; archives = []
        for f in sorted((candidate / 'raw-UG-objects').iterdir()):
            target = library / f.name; shutil.copyfile(f, target); objects.append(target)
        for f in sorted((candidate / 'raw-dependency-archives').iterdir()):
            target = library / f.name; shutil.copyfile(f, target); archives.append(target)
        receipt['private_C_symbols'] = isolate(library, objects, archives, toolbin, run, logs, a.arch)
        combined = library / 'recovered_ugrep.lib'
        run('archive-private-UG', [toolbin / 'llvm-ar.exe', 'rcs', combined, *objects])
        host_source = library / 'ugrep-library-host.cpp'
        host_source.write_text('extern "C" int ' + ENTRY + '(int, const wchar_t **);\n'
            'int wmain(int argc, const wchar_t **argv) { return ' + ENTRY + '(argc, argv); }\n')
        host = library / 'ugrep-library-host.exe'
        run('link-private-library-host', [toolbin / 'clang-cl.exe', '/nologo', '/O2', '/EHsc', '/MT', host_source,
            '/Fo' + str(out / 'host.obj'), '/Fe' + str(host), '/link', combined, *archives, 'advapi32.lib'])
        fixture = out / 'owned-fixtures'; fixture.mkdir()
        text = fixture / 'owned 空格 猫.txt'; text.write_bytes('first\nNEEDLE\npreneedle\nλ猫\n'.encode())
        payload = b'owned COMPRESSED_NEEDLE\n'
        (fixture / 'owned.gz').write_bytes(gzip.compress(payload, mtime=0)); (fixture / 'owned.bz2').write_bytes(bz2.compress(payload))
        with zipfile.ZipFile(fixture / 'owned.zip', 'w', compression=zipfile.ZIP_DEFLATED) as z: z.writestr('owned.txt', payload)
        cases = [('version', ['--version'], 0), ('literal', ['--no-config', '-F', '-n', 'NEEDLE', text], 0),
            ('PCRE-lookbehind', ['--no-config', '-P', '-o', '(?<=pre)needle', text], 0),
            ('Unicode', ['--no-config', '-F', '-o', 'λ猫', text], 0), ('absent', ['--no-config', 'owned-absent', text], 1),
            ('invalid-regex', ['--no-config', '-P', '(', text], 2),
            *[('compressed-' + s, ['--no-config', '-z', '-h', '-o', 'COMPRESSED_NEEDLE', fixture / ('owned.' + s)], 0) for s in ['gz', 'bz2', 'zip']]]
        pairs = []
        for label, args, code in cases:
            raw = run('candidate-' + label, [candidate / 'ugrep-source-host.exe', *args], expected=code)
            private = run('private-' + label, [host, *args], expected=code)
            assert raw == private, 'Private COFF graph changed stdout: ' + label
            assert (logs / ('candidate-' + label + '.stderr')).read_bytes() == (logs / ('private-' + label + '.stderr')).read_bytes()
            pairs.append(dict(case=label, exit_code=code, stdout_sha256=sha(logs / ('private-' + label + '.stdout')),
                stderr_sha256=sha(logs / ('private-' + label + '.stderr'))))
        run('private-host-PE-records', [toolbin / 'llvm-readobj.exe', '--file-headers', '--sections', '--coff-imports', host])
        receipt.update(status='native_Windows_private_COFF_library_and_nine_standalone_host_pairs_passed',
            private_host_sha256=sha(host), private_UG_archive_sha256=sha(combined), standalone_host_pairs=pairs,
            object_count=len(receipt['private_C_symbols']['object_proofs']),
            expected_native_version_hex=json.loads((candidate / 'receipt.json').read_bytes())['expected_native_version_hex'])
        shutil.copytree(candidate, package / 'source-candidate')
        recipes = package / 'recipes/windows-native-components'; recipes.mkdir(parents=True)
        for name in ['build_private_library.py', 'private_symbols.py', 'coff_objects.py', 'coff_admission.py',
            'coff-checker-pins.json', 'coff-native-controls-qualification.json', 'verify_coff_objects.py',
            'component_libraries.py', 'source-component-pins.json', 'toolchain.py']: shutil.copyfile(ROOT / name, recipes / name)
        for folder, names in [('bun-runtime', ['native_libraries.py']), ('platform-runtime', ['build_windows.py', 'build_macos.py'])]:
            path = package / 'recipes' / folder; path.mkdir()
            for name in names: shutil.copyfile(ROOT.parent / folder / name, path / name)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        rows = [dict(file=f.relative_to(package).as_posix(), bytes=f.stat().st_size, sha256=sha(f)) for f in sorted(package.rglob('*')) if f.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=rows), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='Windows_private_source_library_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally: (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
