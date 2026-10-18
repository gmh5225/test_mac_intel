"""Build public native Windows Ugrep sources before full-engine integration."""
from pathlib import Path
import argparse
import bz2
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import zipfile

from toolchain import ROOT, prepare, sha


def unpack(archive, output, prefix, name):
    assert not output.exists(); output.mkdir()
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers(); assert len(members) < 10000
        links = [(m.name, m.linkname) for m in members if m.issym() or m.islnk()]
        expected = [(prefix + 'tests/cli-tests/bin/' + n, 'zstd') for n in ['unzstd', 'zstdcat']] if name == 'zstd' else []
        assert links == expected, 'Unqualified source archive link projection'
        seen = set()
        for member in members:
            assert member.name == prefix.rstrip('/') or member.name.startswith(prefix)
            rel = Path(member.name[len(prefix):])
            if str(rel) == '.': continue
            assert not rel.is_absolute() and '..' not in rel.parts and rel.as_posix().casefold() not in seen
            seen.add(rel.as_posix().casefold()); path = output / rel
            if member.issym(): continue
            if member.isdir(): path.mkdir(parents=True, exist_ok=True)
            else:
                assert member.isfile() and member.size <= 16 * 1024 * 1024
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream, path.open('xb') as target: shutil.copyfileobj(stream, target)
        for member, target in links:
            path = output / member[len(prefix):]; original = path.parent / target
            assert original.is_file() and not original.is_symlink()
            shutil.copyfile(original, path)
    return [dict(file=n[len(prefix):], target=t, projection='unused_development_alias_materialized_as_equal_bytes') for n, t in links]


def pe(path, arch):
    raw = path.read_bytes(); assert raw[:2] == b'MZ'
    offset = struct.unpack_from('<I', raw, 60)[0]
    assert raw[offset:offset + 4] == b'PE\0\0' and struct.unpack_from('<H', raw, offset + 4)[0] == {'x64': 0x8664, 'arm64': 0xaa64}[arch]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    assert platform.system() == 'Windows' and os.environ['RUNNER_ARCH'].lower() == args.arch
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    inputs = out / 'source-inputs'; inputs.mkdir(); sources = out / 'sources'; sources.mkdir()
    env = dict(os.environ); token = env.get('GH_TOKEN')
    for key in list(env):
        if key.startswith('ACTIONS_') or any(s in key.upper() for s in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    receipt = dict(status='started', arch=args.arch, native_CPU=True, public_sources_only=True, commands=[],
        original_executed=False, full_engine_integrated=False, private_C_namespace_qualified=False, goal_complete=False)
    def run(label, command, *, data=None, cwd=None, expected=0, timeout=1200):
        command = list(map(str, command)); print('Starting ' + label, flush=True)
        row = dict(label=label, argv=command); receipt['commands'].append(row)
        with (logs / (label + '.stdout')).open('xb') as stdout, (logs / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(command, cwd=cwd, env=env, input=data, stdout=stdout, stderr=stderr, timeout=timeout)
        row['exit_code'] = result.returncode
        assert result.returncode == expected, label + ' failed; retained public diagnostics'
        assert (logs / (label + '.stdout')).stat().st_size <= 64 * 1024 * 1024 and (logs / (label + '.stderr')).stat().st_size <= 64 * 1024 * 1024
        return (logs / (label + '.stdout')).read_bytes()
    try:
        toolbin, cmake, receipt['toolchain'] = prepare(args.arch, out, env, run, token)
        selected = [r for r in json.loads((ROOT.parent / 'extra-components/sources.json').read_bytes())['files']
            if r['name'] in ['ugrep', 'pcre2', 'zlib', 'bzip2', 'zstd', 'brotli']]
        assert len(selected) == 6; receipt['sources'] = selected
        projections = []
        for row in selected:
            archive = inputs / (row['name'] + '.tar.gz')
            run('download-' + row['name'], ['curl.exe', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', archive, row['url']])
            assert archive.stat().st_size <= 16 * 1024 * 1024 and sha(archive) == row['sha256']
            if 'bytes' in row: assert archive.stat().st_size == row['bytes']
            projections += unpack(archive, sources / row['name'], row['prefix'], row['name'])
        receipt['declared_archive_alias_projections'] = projections
        config = out / 'owned-ugrep-config.h'
        config.write_text('#pragma once\n// Feature definitions are owned by the CMake source target.\n')
        build = out / 'build'
        run('configure-source-components', [cmake, '-S', ROOT, '-B', build, '-G', 'NMake Makefiles',
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER:FILEPATH=' + (toolbin / 'clang-cl.exe').as_posix(), '-DCMAKE_CXX_COMPILER:FILEPATH=' + (toolbin / 'clang-cl.exe').as_posix(),
            '-DCMAKE_LINKER:FILEPATH=' + (toolbin / 'lld-link.exe').as_posix(), '-DCMAKE_AR:FILEPATH=' + (toolbin / 'llvm-lib.exe').as_posix(),
            '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded', '-DSOURCE_ROOT:PATH=' + sources.as_posix(), '-DUG_CONFIG:FILEPATH=' + config.as_posix(), '-DRECOVERY_ARCH=' + args.arch])
        run('build-source-components', [cmake, '--build', build, '--parallel', '2'], timeout=2400)
        upstream = {}
        for name in ['pcre2', 'brotli', 'zlib']:
            result = run('upstream-' + name, [cmake.parent / 'ctest.exe', '--test-dir', build / name, '--output-on-failure'], timeout=600)
            count = re.findall(rb'100% tests passed, 0 tests failed out of ([1-9][0-9]*)', result); assert len(count) == 1
            upstream[name] = int(count[0])
        receipt['upstream_test_counts'] = upstream
        binary = build / 'ugrep-source-host.exe'; pe(binary, args.arch)
        fixture = out / 'owned-fixtures'; fixture.mkdir()
        source = fixture / 'owned 空格 猫.txt'; source.write_bytes('first\nNEEDLE\npreneedle\nλ猫\n'.encode())
        env.update(NO_COLOR='1', TERM='dumb', LC_ALL='C', LANG='C')
        env.pop('ARGV0', None)
        version = run('owned-UG-version', [binary, '--version'])
        expected = ('ugrep 7.8.4 WIN64 ' + ('+sse2' if args.arch == 'x64' else '+neon/AArch64') +
            '; -P:pcre2jit; -z:zlib,bzip2,zstd,brotli,7z,tar/pax/cpio/zip\r\n'
            'License: BSD-3-Clause; ugrep user manual: <https://ugrep.com>\r\n'
            'Written by Robert van Engelen and others: <https://github.com/Genivia/ugrep>\r\n'
            'Ugrep utilizes the RE/flex regex library: <https://github.com/Genivia/RE-flex>\r\n').encode()
        assert version == expected, 'Windows Ugrep metadata does not match the measured original features'
        # Windows init switches stdout to binary mode. Full-line output copies
        # the input LF; -o uses Output::nl(), which explicitly emits CRLF.
        # Keep these two upstream byte contracts separate.
        cases = [('literal', ['--no-config', '-F', '-n', 'NEEDLE', source], 0, b'2:NEEDLE\n'),
            ('PCRE-lookbehind', ['--no-config', '-P', '-o', '(?<=pre)needle', source], 0, b'needle\r\n'),
            ('Unicode', ['--no-config', '-F', '-o', 'λ猫', source], 0, 'λ猫\r\n'.encode()),
            ('absent', ['--no-config', 'owned-absent', source], 1, b''),
            ('invalid-regex', ['--no-config', '-P', '(', source], 2, None)]
        payload = b'owned COMPRESSED_NEEDLE\n'
        (fixture / 'owned.gz').write_bytes(gzip.compress(payload, mtime=0)); (fixture / 'owned.bz2').write_bytes(bz2.compress(payload))
        with zipfile.ZipFile(fixture / 'owned.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive: archive.writestr('owned.txt', payload)
        for suffix in ['gz', 'bz2', 'zip']:
            cases.append(('compressed-' + suffix, ['--no-config', '-z', '-h', '-o', 'COMPRESSED_NEEDLE', fixture / ('owned.' + suffix)], 0, b'COMPRESSED_NEEDLE\r\n'))
        controls = []
        for label, arguments, code, wanted in cases:
            observed = run('owned-UG-' + label, [binary, *arguments], expected=code, timeout=30)
            assert wanted is None or observed == wanted, label
            controls.append(dict(case=label, expected_exit=code, stdout_sha256=hashlib.sha256(observed).hexdigest(), stdout_hex=observed.hex()))
        # Preserve the non-LTO source objects, not only a standalone executable.
        objects = sorted((build / 'CMakeFiles/owned_ugrep_source.dir').rglob('*.obj')); assert len(objects) == 28
        archives = {}
        for line in (build / 'recovery-library-paths.tsv').read_text().splitlines():
            target, path = line.split('\t'); file = Path(path)
            assert target not in archives and file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(build)
            assert file.suffix == '.lib'; archives[target] = file
        assert set(archives) == {'owned_viiz', 'owned_bzip2', 'pcre2-8-static', 'zlibstatic', 'libzstd_static', 'brotlidec', 'brotlicommon'}
        package = out / 'public-components'; package.mkdir(); shutil.copyfile(binary, package / binary.name)
        raw = package / 'raw-UG-objects'; raw.mkdir(); indexed = []
        for index, obj in enumerate(objects):
            name = f'{index:04d}-' + obj.name; shutil.copyfile(obj, raw / name)
            indexed.append(dict(file=name, build_file=obj.relative_to(build).as_posix(), bytes=obj.stat().st_size, sha256=sha(obj)))
        (package / 'raw-UG-objects.json').write_text(json.dumps(indexed, indent=2) + '\n')
        libraries = package / 'raw-dependency-archives'; libraries.mkdir()
        for name, file in archives.items(): shutil.copyfile(file, libraries / (name + '.lib'))
        shutil.copytree(inputs, package / 'source-inputs'); shutil.copyfile(sources / 'ugrep/LICENSE.txt', package / 'UGREP-LICENSE.txt')
        recipe = package / 'recipes/windows-native-components'; recipe.mkdir(parents=True)
        for name in ['build_components.py', 'toolchain.py', 'CMakeLists.txt']: shutil.copyfile(ROOT / name, recipe / name)
        platform_recipes = package / 'recipes/platform-runtime'; platform_recipes.mkdir()
        for name in ['build_windows.py', 'build_macos.py']: shutil.copyfile(ROOT.parent / 'platform-runtime' / name, platform_recipes / name)
        pins = package / 'recipes/extra-components'; pins.mkdir(); shutil.copyfile(ROOT.parent / 'extra-components/sources.json', pins / 'sources.json')
        shutil.copyfile(config, package / config.name)
        receipt.update(status='native_public_Windows_ugrep_source_candidate_and_owned_cases_passed', binary_sha256=sha(binary), bytes=binary.stat().st_size,
            expected_native_version_hex=expected.hex(), raw_UG_objects=len(objects), raw_dependency_archives=len(archives), owned_controls=controls,
            exact_original_transitive_versions_proven=False, original_source_or_client_binaries_used=False,
            scope='Public standalone Ugrep C/C++ candidate with measured platform/features. Private COFF namespaces, original AppContainer role pairs and complete Bun integration are separate admission gates.')
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='Windows_public_source_component_candidate_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally: (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
