"""Build plain Mach-O Ugrep objects against the same Apple SDK ABI as Bun."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import platform
import resource
import shlex
import shutil
import subprocess
import sys
import tarfile
from llvm_tools import prepare as prepare_llvm
from macho_objects import compare_objects
from private_symbols import isolate

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import unpack
sys.path.insert(0, str(ROOT.parent / 'platform-runtime'))
from build_macos import CMAKE_ASSET, CMAKE_SHA256


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    p.add_argument('--output', required=True, type=Path); p.add_argument('--source-inputs', type=Path)
    p.add_argument('--llvm-tools-archive', type=Path); p.add_argument('--cmake-archive', type=Path); args = p.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[args.arch]
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    inputs = out / 'source-inputs'; inputs.mkdir(); sources = out / 'sources'; sources.mkdir(); prefix = out / 'dependencies'; prefix.mkdir()
    env = {k: v for k, v in os.environ.items() if not any(word in k.upper() for word in ['TOKEN', 'SECRET', 'PASSWORD']) and not k.startswith('ACTIONS_')}
    env.update(HOME=str(out / 'home'), LANG='C.UTF-8', LC_ALL='C.UTF-8', GIT_CEILING_DIRECTORIES=str(out))
    (out / 'home').mkdir(); commands = []
    receipt = dict(status='started', arch=args.arch, commands=commands, captured_client_executed=False,
        original_binary_reused=False, exact_original_transitive_versions_proven=False, compiler_objects_are_llvm_bitcode=False,
        goal_complete=False)
    recipe_names = ['build_ugrep.py', 'llvm_tools.py', 'llvm-tools-pins.json', 'macho_objects.py', 'private_symbols.py']
    receipt['recipe_inputs'] = {name: sha(ROOT / name) for name in recipe_names}
    receipt['source_pins_sha256'] = sha(ROOT.parent / 'extra-components/sources.json')

    def run(label, argv, cwd=None, environment=None, timeout=1200):
        argv = list(map(str, argv)); commands.append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None))
        print('Starting ' + label, flush=True)
        completed = subprocess.run(argv, cwd=cwd, env=environment or env, capture_output=True, timeout=timeout)
        (logs / (label + '.stdout')).write_bytes(completed.stdout); (logs / (label + '.stderr')).write_bytes(completed.stderr)
        assert completed.returncode == 0, label + ' failed with exit ' + str(completed.returncode)
        return completed

    def download(label, url, path):
        run(label, ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', path, url])

    def make(label, directory, *targets, environment=None):
        return run(label, ['make', '-j2', *targets], directory, environment)

    try:
        toolbin, llvm_receipt = prepare_llvm(args.arch, out / 'llvm-tools', run, args.llvm_tools_archive)
        receipt['llvm_tools'] = llvm_receipt
        cmake_archive = out / CMAKE_ASSET
        if args.cmake_archive: shutil.copyfile(args.cmake_archive, cmake_archive)
        else: download('download-cmake', 'https://github.com/Kitware/CMake/releases/download/v3.30.5/' + CMAKE_ASSET, cmake_archive)
        assert sha(cmake_archive) == CMAKE_SHA256
        cmake_root = out / 'cmake'; cmake_root.mkdir()
        with tarfile.open(cmake_archive, 'r:gz') as archive: archive.extractall(cmake_root, filter='data')
        candidates = list(cmake_root.glob('*/CMake.app/Contents/bin/cmake')); assert len(candidates) == 1
        cmake = candidates[0]; env['PATH'] = str(cmake.parent) + os.pathsep + env['PATH']
        assert run('cmake-version', [cmake, '--version']).stdout.startswith(b'cmake version 3.30.5\n')
        compiler = Path(run('clang-path', ['xcrun', '--find', 'clang']).stdout.decode().strip())
        cxx = Path(run('clangxx-path', ['xcrun', '--find', 'clang++']).stdout.decode().strip())
        compiler_version = run('compiler-version', [compiler, '--version']).stdout.decode(); assert 'Apple clang version 17.' in compiler_version
        sdk = Path(run('sdk-path', ['xcrun', '--show-sdk-path']).stdout.decode().strip())
        sdk_version = run('sdk-version', ['xcrun', '--show-sdk-version']).stdout.decode().strip(); assert sdk_version == '15.5'
        resource_dir = Path(run('compiler-resource-dir', [compiler, '-print-resource-dir']).stdout.decode().strip())
        triple = {'arm64': 'arm64-apple-macosx', 'x64': 'x86_64-apple-macosx'}[args.arch]
        ccflags = ['--target=' + triple, '-isysroot', str(sdk), '-mmacosx-version-min=13.0']
        cpp_headers = ['-nostdinc', '-isystem', str(sdk / 'usr/include/c++/v1'), '-isystem', str(resource_dir / 'include'),
            '-isystem', str(sdk / 'usr/include'), '-iframework', str(sdk / 'System/Library/Frameworks')]
        flags = '-O2 -fPIC -fno-lto'
        env.update(CC=shlex.join([str(compiler), *ccflags]), CXX=shlex.join([str(cxx), *ccflags]),
            AR=str(toolbin / 'llvm-ar'), RANLIB=str(toolbin / 'llvm-ranlib'), CFLAGS=flags,
            CXXFLAGS=flags + ' ' + shlex.join(cpp_headers), CPPFLAGS='-I' + str(prefix / 'include'),
            LDFLAGS='-L' + str(prefix / 'lib'), PKG_CONFIG_LIBDIR=str(prefix / 'lib/pkgconfig'),
            SDKROOT=str(sdk), MACOSX_DEPLOYMENT_TARGET='13.0')
        assert (toolbin / 'llvm-ranlib').is_file()
        receipt['compiler'] = dict(version=compiler_version, path=str(compiler), sha256=sha(compiler),
            sdk=str(sdk), sdk_version=sdk_version, minimum_os='13.0', target=triple, non_lto=True)
        # Apple ld's -no_compact_unwind drops this object's only unwind data
        # on ARM64. The integrated engine must remove that flag for Ugrep.
        # Plain machine-code objects keep the SDK C++ ABI and compact unwind.
        receipt['required_outer_link_policy'] = 'retain_compact_unwind; omit -no_compact_unwind'
        receipt['core_engine_unwind_patch_pending'] = True
        throw_source = logs / 'owned-exception.cpp'
        throw_source.write_text('#include <stdexcept>\n#include <cstdio>\nint main() { try { throw std::runtime_error("owned-exception"); } catch (const std::exception &error) { std::puts(error.what()); return 0; } }\n')
        throw_host = out / 'owned-exception'
        run('exception-outer-link-build', [cxx, *ccflags, *cpp_headers, '-O2', '-fno-lto', throw_source, '-o', throw_host])
        assert run('exception-outer-link-control', [throw_host]).stdout == b'owned-exception\n'
        unwind = run('exception-outer-link-sections', ['xcrun', 'llvm-objdump', '--macho', '--section-headers', throw_host]).stdout
        assert b'__unwind_info' in unwind
        names = {'ugrep', 'pcre2', 'zlib', 'bzip2', 'zstd', 'brotli'}
        selected = [row for row in json.loads((ROOT.parent / 'extra-components/sources.json').read_bytes())['files'] if row['name'] in names]
        assert {row['name'] for row in selected} == names; receipt['source_inputs'] = selected
        for row in selected:
            path = inputs / (row['name'] + '.tar.gz')
            if args.source_inputs: shutil.copyfile(args.source_inputs / path.name, path)
            else: download('download-' + row['name'], row['url'], path)
            assert path.stat().st_size <= 16777216 and sha(path) == row['sha256']
            if 'bytes' in row: assert path.stat().st_size == row['bytes']
            unpack(path, sources / row['name'], row['prefix'])
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if member.isfile(): os.utime(sources / row['name'] / member.name[len(row['prefix']):], (member.mtime, member.mtime), follow_symlinks=False)
        def build_cmake(name, directory, *options):
            build = out / (name + '-build')
            run(name + '-configure', [cmake, '-S', directory, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_INSTALL_LIBDIR=lib', '-DBUILD_SHARED_LIBS=OFF',
                '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DCMAKE_OSX_SYSROOT=' + str(sdk),
                '-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0', '-DCMAKE_OSX_ARCHITECTURES=' + ('arm64' if args.arch == 'arm64' else 'x86_64'), *options])
            run(name + '-build', [cmake, '--build', build, '--parallel', '2']); run(name + '-install', [cmake, '--install', build]); return build
        z = sources / 'zlib'; run('zlib-configure', [z / 'configure', '--static', '--prefix=' + str(prefix)], z)
        make('zlib-build', z); make('zlib-check', z, 'check'); make('zlib-install', z, 'install')
        b = sources / 'bzip2'
        make('bzip2-build', b, 'libbz2.a', 'bzip2', 'bzip2recover', 'CC=' + env['CC'], 'AR=' + env['AR'], 'RANLIB=' + env['RANLIB'], 'CFLAGS=' + env['CFLAGS'])
        make('bzip2-check', b, 'test'); make('bzip2-install', b, 'install', 'PREFIX=' + str(prefix))
        build_cmake('zstd', sources / 'zstd/build/cmake', '-DZSTD_BUILD_SHARED=OFF', '-DZSTD_BUILD_STATIC=ON',
            '-DZSTD_BUILD_PROGRAMS=ON', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_ZLIB_SUPPORT=OFF', '-DZSTD_LZMA_SUPPORT=OFF', '-DZSTD_LZ4_SUPPORT=OFF')
        brotli = build_cmake('brotli', sources / 'brotli'); run('brotli-check', [cmake.parent / 'ctest', '--test-dir', brotli, '--output-on-failure'])
        pc = sources / 'pcre2'; run('pcre2-configure', [pc / 'configure', '--prefix=' + str(prefix), '--enable-static', '--disable-shared',
            '--enable-jit', '--disable-pcre2-16', '--disable-pcre2-32'], pc)
        make('pcre2-build', pc); make('pcre2-check', pc, 'check'); make('pcre2-install', pc, 'install')
        ug = sources / 'ugrep'; ug_env = dict(env, LIBS='-lbrotlicommon -lm', PTHREAD_LIBS='-pthread', PTHREAD_CFLAGS='-pthread')
        # This Ugrep switch requests a fully static executable, which Darwin
        # does not support. Dependencies above still produce only .a libraries.
        options = ['--host=' + ('aarch64-apple-macosx' if args.arch == 'arm64' else 'x86_64-apple-macosx'), '--disable-static',
            '--without-lzma', '--without-lz4', *['--with-' + n + '=' + str(prefix) for n in ['pcre2', 'zlib', 'bzlib', 'zstd', 'brotli']]]
        # Ugrep's AC_ARG_ENABLE(neon) treats any supplied option as disabling
        # NEON, even --enable-neon. ARM64 must use its default detection.
        if args.arch == 'x64': options.append('--disable-avx2')
        run('ugrep-configure', [ug / 'configure', *options], ug, ug_env); make('ugrep-build', ug, environment=ug_env)
        original_version = run('upstream-version', [ug / 'bin/ugrep', '--version']).stdout
        observed_version = (ROOT / ('expected-ugrep-version-' + args.arch + '.txt')).read_bytes()
        expected_version = observed_version
        if args.arch == 'x64':
            # The original's local x64 observation used Rosetta. RE/flex's
            # upstream banner tests CPUID leaf 1 ECX bit 26; native Intel can
            # report a different value. Derive this host's exact banner from
            # a separate C probe instead of disabling the implementation.
            probe_source = logs / 'owned-cpuid.c'; probe = out / 'owned-cpuid'
            probe_source.write_text('#include <cpuid.h>\n#include <stdio.h>\nint main(void) { unsigned a=0,b=0,c=0,d=0; if (!__get_cpuid(1,&a,&b,&c,&d)) return 2; printf("%u %u %u %u\\n",a,b,c,d); return 0; }\n')
            run('cpuid-build', [compiler, *ccflags, '-O2', probe_source, '-o', probe])
            cpuid = list(map(int, run('cpuid-control', [probe]).stdout.split())); assert len(cpuid) == 4
            if cpuid[2] & (1 << 26): expected_version = observed_version.replace(b' (no sse2!)', b' +sse2')
            receipt['native_cpu_banner_control'] = dict(cpuid_leaf_1=cpuid, reference_observation_host='Rosetta',
                native_original_version_comparison_pending=True)
        assert original_version == expected_version
        receipt['local_reference_version_bytes_reproduced'] = original_version == observed_version
        receipt['expected_native_version_hex'] = expected_version.hex()
        make('ugrep-upstream-check', ug, 'check', environment=ug_env)
        library = out / 'native-library'; library.mkdir(); objects = library / 'objects'; objects.mkdir()
        paths = []
        for name in ['ugrep', 'cnf', 'glob', 'output', 'query', 'screen', 'stats', 'vkey', 'zopen']:
            original = ug / 'src' / ('ugrep-' + name + '.o'); assert original.is_file()
            destination = objects / original.name; shutil.copyfile(original, destination); paths.append(destination)
        main = objects / 'ugrep-ugrep.o'; original_main = library / 'original-main.o'; shutil.copyfile(main, original_main)
        run('rename-main', [toolbin / 'llvm-objcopy', '--redefine-sym', '_main=_neverd_recovered_ugrep_main', main])
        receipt['main_rename_proof'] = compare_objects(original_main, main, {'_main': '_neverd_recovered_ugrep_main'})
        names = ['reflex', 'viiz', 'pcre2-8', 'z', 'bz2', 'zstd', 'brotlidec', 'brotlicommon']; archives = []
        for name in names:
            original = ug / 'lib/libreflex.a' if name == 'reflex' else ug / 'lzma/C/libviiz.a' if name == 'viiz' else prefix / 'lib' / ('lib' + name + '.a')
            path = library / ('lib' + name + '.a'); assert original.is_file(); shutil.copyfile(original, path); archives.append(path)
        receipt['private_c_symbols'] = isolate(library, paths, archives, toolbin, run, logs)
        exported = library / 'librecovered_ugrep.a'; run('export-library', [toolbin / 'llvm-ar', 'rcs', exported, *paths])
        host_source = library / 'ugrep-library-host.c'; host_source.write_text('extern int neverd_recovered_ugrep_main(int, char **);\nint main(int argc, char **argv) { return neverd_recovered_ugrep_main(argc, argv); }\n')
        run('compile-host', [compiler, *ccflags, '-O2', '-fno-lto', '-c', host_source, '-o', library / 'host.o'])
        host = library / 'ugrep-library-host'
        run('link-host', [cxx, *ccflags, library / 'host.o', exported, *archives, '-pthread', '-o', host])
        host_sections = run('library-host-sections', ['xcrun', 'llvm-objdump', '--macho', '--section-headers', host]).stdout
        assert b'__unwind_info' in host_sections and b'__gcc_except_tab' in host_sections
        fixture = library / 'input.txt'; fixture.write_bytes(b'first\nNEEDLE\npreneedle\n')
        compressed = library / 'input.gz'; compressed.write_bytes(gzip.compress(fixture.read_bytes(), mtime=0))
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        controls = []
        for label, argv, code, stdout in [
            ('version', ['--version'], 0, original_version), ('literal', ['--no-config', '-n', 'NEEDLE', str(fixture)], 0, b'2:NEEDLE\n'),
            ('pcre', ['--no-config', '-P', '-o', '(?<=pre)needle', str(fixture)], 0, b'needle\n'),
            ('gzip', ['--no-config', '-z', '-n', 'NEEDLE', str(compressed)], 0, b'2:NEEDLE\n'),
            ('invalid-regex', ['--no-config', '[', str(fixture)], 2, b'')]:
            result = subprocess.run([str(host), *argv], env=env, capture_output=True, timeout=30, preexec_fn=limits)
            (library / (label + '.stdout')).write_bytes(result.stdout); (library / (label + '.stderr')).write_bytes(result.stderr)
            controls.append(dict(label=label, argv=argv, exit_code=result.returncode, stdout_hex=result.stdout.hex(), stderr_hex=result.stderr.hex(), fsize_zero=True))
            assert result.returncode == code and result.stdout == stdout
            if label == 'invalid-regex': assert b'mismatched [ ]' in result.stderr
            else: assert not result.stderr
        for destination in [ug / 'src/ugrep', ug / 'bin/ugrep']: shutil.copyfile(host, destination); assert sha(destination) == sha(host)
        make('library-host-upstream-check', ug, 'check', environment=ug_env)
        assert all(sha(p) == sha(host) for p in [ug / 'src/ugrep', ug / 'bin/ugrep'])
        receipt.update(status='macos_ugrep_source_library_and_upstream_host_checks_passed', controls=controls,
            source_objects=9, host_sha256=sha(host), library_sha256=sha(exported), entry_symbol='neverd_recovered_ugrep_main',
            source_profile_version_bytes_verified=True, core_engine_integration_pending=True)
        package = out / 'public-library'; package.mkdir(); shutil.copytree(library, package / 'native-library')
        shutil.copytree(inputs, package / 'source-inputs'); shutil.copyfile(sources / 'ugrep/LICENSE.txt', package / 'UGREP-LICENSE.txt')
        shutil.copyfile(ROOT / ('expected-ugrep-version-' + args.arch + '.txt'), package / 'expected-original-version.txt')
        for name in recipe_names:
            assert sha(ROOT / name) == receipt['recipe_inputs'][name], 'Recipe changed during the build'
            shutil.copyfile(ROOT / name, package / name)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='macos_ugrep_source_library_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
