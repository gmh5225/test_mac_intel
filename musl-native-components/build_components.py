"""Compile and test the public Ugrep/Bfs/PCRE2 graphs on native musl targets."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
from sdk import profile
from elf_objects import compare_objects
from private_symbols import isolate


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', choices=['arm64', 'x64'], required=True); args = parser.parse_args()
    out = Path('/tmpfs/bun'); source = out / 'embedded'; logs = Path('/diagnostics')
    root = Path('/repo/musl-native-components'); target = profile(args.arch)
    toolbin = Path('/usr/lib/llvm-23/bin'); cc = toolbin / 'clang'; cxx = toolbin / 'clang++'
    ccflags = ['--target=' + target['triple'], '--sysroot=' + target['sysroot'], '--ld-path=' + str(toolbin / 'ld.lld')]
    prefix = out / 'dependencies'; prefix.mkdir(); libraries = out / 'native-libraries'; libraries.mkdir()
    flags = '-O2 -fPIC -fno-lto -ffunction-sections -fdata-sections'
    env = dict(PATH=os.environ['PATH'], HOME=str(out / 'home'), LANG='C.UTF-8', LC_ALL='C.UTF-8',
        CC=shlex.join([str(cc), *ccflags]), CXX=shlex.join([str(cxx), *ccflags]), AR=str(toolbin / 'llvm-ar'), RANLIB=str(toolbin / 'llvm-ranlib'),
        CFLAGS=flags, CXXFLAGS=flags, CPPFLAGS='-I' + str(prefix / 'include'), LDFLAGS='-L' + str(prefix / 'lib'),
        PKG_CONFIG_LIBDIR=str(prefix / 'lib/pkgconfig'), GIT_CEILING_DIRECTORIES=str(out))
    commands = []
    def run(label, argv, cwd=None, environment=None, data=None, timeout=1200):
        argv = list(map(str, argv)); commands.append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None))
        print('Starting ' + label, flush=True)
        r = subprocess.run(argv, cwd=cwd, env=environment or env, input=data, capture_output=True, timeout=timeout)
        (logs / (label + '.stdout')).write_bytes(r.stdout); (logs / (label + '.stderr')).write_bytes(r.stderr)
        if r.returncode != 0 and cwd is not None:
            retained = logs / (label + '-source-logs'); retained.mkdir()
            total = 0
            for path in sorted(Path(cwd).rglob('*')):
                if not path.is_file() or path.is_symlink(): continue
                if not (path.suffix in ['.log', '.trs'] or path.name.startswith('testtry')): continue
                assert path.stat().st_size <= 8 * 1024 * 1024, 'Oversized public source-test diagnostic'
                total += path.stat().st_size
                assert total <= 32 * 1024 * 1024, 'Public source-test diagnostics exceed budget'
                destination = retained / path.relative_to(cwd); destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        assert r.returncode == 0, (label, r.returncode)
        return r
    def make(label, cwd, *argv, environment=None): return run(label, ['make', '-j2', *argv], cwd, environment)
    def cmake(name, directory, *options):
        build = out / (name + '-build')
        run(name + '-configure', ['cmake', '-S', directory, '-B', build, '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
            '-DCMAKE_INSTALL_LIBDIR=lib', '-DBUILD_SHARED_LIBS=OFF', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
            '-DCMAKE_C_COMPILER=' + str(cc), '-DCMAKE_CXX_COMPILER=' + str(cxx), '-DCMAKE_C_COMPILER_TARGET=' + target['triple'],
            '-DCMAKE_CXX_COMPILER_TARGET=' + target['triple'], '-DCMAKE_SYSROOT=' + target['sysroot'],
            '-DCMAKE_EXE_LINKER_FLAGS=--ld-path=' + str(toolbin / 'ld.lld'), *options])
        run(name + '-build', ['cmake', '--build', build, '--parallel', '2']); run(name + '-install', ['cmake', '--install', build]); return build
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def controls(role, host, cases):
        rows = []; folder = libraries / role
        for label, argv, code, expected in cases:
            r = subprocess.run([str(host), *map(str, argv)], env=env, capture_output=True, timeout=30, preexec_fn=limits)
            (folder / (label + '.stdout')).write_bytes(r.stdout); (folder / (label + '.stderr')).write_bytes(r.stderr)
            assert r.returncode == code and (expected is None or r.stdout == expected), (role, label, r.returncode)
            if label == 'invalid': assert not r.stdout and b'mismatched [ ]' in r.stderr
            else: assert not r.stderr, (role, label, r.stderr)
            rows.append(dict(case=label, argv=list(map(str, argv)), exit_code=r.returncode, stdout_hex=r.stdout.hex(), stderr_hex=r.stderr.hex(), rlimit_fsize=0))
        return rows
    def dynamic(role, host):
        r = run(role + '-dynamic', [toolbin / 'llvm-readelf', '-d', host]).stdout.decode()
        needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', r)
        assert needed == [target['libc']], (role, needed)
        r = run(role + '-versions', [toolbin / 'llvm-readelf', '--version-info', host]).stdout
        assert not re.search(rb'(?:GLIBC|GLIBCXX|CXXABI)_\d', r)
        return dict(needed_libraries=needed, GNU_symbol_versions_imported=False)
    def export(role, objects, archives):
        library = libraries / role; library.mkdir(); owned = library / 'objects'; owned.mkdir(); paths = []
        main_proof = None
        for obj in objects:
            path = owned / obj.name; shutil.copyfile(obj, path); paths.append(path)
            if obj.name in ['main.o', 'ugrep-ugrep.o']:
                before = library / 'original-main.o'; shutil.copyfile(path, before)
                run(role + '-rename-main', [toolbin / 'llvm-objcopy', '--redefine-sym=main=neverd_recovered_' + role + '_main', path])
                main_proof = compare_objects(before, path, {'main': 'neverd_recovered_' + role + '_main'})
        assert main_proof is not None
        deps = []
        for archive in archives:
            path = library / archive.name; shutil.copyfile(archive, path); deps.append(path)
        def scoped_run(label, argv, cwd=None): return run(role + '-' + label, argv, cwd)
        private = isolate(library, paths, deps, toolbin, scoped_run, logs, entry='neverd_recovered_' + role + '_main', prefix='neverd_' + role + '_native_')
        archive = library / ('librecovered_' + role + '.a'); run(role + '-export', [toolbin / 'llvm-ar', 'rcs', archive, *paths])
        host_source = library / (role + '-library-host.c')
        host_source.write_text('extern int neverd_recovered_' + role + '_main(int,char **);\nint main(int argc,char **argv){return neverd_recovered_' + role + '_main(argc,argv);}\n')
        run(role + '-host-compile', [cc, *ccflags, '-O2', '-c', host_source, '-o', library / 'host.o'])
        host = library / (role + '-library-host')
        run(role + '-host-link', [cxx, *ccflags, library / 'host.o', '-Wl,--start-group', archive, *deps, '-Wl,--end-group',
            '-static-libstdc++', '-static-libgcc', '-pthread', '-ldl', '-lm', '-lrt', '-Wl,--eh-frame-hdr', '-o', host])
        return host, dict(main_rename_proof=main_proof, private_c_symbols=private, objects=len(paths),
            archives={p.name: sha(p) for p in [archive, *deps]}, host_sha256=sha(host), **dynamic(role, host))

    run('clang-version', [cc, '--version']); run('clangxx-version', [cxx, '--version']); run('cmake-version', ['cmake', '--version'])
    # Own ABI control disconfirms accidental host-libstdc++ and a broken loader
    # path before any configure program or upstream suite runs.
    thread = logs / 'owned-thread.cc'
    thread.write_text('#include <condition_variable>\n#include <thread>\n#include <iostream>\nint main(){std::mutex m;std::condition_variable c;bool ready=false;std::thread t([&]{{std::lock_guard<std::mutex> g(m);ready=true;}c.notify_one();});{std::unique_lock<std::mutex> l(m);c.wait(l,[&]{return ready;});}t.join();std::cout<<"owned musl thread\\n";}\n')
    run('owned-thread-build', [cxx, *ccflags, thread, '-static-libstdc++', '-static-libgcc', '-pthread', '-o', out / 'owned-thread'])
    assert run('owned-thread', [out / 'owned-thread']).stdout == b'owned musl thread\n'
    thread_dynamic = dynamic('owned-thread', out / 'owned-thread')
    z = source / 'zlib'; run('zlib-configure', [z / 'configure', '--static', '--prefix=' + str(prefix)], z); make('zlib-build', z); make('zlib-check', z, 'check'); make('zlib-install', z, 'install')
    b = source / 'bzip2'; make('bzip2-build', b, 'libbz2.a', 'bzip2', 'bzip2recover', 'CC=' + env['CC'], 'AR=' + env['AR'], 'RANLIB=' + env['RANLIB'], 'CFLAGS=' + env['CFLAGS']); make('bzip2-check', b, 'test'); make('bzip2-install', b, 'install', 'PREFIX=' + str(prefix))
    cmake('zstd', source / 'zstd/build/cmake', '-DZSTD_BUILD_SHARED=OFF', '-DZSTD_BUILD_STATIC=ON', '-DZSTD_BUILD_PROGRAMS=ON', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_ZLIB_SUPPORT=OFF', '-DZSTD_LZMA_SUPPORT=OFF', '-DZSTD_LZ4_SUPPORT=OFF')
    brotli = cmake('brotli', source / 'brotli'); run('brotli-check', ['ctest', '--test-dir', brotli, '--output-on-failure'])
    pc = source / 'pcre2'
    run('pcre2-configure', [pc / 'configure', '--host=' + target['triple'], '--prefix=' + str(prefix), '--enable-static', '--disable-shared',
        '--enable-jit' if target['pcre2_jit'] else '--disable-jit', '--disable-pcre2-16', '--disable-pcre2-32'], pc)
    make('pcre2-build', pc); make('pcre2-check', pc, 'check'); make('pcre2-install', pc, 'install')
    ug = source / 'ugrep'; ug_env = dict(env, LIBS='-lbrotlicommon -lm', PTHREAD_LIBS='-pthread', PTHREAD_CFLAGS='-pthread')
    options = ['--host=' + target['triple'], '--without-lzma', '--without-lz4', *['--with-' + name + '=' + str(prefix) for name in ['pcre2', 'zlib', 'bzlib', 'zstd', 'brotli']]]
    if args.arch == 'x64': options += ['--disable-avx2']
    run('ugrep-configure', [ug / 'configure', *options], ug, ug_env); make('ugrep-build', ug, environment=ug_env)
    raw_version = run('ugrep-original-source-version', [ug / 'bin/ugrep', '--version']).stdout
    reference = (root / ('expected-ugrep-version-' + args.arch + '.txt')).read_bytes()
    assert raw_version in [reference, reference.replace(b' (no sse2!)', b' +sse2')], 'Ugrep build profile differs'
    make('ugrep-upstream-check', ug, 'check', environment=ug_env)
    ug_objects = [ug / 'src' / ('ugrep-' + name + '.o') for name in ['ugrep', 'cnf', 'glob', 'output', 'query', 'screen', 'stats', 'vkey', 'zopen']]
    deps = [ug / 'lib/libreflex.a', ug / 'lzma/C/libviiz.a', *[prefix / 'lib' / ('lib' + name + '.a') for name in ['pcre2-8', 'z', 'bz2', 'zstd', 'brotlidec', 'brotlicommon']]]
    ug_host, ug_receipt = export('ugrep', ug_objects, deps)
    sections = run('ugrep-exception-sections', [toolbin / 'llvm-readelf', '-S', ug_host]).stdout
    assert b'.eh_frame' in sections and b'.gcc_except_table' in sections
    fixture = libraries / 'ugrep/input.txt'; fixture.write_bytes(b'first\nNEEDLE\npreneedle\n'); compressed = fixture.with_suffix('.gz'); compressed.write_bytes(gzip.compress(fixture.read_bytes(), mtime=0))
    ug_receipt['controls'] = controls('ugrep', ug_host, [('version', ['--version'], 0, raw_version), ('literal', ['--no-config', '-n', 'NEEDLE', fixture], 0, b'2:NEEDLE\n'),
        ('pcre', ['--no-config', '-P', '-o', '(?<=pre)needle', fixture], 0, b'needle\n'), ('gzip', ['--no-config', '-z', '-n', 'NEEDLE', compressed], 0, b'2:NEEDLE\n'), ('invalid', ['--no-config', '[', fixture], 2, b'')])
    for path in [ug / 'src/ugrep', ug / 'bin/ugrep']: shutil.copyfile(ug_host, path)
    make('ugrep-host-upstream-check', ug, 'check', environment=ug_env)
    assert all(sha(p) == sha(ug_host) for p in [ug / 'src/ugrep', ug / 'bin/ugrep'])
    onig = cmake('onig', source / 'oniguruma', '-DBUILD_TEST=ON'); run('onig-check', ['ctest', '--test-dir', onig, '--output-on-failure'])
    onig_exact = out / 'build/release/deps/oniguruma'; onig_exact.mkdir(parents=True); shutil.copyfile(onig / 'libonig.a', onig_exact / 'libonig.a')
    bf = source / 'bfs'
    cpp = '-Dposix_getdents=__bfs_poison_posix_getdents_musl_1_2_5 -Dgetdents64=__bfs_poison_getdents64_glibc_2_30 -Dposix_spawn_file_actions_addfchdir_np=__bfs_poison_addfchdir_np_glibc_2_29 -I/tmpfs/bun/embedded/oniguruma/src'
    bf_env = dict(env, CPPFLAGS=cpp, LDFLAGS='-L' + str(onig_exact) + ' -no-pie', LDLIBS='-lonig', LTO='0', VERSION='4.1.1', PKG_CONFIG_LIBDIR=str(out / 'no-host-pkgconfig'))
    bf_env.pop('CFLAGS'); bf_env.pop('CXXFLAGS')
    build_flags = ['XCPPFLAGS=-Isrc -Igen -include src/prelude.h -DNDEBUG -MD -MP -Wundef-prefix=BFS_ ' + cpp,
        'XLDFLAGS=-Wl,-z,now ' + bf_env['LDFLAGS'], 'XLDLIBS=-lonig -lrt']
    run('bfs-configure', [bf / 'configure', '--enable-release', '--with-oniguruma', '--without-libselinux', '--without-libacl', *build_flags], bf, bf_env)
    make('bfs-build', bf, 'V=1', *build_flags, environment=bf_env)
    bf_version = run('bfs-original-source-version', [bf / 'bin/bfs', '--version']).stdout
    assert bf_version == (root / ('expected-bfs-version-' + args.arch + '.txt')).read_bytes(), 'Bfs measured compiler inputs differ'
    make('bfs-upstream-check', bf, 'check', *build_flags, environment=bf_env)
    bf_host, bf_receipt = export('bfs', sorted((bf / 'obj/src').glob('*.o')), [onig_exact / 'libonig.a'])
    bf_receipt['controls'] = controls('bfs', bf_host, [('version', ['--version'], 0, bf_version), ('name', [fixture.parent, '-name', 'input.txt', '-printf', '%f\n'], 0, b'input.txt\n'),
        ('regex', [fixture.parent, '-regextype', 'posix-extended', '-regex', '.*/input[.]txt', '-printf', '%f\n'], 0, b'input.txt\n'), ('absent', [fixture.parent, '-name', 'absent-owned', '-print'], 0, b'')])
    shutil.copyfile(bf_host, bf / 'bin/bfs'); make('bfs-host-upstream-check', bf, 'check', *build_flags, environment=bf_env)
    assert sha(bf / 'bin/bfs') == sha(bf_host)
    # The unprefixed PCRE2 graph is separately owned by the rg source graph;
    # Ugrep's private copy is never substituted into Cargo's external sys crate.
    pc_rg = libraries / 'rg-pcre2'; pc_rg.mkdir(); shutil.copytree(prefix / 'include', pc_rg / 'include')
    shutil.copyfile(prefix / 'lib/libpcre2-8.a', pc_rg / 'libpcre2-8.a')
    (pc_rg / 'pcre2.pc').write_text('prefix=' + str(pc_rg) + '\nlibdir=${prefix}\nincludedir=${prefix}/include\n\nName: libpcre2-8\nDescription: Source-built PCRE2 8-bit\nVersion: 10.45\nLibs: -L${libdir} -lpcre2-8\nCflags: -I${includedir}\n')
    receipt = dict(status='musl_source_component_graphs_hosts_and_upstream_checks_passed', arch=args.arch, target_profile=target,
        components=dict(ugrep=ug_receipt, bfs=bf_receipt), commands=commands, owned_static_cxx_thread_control=thread_dynamic,
        captured_client_executed=False, compiled_rust_archive_used=False, original_prefix_reused=False,
        rg_pcre2_archive_sha256=sha(pc_rg / 'libpcre2-8.a'), zstd_upstream_suite_run=False, goal_complete=False)
    (libraries / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
