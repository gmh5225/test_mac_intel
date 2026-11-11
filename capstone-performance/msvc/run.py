"""Measure ordinary MSVC Capstone and iced on the same pinned Windows thread."""
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(source))
from corpus import digest, elf_text, pe_text

evidence = Path('capstone-evidence').resolve()
evidence.mkdir(exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='capstone-msvc-', dir=os.environ['RUNNER_TEMP']))
manifest = json.loads((source / 'manifest.json').read_text())
crt = sys.argv[1]
assert crt in ('MD', 'MT') and platform.machine() == 'AMD64'
os.environ['CARGO_TARGET_DIR'] = str(work / 'cargo-target')
if crt == 'MT':
    os.environ['RUSTFLAGS'] = '-C target-feature=+crt-static'


def write(name, value):
    (evidence / name).write_text(json.dumps(value, indent=2) + '\n')


def run(cmd, name, cwd=None):
    with (evidence / (name + '.log')).open('w', encoding='utf-8') as log:
        subprocess.run(list(map(str, cmd)), cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True)
    return (evidence / (name + '.log')).read_text(encoding='utf-8', errors='replace').strip()


def fetch(name, repo, rev):
    target = work / name
    run(['git', 'init', target], name + '-init')
    run(['git', 'config', 'core.autocrlf', 'false'], name + '-lf', target)
    run(['git', 'fetch', '--depth=1', 'https://github.com/NeverSight/' + repo + '.git', rev],
        name + '-fetch', target)
    run(['git', 'checkout', '--detach', 'FETCH_HEAD'], name + '-checkout', target)
    assert run(['git', 'rev-parse', 'HEAD'], name + '-revision', target) == rev
    return target


def make_programs():
    base = fetch('base', 'capstone', manifest['capstone_revision'])
    fetch('iced', 'iced', manifest['iced_revision'])
    new = work / 'new'
    run(['git', 'worktree', 'add', '--detach', new, 'HEAD'], 'new-worktree', base)
    run(['git', '-c', 'core.autocrlf=false', 'apply', source / 'windows-formatter.patch'], 'new-patch', new)
    adapter = work / 'adapter'
    adapter.mkdir()
    for name in ['Cargo.lock', 'iced.rs']:
        shutil.copyfile(source / name, adapter / name)
    (adapter / 'Cargo.toml').write_text("""[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path = "../iced/src/rust/iced-x86", default-features = false, features = ["std","decoder","intel","instr_info"] }
[profile.release]
panic = "abort"
opt-level = 3
""")
    run(['cargo', 'build', '--release', '--locked', '--manifest-path', adapter / 'Cargo.toml'], 'cargo-build')
    executables = {}
    probes = {}
    for label, src in [('base', base), ('new', new)]:
        build = work / (label + '-build')
        with (src / 'CMakeLists.txt').open('a') as f:
            f.write('\n' + (source / 'msvc' / 'targets.cmake').read_text())
        run(['cmake', '-S', src, '-B', build, '-G', 'Visual Studio 17 2022', '-A', 'x64',
             '-DEVIDENCE_SOURCE=' + source.as_posix(),
             '-DICED_ADAPTER=' + (work / 'cargo-target/release/iced_compare.lib').as_posix(),
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON',
             '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=' + ('ON' if crt == 'MT' else 'OFF'),
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], label + '-config')
        def build_targets(targets, step):
            run(['cmake', '--build', build, '--config', 'Release', '--parallel', '4',
                 '--target', *targets], label + '-' + step)
        build_targets(['native_compare', 'native_snapshot', 'native_sstream'], 'build')
        programs = {n: build / 'Release' / ('native_' + n + '.exe') for n in ('compare', 'snapshot', 'sstream')}
        executables[label] = programs
        run([programs['sstream']], label + '-sstream')
        if label == 'new':
            build_targets(['native_checked'], 'build-printer-test')
            outcome = run([build / 'Release/native_checked.exe'], 'full-printer-state')
            assert 'complete printer' in outcome
        # Instrument the two owners after links above. Timed executables stay byte-identical.
        hashes = {key: digest(p.read_bytes()) for key, p in programs.items()}
        for file, func in [('SStream.c', 'stream_hooks'), ('arch/X86/X86Mapping.c', 'mapping_hooks')]:
            fmt = 'cs_default_vsnprintf' if label == 'new' else 'vsnprintf'
            with (src / file).open('a') as f:
                f.write('''
#include <stdlib.h>
#include <stdio.h>
unsigned ''' + func + '''(void){
 return (cs_mem_malloc == malloc) | ((cs_mem_calloc == calloc) << 1) |
        ((cs_mem_realloc == realloc) << 2) | ((cs_mem_free == free) << 3) |
        ((cs_vsnprintf == vsnprintf) << 4) | ((cs_vsnprintf == ''' + fmt + ''') << 5);
}
''')
        build_targets(['native_hooks'], 'instrumented-build')
        probes[label] = json.loads(run([build / 'Release/native_hooks.exe'], label + '-probe'))
        assert hashes == {key: digest(p.read_bytes()) for key, p in programs.items()}
        write(label + '-programs.json', hashes)
    write('hooks.json', dict(bit_names=['malloc', 'calloc', 'realloc', 'free', 'local_vsnprintf',
          'selected_default_vsnprintf'], probes=probes))
    assert probes['new']['stream'] & 32 and probes['new']['mapping'] & 32
    assert not probes['new']['custom'] & 32
    assert probes['new']['restored'] == probes['new']['stream']
    return executables


def get_cases():
    cases = []
    def add(name, bits, data, binary_hash=None):
        p = work / (name + '.text')
        p.write_bytes(data)
        cases.append(dict(name=name, bits=bits, path=str(p), size=len(data), sha256=digest(data),
                          binary_sha256=binary_hash))
    for row in manifest['inputs']:
        if row['kind'] != 'pe':
            continue
        p = work / (row['name'] + '.exe')
        run(['curl.exe', '-fsSL', '--retry', '3', '--max-time', '120', row['url'], '-o', p],
            'download-' + row['name'])
        binary = p.read_bytes()
        assert digest(binary) == row['package_sha256']
        data = pe_text(binary)
        assert digest(data) == row['text_sha256']
        add(row['name'], row['selector'], data, digest(binary))
    for bits, system in [(32, 'SysWOW64'), (64, 'System32')]:
        p = Path(os.environ['SystemRoot']) / system / 'kernel32.dll'
        b = p.read_bytes()
        assert struct.unpack_from('<H', b, struct.unpack_from('<I', b, 60)[0] + 4)[0] == (0x14c if bits == 32 else 0x8664)
        add('kernel32-' + str(bits), bits, pe_text(b), digest(b))
    for name, bits, flags in [('scalar32', 32, ['-fno-vectorize','-fno-slp-vectorize']),
                             ('scalar64', 64, ['-fno-vectorize','-fno-slp-vectorize']),
                             ('simd64', 64, ['-mavx2','-mfma'])]:
        obj = work / (name + '.o')
        triple = ('i686' if bits == 32 else 'x86_64') + '-unknown-linux-gnu'
        run(['clang', '-target', triple, '-O3', '-ffreestanding', *flags, '-c',
             source / ('simd.c' if name == 'simd64' else 'scalar.c'), '-o', obj], name + '-compile')
        add(name, bits, elf_text(obj.read_bytes()))
    write('cases.json', cases)
    return cases


def snapshot(programs, cases):
    results = []
    for case in cases:
        for att in (0, 1):
            for text, detail in [(0, 0), (1, 0), (1, 1), (0, 1)]:
                hashes = []
                for exe in programs.values():
                    cmd = [str(exe['snapshot']), str(case['bits']), str(att), str(text), str(detail), '0', case['path']]
                    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
                        h = hashlib.sha256()
                        while block := proc.stdout.read(256 * 1024):
                            h.update(block)
                        if proc.wait():
                            raise RuntimeError(cmd)
                    hashes.append(h.hexdigest())
                results.append([case['name'], att, text, detail, hashes])
                write('snapshot.json', results)
                assert hashes[0] == hashes[1], results[-1]


def measure(programs, cases):
    design = [('base','new','iced','new','base'), ('new','base','iced','base','new')]
    rows = []
    def sample(label, case, mode, repeats):
        exe = programs['base' if label == 'iced' else label]['compare']
        args = [str(exe), 'iced' if label == 'iced' else 'capstone', mode,
                str(case['bits']), str(repeats), case['path']]
        return json.loads(subprocess.check_output(args))
    for case in cases:
        for mode in ('scan','format','detail'):
            repeats = 1
            while True:
                probe = sample('base', case, mode, repeats)
                if probe['wall_ns'] >= 12000000:
                    break
                repeats *= 4
            repeats = max(1, math.ceil(repeats * 220000000 / probe['wall_ns']))
            pairs = []
            for cycle in range(6):
                raw = [(l, sample(l, case, mode, repeats)) for l in design[cycle % 2]]
                cs = [r for l, r in raw if l != 'iced']
                assert len({tuple(r[k] for k in ('instructions','rejected','boundary_hash','value_hash')) for r in cs}) == 1
                common = len({tuple(r[k] for k in ('instructions','rejected','boundary_hash')) for l,r in raw}) == 1
                def times(label):
                    return [r['thread_cycles'] for l,r in raw if l == label]
                a, b, i = times('base'), times('new'), times('iced')[0]
                pairs.append(dict(raw=raw, base_aa=a[0]/a[1], new_aa=b[0]/b[1],
                                  gain=statistics.mean(a)/statistics.mean(b),
                                  vs_iced=i/statistics.mean(b) if common else None))
            rows.append(dict(name=case['name'], mode=mode, repeats=repeats, pairs=pairs,
                             gain=statistics.median(p['gain'] for p in pairs),
                             vs_iced=statistics.median(p['vs_iced'] for p in pairs) if common else None))
            write('measurement.json', rows)


try:
    write('inputs.json', dict(crt=crt, platform=platform.platform(), cpu=platform.processor(),
          image=os.environ.get('ImageVersion'), capstone=manifest['capstone_revision'],
          iced=manifest['iced_revision'], patch=digest((source / 'windows-formatter.patch').read_bytes())))
    assert digest((source / 'windows-formatter.patch').read_bytes()) == 'fa4a02edfd99bda300c030295c099e2606a25cc4d9321b7fe72c935072da8cf7'
    programs = make_programs()
    cases = get_cases()
    snapshot(programs, cases)
    measure(programs, cases)
    write('completed.json', dict(success=True))
finally:
    before = sum(p.stat().st_size for p in work.rglob('*') if p.is_file())
    def writable(func, path, exc):
        os.chmod(path, 0o700)
        func(path)
    shutil.rmtree(work, onerror=writable)
    write('cleanup.json', dict(logical_bytes=before, removed=not work.exists()))
