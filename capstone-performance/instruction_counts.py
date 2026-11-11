from pathlib import Path
from tempfile import TemporaryDirectory
import gzip
import json
import math
import os
import platform
import shutil
import subprocess as sp
import sys

import corpus
from run import command, fetch, sha

SOURCE = Path(__file__).resolve().parent
EVIDENCE = SOURCE.parent / 'capstone-evidence'
MODES = ('scan', 'format', 'detail')
LIBS = ('capstone', 'iced')
RESULT_FIELDS = ('instructions', 'rejected', 'boundary_hash', 'value_hash')


def write(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + '\n')


def measure(root):
    import run
    run.WORK = root
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    for tool in ('valgrind', 'clang', 'rustc', 'cmake'):
        command([tool, '--version'], 'version-' + tool)
    command(['lscpu', '--json'], 'host')
    capstone = fetch('capstone', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    iced = fetch('iced', 'https://github.com/NeverSight/iced.git', manifest['iced_revision'])
    build = root / 'build'
    command(['cmake', '-S', capstone, '-B', build, '-G', 'Ninja',
             '-DCMAKE_C_COMPILER=clang', '-DCMAKE_BUILD_TYPE=Release',
             '-DCMAKE_C_FLAGS_RELEASE=-O3 -gline-tables-only -DNDEBUG',
             '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    command(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'], 'build')
    adapter = root / 'adapter'
    adapter.mkdir()
    shutil.copyfile(SOURCE / 'iced.rs', adapter / 'iced.rs')
    shutil.copyfile(SOURCE / 'Cargo.lock', adapter / 'Cargo.lock')
    (adapter / 'Cargo.toml').write_text('''[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path = "../iced/src/rust/iced-x86", default-features = false, features = ["std", "decoder", "intel", "instr_info"] }
[profile.release]
opt-level = 3
debug = "line-tables-only"
panic = "abort"
''')
    command(['cargo', 'build', '--locked', '--release', '--manifest-path', adapter / 'Cargo.toml'], 'build-iced')
    binary = root / 'compare'
    command(['clang++', '-O3', '-gline-tables-only', '-DNDEBUG', '-std=c++17',
             '-I', capstone / 'include', SOURCE / 'compare.cpp', build / 'libcapstone.a',
             adapter / 'target/release/libiced_compare.a', '-lpthread', '-ldl', '-lm', '-o', binary], 'consumer')
    selected = ('putty-32-0.85', 'putty-64-0.85', 'amd64-ls')
    inputs = root / 'inputs'
    inputs.mkdir()
    (inputs / 'manifest.json').write_text(json.dumps(dict(inputs=[c for c in manifest['inputs'] if c['name'] in selected])))
    for file in ('scalar.c', 'simd.c'):
        shutil.copyfile(SOURCE / file, inputs / file)
    cases = corpus.prepare(inputs, root, EVIDENCE, command)
    assert len(cases) == 6
    pe64 = next(c for c in cases if c['name'] == 'putty-64-0.85')
    data = Path(pe64['path']).read_bytes()
    sections = [list(map(int, line.split())) for line in (SOURCE / 'pe64-functions.tsv').read_text().splitlines()]
    assert len(sections) == 32 and all(off >= 0 and n > 0 and off + n <= len(data) for off, n in sections)
    target = root / 'putty64-functions.text'
    target.write_bytes(b''.join(data[off:off+n] for off, n in sections))
    cases.append(dict(name='putty64-common-functions', selector=64, path=str(target),
                      text_sha256=sha(target), offsets_and_sizes=sections, original_text_sha256=pe64['text_sha256']))
    write('inputs.json', dict(consumer=sha(SOURCE / 'compare.cpp'), adapter=sha(SOURCE / 'iced.rs'), capstone=manifest['capstone_revision'],
                              iced=manifest['iced_revision'], binary_sha256=sha(binary), cases=cases))
    results = []
    for case in cases:
        for mode in MODES:
            common = []
            for library in LIBS:
                label = f"{case['name']}-{mode}-{library}"
                def args(n):
                    return [str(binary), library, mode, str(case['selector']), str(n), case['path']]
                first = json.loads(sp.check_output(args(1)))
                # The repeat count is fixed by input size and equal for both adapters.
                repeats = max(1, math.ceil(90000 / Path(case['path']).stat().st_size))
                plain = json.loads(sp.check_output(args(repeats)))
                dump = root / 'profile.out'
                proc = sp.run(['valgrind', '--tool=callgrind', '--instr-atstart=no', '--collect-atstart=no',
                               '--cache-sim=yes', '--branch-sim=yes', '--dump-line=yes', '--callgrind-out-file='+str(dump),
                               *args(repeats)], stdout=sp.PIPE, stderr=sp.PIPE, text=True)
                (EVIDENCE / (label+'.log')).write_text(proc.stderr)
                if proc.returncode:
                    print(proc.stderr[-4000:], flush=True)
                proc.check_returncode()
                seen = json.loads(proc.stdout)
                assert all(plain[k] == seen[k] for k in RESULT_FIELDS), (label, plain, seen)
                lines = dump.read_text().splitlines()
                events = next(s.split()[1:] for s in lines if s.startswith('events:'))
                totals = list(map(int,next(s.split()[1:] for s in lines if s.startswith('totals:'))))
                assert len(totals) <= len(events) and totals[events.index('Ir')] > seen['instructions'] > 0, (label, events, totals)
                totals.extend([0] * (len(events) - len(totals)))
                annotation = sp.check_output(['callgrind_annotate', '--show=Ir,Dr,Dw,Bc,Bi,Bcm,Bim', '--show-percs=no',
                                             '--threshold=99', '--auto=no', str(dump)], text=True)
                (EVIDENCE / (label+'-functions.txt')).write_text(annotation)
                with dump.open('rb') as src, gzip.open(EVIDENCE / (label+'.callgrind.gz'), 'wb', compresslevel=5) as dest:
                    shutil.copyfileobj(src, dest)
                dump.unlink()
                common.append(tuple(seen[k] for k in RESULT_FIELDS[:3]))
                results.append(dict(case=case['name'], mode=mode, library=library, first=first, output=seen,
                                    native=plain, events=dict(zip(events, totals))))
                write('counts.json', results)
                print(label, seen['instructions'], totals[events.index('Ir')], flush=True)
            agrees = common[0] == common[1]
            for row in results[-2:]:
                row['same_boundaries'] = agrees
            write('counts.json', results)
    assert len(results) == 42

if __name__ == '__main__':
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    EVIDENCE.mkdir()
    with TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as tmp:
        root = Path(tmp)
        try:
            measure(root)
        finally:
            size = sum(q.stat().st_size for q in root.rglob('*') if q.is_file())
    write('cleanup.json', dict(removed=not root.exists(), logical_bytes=size))
