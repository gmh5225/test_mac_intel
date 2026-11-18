from pathlib import Path
import hashlib
import json
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
out = r.parent / 'evidence'
out.mkdir()
meta = json.loads((r / 'candidate.json').read_text())
w = Path(tempfile.mkdtemp(prefix='capstone-output-fallback-census-'))
s, b = w / 'source', w / 'build'
def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
def run(name, args):
    with (out / (name + '.log')).open('wb') as log:
        sp.run(list(map(str, args)), cwd=s, stdout=log, stderr=sp.STDOUT, check=True)
def git(*args):
    return sp.check_output(['git', '-C', s, *args], text=True).strip()
try:
    sp.run(['git', 'clone', '-q', '--shared', '--no-checkout', r.parent / 'source', s], check=True)
    git('checkout', '-q', '--detach', meta['parent'])
    run('configure', ['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_C_COMPILER=clang', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
        *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
        '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_MACOS_THIN=ON',
        '-DCAPSTONE_BUILD_CSTEST=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'])
    shim = (r / 'owned-shim.txt').read_text()
    for label in ('base', 'candidate'):
        if label == 'candidate':
            assert hashlib.sha256((r / 'candidate.patch').read_bytes()).hexdigest() == meta['sha256']
            git('apply', '--index', str(r / 'candidate.patch'))
            assert git('write-tree') == meta['tree']
        iterator = s / 'arch/X86/X86OutputIterator.c'
        original = iterator.read_text()
        iterator.write_text(original + shim)
        run('build-' + label, ['cmake', '--build', b, '--target', 'capstone_shared', '--parallel', '4'])
        shutil.copyfile(b / 'libcapstone.so', w / (label + '.so'))
        iterator.write_text(original)
        assert not git('diff')
    run('census-build', ['clang++', '-O2', '-std=c++17', '-I', s / 'include', r / 'census.cpp', '-ldl', '-o', w / 'census'])
    import frozen_deb
    rows = []
    for name, bits, binary, spans, provenance in frozen_deb.prepare(w):
        intervals = w / (name + '.tsv')
        intervals.write_text(''.join('%d %d %d\n' % tuple(x) for x in spans))
        run(name, [w / 'census', w / 'base.so', w / 'candidate.so', binary, intervals, bits])
        lines = (out / (name + '.log')).read_text().splitlines()
        summary = lines[0].split('\t')
        assert summary[0] == 'summary' and len(summary) == 4
        counts = []
        for line in lines[1:]:
            tag, admission, prefix, operand, mnemonic, count, example = line.split('\t')
            assert tag == 'row'
            counts.append(dict(admission=admission, prefix=prefix, operand=operand, mnemonic=mnemonic,
                count=int(count), example=example))
        counts.sort(key=lambda x: -x['count'])
        rows.append(dict(case=name, bits=bits, provenance=provenance, complete_functions=int(summary[1]),
            excluded_partial_functions=int(summary[2]), complete_record_comparisons=int(summary[3]), counts=counts))
        save('census', rows)
    assert len(rows) == 5
    save('complete', dict(success=True, source=meta, cases=len(rows),
        comparisons=sum(x['complete_record_comparisons'] for x in rows),
        scope='Instruction admission census on frozen real-library function extents. Baseline and candidate complete records/cursors/errors match before classifying existing hits, new hits and residual full-decoder fallback. Only wholly decoded functions contribute to counts. Diagnostic counts are not throughput measurements.'))
finally:
    size = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=size, removed=not w.exists()))
