from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
from layout import decoder_proof, linked_proof

r = Path(__file__).resolve().parent
s, e = r.parent / 'source', r.parent / 'evidence'
e.mkdir()
cc = os.environ['MEASURE_CC']
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
meta = json.loads((r / 'candidate.json').read_text())
base_meta = json.loads((r / 'base.json').read_text())

def write(name, data):
    (e / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')

def run(label, args, cwd=None):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as stream:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=stream, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((label, (e / (label + '.log')).read_text()[-3000:]))

git = lambda *args: sp.check_output(['git', '-C', s, *args], text=True).strip()
assert git('rev-parse', 'HEAD') == meta['parent'] == base_meta['parent']
assert sha(r / 'base.patch') == base_meta['sha256']
assert sha(r / 'candidate.patch') == meta['compound_sha256']
write('inputs', dict(base=base_meta, candidate=meta, consumer_sha256=sha(r / 'single.cpp')))
write('compiler', dict(compiler=sp.check_output([cc, '--version'], text=True)))
with tempfile.TemporaryDirectory(prefix='capstone-evex-transfer-scan-') as temporary:
    t, b = Path(temporary), Path(temporary) / 'build'
    try:
        run('configure', ['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_C_COMPILER=' + cc, '-DCMAKE_C_FLAGS=' + ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
            '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
            *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ('X86', 'ARM', 'AARCH64', 'MIPS')],
            '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
            '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'])
        run('consumer', ['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s / 'include',
                         '-c', r / 'single.cpp', '-o', t / 'single.o'])
        units = sorted(set(['api', 'x86_simple_output', 'x86_encoding_accuracy', 'x86_reg_access',
                            'detail_option', 'text_option', 'x86_buffer_bounds', 'x86_scan_batch',
                            'aarch64_scan', 'mips_scan', 'arm_post_index']) |
                       {f.stem for f in (s / 'tests/unit').glob('x86_*.c')
                        if f.stem.startswith(('x86_apx', 'x86_amx', 'x86_evex'))})
        objects = {}
        for label, source in [('base', base_meta), ('candidate', meta)]:
            patch = r / (label + '.patch')
            run('apply-' + label, ['git', 'apply', patch], s)
            git('add', '-A')
            assert git('write-tree') == source['tree']
            git('reset', '-q')
            run('build-' + label, ['cmake', '--build', b, '--target', 'capstone_static', 'capstone_shared',
                                   *units, '--parallel', '4'])
            objroot = b / 'CMakeFiles/capstone.dir'
            # CMake can leave removed-source orphans on disk; only selected
            # archive members represent the current runtime.
            members = sp.check_output(['ar', 't', b / 'libcapstone.a'], text=True).splitlines()
            assert len(members) == len(set(members))
            active = {str(f.relative_to(objroot)): f for f in objroot.rglob('*.o') if f.name in members}
            assert len(active) == len(members)
            objects[label] = {name: sha(f) for name, f in active.items()}
            write('objects', objects)
            run('link-' + label, ['clang++', t / 'single.o', b / 'libcapstone.a', '-lm', '-o', t / 'consumer'])
            (e / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', t / 'consumer']))
            (e / (label + '-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', t / 'consumer']))
            (e / (label + '-evex-assembly.log')).write_bytes(sp.check_output(['objdump', '-d', '-j', '.cs_x86_evex_scan_text', objroot / 'arch/X86/X86EvexScan.c.o']))
            if label == 'base':
                shutil.copyfile(objroot / 'arch/X86/X86EvexScan.c.o', t / 'base-decoder.o')
            else:
                changed = [n for n in objects['base'] if objects['base'][n] != objects[label].get(n)]
                added = sorted(set(objects[label]) - set(objects['base']))
                assert changed == ['arch/X86/X86EvexScan.c.o'], changed
                assert not added, added
                write('decoder-proof', decoder_proof(t / 'base-decoder.o', objroot / changed[0]))
                # Keep semantic validation even if layout qualification fails.
                try:
                    layout = linked_proof(e / 'base-symbols.txt', e / 'candidate-symbols.txt')
                except AssertionError as exc:
                    layout = dict(passed=False, error=str(exc))
                else:
                    layout['passed'] = True
                write('linked-proof', layout)
                run('units', ['ctest', '--test-dir', b, '--no-tests=error', '--output-on-failure', '-j4',
                               '-R', '^unit_(' + '|'.join(units) + ')$'])
                run('generator', ['clang++', '-O2', '-std=c++17', '-I', s / 'include',
                                   s / 'suite/synctools/x86_vector_output.cpp', b / 'libcapstone.a', '-o', t / 'generator'])
                for flag, name in [([], 'X86GenVectorOutput.inc'), (['--evex-scan'], 'X86GenEvexScan.inc')]:
                    generated = sp.check_output([t / 'generator', *flag], stderr=sp.PIPE)
                    assert generated == (s / 'arch/X86' / name).read_bytes(), name

            # This test shim is outside the production snapshot and compared
            # only after the uninstrumented runtime/layout checks above.
            iterator = s / 'arch/X86/X86OutputIterator.c'
            original = iterator.read_bytes()
            iterator.write_bytes(original + b'\nCAPSTONE_EXPORT bool CAPSTONE_API cs_test_owned_iter(csh h, const uint8_t **c, size_t *n, uint64_t *a, cs_insn *i) { return X86_disasmIter(h,c,n,a,i); }\n')
            run('owned-' + label, ['cmake', '--build', b, '--target', 'capstone_shared', '--parallel', '4'])
            shutil.copyfile(b / 'libcapstone.so', t / (label + '.so'))
            iterator.write_bytes(original)
            run('restore-' + label, ['git', 'apply', '-R', patch], s)

        for name in ('records', 'owned', 'guard'):
            run('compile-' + name, ['clang++', '-O2', '-std=c++17', '-I', s / 'include',
                                    r / (name + '.cpp'), '-ldl', '-o', t / name])
            run(name, [t / name, t / 'base.so', t / 'candidate.so'])
        assert not git('status', '--porcelain')
        write('complete', dict(source=meta, base=base_meta, semantic_checks_complete=True,
            generated_outputs_reproduced=True, unit_checks=len(units),
            records=(e / 'records.log').read_text().strip(), owned=(e / 'owned.log').read_text().strip(),
            guard=(e / 'guard.log').read_text().strip(), layout_passed=layout['passed'],
            timing_qualified=False, foundation_product_pending=True))
    finally:
        size = sum(f.lstat().st_size for f in t.rglob('*') if f.is_file())
        shutil.rmtree(t)
        write('cleanup', dict(bytes=size, removed=not t.exists()))
