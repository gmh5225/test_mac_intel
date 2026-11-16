from pathlib import Path
import gzip
import hashlib
import json
import os
import shutil
import struct
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
s, e = r.parent / 'source', r.parent / 'evidence'
e.mkdir()
meta = json.loads((r / 'candidate.json').read_text())

def save(name, value):
    (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

def run(label, args):
    with (e / (label + '.log')).open('wb') as log:
        sp.run(list(map(str, args)), cwd=s, stdout=log, stderr=sp.STDOUT, check=True)

def allocated(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    phoff, shoff, phsize, phnum, shsize, shnum, names = header[5], header[6], header[9], header[10], header[11], header[12], header[13]
    assert phsize == 56 and shsize == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize) for i in range(shnum)]
    st = sections[names]
    strings = data[st[4]:st[4]+st[5]]
    result = {}
    for sec in sections:
        if not sec[2] & 2:
            continue
        name = strings[sec[0]:strings.index(b'\0', sec[0])].decode()
        payload = data[sec[4]:sec[4]+sec[5]] if sec[1] != 8 else b''
        result[name] = dict(type=sec[1], flags=sec[2], address=sec[3], offset=sec[4],
                            size=sec[5], alignment=sec[8], sha256=hashlib.sha256(payload).hexdigest())
    return dict(sections=result, program_headers=[list(struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize)) for i in range(phnum)])

w = Path(tempfile.mkdtemp(prefix='capstone-linkage-audit-'))
try:
    assert sp.check_output(['git', 'rev-parse', 'HEAD'], cwd=s, text=True).strip() == meta['parent']
    assert hashlib.sha256((r / 'scan.patch').read_bytes()).hexdigest() == meta['sha256']
    run('apply-parent', ['git', 'apply', '--index', r / 'scan.patch'])
    assert sp.check_output(['git', 'write-tree'], cwd=s, text=True).strip() == meta['tree']
    cc = os.environ['MEASURE_CC']
    save('inputs', dict(parent_candidate=meta, compiler=sp.check_output([cc, '--version'], text=True)))
    b = w / 'build'
    run('configure', ['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                      '-DCMAKE_C_COMPILER=' + cc,
                      '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer ' +
                      ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
                      '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                      *['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ['X86','ARM','AARCH64','MIPS']],
                      '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
                      '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'])
    run('consumer', ['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s/'include',
                     '-c', r/'single.cpp', '-o', w/'consumer.o'])
    code = s / 'arch/X86/X86DisassemblerDecoder.c'
    before = code.read_text()
    objects, binaries = {}, {}
    for label in ['base', 'external']:
        if label == 'external':
            old = 'static CS_PRESERVE_MOST bool\ndecodeScanResultGeneric('
            assert before.count(old) == 1 and before.count('decodeScanResultGeneric') == 2
            changed = before.replace(old, 'CAPSTONE_INTERNAL CS_PRESERVE_MOST bool\ndecodeScanResultGeneric(')
            changed = changed.replace('decodeScanResultGeneric', 'X86_decodeScanResultGeneric')
            assert changed.replace('X86_decodeScanResultGeneric', 'decodeScanResultGeneric').replace(
                'CAPSTONE_INTERNAL CS_PRESERVE_MOST bool\ndecodeScanResultGeneric(', old) == before
            code.write_text(changed)
            header = s / 'arch/X86/X86FeatureExtension.h'
            text = header.read_text()
            marker = 'bool X86_printFeatureExtension('
            assert text.count(marker) == 1
            decl = ('struct X86ScanResult;\nCAPSTONE_INTERNAL CS_PRESERVE_MOST bool\n'
                    'X86_decodeScanResultGeneric(csh ud, const uint8_t *code, size_t code_len,\n'
                    '    cs_insn *insn, struct X86ScanResult *result, uint8_t opcode, bool tryExtension);\n\n')
            header.write_text(text.replace(marker, decl + marker))
            run('diff-check', ['git', 'diff', '--check'])
            (e / 'linkage.patch').write_bytes(sp.check_output(['git', 'diff'], cwd=s))
        run('build-' + label, ['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'])
        obj = b / 'CMakeFiles/capstone.dir/arch/X86/X86DisassemblerDecoder.c.o'
        (e / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', obj]))
        with gzip.open(e / (label + '-assembly.gz'), 'wb') as out:
            out.write(sp.check_output(['objdump', '-dr', obj]))
        objroot = b / 'CMakeFiles/capstone.dir'
        objects[label] = {str(f.relative_to(objroot)): hashlib.sha256(f.read_bytes()).hexdigest() for f in objroot.rglob('*.o')}
        exe = w / label
        run('link-' + label, ['clang++', w/'consumer.o', b/'libcapstone.a', '-lm', '-o', exe])
        binaries[label] = allocated(exe)
    changed_objects = [n for n in objects['base'] if objects['base'][n] != objects['external'][n]]
    assert changed_objects == ['arch/X86/X86DisassemblerDecoder.c.o'], changed_objects
    diffs = {n: dict(before=binaries['base']['sections'].get(n), after=binaries['external']['sections'].get(n))
             for n in binaries['base']['sections'].keys() | binaries['external']['sections'].keys()
             if binaries['base']['sections'].get(n) != binaries['external']['sections'].get(n)}
    save('linked-review', dict(allocated_differences=diffs, program_headers_equal=binaries['base']['program_headers']==binaries['external']['program_headers']))
    save('complete', dict(success=True, implementation_tokens_identical=True, changed_objects=changed_objects,
                         parent_candidate=meta, qualification=False, purpose='Linkage feasibility only'))
finally:
    size = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(removed=not w.exists(), bytes=size))
