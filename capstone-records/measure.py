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


w = Path(tempfile.mkdtemp(prefix='capstone-vex32-archive-audit-'))
try:
    assert sp.check_output(['git', 'rev-parse', 'HEAD'], cwd=s, text=True).strip() == meta['parent']
    assert hashlib.sha256((r / 'scan.patch').read_bytes()).hexdigest() == meta['sha256']
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
    objects, binaries = {}, {}
    for label in ['published', 'isolated', 'ordered']:
        if label == 'isolated':
            run('apply-isolated', ['git', 'apply', '--index', r / 'scan.patch'])
            assert sp.check_output(['git', 'write-tree'], cwd=s, text=True).strip() == meta['tree']
        if label == 'ordered':
            for name, old, new in [
                ('CMakeLists.txt',
                 '        arch/X86/X86VectorOutput.c\n        arch/X86/X86Vex32Output.c\n',
                 '        arch/X86/X86Vex32Output.c\n        arch/X86/X86VectorOutput.c\n'),
                ('Makefile',
                 '\tLIBOBJ_X86 += $(OBJDIR)/arch/X86/X86VectorOutput.o\n\tLIBOBJ_X86 += $(OBJDIR)/arch/X86/X86Vex32Output.o\n',
                 '\tLIBOBJ_X86 += $(OBJDIR)/arch/X86/X86Vex32Output.o\n\tLIBOBJ_X86 += $(OBJDIR)/arch/X86/X86VectorOutput.o\n')]:
                file = s / name
                text = file.read_text()
                assert text.count(old) == 1, name
                file.write_text(text.replace(old, new))
            assert set(sp.check_output(['git', 'diff', '--name-only'], cwd=s, text=True).splitlines()) == {'CMakeLists.txt', 'Makefile'}
            run('diff-check', ['git', 'diff', '--check'])
            (e / 'order.patch').write_bytes(sp.check_output(['git', 'diff'], cwd=s))
            run('stage-order', ['git', 'add', '-A'])
            save('ordered-tree', dict(tree=sp.check_output(['git', 'write-tree'], cwd=s, text=True).strip()))
        run('build-' + label, ['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'])
        objroot = b / 'CMakeFiles/capstone.dir'
        objects[label] = {str(f.relative_to(objroot)): hashlib.sha256(f.read_bytes()).hexdigest() for f in objroot.rglob('*.o')}
        (e / (label + '-members.txt')).write_bytes(sp.check_output(['ar', 't', b/'libcapstone.a']))
        exe = w / label
        run('link-' + label, ['clang++', w/'consumer.o', b/'libcapstone.a', '-lm', '-o', exe])
        (e / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', exe]))
        binaries[label] = allocated(exe)
    assert objects['isolated'] == objects['ordered']
    changed = [n for n in objects['published'] if objects['published'][n] != objects['isolated'][n]]
    assert changed == ['arch/X86/X86OutputIterator.c.o'], changed
    assert set(objects['isolated']) - set(objects['published']) == {'arch/X86/X86Vex32Output.c.o'}
    save('object-digests', objects)
    save('allocated', binaries)
    save('complete', dict(success=True, implementation_objects_identical=True,
                         parent_candidate=meta, qualification=False, purpose='Archive order feasibility only'))
finally:
    size = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(removed=not w.exists(), bytes=size))
