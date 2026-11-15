"""Inspect ELF placement before spending a source LLVM build on layout control."""
from pathlib import Path
import gzip
import hashlib
import json
import shutil
import subprocess as sp
import tempfile

from elftools.elf.elffile import ELFFile
import arm_layout

r = Path(__file__).resolve().parent
s = r.parent/'source'
out = r.parent/'evidence'
out.mkdir()


def save(name, value):
    (out/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n')


def run(args, label):
    with (out/(label+'.log')).open('wb') as log:
        sp.run(list(map(str, args)), stdout=log, stderr=sp.STDOUT, check=True)


def shape(path):
    with path.open('rb') as f:
        elf = ELFFile(f)
        return dict(sections={section.name: dict(address=section['sh_addr'], size=section['sh_size'],
                                               alignment=section['sh_addralign'], flags=section['sh_flags'])
                              for section in elf.iter_sections() if section['sh_flags'] & 2},
                    segments=[dict(segment.header) for segment in elf.iter_segments()])


reference = '729680277dd762704ea3270291b7a75318f51583'
assert sp.check_output(['git', '-C', s, 'rev-parse', 'HEAD'], text=True).strip() == reference
save('compiler', dict(gcc=sp.check_output(['gcc', '--version'], text=True),
                     clang=sp.check_output(['clang++', '--version'], text=True)))
w = Path(tempfile.mkdtemp(prefix='capstone-arm-layout-preflight-'))
try:
    b = w/'build'
    main = w/'main.c'
    main.write_text('#include <capstone/capstone.h>\n#include <stdio.h>\n'
                    'int main(void) { csh h; cs_insn *i; unsigned char bytes[]={0,0,0xa0,0xe3};\n'
                    'if(cs_open(CS_ARCH_ARM,CS_MODE_ARM,&h)) return 1;\n'
                    'if(cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 2;\n'
                    'size_t n=cs_disasm(h,bytes,4,0x1000,0,&i); if(n!=1) return 3;\n'
                    'printf("%u %u %s %s\\n",i->id,i->size,i->mnemonic,i->op_str);\n'
                    'cs_free(i,n); return cs_close(&h); }\n')
    run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=gcc', '-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers',
         '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86', 'ARM', 'AARCH64', 'MIPS']],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    shapes, binaries, slot_size, signature = {}, {}, None, None
    for label in ['base', 'candidate']:
        if label == 'candidate':
            run(['git', '-C', s, 'apply', r/'candidate.patch'], 'apply')
        run(['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'], 'build-'+label)
        archive = b/'libcapstone.a'
        obj = b/'CMakeFiles/capstone.dir/arch/ARM/ARMMapping.c.o'
        with gzip.open(out/(label+'-ARMMapping.o.gz'), 'wb') as f:
            f.write(obj.read_bytes())
        save(label+'-input-shape', shape(obj))
        run(['gcc', '-O3', '-I'+str(s/'include'), '-c', main, '-o', w/'main.o'], 'main-'+label)
        normal = w/('normal-'+label)
        run(['clang++', w/'main.o', archive, '-lm', '-o', normal], 'link-'+label)
        value = sp.check_output([normal], text=True)
        if signature is None: signature = value
        assert value == signature
        renamed, script, info = arm_layout.reserve(obj, w/('slot-'+label), slot_size)
        slot_size = info['slot_size']
        save(label+'-slot', info)
        original = archive.read_bytes()
        try:
            run(['ar', 'r', archive, renamed], 'archive-'+label)
            binary = w/('diagnostic-'+label)
            run(['clang++', w/'main.o', archive, '-lm', '-Wl,-T,'+str(script), '-o', binary], 'slot-link-'+label)
            assert sp.check_output([binary], text=True) == signature
            shapes[label] = shape(binary)
            save(label+'-linked-shape', shapes[label])
            binaries[label] = binary
        finally:
            archive.write_bytes(original)
    differences = {name: [shapes['base']['sections'].get(name), shapes['candidate']['sections'].get(name)]
                   for name in set(shapes['base']['sections']) | set(shapes['candidate']['sections'])
                   if shapes['base']['sections'].get(name) != shapes['candidate']['sections'].get(name)}
    save('placement-differences', differences)
    try:
        result = arm_layout.compare(binaries)
    except AssertionError as exc:
        result = dict(controlled=False, reason=str(exc))
    else:
        result['controlled'] = True
    save('complete', dict(diagnostic_only=True, result=result, signature=signature,
                          differing_sections=len(differences)))
finally:
    size = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(removed=not w.exists(), bytes=size))
