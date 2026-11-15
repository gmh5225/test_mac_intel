from pathlib import Path
import gzip
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
import corpus

r = Path(__file__).resolve().parent
source = r.parent / 'source'
evidence = r.parent / 'evidence'
evidence.mkdir()


def save(name, value):
    (evidence / name).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label):
    with (evidence / (label + '.log')).open('wb') as log:
        sp.run(list(map(str, args)), cwd=source, stdout=log,
               stderr=sp.STDOUT, check=True)


w = Path(tempfile.mkdtemp(prefix='capstone-cross-architecture-cost-'))
try:
    inputs = json.loads((r / 'inputs.json').read_text())
    assert sp.check_output(['git', '-C', source, 'rev-parse', 'HEAD'],
                           text=True).strip() == inputs['capstone']
    assert not sp.check_output(['git', '-C', source, 'status', '--porcelain'])
    cc = os.environ['MEASURE_CC']
    save('inputs.json', inputs)
    save('cpu.json', dict(cpu=Path('/proc/cpuinfo').read_text(),
                          compiler=sp.check_output([cc, '--version'], text=True)))
    build = w / 'build'
    run(['cmake', '-S', source, '-B', build, '-G', 'Ninja',
         '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + cc,
         '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer ' +
         ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else
          '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in
           ['X86', 'ARM', 'AARCH64', 'MIPS', 'PPC', 'RISCV', 'LOONGARCH', 'ARC']],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    meta=inputs['candidate']
    patch=r/'candidate.patch'
    assert hashlib.sha256(patch.read_bytes()).hexdigest()==meta['sha256']
    cases=corpus.prepare(r,w,evidence,run)
    assert len(cases)==7
    costs=[];objects={};signatures={}
    consumer = w / 'single.o'
    run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-fPIE', '-I', source,
         '-I', source / 'include', '-c', r / 'single.cpp', '-o', consumer], 'consumer')
    save('consumer-object.json', dict(sha256=hashlib.sha256(consumer.read_bytes()).hexdigest(),
                                    scope='One object linked into both ELF types and source variants.'))
    for label in ['integer','scan']:
        engine='capstone' if label=='integer' else 'scan'
        if label=='scan':
            run(['git','apply',patch],'apply')
            run(['git','add','-A'],'stage')
            tree=sp.check_output(['git','-C',source,'write-tree'],text=True).strip()
            assert tree==meta['tree'],tree
            save('candidate-tree.json',dict(tree=tree))
        run(['cmake', '--build', build, '--target', 'capstone_static',
             '--parallel', '4'], 'build')
        objroot=build/'CMakeFiles/capstone.dir'
        objects[label]={str(f.relative_to(objroot)):hashlib.sha256(f.read_bytes()).hexdigest()for f in objroot.rglob('*.o')}
        if label=='scan':
            changed={f for f in objects['integer']if objects['integer'][f]!=objects[label][f]}
            assert set(objects['integer'])==set(objects[label])
            assert changed=={'Mapping.c.o','arch/AArch64/AArch64Mapping.c.o','arch/ARM/ARMMapping.c.o','arch/Mips/MipsMapping.c.o','arch/PowerPC/PPCMapping.c.o','arch/RISCV/RISCVMapping.c.o','arch/LoongArch/LoongArchMapping.c.o','arch/ARC/ARCMapping.c.o'}, changed
            save('object-delta.json',dict(changed=sorted(changed),total=len(objects[label])))
        (evidence / (label+'-object-sizes.txt')).write_bytes(sp.check_output(['size', build/'libcapstone.a']))
        for flavor, flag in [('pie', '-pie'), ('exec', '-no-pie')]:
            exe = w / (flavor + '-' + label)
            run(['clang++', flag, consumer, build / 'libcapstone.a', '-lm', '-o', exe], 'link-' + flavor + '-' + label)
            header=sp.check_output(['readelf', '-hW', exe], text=True)
            assert ('DYN (Position-Independent Executable file)' if flavor == 'pie' else 'EXEC (Executable file)') in header, header
            (evidence / (flavor+'-'+label+'-elf.txt')).write_text(header + sp.check_output(['readelf', '-lW', exe], text=True))
            with gzip.open(evidence / (flavor+'-'+label+'-linked-assembly.gz'), 'wb') as out:
                out.write(sp.check_output(['objdump', '-dr', exe]))
            (evidence / (flavor+'-'+label+'-symbols.txt')).write_bytes(
                sp.check_output(['nm', '-n', '-S', '--defined-only', exe]))
    run(['clang', '-O2', r/'exec-launcher.c', '-o', w/'exec-launcher'], 'exec-launcher')
    from native import measure
    selected=[v for v in cases if v['selector']in (2,11)]
    assert len(selected)==2
    measure(w,selected,save)
    run(['git','reset','--hard',inputs['capstone']],'restore')
    assert not sp.check_output(['git', '-C', source, 'status', '--porcelain'])
    save('complete.json', dict(success=True, traces=len(costs),
                               source_unchanged=False, restored=True, native_qualification=False, scope='PIE versus ET_EXEC and ASLR factorial; unchanged source and consumer object'))
finally:
    files = [f for f in w.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    shutil.rmtree(w)
    save('cleanup.json', dict(removed=not w.exists(), bytes=size, files=len(files)))
