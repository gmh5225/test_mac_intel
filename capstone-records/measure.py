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
    objects={}
    plan=json.loads((r/'plan.json').read_text())
    save('plan.json',plan)
    consumer=w/'consumer.o'
    run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',source,'-I',source/'include','-c',r/'single.cpp','-o',consumer],'consumer')
    save('consumer-object.json',dict(sha256=hashlib.sha256(consumer.read_bytes()).hexdigest()))
    for offset in plan['padding_bytes']:
        if not offset:
            continue
        asm=w/f'padding-{offset}.s'
        asm.write_text('.text\n.globl capstone_layout_padding\n.hidden capstone_layout_padding\n.type capstone_layout_padding,@object\ncapstone_layout_padding:\n.space '+str(offset)+',0\n.size capstone_layout_padding,.-capstone_layout_padding\n.section .note.GNU-stack,"",@progbits\n')
        run(['clang','-c',asm,'-o',w/f'padding-{offset}.o'],'padding-'+str(offset))
    linked={}
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
            assert {'arch/PowerPC/PPCInstPrinter.c.o','arch/PowerPC/PPCMapping.c.o'} <= changed <= {'Mapping.c.o','arch/PowerPC/PPCInstPrinter.c.o','arch/PowerPC/PPCMapping.c.o'}, changed
            save('object-delta.json',dict(changed=sorted(changed),total=len(objects[label])))
        (evidence / (label+'-object-sizes.txt')).write_bytes(sp.check_output(['size', build/'libcapstone.a']))
        for offset in plan['padding_bytes']:
            exe=w/f'{offset}-{label}'
            padding=[] if not offset else [w/f'padding-{offset}.o']
            run(['clang++',consumer,*padding,build/'libcapstone.a','-lm','-o',exe],f'link-{offset}-{label}')
            header=sp.check_output(['readelf','-hW',exe],text=True)
            assert 'DYN (Position-Independent Executable file)' in header,header
            symbols=sp.check_output(['nm','-n','-S','--defined-only',exe],text=True)
            (evidence/f'{offset}-{label}-symbols.txt').write_text(symbols)
            (evidence/f'{offset}-{label}-elf.txt').write_text(header+sp.check_output(['readelf','-lWS',exe],text=True))
            if not offset:
                with gzip.open(evidence/f'{label}-linked-assembly.gz','wb') as out:
                    out.write(sp.check_output(['objdump','-dr',exe]))
            selected={}
            for line in symbols.splitlines():
                fields=line.split()
                if len(fields)==4 and fields[-1] in ('capstone_layout_padding','trace_span','cs_version','cs_disasm_iter','PPC_getInstruction','LoongArch_getInstruction','LoongArch_initMCInst','ARC_getInstruction'):
                    selected[fields[-1]]=dict(address=int(fields[0],16),size=int(fields[1],16))
            if offset:
                assert selected['capstone_layout_padding']['size']==offset
                assert selected['trace_span']==linked[f'0-{label}']['symbols']['trace_span']
                assert selected['cs_version']['address'] == linked[f'0-{label}']['symbols']['cs_version']['address'] + offset
            linked[f'{offset}-{label}']=dict(sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),symbols=selected)
    save('linked.json',linked)
    save('layout-address-counts.json', {label + '/' + key: len({linked[f'{offset}-{label}']['symbols'][key]['address'] for offset in plan['padding_bytes']}) for label in ('integer','scan') for key in ('cs_disasm_iter','PPC_getInstruction','LoongArch_getInstruction','ARC_getInstruction')})
    from native import measure
    measure(w,cases,plan,save)
    run(['git','reset','--hard',inputs['capstone']],'restore')
    assert not sp.check_output(['git', '-C', source, 'status', '--porcelain'])
    save('complete.json', dict(success=True, layouts=len(plan['padding_bytes']),
                               cases=len(plan['cases']), restored=True, native_qualification=False, scope='Predeclared text-layout sensitivity diagnostic, not product qualification'))
finally:
    files = [f for f in w.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    shutil.rmtree(w)
    save('cleanup.json', dict(removed=not w.exists(), bytes=size, files=len(files)))
