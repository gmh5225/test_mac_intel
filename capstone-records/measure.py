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
            assert changed=={'arch/AArch64/AArch64Mapping.c.o', 'arch/ARM/ARMMapping.c.o', 'arch/Mips/MipsMapping.c.o', 'arch/PowerPC/PPCMapping.c.o', 'arch/RISCV/RISCVMapping.c.o', 'arch/LoongArch/LoongArchMapping.c.o', 'arch/ARC/ARCMapping.c.o'}, changed
            save('object-delta.json',dict(changed=sorted(changed),total=len(objects[label])))
        (evidence / (label+'-object-sizes.txt')).write_bytes(sp.check_output(['size', build/'libcapstone.a']))
        exe = w / label
        run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', source,
             '-I', source / 'include', r / 'single.cpp', build / 'libcapstone.a',
             '-lm', '-o', exe], 'link')
        with gzip.open(evidence / (label+'-linked-assembly.gz'), 'wb') as out:
            out.write(sp.check_output(['objdump', '-dr', exe]))
        (evidence / (label+'-symbols.txt')).write_bytes(
            sp.check_output(['nm', '-n', '-S', '--defined-only', exe]))
        for case in cases:
            for mode in range(3):
                name = case['name'] + '-' + str(mode) + '-' + engine
                args = [str(exe), str(case['selector']), str(mode), case['path'], '1']
                native = json.loads(sp.check_output(args, text=True))
                key = (case['name'], mode)
                if label == 'integer': signatures[key] = native['first']
                else: assert signatures[key] == native['first'], (key, signatures[key], native['first'])
                raw = w / (name + '.callgrind')
                run(['valgrind', '--tool=callgrind', '--cache-sim=yes',
                     '--branch-sim=yes', '--dump-instr=yes', '--collect-jumps=yes',
                     '--collect-atstart=no', '--callgrind-out-file=' + str(raw),
                     *args], 'profile-' + name)
                log = (evidence / ('profile-' + name + '.log')).read_text()
                observed = [json.loads(line) for line in log.splitlines()
                            if line.startswith('{') and '"first"' in line]
                assert len(observed) == 1
                assert observed[0]['first'] == native['first']
                assert observed[0]['result'] == native['result']
                payload = raw.read_bytes()
                with gzip.open(evidence / (name + '.callgrind.gz'), 'wb') as out:
                    out.write(payload)
                costs.append(dict(case=case['name'], mode=mode, variant=engine,
                                  instructions=native['first']['instructions'],
                                  rejected=native['first']['rejected'],
                                  signature=native['first'], captured_passes=1,
                                  raw_sha256=hashlib.sha256(payload).hexdigest()))
                save('instruction-costs.json', costs)
                raw.unlink()
    run(['git','reset','--hard',inputs['capstone']],'restore')
    assert not sp.check_output(['git', '-C', source, 'status', '--porcelain'])
    save('complete.json', dict(success=True, traces=len(costs),
                               source_unchanged=False, restored=True, native_qualification=False))
finally:
    files = [f for f in w.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    shutil.rmtree(w)
    save('cleanup.json', dict(removed=not w.exists(), bytes=size, files=len(files)))
