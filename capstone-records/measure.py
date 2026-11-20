from pathlib import Path
import hashlib, itertools, json, os, platform, shutil, statistics, subprocess as sp, tempfile
import corpus
r = Path(__file__).resolve().parent
s = r.parent / 'source'
out = r.parent / 'evidence'
out.mkdir(exist_ok=True)
cc = os.environ['MEASURE_CC']
def write(name, value):
    (out / (name+'.json')).write_text(json.dumps(value, indent=2)+'\n')
def run(args, name, cwd=None):
    print(name, flush=True)
    with (out / (name+'.log')).open('w') as stream:
        rc = sp.run(list(map(str,args)), cwd=cwd, stdout=stream, stderr=sp.STDOUT).returncode
    if rc:
        raise RuntimeError(name+'\n'+(out/(name+'.log')).read_text(errors='replace')[-3000:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):
    return sp.check_output(['git','-C',s,*args],text=True).strip()
meta=json.loads((r/'lineage.json').read_text())
assert git('rev-parse','HEAD')==meta['bounds']['parent']
write('environment',dict(cc=sp.check_output([cc,'--version'],text=True),host=platform.platform(),
    cpu=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith(('model name','CPU part'))),None)))
with tempfile.TemporaryDirectory(prefix='capstone-descriptor-inline-') as temp:
    t=Path(temp); b=t/'build'
    try:
        cases=corpus.prepare(r,t,out,run)
        selections=['ppc64el-ls','arm-sort','arm-cp','riscv64-ls','riscv64-cp','putty-32-0.85','putty-64-0.85','amd64-ls','libssl3t64-i386','libjpeg62-turbo-i386','scalar32','scalar64','simd64','arm-ls','arm64-ls','mips64el-ls']
        cases=[c for c in cases if c['name'] in selections]
        assert set(c['name'] for c in cases)==set(selections)
        common=['-I',s,'-I',s/'include']
        run(['clang++','-std=c++17','-O3','-DNDEBUG',*common,'-c',r/'single.cpp','-o',t/'one.o'],'consumer')
        for a in ('arm','riscv','aarch64','ppc'):
            run(['clang++','-std=c++17','-O2',*common,r/(a+'-states.cpp'),'-ldl','-o',t/(a+'-states')],a+'-records-build')
        flags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','X86','RISCV','PPC')],
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
        libs={}; binaries={}; objects={}
        for label,patch in [('base','bounds'),('candidate','inline')]:
            path=r/(patch+'.patch'); assert sha(path)==meta[patch]['sha256']
            git('apply','--index',str(path))
            assert git('write-tree')==meta[patch]['tree']
            run(['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static'],'build-'+label)
            libs[label]=t/(label+'.so');shutil.copy2(b/'libcapstone.so',libs[label])
            exe=t/label
            run(['clang++',t/'one.o',b/'libcapstone.a','-lm','-o',exe],'link-'+label)
            binaries[label]=exe
            obj=b/'CMakeFiles/capstone.dir'
            objects[label]={str(f.relative_to(obj)):sha(f) for f in obj.rglob('*.o')}
            for target in ('MCInst.c.o','arch/ARM/ARMDisassembler.c.o','arch/RISCV/RISCVDisassembler.c.o','arch/PowerPC/PPCInstPrinter.c.o'):
                refs=sp.check_output(['nm','-u',obj/target],text=True)
                assert ('MCInstrDesc_get' in refs)==(label=='base'),(label,target)
            assert ' T MCInstrDesc_get' in sp.check_output(['nm','-g',obj/'MCInstrDesc.c.o'],text=True)
        assert objects['base'].keys()==objects['candidate'].keys()
        changed=sorted(k for k in objects['base'] if objects['base'][k]!=objects['candidate'][k])
        write('objects',dict(changed=changed,lineage=meta))
        assert {'MCInst.c.o','arch/PowerPC/PPCInstPrinter.c.o','arch/ARM/ARMDisassembler.c.o','arch/RISCV/RISCVDisassembler.c.o'}<=set(changed)<={'MCInst.c.o','arch/PowerPC/PPCInstPrinter.c.o','arch/ARM/ARMDisassembler.c.o','arch/RISCV/RISCVDisassembler.c.o','MCInstrDesc.c.o'},changed
        targets=['mcinst','mapping','arm_private_stream','arm_post_index','detail_option','text_option']
        run(['cmake','--build',b,'--target',*targets,'--parallel','4'],'build-tests')
        run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(targets)+')$','-j3'],'tests')
        run([t/'arm-states',libs['base'],libs['candidate']],'full-arm')
        for arch in ('aarch64','ppc'):run([t/(arch+'-states'),libs['base'],libs['candidate']],'full-'+arch)
        for args in [[],['custom']]:
            run([t/'riscv-states',libs['base'],libs['candidate'],t/'corpus',*args],'full-riscv'+('' if not args else '-custom'))
        shutil.copy2(binaries['base'],t/'copy');binaries['copy']=t/'copy'
        payload={k:v.read_bytes() for k,v in binaries.items()}; assert payload['base']==payload['copy']!=payload['candidate']
        size=max(map(len,payload.values())); image=t/'same'; image.write_bytes(bytes(size));image.chmod(0o755);inode=image.stat().st_ino
        padded={k:v+bytes(size-len(v)) for k,v in payload.items()}
        fixed=['setarch',platform.machine(),'-R']; sp.run([*fixed,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        write('controls',dict(images={k:sha(v) for k,v in binaries.items()},inode=inode,aslr_disabled=True,cpu=list(os.sched_getaffinity(0)),
             cycle_count=9,target_ms=32,fixed_bytes=size,consumer_sha256=sha(r/'single.cpp')))
        def sample(key,c,m,n,route):
            with image.open('r+b') as stream:assert stream.write(padded[key])==size
            assert image.stat().st_ino==inode and image.stat().st_size==size
            return json.loads(sp.check_output([*fixed,str(image),*map(str,[c['selector'],m,c['path'],n])],text=True,env=dict(os.environ,CAPSTONE_PUBLIC_ONLY=str(int(route=='public')))))
        rows=[]
        for c in cases:
            for m in (0,1,2):
                routes=['private' if m and c['selector']>=16 else 'public']
                for route in routes:
                    probe=sample('base',c,m,2,route)
                    n=max(2,min(4000,round(64e6/probe['cpu_ns'])))
                    pairs=[];reference=None
                    for i in range(9):
                        names=['base','copy','candidate']; order=names[i%3:]+names[:i%3];ticks={key:[] for key in names}
                        for key in order+order[::-1]:
                            row=sample(key,c,m,n,route)
                            if reference is None: reference=(row['first'],row['result'])
                            assert reference==(row['first'],row['result'])
                            ticks[key].append([row['cpu_ns'],row['wall_ns']])
                        pairs.append(ticks)
                    rows.append(dict(case=c['name'],route=route,mode=m,repeats=n,reference=reference,cycles=pairs))
                    write('timings',rows)
        write('complete',dict(rows=len(rows),tested_base_tree=meta['bounds']['tree'],tested_candidate_tree=meta['inline']['tree']))
    finally:
        n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
