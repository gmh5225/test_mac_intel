from pathlib import Path
import re, hashlib, itertools, json, os, platform, shutil, statistics, subprocess as sp, tempfile
import corpus
import layout as linked
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
with tempfile.TemporaryDirectory(prefix='capstone-mips-feature-masks-') as temp:
    t=Path(temp); b=t/'build'
    try:
        cases=corpus.prepare(r,t,out,run)
        selections=['ppc64el-ls','simd64','putty-32-0.85','arm64-ls','mips64el-ls']
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
        libs={}; binaries={}; objects={}; archives={}; affected={}
        for label,patch in [('base','bounds'),('candidate','nano_branch')]:
            if label!='base':
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
            affected[label]=t/(label+'-mips.o')
            shutil.copy2(obj/'arch/Mips/MipsDisassembler.c.o',affected[label])
            archives[label]=t/(label+'-lib.a')
            shutil.copy2(b/'libcapstone.a',archives[label])
            symbols=sp.check_output(['nm','-n','-S','--defined-only',exe],text=True).splitlines()
            keep={'Mips_getFeatureBits','Mips_LLVM_getInstruction','RISCV_getInstruction','RISCV_LLVM_getInstruction','addSPOperands','MCInstrDesc_get','cs_decode_full_insn','cs_disasm_iter','Mips_getInstruction','Mips_get_insn_id'}
            (out/(label+'-symbols.txt')).write_text('\n'.join(line for line in symbols if line.split()[-1] in keep)+'\n')
        assert objects['base'].keys()==objects['candidate'].keys()
        changed=sorted(k for k in objects['base'] if objects['base'][k]!=objects['candidate'][k])
        write('objects',dict(changed=changed,lineage=meta))
        assert changed==['arch/Mips/MipsDisassembler.c.o'],changed
        binaries['layout'],match=linked.match_text(t,binaries['base'],binaries['candidate'],affected,archives,t/'one.o',run)
        write('size-control',match)
        write('linked-symbol-match',linked.address_match(binaries))
        target_cases=[('mips64el-ls',0,'public'),('ppc64el-ls',0,'public'),('simd64',1,'private')]
        costs=[]
        for name,mode,route in target_cases:
            c=next(v for v in cases if v['name']==name)
            for label,exe in binaries.items():
                trace=t/'trace'
                obs=sp.run(['valgrind','--tool=callgrind','--callgrind-out-file='+str(trace),str(exe),str(c['selector']),str(mode),c['path'],'1'],text=True,capture_output=True,check=True,env=dict(os.environ,CAPSTONE_PUBLIC_ONLY=str(int(route=='public'))))
                lines=trace.read_text().splitlines()
                total=int(next(x for x in lines if x.startswith('summary:')).split()[1])
                top=linked.hot(trace).most_common(90)
                write('linked-'+name+'-'+label,linked.layout(exe,dict(top)))
                costs.append(dict(case=name,mode=mode,route=route,label=label,guest_instructions=total,top=top,record=json.loads(obs.stdout)['first']))
                trace.unlink()
        write('costs',costs)
        for name,mode,route in target_cases:
            records=[v['record'] for v in costs if v['case']==name]
            assert len(records)==3 and records[0]==records[1]==records[2]
        shutil.copy2(binaries['base'],t/'copy');binaries['copy']=t/'copy'
        payload={k:v.read_bytes() for k,v in binaries.items()}; assert payload['base']==payload['copy']!=payload['candidate']
        size=max(map(len,payload.values())); image=t/'same'; image.write_bytes(bytes(size));image.chmod(0o755);inode=image.stat().st_ino
        padded={k:v+bytes(size-len(v)) for k,v in payload.items()}
        fixed=['setarch',platform.machine(),'-R']; sp.run([*fixed,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        write('controls',dict(images={k:sha(v) for k,v in binaries.items()},inode=inode,aslr_disabled=True,cpu=list(os.sched_getaffinity(0)),
             cycle_count=20,target_ms=45,fixed_bytes=size,consumer_sha256=sha(r/'single.cpp')))
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
                    n=max(2,min(4000,round(90e6/probe['cpu_ns'])))
                    pairs=[];reference=None
                    for i in range(20):
                        names=['base','copy','candidate','layout']; order=names[i%4:]+names[:i%4];ticks={key:[] for key in names}
                        for key in order+order[::-1]:
                            row=sample(key,c,m,n,route)
                            if reference is None: reference=(row['first'],row['result'])
                            assert reference==(row['first'],row['result'])
                            ticks[key].append([row['cpu_ns'],row['wall_ns']])
                        pairs.append(ticks)
                    rows.append(dict(case=c['name'],route=route,mode=m,repeats=n,reference=reference,cycles=pairs))
                    write('timings',rows)
        write('complete',dict(rows=len(rows),tested_base_tree=meta['bounds']['tree'],tested_candidate_tree=meta['nano_branch']['tree']))
    finally:
        n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
