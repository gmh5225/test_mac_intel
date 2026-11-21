from pathlib import Path
import re, hashlib, itertools, json, os, platform, shutil, statistics, subprocess as sp, tempfile
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
with tempfile.TemporaryDirectory(prefix='capstone-mips-feature-masks-') as temp:
    t=Path(temp); b=t/'build'
    try:
        cases=corpus.prepare(r,t,out,run)
        import kernel
        image,provenance=kernel.prepare(t)
        assert provenance==json.loads((r/'kernel.json').read_text())
        k=t/'malta-i7200.text';k.write_bytes(image);write('kernel',provenance)
        cases.append(dict(name='malta-nanomips-kernel',selector=13,path=str(k)))
        selections=['malta-nanomips-kernel','ppc64el-ls','arm-sort','arm-cp','riscv64-ls','riscv64-cp','putty-32-0.85','putty-64-0.85','amd64-ls','libssl3t64-i386','libjpeg62-turbo-i386','scalar32','scalar64','simd64','arm-ls','arm64-ls','mips64el-ls']
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
            symbols=sp.check_output(['nm','-n','-S','--defined-only',exe],text=True).splitlines()
            keep={'Mips_getFeatureBits','Mips_LLVM_getInstruction','RISCV_getInstruction','RISCV_LLVM_getInstruction','addSPOperands','MCInstrDesc_get','cs_decode_full_insn','cs_disasm_iter','Mips_getInstruction','Mips_get_insn_id'}
            (out/(label+'-symbols.txt')).write_text('\n'.join(line for line in symbols if line.split()[-1] in keep)+'\n')
        assert objects['base'].keys()==objects['candidate'].keys()
        changed=sorted(k for k in objects['base'] if objects['base'][k]!=objects['candidate'][k])
        write('objects',dict(changed=changed,lineage=meta))
        assert changed==['arch/Mips/MipsDisassembler.c.o'],changed
        run(['python3','-B',s/'suite/synctools/fixed_len_decoder.py','--check'],'check-generated-direct')
        targets=['mcinst','mapping','arm_private_stream','arm_post_index','detail_option','text_option','riscv_writeback_postprocess','mips_scan','mips_nanomips_branch']
        run(['cmake','--build',b,'--target',*targets,'--parallel','4'],'build-tests')
        run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(targets)+')$','-j3'],'tests')
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_writeback_postprocess_(newlines|generator)$'],'generator-tests')
        run([t/'arm-states',libs['base'],libs['candidate']],'full-arm')
        for arch in ('aarch64','ppc'):run([t/(arch+'-states'),libs['base'],libs['candidate']],'full-'+arch)
        for args in [[],['custom']]:
            run([t/'riscv-states',libs['base'],libs['candidate'],t/'corpus',*args],'full-riscv'+('' if not args else '-custom'))
        unit=next(f for f in b.rglob('mips_nanomips_branch') if f.is_file())
        run([unit],'compact-pool')
        diet=t/'diet'
        run(['cmake','-S',s,'-B',diet,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_DIET=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'diet-configure')
        run(['cmake','--build',diet,'--parallel','3','--target','mips_nanomips_branch'],'diet-build')
        run([next(f for f in diet.rglob('mips_nanomips_branch') if f.is_file())],'diet-compact-pool')
        run(['clang++','-O2',*common,r/'verify-mips.cpp','-ldl','-o',t/'mips-states'],'mips-build')
        run([t/'mips-states',libs['base'],libs['candidate']],'full-mips')
        if platform.machine()=='x86_64':
            costs=[]
            for name,m,route in [('mips64el-ls',m,'public') for m in (0,1,2)]:
                c=next(x for x in cases if x['name']==name)
                for key,exe in binaries.items():
                    trace=t/'calls.out';tag='trace-'+name+'-'+route+'-'+key
                    rr=sp.run(['valgrind','--tool=callgrind','--callgrind-out-file='+str(trace),str(exe),str(c['selector']),str(m),c['path'],'1'],capture_output=True,text=True,check=True,env=dict(os.environ,CAPSTONE_PUBLIC_ONLY=str(int(route=='public'))))
                    names={};callee=None;caller=None;calls={}
                    def resolved(atom):
                        match=re.fullmatch(r'\((\d+)\)(?: (.*))?',atom)
                        if not match:return atom
                        n,val=match.groups()
                        if val is not None:names[n]=val
                        return names.get(n,'('+n+')')
                    summary=None
                    for line in trace.read_text(errors='replace').splitlines():
                        if line.startswith('fn='):caller=resolved(line[3:])
                        elif line.startswith('cfn='):callee=resolved(line[4:])
                        elif line.startswith('calls=') and callee and caller:
                            if any(k in callee or k in caller for k in ('Mips_getFeatureBits','Mips_LLVM_getInstruction','addSPOperands','MCInstrDesc_get','MCInst_insert0','RISCV_getInstruction','RISCV_LLVM_getInstruction','Mips_getInstruction','cs_disasm_iter','cs_decode_full_insn')):
                                edge=caller+' -> '+callee;calls[edge]=calls.get(edge,0)+int(line[6:].split()[0])
                        elif line.startswith('summary:'):summary=int(line.split()[1])
                    assert summary is not None and calls
                    costs.append(dict(variant=key,case=name,route=route,mode=m,total_ir=summary,edges=calls,first=json.loads(rr.stdout)['first']))
                    trace.unlink()
            write('call-costs',costs)
        shutil.copy2(binaries['base'],t/'copy');binaries['copy']=t/'copy'
        payload={k:v.read_bytes() for k,v in binaries.items()}; assert payload['base']==payload['copy']!=payload['candidate']
        size=max(map(len,payload.values())); image=t/'same'; image.write_bytes(bytes(size));image.chmod(0o755);inode=image.stat().st_ino
        padded={k:v+bytes(size-len(v)) for k,v in payload.items()}
        fixed=['setarch',platform.machine(),'-R']; sp.run([*fixed,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        write('controls',dict(images={k:sha(v) for k,v in binaries.items()},inode=inode,aslr_disabled=True,cpu=list(os.sched_getaffinity(0)),
             cycle_count=13,target_ms=105,fixed_bytes=size,consumer_sha256=sha(r/'single.cpp')))
        def sample(key,c,m,n,route):
            with image.open('r+b') as stream:assert stream.write(padded[key])==size
            assert image.stat().st_ino==inode and image.stat().st_size==size
            return json.loads(sp.check_output([*fixed,str(image),*map(str,[c['selector'],m,c['path'],n])],text=True,env=dict(os.environ,CAPSTONE_PUBLIC_ONLY=str(int(route=='public')))))
        rows=[]
        for c in cases:
            if c['name'] not in ('mips64el-ls','ppc64el-ls','malta-nanomips-kernel','amd64-ls'):continue
            for m in (0,1,2):
                routes=['private' if m and c['selector']>=16 else 'public']
                for route in routes:
                    probe=sample('base',c,m,2,route)
                    n=max(2,min(4000,round(210e6/probe['cpu_ns'])))
                    pairs=[];reference=None
                    for i in range(13):
                        names=['base','copy','candidate']; order=names[i%3:]+names[:i%3];ticks={key:[] for key in names}
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
