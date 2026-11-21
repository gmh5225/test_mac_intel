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
        selections=['malta-nanomips-kernel','mips64el-ls','ppc64el-ls']
        cases=[c for c in cases if c['name'] in selections]
        assert set(c['name'] for c in cases)==set(selections)
        common=['-I',s,'-I',s/'include']
        run(['clang++','-std=c++17','-O3','-DNDEBUG',*common,'-c',r/'single.cpp','-o',t/'one.o'],'consumer')
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
            alt=label+'-isolated';directory=t/alt;directory.mkdir()
            archive=directory/'libcapstone.a';shutil.copy2(b/'libcapstone.a',archive)
            member='MipsDisassembler.c.o';source=directory/member
            def members(f):
                return {n:hashlib.sha256(sp.check_output(['ar','p',f,n])).hexdigest() for n in sp.check_output(['ar','t',f],text=True).splitlines()}
            original=members(archive);source.write_bytes(sp.check_output(['ar','p',archive,member]))
            from re import findall
            sections=sp.check_output(['objdump','-h',source],text=True)
            names=[k for k in findall(r'^\s*\d+\s+(\S+)\s+[0-9a-f]+',sections,re.M) if k=='.text' or k.startswith('.text.') or k=='.rodata' or k.startswith('.rodata.')]
            assert '.text' in names and '.rodata' in names,names
            run(['objcopy',*sum((['--rename-section',name+'=.cs_mips_'+name[1:]] for name in names),[]),source],'isolate-'+label)
            run(['ar','r',archive,source],'replace-'+label);run(['ranlib',archive],'index-'+label)
            new=members(archive);assert new.keys()==original.keys() and {n for n in new if new[n]!=original[n]}=={member}
            isolated=t/(label+'-layout');run(['clang++',t/'one.o',archive,'-lm','-o',isolated],'link-'+alt);binaries[alt]=isolated
            write(label+'-member',dict(renamed=names,original=original[member],isolated=new[member],unchanged=len(new)-1,consumer=sha(t/'one.o')))
            for tag,f in [(label,exe),(alt,isolated)]:
                symbols=sp.check_output(['nm','-n','-S','--defined-only',f],text=True)
                selected={v[3]:[int(v[0],16),int(v[1],16)]for line in symbols.splitlines()if len(v:=line.split())==4 and (v[3].startswith(('PPC','Mips')) or v[3]in ('cs_decode_full_insn','cs_disasm_iter','cs_malloc','cs_free','decodeInstruction','checkDecoderPredicate'))}
                assert all(k in selected for k in ('Mips_LLVM_getInstruction','cs_disasm_iter','PPC_getInstruction')),list(selected)
                write(tag+'-symbols',selected)
                (out/(tag+'-elf.txt')).write_text(sp.check_output(['readelf','-SW',f],text=True))
        assert objects['base'].keys()==objects['candidate'].keys()
        changed=sorted(k for k in objects['base'] if objects['base'][k]!=objects['candidate'][k])
        write('objects',dict(changed=changed,lineage=meta))
        write('consumer',dict(sha256=sha(t/'one.o'),sources=meta))
        assert changed==['arch/Mips/MipsDisassembler.c.o'],changed
        if platform.machine()=='x86_64':
            cache=[]
            for name in ('ppc64el-ls','mips64el-ls'):
                c=next(x for x in cases if x['name']==name)
                for tag,exe in binaries.items():
                    trace=t/'cache.out';options=['--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(trace)]
                    command=['valgrind',*options,str(exe),str(c['selector']),'0',c['path'],'1']
                    run(command,'cache-'+name+'-'+tag)
                    dump=trace.read_text(errors='replace').splitlines()
                    events=next(v[8:].split()for v in dump if v.startswith('events: '))
                    totals=list(map(int,next(v.split()[1:]for v in dump if v.startswith('summary:'))))
                    assert len(events)==len(totals) and 'I1mr' in events and 'Bim' in events
                    cache.append(dict(case=name,variant=tag,events=dict(zip(events,totals))))
                    trace.unlink()
            write('cache',cache)
        shutil.copy2(binaries['base'],t/'copy');binaries['copy']=t/'copy'
        payload={k:v.read_bytes() for k,v in binaries.items()}; assert payload['base']==payload['copy']!=payload['candidate']
        size=max(map(len,payload.values())); image=t/'same'; image.write_bytes(bytes(size));image.chmod(0o755);inode=image.stat().st_ino
        padded={k:v+bytes(size-len(v)) for k,v in payload.items()}
        fixed=['setarch',platform.machine(),'-R']; sp.run([*fixed,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        write('controls',dict(images={k:sha(v) for k,v in binaries.items()},inode=inode,aslr_disabled=True,cpu=list(os.sched_getaffinity(0)),
             cycle_count=13,target_ms=45,fixed_bytes=size,consumer_sha256=sha(r/'single.cpp')))
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
                    for i in range(13):
                        names=['base','copy','candidate','base-isolated','candidate-isolated']; order=names[i%len(names):]+names[:i%len(names)];ticks={key:[] for key in names}
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
