import re
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
with tempfile.TemporaryDirectory(prefix='capstone-public-iter-') as temp:
    t=Path(temp); b=t/'build'
    try:
        cases=corpus.prepare(r,t,out,run)
        selections=['putty-32-0.85','putty-64-0.85','amd64-ls','libssl3t64-i386','libjpeg62-turbo-i386','scalar32','scalar64','simd64','arm-ls','arm64-ls','mips64el-ls','libzstd1-amd64','libssl3t64-amd64','libzstd1-i386']
        cases=[c for c in cases if c['name'] in selections]
        assert set(c['name'] for c in cases)==set(selections)
        common=['-I',s,'-I',s/'include']
        run(['clang++','-std=c++17','-O3','-DNDEBUG',*common,'-c',r/'single.cpp','-o',t/'one.o'],'consumer')
        run(['clang++','-std=c++17','-O2',*common,r/'public-records.cpp','-ldl','-o',t/'states'],'public-records-build')
        flags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','X86')],
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
        libs={}; binaries={}; objects={}
        for label,patch in [('base','bounds'),('candidate','iterator')]:
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
        assert objects['base'].keys()==objects['candidate'].keys()
        changed=sorted(k for k in objects['base'] if objects['base'][k]!=objects['candidate'][k])
        write('objects',dict(changed=changed,lineage=meta))
        assert set(changed)=={'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o'},changed
        targets=['mcinst','x86_simple_output','x86_printer_prechecked','text_option','detail_option','x86_x87_environment_hardware']
        run(['cmake','--build',b,'--target',*targets,'--parallel','4'],'build-tests')
        run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(targets)+')$','-j3'],'tests')
        run(['clang++','-std=c++17','-O2','-I',s/'include',s/'suite/synctools/x86_simple_output.cpp',b/'libcapstone.a','-o',t/'generator'],'generator-build')
        with (out/'generate.log').open('w') as log:
            regenerated=sp.check_output([t/'generator'],stderr=log)
        assert regenerated==(s/'arch/X86/X86GenSimpleOutput.inc').read_bytes()
        if platform.machine()=='x86_64':
            metrics=[]
            for c in [c for c in cases if c['name'] in ('libzstd1-amd64','libssl3t64-i386')]:
                for label,exe in binaries.items():
                    trace=t/'callgrind'
                    run(['env','CAPSTONE_PUBLIC_ONLY=0','valgrind','--tool=callgrind','--callgrind-out-file='+str(trace),exe,c['selector'],2,c['path'],1],'cost-'+c['name']+'-'+label)
                    names={};calls={};callee=None
                    for line in trace.read_text().splitlines():
                        if line.startswith(('fn=','cfn=')):
                            tag,atom=line.split('=',1)
                            hit=re.fullmatch(r'\\((\\d+)\\)(?: (.*))?',atom)
                            if hit:
                                idx,name=hit.groups()
                                if name is not None:names[idx]=name
                                atom=names[idx]
                            if tag=='cfn':callee=atom
                        elif line.startswith('calls=') and callee and callee.startswith(('cs_decode_full_insn','X86_trySimpleOutput','X86_writeByteExtensionOutput','X86_getInstruction','X86_Intel_printInst')):
                            calls[callee]=calls.get(callee,0)+int(line[6:].split()[0])
                        elif line.startswith('summary:'):
                            calls['guest_instructions']=int(line.split()[1])
                    assert calls['guest_instructions'] and (any(k.startswith('X86_writeByteExtensionOutput') for k in calls) == (label=='candidate'))
                    metrics.append(dict(case=c['name'],label=label,calls=calls));trace.unlink()
            write('byte-extension-costs',metrics)
        for c in cases:
            if c['selector']>=16:
                run([t/'states',libs['base'],libs['candidate'],c['path'],c['selector']],'records-'+c['name'])
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
                routes=['public','private'] if m and c['selector']>=16 else ['public']
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
        write('complete',dict(rows=len(rows),tested_base_tree=meta['bounds']['tree'],tested_candidate_tree=meta['iterator']['tree']))
    finally:
        n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
