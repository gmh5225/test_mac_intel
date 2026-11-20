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
with tempfile.TemporaryDirectory(prefix='capstone-ppc-initialization-') as temp:
    t=Path(temp); b=t/'build'
    try:
        member=next(x for x in json.loads((r/'manifest.json').read_text())['inputs'] if x['name']=='ppc64el-ls')
        package=t/'coreutils.deb';run(['curl','--fail','--silent','--show-error','--location','--retry','3','--max-time','120',member['url'],'-o',package],'fetch-coreutils')
        assert sha(package)==member['package_sha256']
        cases=[]
        for command in ('ls','cp','sort','cat'):
            elf=corpus.deb_binary(package,command);text=corpus.elf_text(elf)
            assert elf[:6]==b'\x7fELF\x02\x01' and int.from_bytes(elf[18:20],'little')==21
            dest=t/(command+'.text');dest.write_bytes(text)
            if command=='ls':assert sha(dest)==member['text_sha256']
            cases.append(dict(name='ppc64el-'+command,path=str(dest),selector=3,bytes=len(text),text_sha256=sha(dest),binary_sha256=corpus.digest(elf),package_sha256=sha(package),url=member['url']))
        write('corpus',cases)
        common=['-I',s,'-I',s/'include']
        run(['clang++','-std=c++17','-O3','-DNDEBUG',*common,'-c',r/'single.cpp','-o',t/'one.o'],'build-consumer')
        run(['clang++','-std=c++17','-O2',*common,r/'ppc-states.cpp','-ldl','-o',t/'ppc-states'],'build-ppc-records')
        flags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_PPC_SUPPORT=ON',
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
        libs={}; binaries={}; objects={}
        for label,patch in [('base','bounds'),('control','control'),('candidate','candidate')]:
            if label!='base':
                git('reset','--hard',meta['bounds']['parent'])
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
            active={q.name for q in obj.rglob('*.o')}
            assert 'PPCDisassembler.c.o' in active and 'X86DisassemblerDecoder.c.o' not in active
            assert ('-DCAPSTONE_PPC_INIT_CONSTRUCTED_OPERANDS' in (b/'build.ninja').read_text()) == (label!='base')
            targets=['mcinst','mapping','instruction_bytes','utils','sstream','feature_mode']
            run(['cmake','--build',b,'--parallel','4','--target',*targets],'build-tests-'+label)
            run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(targets)+')$'],'tests-'+label)
        write('objects',objects)
        for label in ('control','candidate'):
            assert sorted(k for k,h in objects[label].items() if objects['base'][k]!=h)==['cs.c.o']
            run([t/'ppc-states',libs['base'],libs[label]],'states-'+label)
            if platform.machine()=='x86_64':
                run(['valgrind','--tool=memcheck','--error-exitcode=87','--track-origins=yes',t/'ppc-states',libs['base'],libs[label],'256'],'memcheck-'+label)
        git('reset','--hard',meta['bounds']['parent'])
        mixed=t/'mixed';mixopts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('PPC','X86','ARM','AARCH64','MIPS','RISCV')],'-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
        run(['cmake','-S',s,'-B',mixed,*mixopts],'mixed-configure')
        mixed_objects={}
        for label in ('base','candidate'):
            if label!='base':git('apply','--index',str(r/'candidate.patch'))
            run(['cmake','--build',mixed,'--parallel','4','--target','capstone_static'],'mixed-'+label)
            assert '-DCAPSTONE_PPC_INIT_CONSTRUCTED_OPERANDS' not in (mixed/'build.ninja').read_text()
            object_root=mixed/'CMakeFiles/capstone.dir'
            mixed_objects[label]={str(q.relative_to(object_root)):sha(q) for q in object_root.rglob('*.o')}
            assert len(mixed_objects[label])>45
        assert mixed_objects['base']==mixed_objects['candidate']
        write('mixed-isolation',dict(identical=True,objects=mixed_objects))
        git('reset','--hard',meta['bounds']['parent'])
        shutil.copy2(binaries['base'],t/'copy');binaries['copy']=t/'copy'
        payload={k:v.read_bytes() for k,v in binaries.items()}; assert payload['base']==payload['copy']!=payload['candidate']
        size=max(map(len,payload.values())); image=t/'same'; image.write_bytes(bytes(size));image.chmod(0o755);inode=image.stat().st_ino
        padded={k:v+bytes(size-len(v)) for k,v in payload.items()}
        fixed=['setarch',platform.machine(),'-R']; sp.run([*fixed,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        write('controls',dict(images={k:sha(v) for k,v in binaries.items()},inode=inode,aslr_disabled=True,cpu=list(os.sched_getaffinity(0)),
             cycle_count=12,target_ms=32,fixed_bytes=size,consumer_sha256=sha(r/'single.cpp')))
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
                    for i in range(12):
                        names=['base','copy','control','candidate']; order=names[i%4:]+names[:i%4];ticks={key:[] for key in names}
                        for key in order+order[::-1]:
                            row=sample(key,c,m,n,route)
                            if reference is None: reference=(row['first'],row['result'])
                            assert reference==(row['first'],row['result'])
                            ticks[key].append([row['cpu_ns'],row['wall_ns']])
                        pairs.append(ticks)
                    rows.append(dict(case=c['name'],route=route,mode=m,repeats=n,reference=reference,cycles=pairs))
                    write('timings',rows)
        write('complete',dict(rows=len(rows),tested_base_tree=meta['bounds']['tree'],tested_candidate_tree=meta['candidate']['tree']))
    finally:
        n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
