from pathlib import Path
import hashlib,json,os,shutil,statistics as st,subprocess as sp,tempfile
import gzip
import corpus
r=Path(__file__).resolve().parent
s=r.parent/'source'
e=r.parent/'evidence'
e.mkdir()
def write(key,obj):(e/(key+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,label,cwd=None):
    print(label,flush=True)
    with (e/(label+'.log')).open('wb')as f:v=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if v.returncode:raise RuntimeError((label,(e/(label+'.log')).read_text(errors='replace')[-900:]))
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as tmp:
    t=Path(tmp);b=t/'build'
    try:
        cases=[x for x in corpus.prepare(r,t,e,run)if x['name'] in ('putty-32-0.85','putty-64-0.85','scalar64','simd64')]
        assert len(cases)==4
        assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc', '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -g1','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
        run(['clang++','-std=c++17','-O3','-DNDEBUG','-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'driver')
        bins={}
        objs={}
        for name in ('base','compact-only','separate'):
            if name!='base':run(['git','apply',r/(name+'.patch')],'select-'+name,s)
            run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+name)
            binary=t/'single'
            run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',binary],'link-'+name)
            bins[name]=t/name;binary.rename(bins[name])
            work=b/'CMakeFiles/capstone.dir'
            objs[name]={str(o.relative_to(work)):hashlib.sha256(o.read_bytes()).hexdigest() for o in work.rglob('*.o')}
            if name!='base':
                assert [k for k in objs[name] if objs[name][k]!=objs['base'][k]]==['arch/X86/X86DisassemblerDecoder.c.o']
                run(['git','apply','-R',r/(name+'.patch')],'restore-'+name,s)
            run(['objdump','-d','--disassemble=cs_disasm_iter',bins[name]],'linked-'+name)
            run(['nm','-n','-S',bins[name]],'symbols-'+name)
        write('objects',objs)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        results=[]
        checks={}
        for case in cases:
            for name,binary in bins.items():
                token=case['name']+'-'+name
                out=t/(token+'.out')
                run(['valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-jumps=yes','--callgrind-out-file='+str(out),binary,case['selector'],0,case['path'],1],'profile-'+token)
                raw=out.read_bytes()
                keys=next(x.split()[1:]for x in raw.splitlines()if x.startswith(b'events:'))
                totals=next(x.split()[1:]for x in raw.splitlines()if x.startswith(b'totals:'))
                counts={k.decode():int(v)for k,v in zip(keys,totals)}
                res=next(json.loads(x)for x in (e/('profile-'+token+'.log')).read_text().splitlines()if x.startswith('{'))
                values=res['result']
                if case['name'] in checks:assert values==checks[case['name']]
                checks[case['name']]=values
                assert counts['Ir']>values['instructions']*45
                (e/(token+'.callgrind.gz')).write_bytes(gzip.compress(raw))
                out.unlink()
                results.append(dict(case=case['name'],label=name,public=values,counters=counts))
                write('counters',results)
        write('complete',dict(rows=len(results),compiler=sp.check_output(['gcc','--version'],text=True).splitlines()[0]))
    finally:
        size=sum(v.stat().st_size for v in t.rglob('*')if v.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
