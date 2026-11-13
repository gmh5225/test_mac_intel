from pathlib import Path
import hashlib,json,os,shutil,statistics as st,subprocess as sp,tempfile
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
        cases=[x for x in corpus.prepare(r,t,e,run)if x['name'] in ('putty-32-0.85','putty-64-0.85','scalar32','scalar64','simd64','amd64-ls')]
        assert len(cases)==6
        assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
        run(['clang++','-std=c++17','-O3','-DNDEBUG','-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'driver')
        bins={}
        objs={}
        for name in ('base','inline','reader','wrapper'):
            if name!='base':run(['git','apply',r/(name+'.patch')],'select-'+name,s)
            run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+name)
            binary=t/'single'
            run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',binary],'link-'+name)
            bins[name]=t/name;binary.rename(bins[name])
            work=b/'CMakeFiles/capstone.dir'
            objs[name]={str(o.relative_to(work)):hashlib.sha256(o.read_bytes()).hexdigest() for o in work.rglob('*.o')}
            if name!='base':
                assert {k for k in objs[name] if objs[name][k]!=objs['base'][k]}<={'arch/X86/X86DisassemblerDecoder.c.o'}
                run(['git','apply','-R',r/(name+'.patch')],'restore-'+name,s)
            run(['objdump','-d','--disassemble=cs_disasm_iter',bins[name]],'linked-'+name)
            run(['nm','-n','-S',bins[name]],'symbols-'+name)
        write('objects',objs)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa'])
        results=[]
        for case in cases:
            for mode in ((0,2) if case['name']=='putty-32-0.85' else (0,)):
                def measure(name,repeats):
                    return json.loads(sp.check_output(list(map(str,[bins[name],case['selector'],mode,case['path'],repeats])),text=True))
                first=measure('base',1); reps=max(1,min(16000,round(130000000/first['cpu_ns'])))
                samples=[]; oracle=None;keys=list(bins)
                for j in range(23):
                    order=keys[j%len(keys):]+keys[:j%len(keys)]; times={k:[]for k in keys}
                    for k in order+order[::-1]:
                        obs=measure(k,reps)
                        sig=(obs['first'],obs['result'])
                        if oracle is None:oracle=sig
                        assert sig==oracle,(case['name'],mode,k,oracle,sig)
                        times[k].append(obs['cpu_ns'])
                    samples.append({k:sum(times['base'])/sum(times[k]) for k in keys})
                results.append(dict(case=case['name'],mode=mode,reps=reps,median={k:st.median(a[k]for a in samples)for k in keys},samples=samples));write('timings',results)
        write('complete',dict(cases=len(results),compiler=sp.check_output(['gcc','--version'],text=True).splitlines()[0]))
    finally:
        size=sum(v.stat().st_size for v in t.rglob('*')if v.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
