from pathlib import Path
import hashlib,json,os,platform,random,shutil,statistics,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;src=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
data=json.loads((r/'diagnostic.json').read_text());provenance=json.loads((r/'provenance.json').read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(cmd,n):
    with(out/(n+'.log')).open('w')as f:z=sp.run(cmd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-1600:]);z.check_returncode()
def git(*a):return sp.check_output(['git','-C',src,*a],text=True).strip()
assert git('rev-parse','HEAD')==data['parent'] and sha(r/'observer.patch')==data['patch_sha256']
run(['git','-C',src,'apply','--index',r/'observer.patch'],'install-observer');assert git('write-tree')==data['tree']
t=Path(tempfile.mkdtemp());b=t/'build';exe=t/'bench'
try:
    opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ('X86','ARM','AARCH64','MIPS')]]
    run(['cmake','-S',src,'-B',b,*opts],'configure');run(['cmake','--build',b,'--parallel','4','--target','capstone_static'],'build')
    run(['clang++','-std=c++17','-O3','-DNDEBUG','-I',src,'-I',src/'include',r/'bench.cpp',b/'libcapstone.a','-o',exe],'compile')
    run(['clang++','-std=c++17','-O2','-I',src/'include',r/'vectors.cpp',b/'libcapstone.a','-o',t/'vectors'],'vectors')
    bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True);os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    count,checked=map(int,sp.check_output([*bind,exe,'verify'],text=True).split());assert checked==6*(count+3)
    image=sha(exe)
    save('image',dict(sha256=image,source_tree=data['tree'],cpu=Path('/proc/cpuinfo').read_text().split('model name')[1].splitlines()[0].strip(),private_ids=count,lookup_observations=checked,compiler=sp.check_output(['clang','--version'],text=True).splitlines()[0]))
    # Keep the original package exporters, but limit reconstruction to this experiment's panels.
    import sys
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py'):shutil.copyfile(r/f,t/f)
    inputs=json.loads((r/'inputs.json').read_text());(t/'inputs.json').write_text(json.dumps({k:v for k,v in inputs.items()if k in ('jpeg-avx2-i386','libssl3t64-i386')}))
    pe=json.loads((r/'pe-images.json').read_text());(t/'pe-images.json').write_text(json.dumps([v for v in pe if v['bits']==32]))
    sys.path.insert(0,str(t));import frozen_deb,pe_panels,itertools
    stats=[];queries=[];samples={}
    for case,bits,file,spans,doc in itertools.chain(frozen_deb.prepare(t),pe_panels.prepare(t)):
        q=provenance[case];assert sha(file)==q['text_sha256'] and not q['excluded_incompatible_extents']
        intervals=t/(case+'.tsv');fmt=lambda ss:''.join('%d %d %d\n'%tuple(a)for a in ss)
        intervals.write_text(fmt(spans))
        if q['selection']=='simd-functions':
            vec=[tuple(map(int,v.split()))for v in sp.check_output([t/'vectors',str(bits),file,intervals],text=True).splitlines()]
            assert len(vec)==len(spans);spans=[a for a,(count,nvec)in zip(spans,vec)if nvec>=8 and nvec>=.15*count]
        intervals.write_text(fmt(spans));assert len(spans)==q['timed_functions'] and sha(intervals)==q['extent_sha256']
        samples[case]=dict(text_sha256=sha(file),extent_sha256=sha(intervals),functions=len(spans))
        for route in (0,1):
            for detail in (0,1):
                def measure(k,n):
                    return list(map(int,sp.check_output([*bind,exe,str(k),str(route),str(detail),file,intervals,str(bits),str(n)],text=True).split()))
                observations=[measure(k,1)for k in (3,4)]
                assert observations[0][2:]==observations[1][2:] and ((observations[0][4]>0)==bool(detail))
                queries.append(dict(case=case,route=route,detail=detail,calls=observations[0][4],insns=observations[0][2]))
                initial=measure(0,1);n=max(1,round(90e6/initial[0]));assert initial[2:4]==observations[0][2:4] and not initial[4]
                cycles=[]
                for i in range(13):
                    order=[0,1,2];order=order[i%3:]+order[:i%3];cycle={str(k):[]for k in order}
                    for k in order+order[::-1]:
                        row=measure(k,n);assert row[2:]==initial[2:];cycle[str(k)].append(row[:2])
                    cycles.append(cycle)
                stats.append(dict(case=case,route=route,detail=detail,reps=n,cycles=cycles,signature=initial[2:4]))
                save('measurements',stats);save('queries',queries)
    assert len(stats)==12 and sha(exe)==image;save('complete',dict(samples=samples,rows=len(stats),sha256=image,protocol='Same executable, same code and data addresses, single CPU, fixed ASLR, alternate stock pointer/copy/descriptor pointer at runtime only.'))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
