from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
from corpus import deb_binary,elf_text
r=Path(__file__).resolve().parent
root=r.parent.parent
src=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
get=lambda *a:sp.check_output(a,text=True).strip()
run=lambda *a:sp.run(a,check=True)
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
q=rd(r/'stages.json');ips=rd(r/'inputs-a64.json');w=Path(tempfile.mkdtemp())
cc=os.environ['CC'];cxx=os.environ['CXX']
try:
    parent=get('git','-C',src,'rev-parse','HEAD')
    assert all(t['parent']==parent for t in q.values())
    if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    b=w/'build'
    package=w/'programs.deb';run('curl','-fsSL','--retry','3','--max-time','120',next(iter(ips.values()))['url'],'-o',package)
    for name,v in ips.items():
        assert sha(package)==v['package_sha256']
        f=w/name;f.write_bytes(elf_text(deb_binary(package,v['command'])));assert sha(f)==v['text_sha256']
    package.unlink();images={};records={};tests={}
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    link=[] if sys.platform=='darwin'else['-no-pie']
    run(cxx,'-std=c++17','-O3','-I',src/'include','-c',r/'program.cpp','-o',w/'timer.o')
    run(cxx,'-std=c++17','-O2','-I',src/'include','-c',r/'records.cpp','-o',w/'records.o')
    for k in ('base',*q):
        run('git','-C',src,'restore','--staged','--worktree','--source','HEAD','--','.')
        if k!='base':
            patch=r/(k+'.patch');assert sha(patch)==q[k]['sha256']
            run('git','-C',src,'apply','--index',patch);assert get('git','-C',src,'write-tree')==q[k]['tree']
        run('cmake','-G','Ninja','-S',src,'-B',b,*flags)
        run('cmake','--build',b,'--parallel','4','--target','capstone_static','aarch64_scan','aarch64_postprocess')
        tests[k]=get('ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_aarch64_(scan|postprocess)$');assert '100% tests passed' in tests[k]
        lib=b/'libcapstone.a';run(cxx,w/'timer.o',lib,*link,'-o',w/k);run(cxx,w/'records.o',lib,'-o',w/'verify')
        images[k]={'lib':sha(lib),'timer':sha(w/k)};records[k]={}
        for hook in (0,1):
            for name,args in [('modes',[])]+[(n+'/'+str(m),[w/n,str(v['ip']),str(m)])for n,v in ips.items()for m in range(4)]:
                f=w/'record.json';p=sp.run([w/'verify',f,str(hook),*args],capture_output=True,check=True)
                records[k][str(hook)+'/'+name]={'fields':rd(f),'diagnostic':hashlib.sha256(p.stdout+p.stderr).hexdigest()}
        assert records[k]==records['base'];save('records',records)
    assert len({v['lib']for v in images.values()})>=2
    save('build',dict(source=q,images=images,tests=tests,compiler=get(cc,'--version').splitlines()[0],machine=platform.machine()))
    shutil.rmtree(b)
    # In every pair, the byte-identical control uses the original executable.
    # Keep the same pathname on Linux. macOS verifies each signed executable in its own inode.
    exe=w/'timed';shutil.copy2(w/'base',exe);bins={k:(w/k).read_bytes() for k in images};bins['copy']=bins['base'];shutil.copy2(w/'base',w/'copy')
    current='base';rows={}
    def take(k,args,reps):
        global current
        if sys.platform=='darwin':path=w/k
        else:
            path=exe
            if k!=current:exe.write_bytes(bins[k]);current=k
        return list(map(int,get(path,*args,str(reps)).split()))
    for name,v in ips.items():
        for mode in (0,1,2):
            key=name+'/'+str(mode);args=[w/name,str(v['ip']),str(mode)]
            first=take('base',args,1);assert first[2]>0
            rounds=max(1,math.ceil(27e6/first[0]))
            pairs=[];labels=list(bins);rng=random.Random(key)
            for _ in range(19):
                rng.shuffle(labels);pair={k:[0,0]for k in labels}
                for k in labels+labels[::-1]:
                    values=take(k,args,rounds);assert values[2:]==first[2:]
                    for i in range(2):pair[k][i]+=values[i]
                pairs.append(pair)
            rows[key]=dict(reps=rounds,result=first[2:],pairs=pairs);save('panels',rows)
    save('complete',dict(complete=True,source=q,inputs=ips,panels=len(rows)))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
