from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from fixtures import fixtures,sha
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());m=rd(r/'experiment.json');q=rd(r/'source.json');win=os.name=='nt'
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def get(*args,**kw):return sp.check_output(args,text=True,**kw).strip()
def run(*args,**kw):sp.run(args,check=True,**kw)
if os.environ.get('SCAN_PROFILE')=='gcc':os.environ.update(CC='gcc',CXX='g++')
if os.environ.get('SCAN_PROFILE')=='clang':os.environ.update(CC='clang',CXX='clang++')
w=Path(tempfile.mkdtemp())
try:
    git=lambda *args:get('git','-C',src,*args)
    assert git('rev-parse','HEAD')==q['base']['commit']
    patch=sp.check_output(['git','-C',p,'cat-file','blob','HEAD:portable-next/candidate.patch']);assert sha(patch)==q['candidate']['sha256']
    patchfile=w/'update.patch';patchfile.write_bytes(patch)
    project=w/'project';project.mkdir();build=w/'build'
    for name in ('CMakeLists.txt','probe.cpp'):shutil.copyfile(r/name,project/name)
    suffix='.exe' if win else '';ident={};exes={}
    for stage in ('base','candidate'):
        if stage=='candidate':run('git','-C',src,'apply','--index',patchfile)
        assert git('write-tree')==q[stage]['tree']
        run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_SOURCE='+str(src),
            '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF',
            '-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON')
        run('cmake','--build',build,'--parallel','4','--target','probe_static','probe_shared')
        dest=w/stage;dest.mkdir()
        for kind in ('static','shared'):
            name='probe_'+kind+suffix;exe,=build.rglob(name)
            target=dest/name;shutil.copy2(exe,target);exes[stage,kind]=target
        libs=[f for f in (build/'capstone').rglob('*') if f.is_file() and (f.name.endswith('.dylib') or f.name.startswith('libcapstone.so') or f.suffix.lower()=='.dll')]
        assert libs
        for f in libs:shutil.copy2(f,dest/f.name)
        ident[stage]={f.name:sha(f.read_bytes()) for f in dest.iterdir()}
        save('images',ident)
    shutil.copytree(w/'base',w/'copy')
    ident['copy']={f.name:sha(f.read_bytes()) for f in (w/'copy').iterdir()}
    assert ident['base']==ident['copy'] and ident['base']!=ident['candidate']
    paths={}
    for stage in ('base','copy','candidate'):
        for kind in ('static','shared'):
            exe=w/stage/('probe_'+kind+suffix);exes[stage,kind]=exe
            actual=Path(get(exe,'--library')).resolve()
            assert actual.parent==(w/stage).resolve(),(actual,exe)
            assert (actual==exe.resolve())==(kind=='static'),(actual,exe)
            paths[stage+'/'+kind]=actual.name
    save('images',dict(digests=ident,loaded=paths))
    samples=list(fixtures(r,w,m));assert len(samples)==6
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    rows={};checks={}
    for name,bits,file,spans in samples:
        for syntax,mode in [('intel',0),('intel',1),('intel',2),('att',1),('att',2)]:
            key=f'{syntax}/{name}/{mode}'
            for kind in ('static','shared'):
                def read(stage,reps):
                    args=[exes[stage,kind],'public-att' if syntax=='att' else 'capstone',str(mode),str(reps),file,spans,str(bits)]
                    return list(map(int,get(*args).split()))
                once=read('base',1);assert len(once)==6 and once[2]>0
                if kind=='static':checks[key]=once[2:]
                assert once[2:]==checks[key] and all(read(k,1)[2:]==checks[key] for k in ('copy','candidate'))
                reps=max(1,math.ceil(18e6/once[1]));expected=read('base',reps)[2:]
                rng=random.Random('public-record/'+key+kind);labels=['base','copy','candidate'];blocks=[]
                for _ in range(13):
                    rng.shuffle(labels);block={k:[] for k in labels}
                    for k in labels+labels[::-1]:
                        v=read(k,reps);assert v[2:]==expected;block[k].append(v[:2])
                    blocks.append({k:[sum(z[i] for z in vals)for i in (0,1)] for k,vals in block.items()})
                rows[kind+'/'+key]=dict(checks=checks[key],reps=reps,cycles=blocks)
                save('timings',rows)
    assert len(rows)==60
    save('complete',dict(complete=True,source=q,os=platform.platform(),machine=platform.machine(),profile=os.environ.get('SCAN_PROFILE',''),workloads=len(rows),checks=checks,loaded=paths))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
