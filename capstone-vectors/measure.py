from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
from arm_corpus import prepare
from arm_time import measure
r=Path(__file__).resolve().parent;src=r.parent/'source';nd=r.parent/'neverd-config';e=r.parent/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a):sp.run(a,check=True)
def out(*a):return sp.check_output(a,text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
q=rd(r/'source.json');w=Path(tempfile.mkdtemp());proj=w/'project'
try:
    assert out('git','-C',src,'rev-parse','HEAD')==q['base']['commit'] and out('git','-C',nd,'rev-parse','HEAD')==q['neverd']
    (proj/'third_party').mkdir(parents=True);(proj/'third_party/capstone').symlink_to(src);(proj/'cmake').mkdir()
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(proj/cm).write_bytes((nd/cm).read_bytes())
    main=(nd/'CMakeLists.txt').read_text();(proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(ARMFormat LANGUAGES C CXX)\n'+main[main.index('# --- Capstone (our fork'):main.index('# --- NeverD CMake helpers')])
    stages={'mixed':(w/'mix',w/'mixed'),'standalone':(w/'one',w/'standalone')}
    corpus=prepare(w,rd(r/'arm-samples.json'));save('arm-corpus',corpus)
    for name,(build,stage) in stages.items():
        stage.mkdir()
        opts=[] if name=='mixed' else ['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
        run('cmake','-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-S',proj if name=='mixed' else src,'-B',build,*opts)
        for file in w.glob('arm-*.text'): (stage/file.name).symlink_to(file)
        for file in w.glob('arm-*.ranges'): (stage/file.name).symlink_to(file)
    run('clang++','-O2','-std=c++17','-I',src/'include',r/'domain.cpp','-ldl','-o',w/'domain')
    products={};guards={}
    for v in ('base','candidate','outlined'):
        run('git','-C',src,'restore','--source=HEAD','--staged','--worktree','--','.')
        if v!='base':
            patch=r/(v+'.patch');assert sha(patch)==q[v]['sha256'];run('git','-C',src,'apply','--index',patch)
        assert out('git','-C',src,'write-tree')==q[v]['tree']
        for name,(build,stage) in stages.items():
            run('cmake','--build',build,'--parallel','4','--target','capstone_static',*(['capstone_shared'] if name=='standalone' else []))
            lib,=build.rglob('libcapstone.a');target=stage/('foreign-'+v)
            run('clang++','-O3','-std=c++17','-no-pie','-I',src/'include',r/'arm-timing.cpp',lib,'-o',target)
            products.setdefault(name,{})[v]=dict(archive=sha(lib),driver=sha(target),objects={str(o.relative_to(build)):sha(o)for o in build.rglob('*.c.o')})
            if name=='standalone':
                libso,=build.rglob('libcapstone.so');output=w/(v+'.so');shutil.copyfile(libso,output)
                if v!='base':
                    guard=json.loads(out(w/'domain',w/'base.so',output,w))
                    assert guard==rd(r/'local-expectations.json')['domain']
                    run('clang','-std=gnu99','-O2','-DCAPSTONE_HAS_ARM','-DCAPSTONE_USE_SYS_DYN_MEM','-DCAPSTONE_ARM_ONLY','-DTEST_PAIR=0','-I',src,'-I',src/'include',r/'stream.c',lib,'-o',w/'stream')
                    stream=list(map(int,out(w/'stream').split()))
                    assert stream==rd(r/'local-expectations.json')['stream'];guards[v]=dict(stream=stream,domain=guard)
        save('products',products)
    base_mixed=products['mixed']['base']
    for tag in ('candidate','outlined'):
        same=products['mixed'][tag]
        assert same['objects']==base_mixed['objects'] and same['driver']==base_mixed['driver'],tag
        changes=[k for k,z in products['standalone']['base']['objects'].items() if products['standalone'][tag]['objects'][k]!=z]
        assert changes and all(k.endswith('/ARMInstPrinter.c.o') for k in changes),changes
    save('guards',guards)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});save('host',dict(cpu=out('lscpu'),compiler=out('clang','--version')))
    for name,(_,stage) in stages.items():
        if name=='standalone':measure(corpus['fixtures'].values(),stage,lambda k,v:save(name+'-'+k,v))
    save('complete',dict(complete=True,source=q,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
