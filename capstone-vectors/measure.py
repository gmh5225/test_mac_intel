from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
from arm_corpus import prepare
from fixed_image import FixedImage
import math,random
r=Path(__file__).resolve().parent;src=r.parent/'source';nd=r.parent/'neverd-config';e=r.parent/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a):sp.run(a,check=True)
def out(*a):return sp.check_output(a,text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
q=rd(r/'source.json');w=Path(tempfile.mkdtemp());proj=w/'project'
try:
    assert out('git','-C',src,'rev-parse','HEAD')==q['checkout'] and out('git','-C',nd,'rev-parse','HEAD')==q['neverd']
    base_patch=r/'base.patch';assert sha(base_patch)==q['base']['sha256'];run('git','-C',src,'apply','--index',base_patch)
    assert out('git','-C',src,'write-tree')==q['base']['tree']
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
    products={}
    selected=w/'selected';selected.mkdir()
    for tag in ('base','candidate'):
        if tag=='candidate':
            patch=r/'candidate.patch';assert sha(patch)==q[tag]['sha256'];run('git','-C',src,'apply','--index',patch)
        assert out('git','-C',src,'write-tree')==q[tag]['tree']
        for name,(build,stage) in stages.items():
            solo=name=='standalone'
            run('cmake','--build',build,'--parallel','4','--target','capstone_static',*(['capstone_shared'] if solo else []))
            lib,=build.rglob('libcapstone.a')
            executable=w/(name+'-'+tag)
            run('clang++','-O3','-std=c++17','-no-pie','-I',src/'include',r/'arm-timing.cpp',lib,'-o',executable)
            objects={str(o.relative_to(build)):sha(o) for o in build.rglob('*.c.o')}
            digests=dict(archive=sha(lib),driver=sha(executable),objects=objects)
            if solo:
                dyn,=build.rglob('libcapstone.so');shutil.copyfile(dyn,w/(tag+'.so'));digests['shared']=sha(dyn)
                if tag=='base':
                    elf=out('readelf','-d',dyn)
                    soname,=[x.split('[')[1].split(']')[0] for x in elf.splitlines() if '(SONAME)'in x]
                    assert soname.startswith('libcapstone.so.')
                    run('clang++','-O3','-std=c++17','-no-pie','-I',src/'include',r/'arm-timing.cpp',dyn,'-Wl,-rpath,$ORIGIN','-o',selected/'arm-shared')
            products.setdefault(name,{})[tag]=digests
    save('products',products)
    assert products['mixed']['base']==products['mixed']['candidate']
    sol=products['standalone'];assert all(sol['base'][k]!=sol['candidate'][k] for k in ('archive','driver','shared'))
    changed=[Path(k).name for k,v in sol['base']['objects'].items() if sol['candidate']['objects'][k]!=v]
    assert changed==['ARMInstPrinter.c.o'],changed
    guard=json.loads(out(w/'domain',w/'base.so',w/'candidate.so',w));assert guard==rd(r/'local-expectations.json')['domain']
    save('guard',guard)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    save('host',dict(hardware=out('lscpu'),compiler=out('clang','--version'),system=os.uname().machine))
    env=dict(os.environ,LD_LIBRARY_PATH=str(selected))
    for style in ('standalone','shared'):
        dynamic=style=='shared';exe=selected/('arm-shared' if dynamic else 'arm-static')
        image=FixedImage(selected/soname if dynamic else exe,{tag:(w/(tag+'.so' if dynamic else 'standalone-'+tag)).read_bytes() for tag in ('base','candidate')},executable=not dynamic)
        if dynamic:assert str(selected/soname) in sp.check_output(['ldd',exe],env=env,text=True)
        rows={}
        for item in corpus['fixtures'].values():
            name=item['name']
            for mode in (0,1,2):
                def take(tag,n):
                    image.select(tag);cmd=['setarch',os.uname().machine,'-R',exe,'arm',w/(name+'.text'),str(mode),str(n),w/(name+'.ranges')]
                    return list(map(int,sp.check_output(cmd,env=env,text=True).split()))
                n=max(1,math.ceil(30e6/take('base',1)[0]))
                labels=['base','copy','candidate','repeat'];expected=take('base',n)[2:]
                assert expected[0]==item['code_bytes']//4*n and expected[1]==0
                rng=random.Random(style+'/'+name+'/'+str(mode));blocks=[]
                for _ in range(35):
                    rng.shuffle(labels);paired={k:[]for k in labels}
                    for tag in labels+labels[::-1]:
                        row=take(tag,n);assert row[2:]==expected
                        paired[tag].append(row[:2])
                    blocks.append({tag:[sum(x[i] for x in pair)for i in (0,1)]for tag,pair in paired.items()})
                rows[name+'/'+str(mode)]=dict(reps=n,expected=expected,cycles=blocks);save(style+'-timings',rows)
        assert len(rows)==12;save('image-'+style,image.receipt())
    save('complete',dict(complete=True,source=q,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
