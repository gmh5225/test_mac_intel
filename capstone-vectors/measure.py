"""Verify the pure-static build against both source controls before timing either consumer."""
from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,subprocess as sp,sys,tempfile
from fixed_image import FixedImage
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';ice=p/'iced-source';nd=p/'neverd-config';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_bytes())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
run=lambda *a,**kw:sp.run(a,check=True,**kw)
get=lambda *a,**kw:sp.check_output(a,text=True,**kw).strip()
def save(name,obj):
    f=e/(name+'.json');tmp=f.with_suffix('.tmp');tmp.write_text(json.dumps(obj,indent=2)+'\n');tmp.replace(f)
def objects(path,pattern):return {str(f.relative_to(path)):sha(f) for f in path.rglob(pattern)}
q=rd(r/'source.json');m=rd(r/'experiment.json');assert all(sha(r/f)==h for f,h in m['drivers'].items());tags=('base','initial','candidate')
cpu=platform.machine();assert cpu in ('x86_64','aarch64');on=cpu=='x86_64';control='initial' if on else 'base'
cc=get('clang','--version').splitlines()[0];assert 'clang version 18.' in cc and get('git','-C',src,'rev-parse','HEAD')==q['base']['commit']
assert get('git','-C',ice,'rev-parse','HEAD')==m['iced_revision'] and get('git','-C',nd,'rev-parse','HEAD')==m['neverd']
w=Path(tempfile.mkdtemp());inc=['-I',src,'-I',src/'include'];ids={};domain={};reals={};timings={}
try:
    flags=['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    profile=w/'profile';(profile/'cmake').mkdir(parents=True);(profile/'third_party').mkdir();(profile/'third_party/capstone').symlink_to(src)
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(profile/cm).write_bytes((nd/cm).read_bytes());s=(nd/'CMakeLists.txt').read_text()
    (profile/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(StaticDecode LANGUAGES C CXX)\n'+s[s.index('# --- Capstone (our fork'):s.index('# --- NeverD CMake helpers')])
    for stage in tags:
        if stage!='base':
            run('git','-C',src,'restore','--staged','--worktree','--source=HEAD','--','.')
            update=r/(stage+'.patch');assert sha(update)==q[stage]['sha256'];run('git','-C',src,'apply','--index',update)
        assert get('git','-C',src,'write-tree')==q[stage]['tree']
        identity={}
        for name,project,args in [('combined',src,flags+['-DCAPSTONE_BUILD_SHARED_LIBS=ON']),('cmake',src,flags+['-DCAPSTONE_BUILD_SHARED_LIBS=OFF']),('mixed',profile,['-DCMAKE_BUILD_TYPE=Release'])]:
            build=w/name;run('cmake','-G','Ninja','-S',project,'-B',build,*args)
            run('cmake','--build',build,'--parallel','4','--target','capstone_static',*(['capstone_shared']if name=='combined'else []))
            lib,=build.rglob('libcapstone.a');identity[name]=dict(archive=sha(lib),objects=objects(build,'*.c.o'))
            if name=='combined':
                dll=next(build.glob('libcapstone.so'));identity[name]['shared']=sha(dll)
                if stage=='base':shutil.copy2(dll.resolve(),w/'baseline.so')
            if name=='cmake':shutil.copyfile(lib,w/(stage+'-cmake.a'))
        make=w/'make'
        # Make has no generated header dependency graph. Rebuild the only affected unit.
        obj=make/'obj/arch/X86/X86VectorFallback64.o';obj.unlink(missing_ok=True)
        run('make','-C',src,'-j4','CC=clang','CAPSTONE_ARCHS=x86','CAPSTONE_STATIC=yes','CAPSTONE_SHARED=no','CAPSTONE_BUILD_CORE_ONLY=yes','BUILDDIR='+str(make))
        lib=make/'libcapstone.a';identity['make']=dict(archive=sha(lib),objects=objects(make/'obj','*.o'))
        shutil.copyfile(lib,w/(stage+'-make.a'))
        ids[stage]=identity;save('identities',ids)
        if stage=='candidate':
            assert identity['combined']==ids['base']['combined'] and identity['mixed']==ids['base']['mixed']==ids['initial']['mixed']
            for name in ('cmake','make'):
                ref=control if name=='make' else 'base'
                assert identity[name]==ids[ref][name],(name,ref)
                lhs=ids['base'][name]['objects'];rhs=ids['initial'][name]['objects']
                diff=[Path(k).name for k in lhs if lhs[k]!=rhs[k]]
                assert (len(diff)==1 and 'X86VectorFallback64.' in diff[0]) if on else not diff,(name,diff)
        if stage=='candidate':
            gen=w/'generator';run('clang++','-O2','-std=c++17',*inc,src/'suite/synctools/x86_vector_output.cpp',w/'candidate-cmake.a','-o',gen)
            tables={}
            for arg,f in [('--vex-sib-transfers','X86GenVexSibTransfers.inc'),('--vex-base-memory','X86GenVexBaseMemory.inc'),('','X86GenVectorOutput.inc')]:
                expected=src/'arch/X86'/f;assert sp.check_output([gen]+([arg]if arg else []))==expected.read_bytes()
                tables[f]=sha(expected)
            save('tables',tables)
        for name in ('cmake','make'):
            lib=w/(stage+'-'+name+'.a')
            run('clang','-shared','-fPIC',*inc,r/'trial-export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(stage+'-'+name+'.so'))
            if stage!='initial':
                for route in ('private','public'):
                    guard=w/'guard';run('clang++','-O2','-std=c++17',*inc,*(['-DUSE_PUBLIC'] if route=='public' else []),r/'sib.cpp',lib,'-o',guard)
                    row=list(map(int,get(guard).split()));assert row[0]==7077888 and 0<row[1]<row[0]
                    if domain:assert row==next(iter(domain.values()))
                    domain[stage+'/'+name+'/'+route]=row;save('guard',domain)
    ad=w/'adapter';ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)));run('cargo','build','--release','--locked',cwd=ad)
    archive=ad/'target/release/libiced_compare.a';switches={}
    for name in ('cmake','make'):
        images={}
        for stage in tags:
            binary=w/(stage+'-'+name);run('clang++','-O3','-std=c++17',*inc,r/'driver.cpp',archive,w/(stage+'-'+name+'.a'),'-ldl','-lpthread','-lm','-no-pie','-o',binary)
            assert 'libcapstone.so' not in get('ldd',binary)
            images[stage]=binary.read_bytes()
        ref=control if name=='make' else 'base'
        assert images['candidate']==images[ref] and (images['base']!=images['initial'])==on
        switches[name]=FixedImage(w/('selected-'+name),images,executable=True)
        for label in switches[name].images:switches[name].select(label)
    run('clang++','-O2','-std=c++17',*inc,r/'vectors.cpp',w/'base-cmake.a','-lm','-ldl','-lpthread','-o',w/'vectors')
    run('clang++','-O2','-std=c++17',*inc,r/'static-real.cpp','-ldl','-o',w/'trial-real')
    run('setarch',cpu,'-R','true')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {f[0]for f in fixtures}==set(m['samples'])
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    for program,bits,file,extents,_ in fixtures:
        spec=m['provenance'][program];assert sha(file)==spec['text_sha256']
        spans=[x for x in extents if tuple(x) not in {tuple(j[:3])for j in spec['excluded_incompatible_extents']}]
        tsv=w/(program+'.tsv')
        def emit():tsv.write_text(''.join('%d %d %d\n'%tuple(x)for x in spans))
        emit()
        if m['samples'][program]=='simd-functions':
            vectors=[list(map(int,line.split()))for line in get(w/'vectors',str(bits),file,tsv).splitlines()]
            assert len(vectors)==len(spans);spans=[x for x,v in zip(spans,vectors)if v[1]>=8 and v[1]>=.15*v[0]];emit()
        assert sha(tsv)==spec['extent_sha256']
        for name,switch in switches.items():
            ks=name+'/'+program
            reals[ks]=[list(map(int,get(w/'trial-real',w/('base-'+name+'.so'),w/('candidate-'+name+'.so'),file,tsv,str(bits),str(i)).split())) for i in range(8)]
            save('records',reals)
            if not on:continue
            for syntax,mode in [('intel',0),('intel',1),('intel',2),('att',1),('att',2)]:
                key=name+'/'+syntax+'/'+program+'/'+str(mode)
                if key not in ('make/intel/libmvec-amd64/1','make/intel/libmvec-amd64/2','make/att/putty-32-0.85/1','make/intel/putty-32-0.85/2'):
                    continue
                def take(tag,n):
                    rival=tag in ('iced','fast');switch.select('base' if rival else tag)
                    engine=tag if rival else ('capstone' if syntax=='intel' else 'public-att')
                    return list(map(int,get('setarch',cpu,'-R',switch.path,engine,str(mode),str(n),file,tsv,str(bits)).split()))
                labels=['base','copy','initial','candidate','repeat']+(['iced']+(['fast']if mode else [])if syntax=='intel'else [])
                n=max(1,math.ceil(25e6/take('base',1)[0]));expected={tag:take(tag,n)[2:]for tag in labels}
                assert all(expected[k]==expected['base']for k in ('copy','initial','candidate','repeat'))
                assert all(x[:3]==expected['base'][:3]for x in expected.values())
                rng=random.Random('pure-static-indexed/'+key);blocks=[]
                for i in range(25):
                    rng.shuffle(labels);visits={tag:[]for tag in labels}
                    for tag in labels+labels[::-1]:
                        row=take(tag,n);assert row[2:]==expected[tag];visits[tag].append(row[:2])
                    blocks.append({t:[sum(v[c] for v in vs)for c in (0,1)]for t,vs in visits.items()})
                timings[key]=dict(reps=n,checks=expected,cycles=blocks);save('timings',timings)
    save('complete',dict(complete=True,source=q,reference=control,enabled=on,compiler=cc,hardware=get('lscpu'),iced=m['iced_revision'],inputs=len(fixtures),timings=len(timings),images={k:v.receipt()for k,v in switches.items()}))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
