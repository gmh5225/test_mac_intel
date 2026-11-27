from pathlib import Path
import hashlib,itertools,json,math,os,random,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
p=r.parent;e=p/'evidence';e.mkdir(exist_ok=True)
src=p/'source';ice=p/'iced-source'
read=lambda f:json.loads(f.read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(*a,**kw):sp.run(a,check=True,**kw)
def get(*a,**kw):return sp.check_output(a,text=True,**kw)
def save(name,data):
    f=e/(name+'.json');t=f.with_suffix('.tmp');t.write_text(json.dumps(data,indent=2)+'\n');t.replace(f)
def once(s,a,b):
    assert s.count(a)==1
    return s.replace(a,b)
m=read(r/'experiment.json');q=read(r/'source.json')
assert get('git','-C',src,'rev-parse','HEAD').strip()==q['base']['commit']
assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
assert sha(r/'candidate.patch')==q['candidate']['sha256']
assert all(sha(r/f)==h for f,h in m['drivers'].items())
w=Path(tempfile.mkdtemp());build=w/'build';ad=w/'adapter';selected=w/'lib';selected.mkdir();ad.mkdir()
try:
    flags=['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ('X86',)]
    flags+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    images={};sources={};copies={};sizes={};symbols={};objects={}
    project=w/'static-project';static_build=w/'static-build';(project/'third_party').mkdir(parents=True)
    (project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    nd=p/'neverd-config';assert get('git','-C',nd,'rev-parse','HEAD').strip()==m['neverd']
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes(sp.check_output(['git','-C',nd,'show',m['neverd']+':'+cm]))
    top=get('git','-C',nd,'show',m['neverd']+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(StaticDecode LANGUAGES C CXX)\n'+top[top.index('# --- Capstone (our fork'):top.index('# --- NeverD CMake helpers')])
    static_images={}
    for stage in ('base','initial','candidate'):
        if stage!='base':
            run('git','-C',src,'restore','--source=HEAD','--staged','--worktree','--','.')
            patch=r/(stage+'.patch');assert sha(patch)==q[stage]['sha256'];run('git','-C',src,'apply','--index',patch)
        assert get('git','-C',src,'write-tree').strip()==q[stage]['tree']
        run('cmake','-G','Ninja','-S',src,'-B',build,*flags)
        run('cmake','--build',build,'--target','capstone_shared','capstone_static','--parallel','4')
        so=(build/'libcapstone.so').resolve()
        lib,=build.rglob('libcapstone.a')
        shutil.copyfile(lib,w/(stage+'.a'))
        if stage=='candidate':
            gen=w/'vector-generator'
            inc=['-I',src,'-I',src/'include']
            run('clang++','-std=c++17','-O2',*inc,src/'suite/synctools/x86_vector_output.cpp',lib,'-o',gen)
            generated={}
            for arg,name in [('--vex-sib-transfers','X86GenVexSibTransfers.inc'),('--vex-base-memory','X86GenVexBaseMemory.inc'),('','X86GenVectorOutput.inc')]:
                data=sp.check_output([gen]+([arg] if arg else []));assert data==(src/'arch/X86'/name).read_bytes()
                generated[name]=hashlib.sha256(data).hexdigest()
            checks={}
            for dispatch,library in [('static',lib),('public',so)]:
                exe=w/('sib-'+dispatch)
                run('clang++','-O2','-std=c++17',*inc,*(['-DUSE_PUBLIC'] if dispatch=='public' else []),r/'sib.cpp',library,'-Wl,-rpath,'+str(build),'-o',exe)
                checks[dispatch]=list(map(int,get(exe).split()))
            assert checks['public']==checks['static'] and checks['public'][0]==7077888
            save('sib-checks',dict(generated=generated,boundaries=checks))

        assert all('CAPSTONE_X86_ONLY' in x['command'] for x in read(build/'compile_commands.json'))
        dll=w/(stage+'.so');shutil.copyfile(so,dll);images[stage]=dll.read_bytes();sources[stage]=sha(dll);sizes[stage]=len(images[stage])
        syms=get('nm','-D','--defined-only','--format=posix',dll).splitlines()
        symbols[stage]=sorted(row.split()[0] for row in syms)
        objects[stage]={str(f.relative_to(build)):sha(f) for f in build.rglob('*.c.o')}
        run('cmake','-G','Ninja','-S',project,'-B',static_build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
        run('cmake','--build',static_build,'--target','capstone_static','--parallel','4')
        static_lib,=static_build.rglob('libcapstone.a')
        static_images[stage]=dict(archive=sha(static_lib),objects={str(f.relative_to(static_build)):sha(f)for f in static_build.rglob('*.c.o')})
        assert len(static_images[stage]['objects'])>=60
        save('static-product',static_images)
    assert static_images['base']==static_images['initial']==static_images['candidate']
    delta=dict(added=sorted(set(symbols['candidate'])-set(symbols['base'])),removed=sorted(set(symbols['base'])-set(symbols['candidate'])))
    save('identities',dict(source=q,images=sources,sizes=sizes,symbols=delta,objects=objects))
    assert symbols['base']==symbols['initial']==symbols['candidate'] and len(set(sources.values()))==3
    from elftools.elf.elffile import ELFFile
    with (w/'base.so').open('rb')as f:
        elf=ELFFile(f);soname=next(tag.soname for tag in elf.get_section_by_name('.dynamic').iter_tags() if tag.entry.d_tag=='DT_SONAME')
    from fixed_image import FixedImage
    image=selected/soname
    shared=FixedImage(image,images)
    select=shared.select
    inc=['-I',src,'-I',src/'include']
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    links=[w/'base.so','-Wl,-rpath,'+str(selected),'-ldl','-lpthread','-lm','-no-pie']
    run('clang++','-O3','-std=c++17',*inc,r/'driver.cpp',ice_lib,*links,'-o',w/'driver')
    run('clang++','-O3','-std=c++17',*inc,r/'foreign.cpp',*links,'-o',w/'foreign')
    run('clang++','-O2','-std=c++17',*inc,r/'vectors.cpp',*links,'-o',w/'vectors')
    for name in ('trial-compare','trial-real','public-guard','foreign-verify','trial-vector-guard','trial-states','trial-guard','cmov-guard'):
        run('clang++','-O2','-std=c++17',*inc,r/(name+'.cpp'),'-ldl','-o',w/name)
    for stage in ('base','initial','candidate'):
        run('clang++','-O3','-std=c++17',*inc,r/'driver.cpp',ice_lib,w/(stage+'.a'),'-ldl','-lpthread','-lm','-no-pie','-o',w/(stage+'-static'))
        assert 'libcapstone.so' not in get('ldd',w/(stage+'-static'))
    static=FixedImage(w/'measured-static',{k:(w/(k+'-static')).read_bytes() for k in ('base','initial','candidate')},executable=True)
    save('dedicated-static',{tag:dict(executable=sha(w/(tag+'-static')),archive=sha(w/(tag+'.a')))for tag in ('base','initial','candidate')})
    for exe in ('driver','foreign','vectors'):
        assert str(image) in get('ldd',w/exe)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R']
    opts=json.loads(get(w/'trial-compare',w/'base.so',w/'candidate.so','options'))
    domain=list(map(int,get(w/'public-guard',w/'base.so',w/'candidate.so').split()))
    assert domain[0]==5105184 and 0<domain[1]<domain[0]
    libs=(w/'base.so',w/'candidate.so')
    states=sp.run([w/'trial-states',*libs,'2048'],text=True,capture_output=True)
    states.check_returncode()
    assert states.stderr.count('case arch=')==48
    scan=list(map(int,get(w/'trial-guard',*libs).split()));assert scan[0]==2162688 and 0<scan[1]<scan[0]
    vector=json.loads(get(w/'trial-vector-guard',*libs))
    cmov=list(map(int,get(w/'cmov-guard',*libs).split()));assert cmov[0]>1000000 and 0<cmov[1]<cmov[0]
    save('options',dict(domain=domain,options=opts,scan=scan,vector=vector,cmov=cmov,random_state_configurations=48,random_per_state=2048))
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    inputs=read(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=read(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m['samples'])
    host=dict(cpu=get('lscpu'),compiler=get('clang','--version').splitlines()[0],source=q,iced=m['iced_revision'],prebuilt=False)
    save('host',host);records={};timings={}
    focus=set(read(r/'focus.json'))
    def measure(key,engines,take):
        if key not in focus:return
        n=max(1,math.ceil(25e6/take('base',1)[0]));expected={k:take(k,n)[2:]for k in engines}
        assert all(expected[k]==expected['base'] for k in ('copy','initial','candidate','repeat'))
        if 'iced' in expected:assert all(v[:3]==expected['base'][:3]for v in expected.values())
        rng=random.Random('shared-library/'+key);blocks=[];order=list(engines)
        for _ in range(35):
            rng.shuffle(order);trial={k:[] for k in order}
            for k in order+order[::-1]:
                row=take(k,n);assert row[2:]==expected[k];trial[k].append(row[:2])
            blocks.append({k:[sum(t[i]for t in v)for i in (0,1)]for k,v in trial.items()})
        timings[key]=dict(reps=n,checks=expected,cycles=blocks)
        save('timings',timings)
    for name,bits,f,extents,_ in fixtures:
        spec=m['provenance'][name];assert sha(f)==spec['text_sha256']
        intervals=[x for x in extents if tuple(x)not in {tuple(j[:3])for j in spec['excluded_incompatible_extents']}]
        intervals_file=w/(name+'.tsv')
        def emit():intervals_file.write_text(''.join('%d %d %d\n'%tuple(x) for x in intervals))
        emit();select('base')
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,line.split()))for line in get(w/'vectors',str(bits),f,intervals_file).splitlines()]
            assert len(view)==len(intervals);intervals=[x for x,j in zip(intervals,view)if j[1]>=8 and j[1]>=.15*j[0]];emit()
        assert sha(intervals_file)==spec['extent_sha256']
        audits=[]
        for stage in ('base','initial','candidate'):
            select(stage)
            audit=[list(map(int,x.split()))for x in get(*invoke,w/'driver','audit','0','1',f,intervals_file,str(bits)).splitlines()]
            assert len(audit)==len(intervals) and all(x[3]==x[4] and x[1]==x[5]for x in audit)
            audits.append(audit)
        assert audits[0]==audits[1]==audits[2]
        records[name]=[list(map(int,get(w/'trial-real',w/'base.so',w/'candidate.so',f,intervals_file,str(bits),str(mode)).split()))for mode in (4,5,6,7)]
        save('records',records)
        for mode in (0,1,2):
            def take(k,n):
                other=k in ('iced','fast');select('base' if other else k)
                return list(map(int,get(*invoke,w/'driver',k if other else 'capstone',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('intel/'+name+'/'+str(mode),['base','copy','initial','candidate','repeat','iced']+(['fast']if mode else []),take)
        for mode in (1,2):
            def take(k,n):
                select(k);return list(map(int,get(*invoke,w/'driver','public-att',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('att/'+name+'/'+str(mode),list(shared.images),take)
        for mode in (0,1,2):
            def take_static(k,n):
                static.select(k)
                return list(map(int,get(*invoke,static.path,'capstone',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('static-intel/'+name+'/'+str(mode),list(static.images),take_static)
        for mode in (1,2):
            def take_att_static(k,n):
                static.select(k)
                return list(map(int,get(*invoke,static.path,'public-att',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('static-att/'+name+'/'+str(mode),list(static.images),take_att_static)
    assert set(timings)==focus
    save('complete',dict(complete=True,source=q,host=host,workloads=len(timings),shared=shared.receipt(),static=static.receipt(),soname=soname))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
