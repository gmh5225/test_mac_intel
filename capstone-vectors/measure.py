from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    from costs import profile
    maps=rd(r/'source.json');ids={'base':'base','candidate':'prefix','outlined':'outlined'}
    images={};tables={};invoke=['setarch',os.uname().machine,'-R']
    for label,tag in ids.items():
        if label!='base':
            run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','.')
            patch=r/(label+'.patch');assert sha(patch)==maps[tag]['sha256']
            run('git','-C',base,'apply','--index',patch)
        assert get('git','-C',base,'write-tree').strip()==maps[tag]['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/label)
        images[label]=sha(w/label)
        listing=get('nm','-S','--defined-only','--format=posix',w/label).splitlines()
        sizes=sorted(int(l.split()[3],16) for l in listing if len(l.split())==4 and l.split()[0]=='x86_simple_outputs')
        assert sizes,sizes
        tables[label]=sizes
        if label=='base':
            run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    assert all(335*stride in tables[label] for label,stride in [('base',88),('candidate',80),('outlined',72)]),tables
    save('tables',tables);cpu=get('lscpu')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host=dict(capstone=m['checkout_commit'],neverd=dev,iced=m['iced_revision'],cpu=cpu,compiler=get('clang','--version').splitlines()[0],os=platform.platform(),images=images,driver_sha256=sha(w/'driver.cpp'),rust_sha256=sha(ad/'iced.rs'))
    save('host',host);observations={};summary={};audits={}
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        if name not in ('putty-32-0.85','libmvec-amd64','jpeg-avx2-i386'):continue
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit(v):path.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path)==spec['extent_sha256']
        def audit_engine(exe):
            rows=[list(map(int,z.split())) for z in get(w/exe,'audit','0','1',f,path,str(bits)).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            return rows
        assert audit_engine('base')==audit_engine('outlined')==audit_engine('candidate')
        audits[name]=dict(functions=len(selected),bytes=spec['bytes'],extent_sha256=sha(path));save('audit',audits)
        for mode in (1,2):
            row={}
            for stage in ('base','candidate','outlined','fast'):
                command=w/('base' if stage=='fast' else stage);engine='fast' if stage=='fast' else 'private'
                epochs={}
                for reps in (1,2):epochs[str(reps)]=profile(w,invoke,[command,engine,str(mode),str(reps),f,path,str(bits)])
                row[stage]=epochs
            for rep in ('1','2'):
                base_result=row['base'][rep]['records']
                assert row['candidate'][rep]['records']==row['outlined'][rep]['records']==base_result
                assert row['fast'][rep]['records'][:3]==base_result[:3]
            observations[f'{name}/{mode}']=row;save('counts',observations)
    assert len(observations)==6
    save('complete',dict(complete=True,source=maps,host=host,images=images,extents=audits))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
