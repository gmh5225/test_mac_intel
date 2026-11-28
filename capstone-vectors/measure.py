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
    from training import fetch
    foreign=fetch(r,w);assert len(foreign)==5;save('foreign-corpus',foreign)
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    ref=w/'native.c';ref.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const keep = X86_disasmIterText;\n')
    run('clang','-O2','-I',base,'-I',base/'include','-c',ref,'-o',w/'ref.o')
    fix=rd(r/'fix.json');assert fix['parent']==q['commit'] and sha(r/'fix.patch')==fix['sha256']
    images={}
    for tag in ('base','fixed'):
        if tag=='fixed':
            run('git','-C',base,'apply','--index',r/'fix.patch');assert get('git','-C',base,'write-tree').strip()==fix['tree']
            run(sys.executable,'-B',base/'suite/synctools/x86_mapping_counts.py','--check');run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/('x86-'+tag))
        run('clang++',w/'foreign.o',w/'ref.o',lib,*flags,'-o',w/('foreign-'+tag))
        run('clang','-fPIC','-shared','-I',base/'include',r/'export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(tag+'.so'))
        objs={str(p.relative_to(build)):sha(p)for p in build.rglob('*.c.o')};assert len(objs)>=60
        images[tag]=dict(x86=sha(w/('x86-'+tag)),foreign=sha(w/('foreign-'+tag)),archive=sha(lib),objects=objs)
    changed=[Path(k).name for k,v in images['base']['objects'].items()if images['fixed']['objects'][k]!=v]
    assert 'X86Mapping.c.o' in changed and set(changed)<={'X86Mapping.c.o','X86Disassembler.c.o','X86DisassemblerDecoder.c.o'},changed
    save('linked',dict(images=images,changed=changed,source=fix,dev=dev,iced=m['iced_revision']))
    check=r/'string-cases.c';fixture=(r/'cases.tsv').read_bytes()
    expected=rd(r/'expected.json');assert len(expected)==len(fixture.splitlines())==3584
    run('clang','-O2','-I',base/'include',check,lib,'-o',w/'check-registers')
    rows=sp.check_output([w/'check-registers'],input=fixture).splitlines();assert len(rows)==14336
    for pos,row in enumerate(rows):
        i,a,t,size,ident,ops,mn,rr,ww,dup=map(int,row.split())
        assert (i,a,t)==(pos//4,(pos//2)%2,pos%2) and size>0 and ident and dup==0
        assert [rr,ww]==(expected[i][:2] if t else expected[i][2:])
    save('string-encodings',dict(count=len(expected),checks=len(rows),digest=hashlib.sha256(b'\n'.join(rows)).hexdigest()))
    os.link(w/'x86-base',w/'runner')
    for route in ('public','fixed'):run('clang++','-O2','-std=c++17','-I',base/'include',r/('records-'+route+'.cpp'),'-ldl','-o',w/('records-'+route))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cases={}
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
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
        checks=[list(map(int,row.split()))for row in get(w/'runner','audit','0','1',f,path,str(bits)).splitlines()]
        assert len(checks)==len(selected) and all(z[3]==z[4] and z[1]==z[5] for z in checks)
        for mode in (0,1,2):
            cases[name+'/'+str(mode)]=(mode,f,path,str(bits))
    assert len(cases)==18
    from compare import run_programs
    run_programs(r,w,cases,foreign,save)
    save('complete',dict(complete=True,source=fix,neverd=dev,iced=m['iced_revision'],cpu=get('lscpu'),cases=list(cases)))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
