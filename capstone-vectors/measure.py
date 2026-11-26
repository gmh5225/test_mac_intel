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
    flags+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    images={};sources={};copies={};sizes={};symbols={};objects={}
    project=w/'static-project';static_build=w/'static-build';(project/'third_party').mkdir(parents=True)
    (project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    nd=p/'neverd-config';assert get('git','-C',nd,'rev-parse','HEAD').strip()==m['neverd']
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes(sp.check_output(['git','-C',nd,'show',m['neverd']+':'+cm]))
    top=get('git','-C',nd,'show',m['neverd']+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(StaticDecode LANGUAGES C CXX)\n'+top[top.index('# --- Capstone (our fork'):top.index('# --- NeverD CMake helpers')])
    static_images={}
    for stage in ('base','candidate'):
        if stage=='candidate':run('git','-C',src,'apply','--index',r/'candidate.patch')
        assert get('git','-C',src,'write-tree').strip()==q[stage]['tree']
        run('cmake','-G','Ninja','-S',src,'-B',build,*flags)
        run('cmake','--build',build,'--target','capstone_shared','--parallel','4')
        so=(build/'libcapstone.so').resolve()
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
    assert static_images['base']==static_images['candidate']
    delta=dict(added=sorted(set(symbols['candidate'])-set(symbols['base'])),removed=sorted(set(symbols['base'])-set(symbols['candidate'])))
    save('identities',dict(source=q,images=sources,sizes=sizes,symbols=delta,objects=objects))
    assert not delta['added'] and not delta['removed'] and sources['base']!=sources['candidate']
    from elftools.elf.elffile import ELFFile
    with (w/'base.so').open('rb')as f:
        elf=ELFFile(f);soname=next(tag.soname for tag in elf.get_section_by_name('.dynamic').iter_tags() if tag.entry.d_tag=='DT_SONAME')
    maximum=max(sizes.values());images={k:v.ljust(maximum,b'\x00')for k,v in images.items()}
    images['copy']=images['base'];image=selected/soname;image.write_bytes(images['base']);inode=image.stat().st_ino
    spans=[]
    for i in range(0,maximum,4096):
        if images['base'][i:i+4096]!=images['candidate'][i:i+4096]:
            if spans and spans[-1][1]==i:spans[-1][1]=min(i+4096,maximum)
            else:spans.append([i,min(i+4096,maximum)])
    previous=None;verified={}
    def select(stage):
        global previous
        if previous!=stage:
            with image.open('r+b',buffering=0)as f:
                for a,b in spans:
                    f.seek(a);assert f.write(memoryview(images[stage])[a:b])==b-a
            previous=stage
        assert image.stat().st_ino==inode
        if stage not in verified:
            verified[stage]=sha(image);assert verified[stage]==hashlib.sha256(images[stage]).hexdigest()
    select('base')
    inc=['-I',src,'-I',src/'include']
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    links=[w/'base.so','-Wl,-rpath,'+str(selected),'-ldl','-lpthread','-lm','-no-pie']
    run('clang++','-O3','-std=c++17',*inc,r/'driver.cpp',ice_lib,*links,'-o',w/'driver')
    run('clang++','-O3','-std=c++17',*inc,r/'foreign.cpp',*links,'-o',w/'foreign')
    run('clang++','-O2','-std=c++17',*inc,r/'vectors.cpp',*links,'-o',w/'vectors')
    invoke=['setarch',os.uname().machine,'-R']
    from costs import profile
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    inputs=read(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=read(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m['samples'])
    host=dict(cpu=get('lscpu'),compiler=get('clang','--version').splitlines()[0],source=q,iced=m['iced_revision'],prebuilt=False)
    save('host',host);records={};timings={}
    for name,bits,f,extents,_ in fixtures:
        if name not in ('libssl3t64-i386','libmvec-amd64','putty-32-0.85'):continue
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
        for stage in ('base','candidate'):
            select(stage)
            audit=[list(map(int,x.split()))for x in get(*invoke,w/'driver','audit','0','1',f,intervals_file,str(bits)).splitlines()]
            assert len(audit)==len(intervals) and all(x[3]==x[4] and x[1]==x[5]for x in audit)
            audits.append(audit)
        assert audits[0]==audits[1]
        cases={'libmvec-amd64':[('capstone',1),('capstone',2),('public-att',2)],'putty-32-0.85':[('capstone',1),('capstone',2)],'libssl3t64-i386':[('public-att',1)]}[name]
        for engine,mode in cases:
            key=('att' if engine=='public-att' else 'intel')+'/'+name+'/'+str(mode);row={}
            for tag in ('base','candidate')+(('fast',) if engine=='capstone' else ()):
                select('base' if tag=='fast' else tag)
                result={}
                for repeats in (1,2):
                    result[str(repeats)]=profile(w,invoke,[w/'driver','fast' if tag=='fast' else engine,str(mode),str(repeats),f,intervals_file,str(bits)])
                row[tag]=result
            for epoch in ('1','2'):
                assert all(item[epoch]['records']==row['base'][epoch]['records'] for k,item in row.items()if k!='fast')
                assert all(item[epoch]['records'][:3]==row['base'][epoch]['records'][:3] for item in row.values())
            timings[key]=row;save('counts',timings)
    assert len(timings)==6
    save('complete',dict(complete=True,source=q,host=host,workloads=len(timings),verified=verified))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
