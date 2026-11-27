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
    from elftools.elf.elffile import ELFFile
    assert get('git','-C',root,'rev-parse','HEAD:third_party/capstone').strip()==q['commit']
    master=p/'iced-master'
    tips={'compat':(ice,m['iced_revision']),'master':(master,m['iced_master'])}
    rust_src='src/rust/iced-x86'
    paths=['src/decoder.rs','src/decoder/handlers','src/formatter','src/info','Cargo.toml']
    hashes={tag:{path:get('git','-C',src,'rev-parse','HEAD:'+rust_src+'/'+path).strip() for path in paths} for tag,(src,rev) in tips.items()}
    assert [f for f in paths if hashes['compat'][f]!=hashes['master'][f]]==['src/decoder.rs']
    ad.mkdir()
    common=w/'iced'/rust_src
    common.parent.mkdir(parents=True)
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(w/'iced')))
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',r/'driver.cpp','-o',w/'driver.o')
    raw_images={};images={}
    for tag,(src,rev) in tips.items():
        assert get('git','-C',src,'rev-parse','HEAD').strip()==rev
        shutil.copytree(src/rust_src,common)
        run('cargo','build','--locked','--release',cwd=ad)
        ice_lib=ad/'target/release/libiced_compare.a'
        exe=w/'program'
        run('clang++',w/'driver.o',lib,ice_lib,'-lpthread','-lm','-ldl','-no-pie','-o',exe)
        with exe.open('rb') as f:
            elf=ELFFile(f);sect=elf.get_section_by_name('.text')
            sym,=elf.get_section_by_name('.symtab').get_symbol_by_name('iced_run')
            body=sect.data()[sym['st_value']-sect['sh_addr']:][:sym['st_size']]
            assert len(body)==sym['st_size'] and len(body)>1000
            images[tag]=dict(executable=sha(exe),archive=sha(ice_lib),text=hashlib.sha256(sect.data()).hexdigest(),iced_run_body=hashlib.sha256(body).hexdigest(),iced_run_address=sym['st_value'],iced_run_size=len(body))
        raw_images[tag]=exe.read_bytes();shutil.rmtree(common);shutil.rmtree(ad/'target')
    exe=w/'program'
    maximum=max(map(len,raw_images.values()))
    padded={k:v.ljust(maximum,b'\0') for k,v in raw_images.items()}
    pages=[idx for idx in range(0,maximum,4096) if padded['compat'][idx:idx+4096]!=padded['master'][idx:idx+4096]]
    exe.write_bytes(padded['master']);inode=exe.stat().st_ino;active='master';verified={}
    def select(tag):
        global active
        if tag!=active:
            with exe.open('r+b',buffering=0) as out:
                for off in pages:
                    chunk=padded[tag][off:off+4096];out.seek(off);assert out.write(chunk)==len(chunk)
            active=tag
        if tag not in verified:
            assert exe.stat().st_ino==inode and exe.read_bytes()==padded[tag];verified[tag]=sha(exe)
    select('compat');select('master')
    info=dict(iced={tag:rev for tag,(_,rev) in tips.items()},neverd=dev,capstone=q,crate_paths=hashes,images=images,driver=sha(w/'driver.o'),capstone_archive=sha(lib),cpu=get('lscpu'),rustc=get('rustc','-Vv'),clang=get('clang','--version').splitlines()[0],differing_pages=len(pages),staged=verified)
    save('host',info)
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R',exe]
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    out={}
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
        audits={}
        for tag in tips:
            select(tag)
            rows=[list(map(int,z.split())) for z in get(*invoke,'audit','0','1',f,path,str(bits)).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            audits[tag]=rows
        assert audits['master']==audits['compat']
        for mode in (0,1,2):
            engines=['capstone','private','iced']+(['fast'] if mode else [])
            keys=[tag+'/'+engine for tag in tips for engine in engines]
            def take(key,repeats):
                tag,engine=key.split('/');select(tag)
                return list(map(int,get(*invoke,engine,str(mode),str(repeats),f,path,str(bits)).split()))
            n=max(1,math.ceil(15e6/min(take(k,1)[0] for k in keys)))
            expected={k:take(k,n)[2:] for k in keys}
            assert all(z[:3]==expected[keys[0]][:3] for z in expected.values())
            assert all(expected['master/'+eng]==expected['compat/'+eng] for eng in engines)
            cycles=[];rng=random.Random('iced-fork/'+name+'/'+str(mode))
            for _ in range(17):
                rng.shuffle(keys);part={k:[] for k in keys}
                for k in keys+keys[::-1]:
                    z=take(k,n);assert z[2:]==expected[k];part[k].append(z[:2])
                cycles.append({k:[a+b for a,b in zip(*rows)] for k,rows in part.items()})
            out[name+'/'+str(mode)]=dict(repeats=n,guards=expected,pairs=cycles,spans=len(selected),bytes=spec['bytes'],text=sha(f),extent=sha(path))
            save('paired',out)
    assert len(out)==18
    save('complete',dict(complete=True,host=info,real_cases=len(out)))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
