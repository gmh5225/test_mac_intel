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
    from elftools.elf.elffile import ELFFile
    from symbol_layout import symbols
    image_layout={};images={};archive={}
    sec_name='.cs_x86_amd64_text'
    def link(label,src,padding):
        args=[]
        if padding:
            assembly=w/'dummy.s';obj=w/'dummy.o'
            assembly.write_text('.section '+sec_name+',"ax"\n.space '+str(padding)+',0\n.section .note.GNU-stack,""\n')
            run('clang','-c',assembly,'-o',obj);args=[obj]
        run('clang++',w/'driver.o',archive[src],*args,ice_lib,*flags,'-o',w/label)
        with (w/label).open('rb') as f:
            elf=ELFFile(f)
            sections={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
        image_layout[label]=sections;images[label]=dict(source=src,padding=padding,exe=sha(w/label))
    for name in ('base','trial'):
        if name=='trial':
            assert sha(r/'candidate.patch')==q['sha256'];run('git','-C',base,'apply','--index',r/'candidate.patch')
            assert get('git','-C',base,'write-tree').strip()==q['tree']
            run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        archive[name]=w/(name+'.a');shutil.copyfile(lib,archive[name])
        link(name,name,0)
    sizes={k:image_layout[k][sec_name][1]for k in ('base','trial')}
    delta=abs(sizes['base']-sizes['trial']);assert 0<delta<4096,sizes
    sel={};target=max(sizes.values())
    for level,cap in [('same',target),('shift',target+delta)]:
        for name in sizes:
            label=name+'-'+level
            link(label,name,cap-sizes[name])
            assert image_layout[label][sec_name][1]==cap
        a=image_layout['base-'+level];b=image_layout['trial-'+level]
        assert a.keys()==b.keys()
        assert all(a[n][:2]==b[n][:2]for n in (sec_name,'.cs_x86_i386_text','.text','.rodata'))
        sel[level]=dict(changed_bytes=[n for n in a if a[n][2]!=b[n][2]],changed_addresses=[n for n in a if a[n][:2]!=b[n][:2]],i386=a['.cs_x86_i386_text'][:2])
    for name,qsize in sizes.items():
        if qsize==target:assert images[name]['exe']==images[name+'-same']['exe']
    save('geometry',dict(sizes=sizes,targets=sel,sections=image_layout,functions={k:symbols(w/k) for k in images}))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',archive['base'],'-o',w/'vectors')
    imgs={k:(w/k).read_bytes() for k in images};length=max(map(len,imgs.values()))
    original_sizes={k:len(v) for k,v in imgs.items()}
    imgs={k:v+bytes(length-len(v)) for k,v in imgs.items()};imgs['duplicate']=imgs['base']
    current=w/'selected';shutil.copy2(w/'base',current);current.write_bytes(imgs['base'])
    inode=current.stat().st_ino;verified={}
    offsets=[pos for pos in range(0,length,4096) if len({v[pos:pos+4096] for v in imgs.values()})>1] or [0]
    def select(k):
        with current.open('r+b',buffering=0) as out:
            for at in offsets:
                out.seek(at);part=imgs[k][at:at+4096];assert out.write(part)==len(part)
        assert current.stat().st_ino==inode and current.stat().st_size==length
        if k not in verified:
            assert hashlib.sha256(current.read_bytes()[:original_sizes.get(k,original_sizes['base'])]).hexdigest()==images['base' if k=='duplicate' else k]['exe']
            verified[k]=sha(current);assert verified[k]==hashlib.sha256(imgs[k]).hexdigest()
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R',current]
    cpu=get('lscpu')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host=dict(capstone=m['checkout_commit'],neverd=dev,iced=m['iced_revision'],cpu=cpu,compiler=get('clang','--version').splitlines()[0],os=platform.platform(),images=images,driver_sha256=sha(w/'driver.cpp'),rust_sha256=sha(ad/'iced.rs'))
    save('host',host);observations={};summary={};audits={}
    for name,bits,f,spans,_ in itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)):
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
        selected_modes={'putty-32-0.85':(0,1,2),'libssl3t64-i386':(0,1,2),'jpeg-avx2-i386':(0,2),'libmvec-amd64':(1,2),'putty-64-0.85':(0,2)}.get(name,())
        for mode in selected_modes:
            def take(k,n):
                select(k)
                return list(map(int,get(*invoke,'private',str(mode),str(n),f,path,str(bits)).split()))
            key=name+'/'+str(mode);labels=list(imgs);rng=random.Random(key)
            repeats=max(1,math.ceil(20e6/take('base',1)[0]))
            expected={k:take(k,repeats)[2:]for k in labels};assert all(v==expected['base']for v in expected.values())
            assert expected['base'][0]>0
            cycles=[]
            for i in range(71):
                rng.shuffle(labels);a={k:take(k,repeats)[:2]for k in labels};b={k:take(k,repeats)[:2]for k in reversed(labels)}
                cycles.append({k:[a[k][j]+b[k][j] for j in range(2)]for k in labels})
            observations[key]=dict(checks=expected,repeats=repeats,cycles=cycles,pairs=len(cycles))
            save('observations',observations);print(key,flush=True)
    assert len(observations)==12
    save('fixed-image',dict(inode=inode,verified=verified,images=images))
    save('complete',dict(complete=True,source=q,host=host,panels=len(observations),pairs=71))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
