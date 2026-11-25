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
    images={}
    maps=rd(r/'source.json')
    assert maps['prefix']==q and maps['base']['commit']==q['parent']
    layout={}
    from elftools.elf.elffile import ELFFile
    from symbol_layout import symbols
    roots=get('git','-C',root,'show',dev+':lib/decode/CMakeLists.txt')
    options=['--undefined=X86_disasmIter','--undefined=X86_disasmIter32']
    assert all('"LINKER:'+text+'"' in roots for text in options)
    sections={'.cs_x86_amd64_text':'ax','.cs_x86_amd64_rodata':'a'}
    def link(tag,label,padding):
        path=w/tag;extra=[]
        directives=[]
        for section,flag in sections.items():
            count=padding.get(section,0)
            if count:directives.append('.section '+section+',"'+flag+'"\\n.space '+str(count)+',0')
        if directives:
            f=w/'tail.s';f.write_text('\\n'.join(directives)+'\\n.section .note.GNU-stack,""\\n')
            run('clang','-c',f,'-o',w/'tail.o');extra=[w/'tail.o']
        ld=['-Wl,'+k for k in options]
        run('clang++',w/'driver.o',*ld,w/(label+'.a'),*extra,ice_lib,*flags,'-o',path)
        with path.open('rb') as f:
            elf=ELFFile(f)
            layout[tag]={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()]for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
        images[tag]=dict(exe=sha(path),symbols=symbols(path),archive=archive[label],padding=padding)
    archive={};objects={}
    for label in ('base','outlined'):
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        assert get('git','-C',base,'write-tree').strip()==maps['base']['tree']
        if label=='outlined':
            assert sha(r/'outlined.patch')==maps['outlined']['sha256']
            run('git','-C',base,'apply','--index',r/'outlined.patch');assert get('git','-C',base,'write-tree').strip()==maps['outlined']['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        archive[label]=sha(lib)
        objects[label]={str(f.relative_to(build)):sha(f)for f in build.rglob('*.c.o')}
        shutil.copyfile(lib,w/(label+'.a'));link('natural-'+label,label,{})
    natural={k:layout['natural-'+k]for k in ('base','outlined')}
    sizes={k:{sec:v[sec][1]for sec in sections}for k,v in natural.items()}
    delta={sec:max(v[sec] for v in sizes.values())-min(v[sec] for v in sizes.values())for sec in sections}
    assert 0<delta[".cs_x86_amd64_text"]<8192 and 0<=delta[".cs_x86_amd64_rodata"]<8192,delta
    assert (delta[".cs_x86_amd64_rodata"]>0)==(os.uname().machine=="aarch64"),delta
    geometry={}
    for style in ('text_only','both'):
        for label in ('base','outlined'):
            use=[*sections]if style=='both' else ['.cs_x86_amd64_text']
            padding={name:max(v[name]for v in sizes.values())-sizes[label][name] for name in use}
            tag=style+'-'+label;link(tag,label,padding)
            if not any(padding.values()):assert images[tag]['exe']==images['natural-'+label]['exe']
        a,b=(layout[style+'-'+k]for k in ('base','outlined'))
        assert a.keys()==b.keys()
        geometry[style]={n:[a[n][:2],b[n][:2],a[n][2]==b[n][2]]for n in a}
        for sec in ('.text','.cs_x86_i386_text','.cs_x86_memory_fallback32_text','.cs_x86_register_fallback32_text','.cs_x86_amd64_text'):
            assert a[sec][:2]==b[sec][:2],(style,sec,a[sec],b[sec])
        if style=='both':
            for sec in ('.rodata','.cs_x86_i386_rodata','.cs_x86_register_fallback32_rodata','.cs_x86_memory_fallback32_rodata','.cs_x86_amd64_rodata'):
                assert a[sec][:2]==b[sec][:2],(sec,a[sec],b[sec])
    save('geometry',dict(natural=natural,matched=geometry,sizes=sizes,delta=delta))
    for label in ('base','outlined'):
        del images['natural-'+label];del layout['natural-'+label]
    assert set(objects['base'])==set(objects['outlined'])
    assert [Path(f).name for f in objects['base']if objects['base'][f]!=objects['outlined'][f]]==['X86Sse64Output.c.o']
    save('sources',dict(capstone=maps,neverd=dev,ice=m['iced_revision'],archives=archive,images=images,options=dict(linker=options,matched=delta),host=platform.platform(),cpu=get('lscpu')))
    save('linked-sections',layout)
    stages={tag:(w/tag).read_bytes() for tag in images}
    lengths={k:len(v)for k,v in stages.items()};length=max(lengths.values())
    stages={k:v+bytes(length-len(v)) for k,v in stages.items()}
    for style in ('text_only','both'):
        stages[style+'-copy']=stages[style+'-base']
    current=w/'selected';shutil.copy2(w/'text_only-base',current);current.write_bytes(stages['text_only-base'])
    inode=current.stat().st_ino;verified={};offsets=[i for i in range(0,length,4096)if len({v[i:i+4096]for v in stages.values()})>1]
    def select(k):
        with current.open('r+b',buffering=0)as f:
            for i in offsets:
                x=stages[k][i:i+4096];f.seek(i);assert f.write(x)==len(x)
        assert current.stat().st_ino==inode
        if k not in verified:
            src=k.replace('-copy','-base')
            assert hashlib.sha256(current.read_bytes()[:lengths[src]]).hexdigest()==images[src]['exe']
            verified[k]=sha(current)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});invoke=['setarch',os.uname().machine,'-R',current]
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    audits={};observations={}
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
        def audit_engine(exe):
            rows=[list(map(int,z.split())) for z in get(w/exe,'audit','0','1',f,path,str(bits)).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            return rows
        assert audit_engine('text_only-base')==audit_engine('both-base')==audit_engine('text_only-outlined')==audit_engine('both-outlined')
        audits[name]=dict(extents=len(selected),sha=sha(path),bytes=spec['bytes']);save('audit',audits)
        for mode in (1,2):
            def take(k,n):
                select(k)
                return list(map(int,get(*invoke,'private',str(mode),str(n),f,path,str(bits)).split()))
            reps=max(1,math.ceil(25e6/take('text_only-base',1)[0]))
            labels=list(stages);expected={k:take(k,reps)[2:]for k in labels}
            assert len({tuple(z)for z in expected.values()})==1
            pairs=[];rng=random.Random(name+str(mode))
            for _ in range(101 if name=='libssl3t64-i386' and mode==2 else 35):
                rng.shuffle(labels);ticks={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    x=take(k,reps);assert x[2:]==expected[k]
                    ticks[k].append(x[:2])
                pairs.append({k:[sum(z[j]for z in ticks[k])for j in (0,1)]for k in labels})
            observations[name+'/'+str(mode)]=dict(cycles=pairs,counts=expected,repeats=reps)
            save('observations',observations)
    assert len(observations)==12 and len(verified)==6
    save('complete',dict(complete=True,inode=inode,verified=verified,panels=len(observations),pairs=35,sections=len(layout),capstone=maps))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
