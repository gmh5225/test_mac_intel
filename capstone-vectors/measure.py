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
    maps=rd(r/'source.json')
    text_section='.cs_x86_amd64_text'
    data_section='.cs_x86_vector_fallback64_rodata'
    previous='.cs_x86_evex_output'
    sections={text_section:'ax',previous:'ax'}
    layouts={};addresses={};objects={};checksums={}
    def link(tag,libpath,gaps):
        tail=[]
        if gaps:
            directives=['.section '+s+',"'+sections[s]+'"\n.space '+str(n)+',0' for s,n in gaps.items() if n]
            directives.append('.section .note.GNU-stack,""')
            source=w/'extent.s';source.write_text('\n'.join(directives)+'\n');obj=w/'extent.o'
            run('clang','-c',source,'-o',obj);tail=[obj]
        path=w/tag
        run('clang++',w/'driver.o',libpath,*tail,ice_lib,*flags,'-o',path)
        with path.open('rb') as f:
            elf=ELFFile(f);layouts[tag]={s.name:[s['sh_addr'],s['sh_size'],hashlib.sha256(s.data()).hexdigest()]for s in elf.iter_sections()if s['sh_flags']&2 and s['sh_type']!='SHT_NOBITS'}
        addresses[tag]=symbols(path)
        checksums[tag]=sha(path)
    for tag in ('base','candidate'):
        if tag=='candidate':
            assert sha(r/'candidate.patch')==maps['prefix']['sha256']
            run('git','-C',base,'apply','--index',r/'candidate.patch')
            assert get('git','-C',base,'write-tree').strip()==maps['prefix']['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        objects[tag]={str(o.relative_to(build)):sha(o)for o in build.rglob('*.c.o')}
        shutil.copy2(lib,w/(tag+'.a'));link(tag,w/(tag+'.a'),{})
    changed={Path(k).name for k,v in objects['base'].items()if v!=objects['candidate'][k]}
    assert changed=={'X86Sse64Output.c.o','X86BatchScan.c.o'}
    first='.cs_x86_i386_text'
    gap=layouts['candidate'][first][0]-layouts['base'][first][0]
    assert 0<gap<4096 and gap%64==0
    short=gap%512;aligned=4096
    link('matched',w/'base.a',{text_section:gap})
    link('i386_only',w/'base.a',{previous:gap})
    link('i386_low',w/'base.a',{previous:short})
    link('page_base',w/'base.a',{previous:aligned})
    link('page_candidate',w/'candidate.a',{previous:aligned-gap})
    watch=[first,'.cs_x86_memory_fallback32_text','.cs_x86_register_fallback32_text']
    for key in watch:
        assert layouts['candidate'][key][:2]==layouts['matched'][key][:2]==layouts['i386_only'][key][:2]
        assert layouts['page_base'][key][:2]==layouts['page_candidate'][key][:2]
        assert layouts['i386_low'][key][0]-layouts['base'][key][0]==short
    for key in ('.cs_x86_native_batch_text','.cs_x86_batch64_text'):
        assert layouts['base'][key][:2]==layouts['i386_only'][key][:2]==layouts['i386_low'][key][:2]
    all_batches={}
    for tag in layouts:
        with (w/tag).open('rb')as f:
            sym=ELFFile(f).get_section_by_name('.symtab')
            all_batches[tag]={k:[[s['st_value'],s['st_size']]for s in sym.get_symbol_by_name(k)]for k in ('X86_scanNativeBatch','scanBatch64','scanBatch32')}
    save('geometry',dict(source=maps,gaps=dict(full=gap,short=short,aligned=aligned),layout=layouts,functions=all_batches,checksums=checksums,objects=objects,compiler=get('clang','--version'),host=get('lscpu')))
    bins={k:(w/k).read_bytes() for k in layouts};bins['duplicate']=bins['base']
    length=max(map(len,bins.values()));bins={k:v.ljust(length,b'\0')for k,v in bins.items()}
    active=w/'selected';active.write_bytes(bins['base']);active.chmod(0o755);inode=active.stat().st_ino
    offsets=[i for i in range(0,length,4096) if len({v[i:i+4096]for v in bins.values()})>1]
    checked={}
    def choose(k):
        with active.open('r+b',buffering=0)as fd:
            for i in offsets:
                fd.seek(i);buf=bins[k][i:i+4096];assert fd.write(buf)==len(buf)
        assert active.stat().st_ino==inode and active.stat().st_size==length
        if k not in checked:
            checked[k]=sha(active);assert checked[k]==hashlib.sha256(bins[k]).hexdigest()
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R',active]
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    rows={};audits={}
    run('clang++','-O2','-std=c++17','-I',base/'include',w/'vectors.cpp',w/'base.a','-o',w/'vectors')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        if name not in ('putty-32-0.85','libssl3t64-i386','jpeg-avx2-i386','libssl3t64-amd64'):continue
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
        expected=audit_engine('base');assert all(audit_engine(k)==expected for k in layouts)
        audits[name]=dict(extents=len(selected),extent_sha256=sha(path),bytes=sum(q[1]for q in selected))
        for mode in (0,1,2):
            def take(k,reps):
                choose(k)
                return list(map(int,get(*invoke,'private',str(mode),str(reps),f,path,str(bits)).split()))
            reps=max(1,math.ceil(25e6/take('base',1)[0]))
            expected={k:take(k,reps)[2:]for k in bins};assert len({tuple(x)for x in expected.values()})==1
            labels=list(bins);rng=random.Random(name+str(mode));pairs=[]
            for _ in range(35):
                rng.shuffle(labels);times={k:[]for k in labels}
                for k in labels+labels[::-1]:
                    ans=take(k,reps);assert ans[2:]==expected[k];times[k].append(ans[:2])
                pairs.append({k:[sum(col)for col in zip(*v)]for k,v in times.items()})
            rows[name+'/'+str(mode)]=dict(reps=reps,checks=expected,pairs=pairs)
            save('paired',rows)
    assert len(checked)==8 and len(rows)==12 and len(audits)==4
    save('complete',dict(complete=True,source=maps,verified=checked,inode=inode,audits=audits))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
