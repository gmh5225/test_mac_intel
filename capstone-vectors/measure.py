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
    alias_section='.cs_alias_lookup'
    last_section='.cs_x86_batch64_text'
    sections={k:'ax' for k in (text_section,alias_section,'.cs_x86_native_batch_text','.cs_x86_batch32_text',last_section)}
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
    assert {Path(k).name for k,v in objects['base'].items()if v!=objects['candidate'][k]}=={'X86Sse64Output.c.o','X86Vex32Output.c.o'}
    base_layout=layouts['base'];candidate=layouts['candidate']
    gap=base_layout[text_section][1]-candidate[text_section][1]
    scan_sections=('.cs_x86_native_batch_text','.cs_x86_batch32_text',last_section)
    assert gap==16 and all(base_layout[k][0]-candidate[k][0]==gap for k in scan_sections)
    for name,section in [('matched',text_section),('before_scan',alias_section),('after_entry',scan_sections[0]),('after_i386',scan_sections[1]),('after_scan',last_section)]:
        link(name,w/'candidate.a',{section:gap})
    scanner=('X86_scanNativeBatch','scanBatch32','scanBatch64')
    for entry in scanner:
        assert addresses['base'][entry]==addresses['matched'][entry]
        for tag,ref in [('before_scan','matched'),('after_scan','candidate')]:
            f=addresses[tag][entry][0];g=addresses[ref][entry][0]
            assert (f['address'],f['size'])==(g['address'],g['size'])
    functions={}
    for tag in layouts:
        with (w/tag).open('rb')as f:
            tab=ELFFile(f).get_section_by_name('.symtab')
            functions[tag]=sorted((s.name,s['st_value'],s['st_size']) for s in tab.iter_symbols() if s['st_info']['type']=='STT_FUNC' and s['st_size'])
    def nonscan(tag):
        lo=layouts[tag][scan_sections[0]][0];end=sum(layouts[tag][last_section][:2])
        return [x for x in functions[tag] if not lo<=x[1]<end]
    assert nonscan('before_scan')==nonscan('after_scan')
    movable=[(b,a)for b,a in zip(functions['before_scan'],functions['after_scan']) if b!=a]
    assert movable and all(b[0]==a[0] and b[1]-a[1]==gap and b[2]==a[2] for b,a in movable)
    assert all(layouts['before_scan'][k][0]==layouts['after_scan'][k][0] for k in base_layout if k not in scan_sections)
    for section in ('.cs_x86_vector_fallback64_text','.cs_x86_i386_text','.cs_x86_native_batch_rodata'):
        assert layouts['base'][section][:2]==layouts['matched'][section][:2]
    partitions={}
    for earlier,later in [('before_scan','after_entry'),('after_entry','after_i386'),('after_i386','after_scan')]:
        diffs=[(x,y) for x,y in zip(functions[earlier],functions[later]) if x!=y]
        assert diffs and all(b[0]==a[0] and b[1]-a[1]==gap and b[2]==a[2] for b,a in diffs)
        partitions[earlier+'/'+later]=[b[0] for b,a in diffs]
    assert sorted(k for names in partitions.values() for k in names)==sorted(b[0] for b,a in movable)
    assert partitions['after_entry/after_i386']==['scanBatch32'] and partitions['after_i386/after_scan']==['scanBatch64']
    save('geometry',dict(partitions=partitions,source=maps,gap=gap,layout=layouts,functions={k:{s:addresses[k][s] for s in scanner} for k in layouts},moved_functions=movable,other_functions=len(nonscan('before_scan')),checksums=checksums,objects=objects,compiler=get('clang','--version'),cpu=get('lscpu')))
    bins={k:(w/k).read_bytes() for k in layouts};bins['duplicate']=bins['after_i386']
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
    from probe import hardware
    from contextlib import ExitStack
    with ExitStack() as stack:
        groups,pmu=stack.enter_context(hardware(r,w,save))
        for name,bits,f,spans,_ in fixtures:
            if name not in ('libssl3t64-i386','putty-32-0.85'):continue
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
            for mode in (0,):
                def take(k,reps):
                    choose(k)
                    return list(map(int,get(*invoke,'private',str(mode),str(reps),f,path,str(bits)).split()))
                reps=max(1,math.ceil(25e6/take('base',1)[0]))
                expected={k:take(k,reps)[2:]for k in bins};assert len({tuple(x)for x in expected.values()})==1
                series={}
                def blocks(label,n,reader):
                    labels=['after_entry','after_i386','duplicate']
                    rng=random.Random(name+'/'+label);out=[]
                    for _ in range(n):
                        rng.shuffle(labels);pair={}
                        for tag in labels+labels[::-1]:
                            got=reader(tag)
                            if tag in pair:
                                for k,value in got.items():pair[tag][k]+=value
                            else:pair[tag]=got
                        out.append(pair)
                    series[label]=out
                def timed(tag):
                    v=take(tag,reps);assert v[2:]==expected[tag]
                    return dict(cpu_ns=v[0],wall_ns=v[1])
                blocks('timing',17,timed)
                for g,events in groups.items():
                    def read_counters(tag):
                        choose(tag)
                        ok,counts,stdout,diag=pmu(events,[active,'private',str(mode),str(reps),f,path,str(bits)])
                        assert ok and list(map(int,stdout.split()))[2:]==expected[tag],(g,tag,diag)
                        return counts
                    blocks(g,13,read_counters)
                rows[name]=dict(reps=reps,checks=expected,series=series)
                save('paired',rows)
    assert len(checked)==8 and len(rows)==2 and len(audits)==2
    save('complete',dict(complete=True,source=maps,verified=checked,inode=inode,audits=audits))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
