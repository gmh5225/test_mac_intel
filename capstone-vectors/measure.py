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
    gas=w/'gas-adapter';gas.mkdir()
    assert {f:sha(r/f) for f in ('gas.rs','gas_driver.cpp','gas-Cargo.toml')}==rd(r/'gas-sources.json')
    shutil.copyfile(r/'Cargo.lock',gas/'Cargo.lock');shutil.copyfile(r/'gas.rs',gas/'iced.rs')
    (gas/'Cargo.toml').write_text((r/'gas-Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=gas)
    gas_lib=gas/'target/release/libiced_compare.a'
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',r/'gas_driver.cpp','-o',w/'att-bench.o')
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    from elftools.elf.elffile import ELFFile
    sources=rd(r/'cross-source.json')
    images={};symbols={};archives={}
    for tag,z in sources.items():
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        if tag!='shipping':
            patch=r/(tag+'.patch')
            assert sha(patch)==z['sha256'] and z['parent']==sources['shipping']['commit']
            run('git','-C',base,'apply','--index',patch)
        assert get('git','-C',base,'write-tree').strip()==z['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        archives[tag]=sha(lib)
        for syntax,driver,formatter in [('att','att-bench.o',gas_lib),('intel','driver.o',ice_lib)]:
            key=syntax+'/'+tag;exe=w/(syntax+'-'+tag)
            run('clang++',w/driver,lib,formatter,*flags,'-o',exe)
            images[key]=exe.read_bytes();selected={};sections={}
            with exe.open('rb')as stream:
                elf=ELFFile(stream);table=elf.get_section_by_name('.symtab')
                for sym in table.iter_symbols():
                    if sym['st_info']['type']!='STT_FUNC' or not sym['st_size']:continue
                    if not any(t in sym.name for t in ('iced_run','cs_disasm_iter','cs_regs_access','X86_reg_access','PackedMemory','PackedVex64','LegacyPacked64','BareSse64','EvexShiftRegisters','X86_writeATTPadding')):continue
                    idx=sym['st_shndx'];sec=elf.get_section(idx)
                    if idx not in sections:sections[idx]=sec.data()
                    off=sym['st_value']-sec['sh_addr']
                    raw=sections[idx][off:off+sym['st_size']]
                    assert len(raw)==sym['st_size']
                    selected[sym.name]=[sym['st_value'],len(raw),hashlib.sha256(raw).hexdigest()]
            assert {'iced_run','cs_disasm_iter','cs_regs_access','X86_reg_access'}<=set(selected)
            if tag in ('standard','extended'):
                assert 'X86_writeATTPadding' in selected,(key,selected)
            symbols[key]=selected
    save('symbols',symbols)
    hashes={k:hashlib.sha256(v).hexdigest()for k,v in images.items()}
    length=max(map(len,images.values()))
    images={k:v.ljust(length,b'\0')for k,v in images.items()}
    path=w/'selected';shutil.copy2(w/'att-shipping',path);path.write_bytes(images['att/shipping'])
    inode=path.stat().st_ino;verified={};pages=[i for i in range(0,length,4096) if len({v[i:i+4096]for v in images.values()})>1]
    assert pages and len(set(hashes.values()))==len(images)
    def select(tag):
        with path.open('r+b',buffering=0)as f:
            for at in pages:
                part=images[tag][at:at+4096];f.seek(at);assert f.write(part)==len(part)
        assert path.stat().st_ino==inode
        if tag not in verified:
            verified[tag]=sha(path)
            assert verified[tag]==hashlib.sha256(images[tag]).hexdigest()
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    prefix=['setarch',os.uname().machine,'-R',path]
    sys.path.insert(0,str(w));import pe_panels
    run(sys.executable,'-B',w/'libmvec.py')
    meta=rd(w/'libmvec.json')
    putty_records=[row for row in rd(w/'pe-images.json') if row['bits']==32]
    (w/'pe-images.json').write_text(json.dumps(putty_records))
    putty,=pe_panels.prepare(w)
    vec=('libmvec-amd64',64,w/'libmvec.text',[(0,meta['bytes'],meta['address'])],meta)
    host=dict(cpu=get('lscpu'),affinity=sorted(os.sched_getaffinity(0)),source=sources,compiler=get('clang','--version').splitlines()[0],neverd=dev,iced=m['iced_revision'],rust_archives=dict(att=sha(gas_lib),intel=sha(ice_lib)),drivers=rd(r/'gas-sources.json'),archives=archives,images=hashes)
    save('host',host);panels={}
    import frozen_deb
    bits_inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in bits_inputs.items()if n=='libssl3t64-amd64'}))
    ssl,=frozen_deb.prepare(w)
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    for name,bits,blob,spans,_ in (vec,putty,ssl):
        spec=m['provenance'][name]
        spans=[s for s in spans if tuple(s) not in {tuple(a[:3])for a in spec['excluded_incompatible_extents']}]
        ranges=w/(name+'.tsv')
        def emit():ranges.write_text(''.join('%d %d %d\n'%tuple(row)for row in spans))
        emit()
        if m['samples'][name]=='simd-functions':
            views=[list(map(int,z.split()))for z in get(w/'vectors',str(bits),blob,ranges).splitlines()]
            assert len(views)==len(spans)
            spans=[s for s,v in zip(spans,views)if v[1]>=8 and v[1]>=.15*v[0]]
            emit()
        assert sha(blob)==spec['text_sha256'] and sha(ranges)==spec['extent_sha256'] and len(spans)==spec['timed_functions']
        counts=[]
        for key in images:
            select(key)
            aud=[list(map(int,row.split()))for row in get(*prefix,'audit','0','1',blob,ranges,str(bits)).splitlines()]
            assert len(aud)==len(spans) and all(a[1]==a[5] and a[3]==a[4] for a in aud)
            samples=tuple(sum(z[i]for z in aud)for i in (1,3,4,5))
            if counts:assert counts[0]==samples
            counts.append(samples)
        for syntax,engines in [('att',('capstone','iced')),('intel',('private','iced','fast'))]:
            for mode in (1,2):
                def sample(label,n):
                    tag,engine=label.split('/');select(syntax+'/'+tag)
                    res=list(map(int,get(*prefix,engine,str(mode),str(n),blob,ranges,str(bits)).split()))
                    assert len(res)==6 and sum(res[2:4])==n*counts[0][1]
                    return res
                labels=[tag+'/'+engine for tag in sources for engine in engines]
                n=max(1,math.ceil(18e6/min(sample(key,1)[0]for key in labels)))
                expected={k:sample(k,n)[2:]for k in labels}
                assert len({tuple(v[:3])for v in expected.values()})==1
                for engine in engines:
                    assert len({tuple(expected[t+'/'+engine])for t in sources if engine in ('iced','fast')or t!='shipping'})==1
                cycles=[];rng=random.Random(name+'/'+syntax+'/syntax-entry/'+str(mode))
                for _ in range(17):
                    order=labels.copy();rng.shuffle(order);row={k:[0,0]for k in labels}
                    for k in order+order[::-1]:
                        res=sample(k,n);assert res[2:]==expected[k]
                        for clock in (0,1):row[k][clock]+=res[clock]
                    cycles.append(row)
                panels[name+'/'+syntax+'/'+str(mode)]=dict(source_sha256=sha(blob),extents=sha(ranges),repeats=n,checks=expected,cycles=cycles)
                save('observations',panels)
    assert set(verified)==set(images) and len(panels)==12
    save('complete',dict(complete=True,source=sources,panels=sorted(panels),inode=inode,pages=len(pages),staged=verified))
finally:
    amount=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=amount))
