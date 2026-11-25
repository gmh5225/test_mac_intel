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
    mixed=w/'mixed'
    run('cmake','-G','Ninja','-S',project,'-B',mixed,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    options=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    run('cmake','-G','Ninja','-S',base,'-B',build,*options)
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'X86PublicOutput.c','X86Sse64Output.c'}<=files and not {'MipsMapping.c','ARMMapping.c'}&files
    mixed_hashes={}
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
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',r/'gas_driver.cpp','-o',w/'gas-driver.o')
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    images={}
    maps=rd(r/'source.json')
    assert maps['prefix']==q and maps['base']['commit']==q['parent']
    layout={}
    from elftools.elf.elffile import ELFFile
    for stem in ('real','states','guard'):
        run('clang++','-O2','-std=c++17','-I',base/'include',r/('trial-'+stem+'.cpp'),'-ldl','-o',w/('trial-'+stem))
    from training import fetch
    from foreign_time import measure as time_foreign
    foreign_rows=fetch(r,w);save('foreign-corpus',foreign_rows)
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    for label in ('base','outlined','candidate'):
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        assert get('git','-C',base,'write-tree').strip()==maps['base']['tree']
        if label=='outlined':
            assert sha(r/'outlined.patch')==maps['outlined']['sha256']
            run('git','-C',base,'apply','--index',r/'outlined.patch');assert get('git','-C',base,'write-tree').strip()==maps['outlined']['tree']
        if label=='candidate':
            assert sha(r/'candidate.patch')==q['sha256']
            run('git','-C',base,'apply','--index',r/'candidate.patch');assert get('git','-C',base,'write-tree').strip()==q['tree']
        run(sys.executable,'-B',base/'suite/synctools/x86_printer_dispatch.py','--check')
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++','-O2','-std=c++17','-I',base/'include',base/'suite/synctools/x86_simple_output.cpp',lib,'-o',w/'generator')
        table=base/'arch/X86/X86GenSimpleOutput.inc'
        assert sp.check_output([w/'generator'])==table.read_bytes()
        if label=='base':projections={}
        projections[label]=sha(table)
        assert len(set(projections.values()))==1
        save('generated-plans',projections)
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/label)
        run('clang++',w/'gas-driver.o',lib,gas_lib,*flags,'-o',w/('att-'+label))
        run('cmake','--build',mixed,'--target','capstone_static','--parallel','4')
        archive,=mixed.rglob('libcapstone.a');objs={str(f.relative_to(mixed)):sha(f) for f in mixed.rglob('*.c.o')}
        assert len(objs)>45 and any('ARMMapping.c.o' in name for name in objs)
        run('clang++',w/'foreign.o',archive,'-no-pie','-o',w/('foreign-'+label))
        mixed_hashes[label]=dict(objects=objs,archive=sha(archive),exe=sha(w/('foreign-'+label)))
        save('mixed-identities',mixed_hashes);assert mixed_hashes[label]==mixed_hashes['base'],label
        from symbol_layout import symbols
        section_data = {str(x.relative_to(build)):sha(x) for x in build.rglob('*.c.o')}
        assert 20<=len(section_data)<len(objs)
        save('code-'+label,dict(objects=section_data,functions=symbols(w/label)))
        run('clang','-fPIC','-shared','-I',base/'include',r/'trial-export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(label+'.so'))
        commands=rd(build/'compile_commands.json')
        entry=next(x['command']for x in commands if x['file'].endswith('/X86DisassemblerDecoder.c'))
        assert 'CAPSTONE_X86_ONLY' in entry
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        with (w/label).open('rb')as f:
            elf=ELFFile(f)
            layout[label]={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest(),sec['sh_flags']] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
    save('linked-sections',layout)
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
    mode_probe={};probe=w/'probe.bin';probe.write_bytes(bytes.fromhex('66 b8 78 56 34 12'))
    span=w/'probe.tsv';span.write_text('0 6 1048576'+chr(10))
    for tag in images:
        select(tag)
        for engine in ('iced','capstone','private'):
            counts=[list(map(int,get(*invoke,engine,'0','1',probe,span,str(bits)).split()))[2:4] for bits in (16,32,64)]
            assert counts==[[1,0],[2,0],[2,0]],(tag,engine,counts)
            mode_probe[tag+'/'+engine]=counts
    save('mode-probe',mode_probe)
    cpu=(get('sysctl','-n','machdep.cpu.brand_string').strip() if sys.platform=='darwin' else get('lscpu'))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    run('clang++','-std=c++17','-O2','-I',base/'include',r/'trial-vector-guard.cpp','-ldl','-o',w/'trial-vector-guard')
    run('clang++','-O2','-std=c++17','-I',base/'include',r/'prefix-guard.cpp','-ldl','-o',w/'prefix-guard')
    proof={}
    for label in ('candidate','outlined'):
        proof[label]=list(map(int,get(w/'prefix-guard',w/'base.so',w/(label+'.so')).split()))
        assert proof[label][0]>1000000 and 0<proof[label][1]<proof[label][0]
    assert proof['outlined']==proof['candidate'];save('prefix-guard',proof)
    guards={};records={}
    for lbl in ('candidate','outlined'):
        parts=sp.run([w/'trial-states',w/'base.so',w/(lbl+'.so'),'2048'],text=True,capture_output=True)
        guards[lbl]=dict(states=parts.stderr.count('case arch='),status=parts.returncode,stderr=parts.stderr.splitlines()[-8:])
        save('extra-states',guards)
        assert parts.returncode==0 and guards[lbl]['states']==48
        z=get(w/'trial-guard',w/'base.so',w/(lbl+'.so')).split()
        assert z==['2162688','999139'];guards[lbl]['scan']=[int(x)for x in z]
        guards[lbl]['vector_guard']=json.loads(get(w/'trial-vector-guard',w/'base.so',w/(lbl+'.so')))
        save('extra-states',guards)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host=dict(capstone=m['checkout_commit'],neverd=dev,iced=m['iced_revision'],cpu=cpu,compiler=get('clang','--version').splitlines()[0],os=platform.platform(),images=images,driver_sha256=sha(w/'driver.cpp'),rust_sha256=sha(ad/'iced.rs'))
    save('host',host);observations={};summary={};audits={}
    from att_timing import start
    time_gas,att_images=start(w);att_rows={}
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {x[0] for x in fixtures}==set(m["samples"])
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
        def audit_engine(exe):
            rows=[list(map(int,z.split())) for z in get(w/exe,'audit','0','1',f,path,str(bits)).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            return rows
        assert audit_engine('base')==audit_engine('outlined')==audit_engine('candidate')
        audits[name]=dict(functions=len(selected),bytes=spec['bytes'],extent_sha256=sha(path));save('audit',audits)
        records[name]={}
        for lbl in ('candidate','outlined'):
            vals=[]
            for route_id in range(8):
                v=list(map(int,get(w/'trial-real',w/'base.so',w/(lbl+'.so'),f,path,str(bits),str(route_id)).split()))
                assert v[0]>0 and all(x==v[:4] for x in vals);vals.append(v[:4])
            assert vals[0][2]==spec['bytes']
            records[name][lbl]=vals[0]
        save('extra-real',records)
        for route in ('capstone','private'):
            for detail in (0,1):
                key=name+'/'+route+'/'+str(detail+1)
                att_rows[key]=time_gas(name,bits,f,path,detail,route)
                save('att-same-image',att_rows);save('att-images',att_images)

        for route in ('private','capstone'):
            def take(engine,mode,n):
                other=engine in ('iced','fast')
                select('base' if other else engine)
                return list(map(int,get(*invoke,engine if other else route,str(mode),str(n),f,path,str(bits)).split()))
            for mode in (0,1,2):
                labels=[*imgs,'iced'] + (['fast'] if mode else [])
                repeats=max(1,math.ceil(30e6/take('base',mode,1)[0]))
                expected={k:take(k,mode,repeats)[2:]for k in labels}
                assert all(v[:3]==expected['base'][:3] for v in expected.values())
                assert expected['base']==expected['duplicate']==expected['candidate']
                assert expected['outlined']==expected['base']
                rows=[];rng=random.Random(name+'/immediate-byte-pairs/'+str(mode))
                for _ in range(35 if (name,mode)==('jpeg-avx2-i386',2) else 17):
                    rng.shuffle(labels);sample={k:[] for k in labels}
                    for k in labels+labels[::-1]:
                        row=take(k,mode,repeats);assert row[2:]==expected[k]
                        sample[k].append(row[:2])
                    rows.append({k:[sum(a[i]for a in times)for i in (0,1)]for k,times in sample.items()})
                key=route+'/'+name+'/'+str(mode);observations[key]=dict(repeats=repeats,checks=expected,cycles=rows)
                summary[key]={label:{k:interval([x[k][i]/x['candidate'][i]for x in rows])for k in labels if k!='candidate'}for i,label in enumerate(('cpu','wall'))}
                save('effects',summary);save('observations',observations);print(key,summary[key]['cpu']['base'],flush=True)
    assert len(summary)==36
    from firmware16 import compare
    sources=rd(r/'input-sources.json');assert sha(r/'scalar.c')==sources['c_sha']
    run('clang',*sources['compile'],r/'scalar.c','-o',w/'scalar.o')
    with (w/'scalar.o').open('rb')as f:
        elf=ELFFile(f);assert elf['e_machine']=='EM_386';blob=elf.get_section_by_name('.text').data()
    path=w/'scalar16.bin';path.write_bytes(blob);spans=w/'scalar16.tsv';spans.write_text(f'0 {len(blob)} 1048576'+chr(10))
    scalar=compare(path,spans,imgs,invoke,select)
    save('scalar16',dict(sha256=sha(path),bytes=len(blob),source=sources['c_sha'],results=scalar))
    save('fixed-image',dict(inode=inode,blocks=len(offsets),verified=verified,bytes=length,original_sizes=original_sizes,staged_sha256={k:hashlib.sha256(v).hexdigest()for k,v in imgs.items()}))
    if platform.machine()=='x86_64':
        from firmware16 import verify
        save('seabios16',verify(w,imgs,invoke,select))
    time_foreign(foreign_rows,w,save)
    save('complete',dict(complete=True,source=q,host=host,images=images,pairs=17,samples=audits,unit='Paired throughput, Public cs_disasm_iter and the native batch / text routes. One same-inode fixed-address executable on one logical CPU, both baseline controls and all three library trees, exact output equality.'))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
