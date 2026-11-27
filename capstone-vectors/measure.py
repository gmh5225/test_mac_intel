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
        run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',r/'clear.cpp',lib,'-o',w/'check-clear')
        if label!='base' and os.uname().machine=='x86_64':
            run(sys.executable,'-B',base/'suite/synctools/x86_operand_specializations.py','--check')
        check=list(map(int,get(w/'check-clear').split()))
        assert check[0]==1769472 and 0<check[1]<check[0]
        save('clear-'+label,check)
        run('clang','-std=c99','-O2','-I',base,'-I',base/'include',r/'map.c',lib,'-o',w/'map')
        domain=list(map(int,get(w/'map').split()));assert sum(domain[:3])==65536 and domain[1]==64
        save('map-domain-'+label,domain)
        run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',r/'register-records.cpp',lib,'-o',w/'register-records')
        rows=get(w/'register-records').splitlines()
        assert len(rows)==8 and all(int(v.split()[0]) and int(v.split()[1]) for v in rows)
        if label!='base':assert rows==rd(e/'gpr-records-base.json'),(label,rows)
        save('gpr-records-'+label,rows)
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/label)
        run('clang++',w/'foreign.o',lib,'-no-pie','-o',w/('foreign-'+label))
        from symbol_layout import symbols
        section_data = {str(x.relative_to(build)):sha(x) for x in build.rglob('*.c.o')}
        assert len(section_data)>=45
        save('code-'+label,dict(objects=section_data,functions=symbols(w/label)))
        run('clang','-O2','-fPIC','-shared','-I',base/'include',r/'trial-export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(label+'.so'))
        commands=rd(build/'compile_commands.json')
        entry=next(x['command']for x in commands if x['file'].endswith('/X86DisassemblerDecoder.c'))
        assert not any(x in entry for x in ('CAPSTONE_STATIC_X86_READERS','CAPSTONE_X86_ITERATOR_READERS'))
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        with (w/label).open('rb')as f:
            elf=ELFFile(f)
            layout[label]={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest(),sec['sh_flags']] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
    for driver in ('access','query'):
        run('clang++','-O2','-std=c++17','-I',base/'include',r/(driver+'.cpp'),'-ldl','-o',w/driver)
    checks={tag:list(map(int,get(w/'access',w/'base.so',w/(tag+'.so')).split())) for tag in ('candidate','outlined')}
    assert checks['candidate']==checks['outlined'] and checks['candidate'][0]==1920000
    save('access-domain',checks)
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
    run('clang++','-O2','-std=c++17','-I',base/'include',r/'cmov-guard.cpp','-ldl','-o',w/'cmov-guard')
    proof={}
    for label in ('candidate','outlined'):
        proof[label]=list(map(int,get(w/'cmov-guard',w/'base.so',w/(label+'.so')).split()))
        assert proof[label][0]>1000000 and 0<proof[label][1]<proof[label][0]
    assert proof['outlined']==proof['candidate'];save('cmov-guard',proof)
    run('clang++','-O2','-std=c++17','-I',base/'include',r/'rip.cpp','-ldl','-o',w/'rip')
    outcomes={}
    for label in ('candidate','outlined'):
        z=sp.run([w/'rip',w/'base.so',w/(label+'.so')],capture_output=True,text=True)
        assert z.returncode==0,(label,z.stderr[-1000:])
        outcomes[label]=json.loads(z.stdout)
    assert outcomes['candidate']==outcomes['outlined'] and outcomes['candidate']['cases']==820176
    save('rip-record',outcomes)
    guards={};records={}
    for lbl in ('candidate','outlined'):
        parts=sp.run([w/'trial-states',w/'base.so',w/(lbl+'.so'),'2048'],text=True,capture_output=True)
        guards[lbl]=dict(states=parts.stderr.count('case arch='),status=parts.returncode,stderr=parts.stderr.splitlines()[-8:])
        save('extra-states',guards)
        assert parts.returncode==0 and guards[lbl]['states']==464
        z=get(w/'trial-guard',w/'base.so',w/(lbl+'.so')).split()
        assert z==['2162688','999139'];guards[lbl]['scan']=[int(x)for x in z]
        guards[lbl]['vector_guard']=json.loads(get(w/'trial-vector-guard',w/'base.so',w/(lbl+'.so')))
        save('extra-states',guards)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host=dict(capstone=m['checkout_commit'],neverd=dev,iced=m['iced_revision'],cpu=cpu,compiler=get('clang','--version').splitlines()[0],os=platform.platform(),images=images,driver_sha256=sha(w/'driver.cpp'),rust_sha256=sha(ad/'iced.rs'))
    save('host',host);observations={};summary={};audits={}
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
        replay=list(map(str.split,get(*invoke[:-1],w/'query',w/'base.so',w/'candidate.so',w/'outlined.so',f,path,str(bits)).splitlines()))
        grouped={}
        target=rd(r/'query-cases.json')[name]
        expected_counts=[target[0],target[1],target[0]-target[1]]
        for group in range(3):
            series=[z for z in replay if int(z[0])==group]
            meta={tuple(int(z[i]) for i in (3,4,5,6,9)) for z in series}
            assert len(series)==17*4 and len(meta)==1
            g,=meta
            assert g[0]==expected_counts[group] and g[1]==min(512,g[0])
            blocks=[{z[2]:[int(z[7]),int(z[8])] for z in series if int(z[1])==i} for i in range(17)]
            assert all(set(row)=={'base','duplicate','candidate','outlined'} and all(min(v)>0 for v in row.values()) for row in blocks)
            grouped[group]=dict(population=g[0],sample=g[1],identity=g[2],repeats=g[3],digest=g[4],pairs=blocks)
        save('query-'+name,grouped)
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
                rows=[];rng=random.Random(name+'/independent-alignment-repeat/'+str(mode))
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
