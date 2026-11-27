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
        from subprocess import check_output
        disassembly=check_output(['objdump','-d','--disassemble=X86_reg_access',w/label],text=True)
        body=disassembly.split('<X86_reg_access>:',1)[1].split('Disassembly of section',1)[0].strip()
        assert body
        save('access-body-'+label,dict(disassembly=body,sha256=hashlib.sha256(body.encode()).hexdigest()))

        run('clang','-fPIC','-shared','-I',base/'include',r/'trial-export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(label+'.so'))
        commands=rd(build/'compile_commands.json')
        import shlex
        entry_mask=next(x for x in commands if x['file'].endswith('/X86VectorFallback64.c'))
        args=shlex.split(entry_mask['command'])
        pos=args.index('-o'); del args[pos:pos+2]
        pos=args.index('-c');del args[pos:pos+2]
        obj=w/('mask-'+label+'.o')
        run(*args,'-I',base,'-DOBSERVED_MASKED','-c',r/'masked-oracle.c','-o',obj,cwd=entry_mask['directory'])
        for stem,name in [('masked-oracle','guard'),('masked-census','coverage')]:
            run('clang++','-O2','-std=c++17','-I',base/'include',r/(stem+'.cpp'),obj,lib,'-o',w/(name+'-'+label))
        masked=list(map(int,get(w/('guard-'+label)).split()))
        assert masked[0]>2805764 and masked[1]==0 and masked[2]>500000
        if label!='base':assert masked==rd(e/'masked-guard-base.json')
        save('masked-guard-'+label,masked)

        entry=next(x['command']for x in commands if x['file'].endswith('/X86DisassemblerDecoder.c'))
        assert not any(x in entry for x in ('CAPSTONE_STATIC_X86_READERS','CAPSTONE_X86_ITERATOR_READERS'))
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        with (w/label).open('rb')as f:
            elf=ELFFile(f)
            layout[label]={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest(),sec['sh_flags']] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
    run('clang++','-std=c++17','-O2','-I',base/'include',r/'accumulator-domain.cpp','-ldl','-o',w/'accumulator-domain')
    general={}
    for tag in ('candidate','outlined'):
        result=list(map(int,get(w/'accumulator-domain',w/'base.so',w/(tag+'.so')).split()))
        assert len(result)==2 and result[0]==11069184 and 0<result[1]<result[0]
        general[tag]=result
    assert general['candidate']==general['outlined']
    save('accumulator-domain',general)
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
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    protocol=rd(r/'protocol.json')
    assert {k:images[k]['archive'] for k in ('base','candidate')}==protocol['archives']
    assert images['candidate']==images['outlined'] and images['candidate']!=images['base']
    results={};random_input=platform.node()
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        if bits!=32:continue
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
        assert name in protocol['samples']
        for syntax in protocol['formats']:
            for route in protocol['routes']:
                for mode in protocol['modes']:
                    engine=route+'-att' if syntax=='att' else route
                    def measure(tag,n):
                        select(tag)
                        return list(map(int,get(*invoke,engine,str(mode),str(n),f,path,str(bits)).split()))
                    reps=max(1,math.ceil(protocol['duration_ns']/measure('base',1)[0]))
                    expected=measure('base',reps)[2:];assert all(measure(k,reps)[2:]==expected for k in imgs)
                    key='/'.join((route,syntax,name,str(mode)));rng=random.Random(key+random_input)
                    rows=[];order=list(imgs)
                    for _ in range(protocol['pairs']):
                        rng.shuffle(order);times={k:[]for k in order}
                        for k in order+order[::-1]:
                            got=measure(k,reps);assert got[2:]==expected
                            times[k].append(got[:2])
                        rows.append({k:[a+b for a,b in zip(*v)]for k,v in times.items()})
                    results[key]=dict(reps=reps,expected=expected,pairs=rows);save('observations',results)
    assert len(results)==24 and verified['base']==verified['duplicate']!=verified['candidate']==verified['outlined']
    save('complete',dict(complete=True,protocol=protocol,source=maps,archives=images,verified=verified,cpu=get('lscpu'),node=platform.node(),driver=sha(w/'driver.cpp')))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
