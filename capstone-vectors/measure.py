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
    assert sha(r/'base.patch')==rd(r/'source.json')['base']['sha256']
    run('git','-C',base,'apply','--index',r/'base.patch')
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
    lines=(w/'driver.cpp').read_text().splitlines()
    keep=[line for line in lines if '(void)batch_span<true,X86_scanNativeBatch>' not in line and 'else if(engine=="private"' not in line]
    assert len(keep)==len(lines)-3
    (w/'public-only.cpp').write_text('\n'.join(keep)+'\n')
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'public-only.cpp','-o',w/'public-only.o')
    assert 'X86_' not in get('nm','-u',w/'public-only.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    images={}
    maps=rd(r/'source.json')
    assert maps['prefix']==q and maps['base']['commit']==q['patch_base']
    layout={}
    from elftools.elf.elffile import ELFFile
    for stem in ('real','states','guard'):
        run('clang++','-O2','-std=c++17','-I',base/'include',r/('trial-'+stem+'.cpp'),'-ldl','-o',w/('trial-'+stem))
    from training import fetch
    from foreign_time import measure as time_foreign
    samples=rd(r/'ppc-samples.json')['fixtures'];training=rd(r/'training.json');origin,=(z for z in training if z['arch']=='ppc64el')
    extra=[dict(origin,name=n,command=n.split('-',1)[1],text_sha256=v['sha256'])for n,v in samples.items()if n!=origin['name']]
    docs=w/'corpus-config';docs.mkdir();(docs/'training.json').write_text(json.dumps(training+extra));all_rows=fetch(docs,w)
    foreign_rows=all_rows[:len(training)];save('foreign-corpus',all_rows)
    for row in all_rows:
        if row['arch']=='ppc64el':assert samples[row['name']]['sha256']==row['text_sha256'] and samples[row['name']]['package']==row['package_sha256']
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    marker=w/'native-reference.c'
    marker.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const native_reader = X86_disasmIterText;\n')
    run('clang','-O2','-I',base,'-I',base/'include','-c',marker,'-o',w/'native-reference.o')
    assert 'X86_disasmIterText' in get('nm','-u',w/'native-reference.o')
    for label in ('base','outlined','candidate'):
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        run('git','-C',base,'apply','--index',r/'base.patch')
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
        run(sys.executable,'-B',base/'suite/synctools/alias_mnemonic_trie.py','--check')
        if os.uname().machine=='x86_64':
            run('clang','-std=c11','-O2','-DCAPSTONE_HAS_POWERPC','-DCAPSTONE_HAS_AARCH64','-I',base,'-I',base/'include',r/'parser.c',lib,'-o',w/'parser')
            exact=int(get(w/'parser'));assert exact==275204
            save('alias-parser-'+label,exact)
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
        run('clang++',w/'foreign.o',lib,'-no-pie','-o',w/('foreign-only-'+label))
        run('clang++',w/'foreign.o',w/'native-reference.o',lib,'-no-pie','-o',w/('foreign-'+label))
        run('clang++',w/'public-only.o',lib,ice_lib,*flags,'-o',w/('ordinary-'+label))
        names=('X86_disasmIterText','cs_decode_full_insn','PPC_setAliasId','cs_disasm_iter')
        modes={}
        for route,exe in [('native',w/label),('public_only',w/('ordinary-'+label)),('foreign',w/('foreign-'+label)),('foreign_only',w/('foreign-only-'+label))]:
            with exe.open('rb') as fh:
                elf=ELFFile(fh);tab=elf.get_section_by_name('.symtab');symbols={}
                for name in names:
                    sym=next((x for x in (tab.get_symbol_by_name(name) or []) if x['st_shndx']!='SHN_UNDEF' and x['st_size']>0),None)
                    if sym is not None:symbols[name]=[sym['st_value'],sym['st_info']['bind'],sym['st_other']['visibility']]
                allocated={v.name:[v['sh_addr'],v['sh_size'],hashlib.sha256(v.data()).hexdigest()] for v in elf.iter_sections() if v['sh_flags']&2 and v['sh_type']!='SHT_NOBITS'}
            resolved='X86_disasmIterText' in symbols;assert resolved==(label!='base' or route in ('native','foreign')),(label,route,symbols)
            active=os.uname().machine=='x86_64' and label!='base'
            assert ('PPC_setAliasId' in symbols)==(os.uname().machine=='x86_64')
            modes[route]=dict(symbols=symbols,allocated=allocated)
        save('link-mode-'+label,modes)
        run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/'memory-test-guard.cpp',lib,'-o',w/'test-guard')
        guarded=list(map(int,get(w/'test-guard').split()))
        assert len(guarded)==3 and 0<guarded[1]<guarded[0] and guarded[0]==6979584
        if label!='base':assert guarded==rd(e/'memory-boundary-base.json')
        save('memory-boundary-'+label,guarded)
        functions=['cs_decode_full_insn','X86_decodeMixedPublicRecord','cs_disasm_iter','X86_disasmIterText','X86_decodeFixedRecord32','X86_decodeFixedRecord64']
        data={}
        for link in ('','ordinary','foreign','foreign-only'):
            path=w/((link+'-' if link else '')+label)
            nm=get('nm','-S','--defined-only',path).splitlines()
            data[link]={fields[3]:fields[:2] for line in nm if len(fields:=line.split())==4 and fields[3] in functions}
        save('public-functions-'+label,data)
        original=(r/'memory-test-guard.cpp').read_text()
        assert original.count('X86_disasmIterText(a,')==1
        (w/'public-guard.cpp').write_text(original.replace('X86_disasmIterText(a,','cs_disasm_iter(a,'))
        run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',w/'public-guard.cpp',lib,'-o',w/'public-guard')
        values=list(map(int,get(w/'public-guard').split()))
        assert values==rd(e/('memory-boundary-'+label+'.json'))
        save('public-guard-'+label,values)
        save('program-hashes-'+label,{key:sha(w/((key+'-' if key else '')+label)) for key in ('','ordinary','foreign','foreign-only')})
        if os.uname().machine=='x86_64' and label!='base':
            assembly={name:get('objdump','-d','--no-show-raw-insn','--disassemble='+name,w/label) for name in ('PPC_printer','PPC_setAliasId')}
            save('record-assembly-'+label,assembly)

        from symbol_layout import symbols
        section_data={str(x.relative_to(build)):sha(x) for x in build.rglob('*.c.o')}
        for stem,unit in [('fallback','X86VectorFallback64.c.o'),('vector','X86VectorOutput.c.o'),('immediate','X86VexRegisterImmediate.c.o')]:
            obj,=build.rglob(unit)
            with obj.open('rb') as f:
                elf=ELFFile(f)
                sections={sec.name:[sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()]
                    for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
                save(stem+'-object-'+label,sections)
        if label=='candidate':
            run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',base/'suite/synctools/x86_vector_output.cpp',lib,'-o',w/'vector-generator')
            generated={}
            for args,name in [(('--vex-base-memory',),'X86GenVexBaseMemory.inc'),((),'X86GenVectorOutput.inc')]:
                projection=sp.check_output([w/'vector-generator',*args])
                assert projection==(base/'arch/X86'/name).read_bytes()
                generated[name]=dict(bytes=len(projection),sha256=hashlib.sha256(projection).hexdigest())
            save('generated-vector-rows',generated)
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
        run('clang++','-O2','-std=c++17','-I',base,'-I',base/'include',r/'sib.cpp',lib,'-o',w/'sib-guard')
        guard=list(map(int,get(w/'sib-guard').split()));assert guard[0]==4718592 and 0<guard[1]<guard[0]
        save('sib-'+label,guard)
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        with (w/label).open('rb')as f:
            elf=ELFFile(f)
            layout[label]={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest(),sec['sh_flags']] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
    for k in ('ppc-states','real-ppc'):run('clang++','-std=c++17','-O2','-I',base/'include',r/(k+'.cpp'),'-ldl','-o',w/k)
    guardians=get(w/'ppc-states',w/'base.so',w/'candidate.so','2048').strip()
    assert '733952' in guardians,guardians
    exact={name:[get(w/'real-ppc',w/'base.so',w/'candidate.so',w/(name+'.text'),str(mode)).splitlines() for mode in range(4)]for name in samples}
    save('ppc-exact',dict(guard=guardians,records=exact))
    run('clang++','-std=c++17','-O2','-I',base/'include',r/'vex3-domain.cpp','-ldl','-o',w/'vex3-domain')
    general={}
    for tag in ('candidate','outlined'):
        result=list(map(int,get(w/'vex3-domain',w/'base.so',w/(tag+'.so')).split()))
        assert len(result)==3 and result[0]==8*256*3*10*16*12 and 0<result[2]<result[1]<result[0]
        general[tag]=result
    assert general['candidate']==general['outlined']
    save('vex3-domain',general)
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
        mask_counts={label:list(map(int,get(w/('coverage-'+label),f,path,str(bits)).split())) for label in ('base','candidate','outlined')}
        assert mask_counts['base']==mask_counts['candidate']==mask_counts['outlined']
        save('masked-real-'+name,mask_counts)

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
        ordinary=rd(e/'public-only-records.json') if (e/'public-only-records.json').exists() else {}
        ordinary[name]={}
        for stage in images:
            ordinary[name][stage]=[list(map(int,get('setarch',os.uname().machine,'-R',w/('ordinary-'+stage),'capstone',str(mode),'1',f,path,str(bits)).split()))[2:]for mode in (0,1,2)]
        assert ordinary[name]['base']==ordinary[name]['outlined']==ordinary[name]['candidate']
        save('public-only-records',ordinary)

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
    time_foreign(foreign_rows,w,save,'foreign-only')
    programs=[dict(name=name,bits=bits,image=path,extents=w/(name+'.tsv')) for name,bits,path,_,_ in fixtures]
    def ordinary_args(row,mode,n):
        return ['capstone',str(mode),str(n),row['image'],row['extents'],str(row['bits'])]
    time_foreign(programs,w,save,'ordinary',ordinary_args,18)
    for style,source in [('ppc-linked','foreign'),('ppc-only','foreign-only')]:
        for tag in ('base','candidate','outlined'):os.link(w/(source+'-'+tag),w/(style+'-'+tag))
        time_foreign(all_rows[len(training):],w,save,style,expected_cases=9)
    save('complete',dict(complete=True,source=q,host=host,images=images,pairs=17,samples=audits,unit='Paired throughput, Public cs_disasm_iter and the native batch / text routes. One same-inode fixed-address executable on one logical CPU, both baseline controls and all three library trees, exact output equality.'))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
