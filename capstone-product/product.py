from pathlib import Path
import hashlib,json,os,random,shutil,statistics,subprocess as sp,sys,tempfile
import corpus,avx_corpus,load_ssl
r=Path(__file__).resolve().parent;nd=r.parent/'neverd';out=r.parent/'product-evidence';out.mkdir(exist_ok=True)
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project'
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
    print(label,flush=True)
    with (out/(label+'.log')).open('w')as f:z=sp.run(list(map(str,args)),stdout=f,stderr=sp.STDOUT,cwd=cwd)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-3500:],flush=True);z.check_returncode()
def git(path,*args):return sp.check_output(['git','-C',path,*args],text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
m=json.loads((r/'source.json').read_text());dev=m['dev']
assert git(nd,'rev-parse','HEAD')==dev and git(cs,'rev-parse','HEAD')==m['checkout']
for k in ('base','layout','selector','oracle'):assert sha(r/(k+'.patch'))==m[k]['sha256']
assert git(cs,'write-tree')==git(cs,'rev-parse','HEAD^{tree}')
llvm=git(ll,'rev-parse','HEAD');remote=git(ll,'ls-remote','origin','refs/heads/main').split()[0];assert llvm==remote
save('source',dict(m,llvm=llvm,main_at_start=remote,prebuilt=False))
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    build=t/'build';cases=corpus.prepare(r,t,out,command)
    foreign=[z for z in cases if z['name'].startswith(('arm64-','mips64el-'))]
    selected={'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','arm-ls','ppc64el-ls','riscv64-ls'}
    cases=[c for c in cases if c['name'] in selected]
    assert {c['name']for c in cases}==selected
    specs=json.loads((r/'mips-samples.json').read_text())['fixtures']
    ls=next(c for c in cases if c['name']=='mips64el-ls');pkg=t/'corpus'/ls['package_sha256']
    for name,spec in specs.items():
        assert sha(pkg)==spec['package'];elf=corpus.deb_binary(pkg,spec['command'])
        assert corpus.digest(elf)==spec['binary_sha256'];data=corpus.elf_text(elf)
        assert corpus.digest(data)==spec['sha256']
        if name==ls['name']:assert ls['text_sha256']==spec['sha256'];continue
        dest=t/(name+'.text');dest.write_bytes(data)
        case=dict(name=name,path=str(dest),selector=4,text_sha256=spec['sha256']);cases.append(case)
        if not any(x['name']==name for x in foreign):foreign.append(case)
    save('mips-inputs',specs)
    rv=next(c for c in cases if c['name']=='riscv64-ls')
    elf=corpus.deb_binary(t/'corpus'/rv['package_sha256'],'ls')
    assert corpus.digest(elf)==rv['binary_sha256'] and corpus.digest(corpus.elf_text(elf))==rv['text_sha256']
    assert elf[:6]==b'\x7fELF\x02\x01' and int.from_bytes(elf[48:52],'little')&1
    assert b'rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_' in elf
    save('new-architectures',dict(riscv=rv['binary_sha256'],ppc=next(c['binary_sha256'] for c in cases if c['name']=='ppc64el-ls')))
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(r/f,t/f)
    command([sys.executable,t/'libmvec.py'],'libmvec')
    glibc=json.loads((t/'libmvec.json').read_text());cases.append(dict(name='libmvec-amd64',selector=64,path=str(t/'libmvec.text'),text_sha256=glibc['text_sha256']))
    cases.append(avx_corpus.prepare(r,t,out,command))
    data=load_ssl.prepare(r,t,out,command)
    cases.append(data)
    shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp')
    with (nd/'CMakeLists.txt').open('a') as f:f.write('\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
    command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
    assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF'in (build/'CMakeCache.txt').read_text()
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests'];products={};identities={}
    from elftools.elf.elffile import ELFFile
    decoder=nd/'lib/decode/X86/X86Decoder.cpp'
    for variant in ('base','layout','selector'):
        command(['git','restore','--source','HEAD','--staged','--worktree','--','.'],'restore-'+variant,cs)
        assert git(cs,'rev-parse','HEAD')==m['base']['commit']
        if variant!='base':command(['git','apply','--index',r/(variant+'.patch')],'apply-'+variant,cs)
        caller='lib/decode/Decoder.cpp'
        entry='X86_disasmIterText'
        assert entry+'(Handle' in (nd/caller).read_text()
        actual=git(cs,'write-tree');assert actual==m[variant]['tree'] and 'return X86_scanNativeBatch(' in decoder.read_text()
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+variant,nd)
        assert git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        assert git(cs,'write-tree')==actual and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(variant+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+variant)
        binary,=build.rglob('capstone-product');products[variant]=t/(variant+'-product');shutil.copy2(binary,products[variant])
        names=sp.check_output(['nm','--defined-only',binary],text=True).splitlines()
        hot=['cs_disasm_iter','cs_regs_access','cs_decode_full_insn','X86_scanNativeBatch','X86_disasmIterText','X86_getInstruction','X86_Vex','AArch64_getInstruction','ARM_getInstruction','Mips_getInstruction','PPC_getInstruction','RISCV_getInstruction','X86_tryATTOutput']
        positions={x.split()[-1]:int(x.split()[0],16) for x in names if len(x.split())==3 and x.split()[-1] in hot}
        assert {'cs_disasm_iter','cs_regs_access','X86_scanNativeBatch','X86_disasmIterText'}<=positions.keys()
        save('hot-symbols-'+variant,positions)
        assert any(x.split()[-1]=='X86_scanNativeBatch' for x in names if x.split())
        archive,=build.rglob('libcapstone.a')
        assert all(list(build.rglob(n+'.c.o')) for n in ('PPCMapping','RISCVMapping','X86Mapping','MipsMapping','ARMMapping','AArch64Mapping'))
        command(['clang++','-std=c++17','-O2','-I',cs/'include',r/'offset.cpp',archive,'-o',t/'offset'],'link-offset-'+variant)
        vals=sp.check_output([t/'offset'],text=True).strip().splitlines();assert len(vals)==48
        assert vals==json.loads((r/'offset-expected.json').read_text())['base'].splitlines()
        save('absolute-offsets-'+variant,vals)
        command(['clang++','-std=c++17','-O2','-I',cs/'include',r/'moffs.cpp',archive,'-o',t/'moffs'],'link-moffs-'+variant)
        counts=list(map(int,sp.check_output([t/'moffs'],text=True,stderr=sp.DEVNULL).split()))
        assert counts==[11520,864,0],(variant,counts)
        save('moffs-'+variant,counts)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'alias-raw.cpp',archive,'-o',t/'alias-raw'],'link-alias-'+variant)
        records={}
        for z in foreign:
            for option in range(5):
                result=list(map(int,sp.check_output([t/'alias-raw','arm'if z['name'].startswith('arm64-')else 'mips',z['path'],str(option)]).split()))
                assert len(result)==4 and result[0]>0
                records[z['name']+'/'+str(option)]=result
        assert len(records)>=10
        if variant=='base':base_records=records
        else:assert base_records==records
        save('alias-records-'+variant,records)
        command(['clang','-O2','-I',cs/'include',r/'probe.c',archive,'-o',t/'mask-access'],'verify-build-'+variant)
        command([t/'mask-access'],'verify-memory-'+variant)
        assert (out/('verify-memory-'+variant+'.log')).read_text().strip()=='3120 encodings and syntax cases, 0 incorrect memory accesses, 0 incorrect shapes'
        test=out/('tests-'+variant+'.log')
        assert '100% tests passed' in test.read_text()
        if variant=='base':
            import frozen_ssl64
            name,bits,path,spans,metadata=next(iter(frozen_ssl64.prepare(t)));q=json.loads((r/'ssl64-extents.json').read_text())
            assert name=='libssl3t64-amd64' and bits==64 and len(spans)==q['input_functions'] and sha(path)==q['text_sha256']
            intervals=t/'openssl-amd64.tsv';intervals.write_text(''.join('%d %d %d\n'%s for s in spans))
            command(['clang++','-O2','-I',cs/'include',r/'vectors.cpp',archive,'-o',t/'vectors'],'vectors')
            views=[list(map(int,x.split()))for x in sp.check_output([t/'vectors','64',path,intervals],text=True).splitlines()]
            assert len(views)==len(spans)
            skip={tuple(s[:3]) for s in q['excluded_incompatible_extents']}
            chosen=[z for z,(total,vectors) in zip(spans,views)if tuple(z)not in skip and vectors>=8 and vectors>=.15*total]
            intervals.write_text(''.join('%d %d %d\n'%s for s in chosen));assert len(chosen)==320 and sha(intervals)==q['extent_sha256']
            cases.append(dict(name=name,selector=bits,path=str(path),intervals=str(intervals),text_sha256=q['text_sha256']))
            save('openssl64-input',dict(extents=len(chosen),bytes=sum(n for _,n,_ in chosen),input=q))

        code_sections={}
        for name in ('X86VectorFallback64.c.o','X86Sse64Output.c.o','AliasMapping.c.o','X86RegisterFallback32.c.o','X86OutputIterator.c.o','X86MemoryFallback32.c.o','X86BatchScan.c.o','X86DisassemblerDecoder.c.o','X86Disassembler.c.o','X86Vex32Output.c.o','X86IntelInstPrinter.c.o','X86ATTInstPrinter.c.o','MipsMapping.c.o','MipsInstPrinter.c.o','PPCMapping.c.o','ARMMapping.c.o','ARMInstPrinter.c.o','AArch64Mapping.c.o','RISCVMapping.c.o'):
            obj,=build.rglob(name)
            with obj.open('rb') as file:
                elf=ELFFile(file);code_sections[name]={sec.name:hashlib.sha256(sec.data()).hexdigest() for sec in elf.iter_sections() if sec['sh_flags']&4}
        save('executable-sections-'+variant,code_sections)
        with binary.open('rb') as file:
            elf=ELFFile(file);layout={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
            save('linked-sections-'+variant,layout)
        identities[variant]=dict(archive=sha(archive),binary=sha(binary),cap_tree=actual,llvm=llvm,decoder=sha(decoder))
    assert m['oracle']==m['layout']
    products['oracle']=products['layout'];identities['oracle']=identities['layout']
    save('absolute-offsets-oracle',json.loads((out/'absolute-offsets-layout.json').read_text()))
    archive_count=len({v['archive'] for v in identities.values()})
    image_count=len({v['binary'] for v in identities.values()})
    if os.uname().machine=='aarch64':
        assert archive_count==image_count==1
    else:
        assert 2<=image_count<=archive_count<=3
    save('products',identities)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cpu=sp.check_output(['lscpu'],text=True);save('host',dict(cpu=cpu,compiler=sp.check_output(['clang','--version'],text=True)))
    shutil.copy2(products['base'],t/'selected')
    imgs={k:v.read_bytes()for k,v in products.items() if k!='oracle'};imgs['copy']=imgs['base']
    length=max(map(len,imgs.values()));imgs={k:v+bytes(length-len(v))for k,v in imgs.items()}
    image=t/'selected';image.write_bytes(imgs['base'])
    inode=image.stat().st_ino;block=4096
    offsets=[at for at in range(0,length,block) if len({v[at:at+block]for v in imgs.values()})>1]
    assert bool(offsets)==(os.uname().machine!="aarch64")
    checked={}
    def execute(k,case,mode,reps):
        # Touch exactly the same file pages, in the same order, before every exec.
        if k!='oracle':
            with image.open('r+b',buffering=0) as dest:
                for at in offsets:
                    dest.seek(at)
                    part=imgs[k][at:at+block]
                    assert dest.write(part)==len(part)
            assert image.stat().st_ino==inode and image.stat().st_size==length
            if k not in checked:
                checked[k]=sha(image);assert checked[k]==hashlib.sha256(imgs[k]).hexdigest()

        sel=str(case['selector']) if case['selector'] in (32,64) else {0:'arm64',1:'arm',2:'riscv64',3:'ppc64el',4:'mips64el'}[case['selector']]
        return list(map(int,sp.check_output(['setarch',os.uname().machine,'-R',products['oracle'] if k=='oracle' else image,case['path'],sel,str(mode),str(reps),*([case['intervals']] if 'intervals' in case else [])],text=True).split()))
    rows=[];rng=random.Random(1739)
    for c in cases:
        for mode in (range(6) if c['selector'] in (32,64) else range(3)):
            single=execute('base',c,mode,1)
            n=max(1,round(25000/single[0]))
            expected=execute('base',c,mode,n)[1:];cycles=[]
            corrected=execute('oracle',c,mode,n)[1:];assert corrected==expected,(c['name'],mode,corrected,expected)
            if c['name']=='jpeg-avx2-i386':assert expected[:2]==[7764*n,0],expected[:2]
            pairs=35 if c['selector']==4 or (c['name'],mode) in (('jpeg-avx2-i386', 3),('libmvec-amd64', 3),('putty-32-0.85',3),('arm-ls',1),('arm-ls',2),('arm64-ls',1),('libssl3t64-i386', 0),('libssl3t64-i386', 3),('arm64-ls', 0),('arm-ls', 0),('ppc64el-ls', 0),('riscv64-ls', 0),('mips64el-ls', 1),('libssl3t64-amd64',3),('putty-32-0.85',1),('putty-32-0.85',2),('libssl3t64-i386',1)) else 13
            for rep in range(pairs):
                keys=list(imgs);rng.shuffle(keys);ticks={v:[] for v in keys}
                for k in keys+keys[::-1]:
                    sample=execute(k,c,mode,n)
                    wanted=expected if k in ('base','copy') else corrected
                    assert wanted==sample[1:],(c['name'],mode,k,wanted,sample)
                    ticks[k].append(sample[0])
                cycles.append(ticks)
            rows.append(dict(case=c['name'],mode=mode,sha=c['text_sha256'],counts=expected[:2],boundary=expected[2],score=expected[3],corrected_score=corrected[3],reps=n,cycles=cycles))
            save('timings',rows)
    assert set(checked)==set(imgs) and checked['copy']==checked['base']
    save('fixed-image',dict(inode=inode,verified=checked,bytes=length,block=block,blocks=len(offsets)))
    save('complete',dict(done=True,pairs=13,ssl_pairs=35,panels=len(rows),source=llvm))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
