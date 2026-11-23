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
for k in ('base','tail','memory'):assert sha(r/(k+'.patch'))==m[k]['sha256']
assert git(cs,'write-tree')==git(cs,'rev-parse','HEAD^{tree}')
llvm=git(ll,'rev-parse','HEAD');remote=git(ll,'ls-remote','origin','refs/heads/main').split()[0];assert llvm==remote
save('source',dict(m,llvm=llvm,main_at_start=remote,prebuilt=False))
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    build=t/'build';cases=corpus.prepare(r,t,out,command)
    foreign=[z for z in cases if z['name'].startswith(('arm64-','mips64el-'))]
    selected={'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls'}
    cases=[c for c in cases if c['name'] in selected]
    assert {c['name']for c in cases}==selected
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
    cmake_file=nd/'CMakeLists.txt'
    normal_cmake=cmake_file.read_text()
    from elftools.elf.elffile import ELFFile
    decoder=nd/'lib/decode/X86/X86Decoder.cpp'
    for variant in ('base','tail','memory'):
        command(['git','restore','--source','HEAD','--staged','--worktree','--','.'],'restore-'+variant,cs)
        if variant!='base':command(['git','apply','--index',r/(variant+'.patch')],'apply-'+variant,cs)
        caller='lib/decode/Decoder.cpp'
        command(['git','restore','--source','HEAD','--worktree','--',caller],'restore-caller-'+variant,nd)
        entry={'base':'X86_disasmIterText','memory':'X86_disasmOneText','tail':'X86_decodeOneText'}[variant]
        if variant!='base':
            patch=r/(variant+'-caller.patch')
            assert sha(patch)==m['caller_patches'][variant]
            command(['git','apply',patch],'apply-caller-'+variant,nd)
        assert entry+'(Handle' in (nd/caller).read_text()
        actual=git(cs,'write-tree');assert actual==m[variant]['tree'] and 'return X86_scanNativeBatch(' in decoder.read_text()
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+variant,nd)
        assert git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        assert git(cs,'write-tree')==actual and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(variant+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+variant)
        binary,=build.rglob('capstone-product');products[variant]=t/(variant+'-product');shutil.copy2(binary,products[variant])
        names=sp.check_output(['nm','--defined-only',binary],text=True).splitlines()
        assert any(x.split()[-1]=='X86_scanNativeBatch' for x in names if x.split())
        archive,=build.rglob('libcapstone.a')
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
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'entry-guard.cpp',archive,'-o',t/'entry-guard'],'build-entry-guard-'+variant)
        command([t/'entry-guard'],'entry-guard-'+variant)
        assert (out/('entry-guard-'+variant+'.log')).read_text().split()[0]=='5734400'
        command(['clang','-O2','-I',cs/'include',r/'registers.c',archive,'-lm','-o',t/'verify'],'compile-records-'+variant)
        command([t/'verify'],'registers-'+variant)
        regs=[v.split() for v in (out/('registers-'+variant+'.log')).read_text().splitlines()]
        assert len(regs)==12 and all(int(v[3])==int(v[4])==16 for v in regs)
        if variant!='base':
            for unit in ('x86_simple_output','x86_reg_access'):
                command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include',cs/('tests/unit/'+unit+'.c'),archive,'-lm','-o',t/unit],'compile-'+unit+'-'+variant)
                command([t/unit],'run-'+unit+'-'+variant)
            save('units-records-'+variant,dict(tree=actual,complete=True))
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'forms.cpp',archive,'-o',t/'forms'],'build-forms-'+variant)
        command([t/'forms'],'forms-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',cs/'suite/synctools/x86_simple_output.cpp',archive,'-o',t/'simple-generator'],'build-generator-'+variant)
        generated=sp.check_output([t/'simple-generator'])
        assert generated==(cs/'arch/X86/X86GenSimpleOutput.inc').read_bytes()
        command(['clang++','-O2','-std=c++17','-I',cs,'-I',cs/'include',cs/'suite/synctools/x86_vector_output.cpp',archive,'-o',t/'vector-generator'],'compile-vector-rows-'+variant)
        generated=sp.check_output([t/'vector-generator']);assert generated==(cs/'arch/X86/X86GenVectorOutput.inc').read_bytes()
        save('vector-table-'+variant,dict(bytes=len(generated),sha256=hashlib.sha256(generated).hexdigest()))
        if (cs/'arch/X86/X86GenVexBaseMemory.inc').is_file():
            memory=sp.check_output([t/'vector-generator','--vex-base-memory']);assert memory==(cs/'arch/X86/X86GenVexBaseMemory.inc').read_bytes()
            save('generated-vex-memory',dict(bytes=len(memory),sha256=hashlib.sha256(memory).hexdigest()))
        obj,=build.rglob('X86Decoder.cpp.o')
        with obj.open('rb') as f:
            ef=ELFFile(f);sections={se.name:hashlib.sha256(se.data()).hexdigest() for se in ef.iter_sections() if se['sh_flags']&4 and se.data_size}
        assert sections
        if variant=='base':reference_sections=sections
        else:assert reference_sections==sections
        symbols={}
        for ln in sp.check_output(['nm','-n','-S','-C','--defined-only',binary],text=True).splitlines():
            fields=ln.split(maxsplit=3)
            if len(fields)!=4 or fields[2].lower()!='t':continue
            name=fields[3]
            if name.startswith(('cs_decode_full_insn','cs_decode_public_insn','cs_disasm_iter','X86_disasmIter','X86_decodeOneText','X86_disasmOneText','X86_scanNativeBatch','X86_get_insn_id','set_implicit_writes','Mips_getInstruction','Mips_disasm','AArch64_getInstruction','AArch64_disasm','matchAArch64AliasPatterns','matchAliasPatterns','AArch64_LLVM_printInstruction','X86_decodeVexMemoryOrFull','neverd::Decoder::classifyX86Prefix')):
                symbols[name]=[int(fields[0],16),int(fields[1],16)]
        assert 'cs_disasm_iter' in symbols and any('classifyX86Prefix' in n for n in symbols)
        with binary.open('rb') as file:
            elf=ELFFile(file)
            linked_sections={s.name:[s['sh_addr'],s.data_size,hashlib.sha256(s.data()).hexdigest()] for s in elf.iter_sections() if s['sh_flags'] & 2 and s['sh_type']=='SHT_PROGBITS'}
        members=sp.check_output(['ar','t',archive],text=True).splitlines()
        assert members.index('X86Vex32Output.c.o') < members.index('X86Sse64Output.c.o') < members.index('AliasMapping.c.o') < members.index('X86MemoryFallback32.c.o') < members.index('X86BatchScan.c.o'),members

        if 'AliasPatternLookup.c.o' in members:
            assert members.index('AliasPatternLookup.c.o')>members.index('X86VectorFallback64.c.o')
            command(['python3','-B',cs/'suite/synctools/alias_pattern_rows.py','--check'],'check-rows-'+variant,cs)
        else:raise AssertionError(('missing shipped alias member',variant))
        assert 'X86PublicOutput.c.o' not in members and 'X86PostPrinter.c.o' not in members
        owner,=build.rglob('NeverDDecode.dir/Decoder.cpp.o')
        refs=sp.check_output(['nm','-u',owner],text=True)
        relevant={ln.split()[-1]for ln in refs.splitlines()if ln.split()[-1] in ('X86_disasmIterText','X86_disasmOneText','X86_decodeOneText')}
        assert relevant=={entry},(variant,relevant)
        save('caller-'+variant,dict(source=sha(nd/caller),object=sha(owner),entry=entry,undefined=refs))
        all_members={n:hashlib.sha256(sp.check_output(['ar','p',archive,n])).hexdigest() for n in members}
        member_digests={n:hashlib.sha256(sp.check_output(['ar','p',archive,n])).hexdigest() for n in ('X86EvexScan.c.o','X86Sse64Output.c.o','X86Vex32Output.c.o','AliasMapping.c.o','X86BatchScan.c.o')}
        import io
        obj_bytes=sp.check_output(['ar','p',archive,'X86ImmediateOutput.c.o'])
        contents=ELFFile(io.BytesIO(obj_bytes))
        immediate_code={se.name:hashlib.sha256(se.data()).hexdigest() for se in contents.iter_sections() if se.data_size and se['sh_flags'] & 4}
        assert '.text' in immediate_code
        if variant=='base':original_immediate=immediate_code
        else:assert original_immediate==immediate_code
        save('layout-'+variant,dict(all_members=all_members,immediate_code=immediate_code,member_digests=member_digests,symbols=symbols,decoder_executable_sections=sections,linked_sections=linked_sections,archive_members=members))

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

        identities[variant]=dict(archive=sha(archive),binary=sha(binary),cap_tree=actual,llvm=llvm,decoder=sha(decoder))
    assert len({z['archive']for z in identities.values()})==3 and len({z['binary']for z in identities.values()})==3
    save('products',identities)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cpu=sp.check_output(['lscpu'],text=True);save('host',dict(cpu=cpu,compiler=sp.check_output(['clang','--version'],text=True)))
    shutil.copy2(products['base'],t/'selected')
    imgs={k:v.read_bytes()for k,v in products.items()};imgs['copy']=imgs['base']
    length=max(map(len,imgs.values()));imgs={k:v+bytes(length-len(v))for k,v in imgs.items()}
    def execute(k,case,mode,reps):
        (t/'selected').write_bytes(imgs[k])
        sel=str(case['selector']) if case['selector'] in (32,64) else {0:'arm64',4:'mips64el'}[case['selector']]
        return list(map(int,sp.check_output(['setarch','x86_64','-R',t/'selected',case['path'],sel,str(mode),str(reps),*([case['intervals']] if 'intervals' in case else [])],text=True).split()))
    rows=[];rng=random.Random(1739)
    for c in cases:
        for mode in (range(4) if c['selector'] in (32,64) else range(3)):
            single=execute('base',c,mode,1)
            n=max(1,round(50000/single[0]))
            expected=execute('base',c,mode,n)[1:];cycles=[]
            if c['name']=='jpeg-avx2-i386':assert expected[:2]==[7764*n,0],expected[:2]
            for rep in range(21):
                keys=list(imgs);rng.shuffle(keys);ticks={v:[] for v in keys}
                for k in keys+keys[::-1]:
                    sample=execute(k,c,mode,n)
                    wanted=expected.copy()
                    assert wanted==sample[1:],(c['name'],mode,k,wanted,sample)
                    ticks[k].append(sample[0])
                cycles.append(ticks)
            rows.append(dict(case=c['name'],mode=mode,sha=c['text_sha256'],counts=expected[:2],boundary=expected[2],score=expected[3],reps=n,cycles=cycles))
            save('timings',rows)
    save('complete',dict(done=True,pairs=21,panels=len(rows),source=llvm))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
