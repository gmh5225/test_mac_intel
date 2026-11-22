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
for k in ('base', 'broadcast', 'repair', 'combined'):assert sha(r/(k+'.patch'))==m[k]['sha256']
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
    shutil.copyfile(r/'oracle.cpp',nd/'capstone-count-clear.cpp')
    with (nd/'CMakeLists.txt').open('a')as f:f.write('\nadd_executable(capstone-count-clear capstone-count-clear.cpp)\ntarget_link_libraries(capstone-count-clear PRIVATE NeverDDecode)\n')
    command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
    assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF'in (build/'CMakeCache.txt').read_text()
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests'];products={};identities={}
    cmake_file=nd/'CMakeLists.txt'
    normal_cmake=cmake_file.read_text()
    from elftools.elf.elffile import ELFFile
    decoder=nd/'lib/decode/X86/X86Decoder.cpp'
    for variant in ('base', 'broadcast', 'repair', 'combined'):
        command(['git','restore','--source','HEAD','--staged','--worktree','--','.'],'restore-'+variant,cs)
        if variant!='base':command(['git','apply','--index',r/(variant+'.patch')],'apply-'+variant,cs)
        actual=git(cs,'write-tree');assert actual==m[variant]['tree'] and 'return X86_scanNativeBatch(' in decoder.read_text()
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+variant,nd)
        assert git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        assert git(cs,'write-tree')==actual and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        if variant=='base':
            command([sys.executable,nd/'scripts/build.py',build,'--target','capstone-count-clear','--parallel','4'],'build-reference-counter',nd)
            binary,=build.rglob('capstone-count-clear');counter=t/'count';shutil.copy2(binary,counter)
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
        command(['clang','-O2','-I',cs/'include',r/'registers.c',archive,'-lm','-o',t/'verify'],'compile-records-'+variant)
        command([t/'verify'],'registers-'+variant)
        regs=[v.split() for v in (out/('registers-'+variant+'.log')).read_text().splitlines()]
        assert len(regs)==12 and all(int(v[3])==int(v[4])==(8 if variant in ('repair','combined') and v[0]!='64' else 16) for v in regs)
        if variant!='base':
            for unit in ('x86_simple_output','x86_reg_access'):
                command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include',cs/('tests/unit/'+unit+'.c'),archive,'-lm','-o',t/unit],'compile-'+unit+'-'+variant)
                command([t/unit],'run-'+unit+'-'+variant)
            save('units-records-'+variant,dict(tree=actual,complete=True))
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
            if name.startswith(('cs_decode_full_insn','cs_disasm_iter','X86_disasmIter','X86_scanNativeBatch','X86_get_insn_id','set_implicit_writes','Mips_getInstruction','Mips_disasm','AArch64_getInstruction','AArch64_disasm','neverd::Decoder::classifyX86Prefix')):
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

        if variant!='base':
            for mode in ('32','64'):
                command(['clang++','-O2','-std=c++17','-I',cs,'-I',cs/'include',r/('native-guard'+mode+'.cpp'),archive,'-o',t/('guard'+mode)],'guard-link-'+mode+'-'+variant)
                command([t/('guard'+mode)],'guard-'+mode+'-'+variant)
        if variant !='base':
            command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-DX86_disasmRecordIter=observed_disasm_record_iter','-DX86_readScanWord=observed_read_scan_word','-c',r/'second.c','-o',t/'observed.o'],'projection-compile-'+variant)
            command(['clang++','-std=c++17','-O2','-I',cs,'-I',cs/'include',r/'vex3.cpp',t/'observed.o',archive,'-o',t/'vex3'],'vex3-link-'+variant)
            command([t/'vex3'],'vex3-oracle-'+variant)
            command(['clang++','-std=c++17','-O2','-I',cs,'-I',cs/'include',r/'mandatory.cpp',t/'observed.o',archive,'-o',t/'mandatory'],'mandatory-link-'+variant)
            command([t/'mandatory'],'mandatory-oracle-'+variant)
            for probe in ('rounded','shift'):
                command(['clang++','-O2','-std=c++17','-I',cs,'-I',cs/'include',r/(probe+'.cpp'),t/'observed.o',archive,'-o',t/probe],'compile-'+probe+variant)
                command([t/probe],'oracle-'+probe+'-'+variant)
        if variant !='base':
            command(['clang++','-O2','-std=c++17','-I',cs/'include',cs/'suite/synctools/x86_simple_output.cpp',archive,'-o',t/'simple-generator'],'simple-generator-'+variant)
            assert sp.check_output([t/'simple-generator','--legacy-packed-memory'])==(cs/'arch/X86/X86GenLegacyPackedMemory.inc').read_bytes()
        if variant == 'combined':
            command(['clang++','-O2','-std=c++17','-I',cs/'include',cs/'suite/synctools/x86_vector_output.cpp',archive,'-o',t/'table-producer'],'evex-producer')
            generated=sp.check_output([t/'table-producer','--evex-scan']);assert generated==(cs/'arch/X86/X86GenEvexScan.inc').read_bytes()
            command(['python3','-B',cs/'suite/synctools/x86_operand_specializations.py','--check'],'generated-tables',cs)
            assert sp.check_output([t/'table-producer','--vex32-memory'])==(cs/'arch/X86/X86GenVex32MemoryOutput.inc').read_bytes()
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

        if variant in ('broadcast', 'repair', 'combined'):
            command(['clang++','-O2','-std=c++17','-I',cs/'include',cs/'suite/synctools/x86_vector_output.cpp',archive,'-o',t/'table-producer'],'evex-table-'+variant)
            assert sp.check_output([t/'table-producer','--evex-scan'])==(cs/'arch/X86/X86GenEvexScan.inc').read_bytes()
            assert sp.check_output([t/'table-producer','--evex-memory'])==(cs/'arch/X86/X86GenEvexMemoryOutput.inc').read_bytes()
        if variant == 'combined':
            command(['python3','-B',cs/'suite/synctools/x86_mapping_counts.py','--check'],'check-mode-repair-'+variant,cs)
        if variant != 'base':
            assert sp.check_output([t/'table-producer','--plain-evex-registers'])==(cs/'arch/X86/X86GenPlainEvexRegisterOutput.inc').read_bytes()
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-DOBSERVE_WITH_SIZE','-c',r/'plain.c','-o',t/'shape.o'],'plain-wrapper-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'plain.cpp',t/'shape.o',archive,'-o',t/'shape'],'plain-link-'+variant)
        command([t/'shape'],'plain-guard-'+variant)
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'indexed.c','-o',t/'indexed.o'],'indexed-wrapper-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'indexed.cpp',t/'indexed.o',archive,'-o',t/'indexed'],'indexed-link-'+variant)
        command([t/'indexed'],'indexed-records-'+variant)
        if variant!='base':
            assert sp.check_output([t/'table-producer','--legacy-register-immediates'])==(cs/'arch/X86/X86GenLegacyRegisterImmediates.inc').read_bytes()
            command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'legacy.c','-o',t/'legacy.o'],'legacy-wrapper-'+variant)
            command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'legacy.cpp',t/'legacy.o',archive,'-o',t/'legacy'],'legacy-link-'+variant)
            command([t/'legacy'],'legacy-guard-'+variant)
        if variant!='base':
            assert sp.check_output([t/'simple-generator','--test32-registers'])==(cs/'arch/X86/X86GenTest32Registers.inc').read_bytes()
        if variant in ('base','broadcast','repair','combined'):
            from observe import install
            observed=t/'probe-source';arch=observed/'arch/X86';arch.mkdir(parents=True,exist_ok=True)
            sources=('X86MemoryFallback32','X86Vex32Output')
            for name in sources:shutil.copy2(cs/('arch/X86/'+name+'.c'),arch/(name+'.c'))
            install(observed)
            for name in sources:
                command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT','-DX86_disasmIter32=observed_text32','-DX86_decodeOutputMiss32=observed_miss32','-I',cs/'arch/X86','-I',cs,'-I',cs/'include','-c',arch/(name+'.c'),'-o',t/(name+'.o')],'lea-compile-'+name+'-'+variant)
            command(['clang++','-std=c++17','-O2','-I',cs/'include',r/'sib-guard.cpp',*[t/(name+'.o') for name in sources],archive,'-o',t/'sib-guard'],'lea-link-'+variant)
            command([t/'sib-guard'],'lea-guard-'+variant)
        if variant!='base':
            assert sp.check_output([t/'table-producer','--evex-rip-memory'])==(cs/'arch/X86/X86GenEvexRipMemory.inc').read_bytes()
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'rip.c','-o',t/'rip.o'],'rip-wrapper-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'rip.cpp',t/'rip.o',archive,'-o',t/'rip'],'rip-link-'+variant)
        command([t/'rip'],'rip-guard-'+variant)
        if variant!='base':
            assert sp.check_output([t/'table-producer','--legacy-map38-registers'])==(cs/'arch/X86/X86GenLegacyMap38Registers.inc').read_bytes()
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'map38.c','-o',t/'map38.o'],'map38-wrapper-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'map38.cpp',t/'map38.o',archive,'-o',t/'map38'],'map38-link-'+variant)
        command([t/'map38'],'map38-guard-'+variant)
        if variant in ('repair','combined'):
            command(['python3','-B',cs/'suite/synctools/x86_mapping_counts.py','--check'],'mapping-writes-'+variant)
        if variant in ('broadcast','combined'):
            assert sp.check_output([t/'table-producer'])==(cs/'arch/X86/X86GenVectorOutput.inc').read_bytes()
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'vexrip.c','-o',t/'vexrip.o'],'vexrip-wrap-'+variant)
        command(['clang++','-O2','-std=c++17','-I',cs/'include',r/'vexrip.cpp',t/'vexrip.o',archive,'-o',t/'vexrip'],'vexrip-link-'+variant)
        command([t/'vexrip'],'vexrip-guard-'+variant)
        command(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',cs,'-I',cs/'include','-c',r/'broadcast.c','-o',t/'bc.o'],'broadcast-wrapper-'+variant)
        command(['clang++','-std=c++17','-O2','-I',cs/'include',r/'broadcast.cpp',t/'bc.o',archive,'-o',t/'bc'],'broadcast-link-'+variant)
        command([t/'bc'],'broadcast-guard-'+variant)
        identities[variant]=dict(archive=sha(archive),binary=sha(binary),cap_tree=actual,llvm=llvm,decoder=sha(decoder))
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
            delta,occurrences=0,0
            if c['selector']==32 and mode==2:
                counted=list(map(int,sp.check_output([counter,c['path'],'32','2','1',*([c['intervals']]if 'intervals'in c else [])],text=True).split()))
                occurrences,delta=counted[:2]
                assert counted[3:]==single[1:]
                assert (occurrences==0)==(delta==0)
                if c['name']=='putty-32-0.85':assert occurrences==3
            for rep in range(13):
                keys=list(imgs);rng.shuffle(keys);ticks={v:[] for v in keys}
                for k in keys+keys[::-1]:
                    sample=execute(k,c,mode,n)
                    wanted=expected.copy()
                    if k in ('repair','combined'):wanted[-1]-=delta*n
                    assert wanted==sample[1:],(c['name'],mode,k,wanted,sample)
                    ticks[k].append(sample[0])
                cycles.append(ticks)
            rows.append(dict(case=c['name'],mode=mode,sha=c['text_sha256'],counts=expected[:2],boundary=expected[2],score=expected[3],clears=occurrences,score_change_per_pass=delta,reps=n,cycles=cycles))
            save('timings',rows)
    save('complete',dict(done=True,pairs=13,panels=len(rows),source=llvm))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
