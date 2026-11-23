from pathlib import Path
import hashlib,json,os,platform,random,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def load(p):return json.loads(p.read_text())
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,a,cwd=None):
    with (out/(n+'.log')).open('w')as f:z=sp.run(a,cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2200:]);z.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
cc=os.environ['CC'];meta=load(d/'tree.json');osrel='22.04'if '22.04' in Path('/etc/os-release').read_text() else '24.04'
t=Path(tempfile.mkdtemp());b=t/'build';assert g('rev-parse','HEAD')==meta['parent'];baseline=g('rev-parse','HEAD^{tree}')
try:
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC','SYSTEMZ','LOONGARCH','SPARC','XTENSA')]])
    imgs={};ids={}
    for k in ('base','active','indexed'):
        if k!='base':
            g('restore','--source',baseline,'--staged','--worktree','--','.')
            selected=load(d/'active-tree.json') if k=='active' else meta
            patch=d/('active.patch' if k=='active' else 'candidate.patch')
            assert sha(patch)==selected['sha256'];g('apply','--index',str(patch));assert g('write-tree')==selected['tree']
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*') if not x.is_symlink()]
        names={'matchAliasPatterns','X86_disasmIter32','X86_disasmIter64','cs_disasm_iter','cs_decode_full_insn','AArch64_getInstruction','Mips_getInstruction','Mips_printInst','AArch64_printInst','Mips_reg_name','RISCV_getInstruction','RISCV_printInst','PPC_getInstruction','Sparc_getInstruction','LoongArch_getInstruction','Xtensa_getInstruction','X86_postprinter','postprocess_full','repair_avx_broadcast'}
        syms={}
        for ln in sp.check_output(['nm','-n','-S','--defined-only',so],text=True).splitlines():
            fs=ln.split()
            if len(fs)==4 and fs[-1] in names:syms[fs[-1]]=list(map(lambda x:int(x,16),fs[:2]))
        assert 'matchAliasPatterns' in syms and 'cs_disasm_iter' in syms
        printer,=b.rglob('MCInstPrinter.c.o')
        cmd('common-code-'+k,['objcopy','--dump-section','.text='+str(t/'common.text'),printer])
        regular_code=sha(t/'common.text')
        if k=='base':original=regular_code
        else:assert regular_code==original
        sections=sp.check_output(['readelf','-SW',so],text=True)
        save('layout-'+k,dict(symbols=syms,common_code=regular_code,linked_sections=sections))
        core=b/'CMakeFiles/capstone.dir';obj={str(v.relative_to(core)):sha(v)for v in core.rglob('*.c.o')}
        assert len(obj)>50
        if k=='base':base_objects=obj
        compared=sorted(n for n in obj if obj[n]!=base_objects.get(n));assert set(obj)==set(base_objects)
        save('objects-'+k,dict(compared=len(obj),changed=compared))
        for symbol in ('cs_disasm_iter','disasmScanIterator','disasmCanonicalIterator'):
            cmd('assembly-'+symbol+'-'+k,['objdump','-d','--disassemble='+symbol,so])
        decoder,=b.rglob('X86DisassemblerDecoder.c.o')
        symbol,=[ln.split() for ln in sp.check_output(['objdump','-t',decoder],text=True).splitlines()if ln.split()[-1:]==['cs_disasm_iter']]
        off=int(symbol[0],16);section=symbol[-3];length=int(symbol[-2],16)
        output=t/'iterator-section.bin'
        cmd('iterator-section-'+k,['objcopy','--dump-section',section+'='+str(output),decoder,t/'iterator.dump.o'])
        body=output.read_bytes()[off:off+length];assert len(body)==length>40
        relocs=sp.check_output(['objdump','-r','-j',section,decoder],text=True)
        calls=[]
        for line in relocs.splitlines():
            z=line.split()
            if len(z)==3 and z[1].startswith('R_') and off<=int(z[0],16)<off+length:
                calls.append([int(z[0],16)-off,z[1],z[2]])
        save('scan-bytes-'+k,dict(section=section,offset=off,size=length,sha256=hashlib.sha256(body).hexdigest(),relocations=calls))
        mapping,=b.rglob('X86Mapping.c.o')
        entries=sp.check_output(['objdump','-t',mapping],text=True).splitlines()
        table={row.split()[-1]:row.split() for row in entries if row.split() and row.split()[-1].split('.')[0] in ('postprocess_full','X86_postprinter')}
        assert any(name.startswith('postprocess_full') for name in table)==(k!='base'),table
        assert ('.cs_x86_postprinter_text' in table['X86_postprinter'])==(k=='indexed'),table
        save('postprinter-sections-'+k,table)
        ids[k]=sha(so)
        imgs[k]=so.read_bytes()
        if cc=='clang':
            cmd('alias-static-'+k,['cmake','--build',b,'--target','capstone_static','--parallel','4'])
            cmd('spans-build-'+k,[cc,'-DNDEBUG','-O2','-DCAPSTONE_HAS_SYSTEMZ','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include',d/'spans.c',b/'libcapstone.a','-o',t/'spans'])
            cmd('spans-'+k,[t/'spans'])
            cmd('alias-compile-'+k,[cc,'-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_HAS_AARCH64','-DCAPSTONE_HAS_MIPS','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include',d/'alias.c',b/'libcapstone.a','-o',t/'alias'])
            cmd('alias-oracle-'+k,[t/'alias'])
            assert int((out/('alias-oracle-'+k+'.log')).read_text())>500000
        import shlex
        units=['x86_x87_environment', 'x86_kmask_width', 'x86_kmask_access', 'x86_gfni_broadcast_detail', 'x86_apx_evex_shift_rotate', 'x86_evex_convert_mask_size', 'x86_evex_mask_conversion_access', 'x86_vfpclass_memory_mask_detail', 'x86_evex_narrow_memory_mask_size', 'x86_vpbroadcast_mask_source_size']
        cmd('regression-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static',*units])
        cmd('regression-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
        tu=next(v for v in load(b/'compile_commands.json') if Path(v['file']).name=='MCInst.c')
        defs=[v for v in shlex.split(tu['command']) if v.startswith('-D')]
        cmd('decorator-link-'+k,[cc,'-O2',*defs,'-I',s,'-I',s/'include',d/'decorators.c',b/'libcapstone.a','-lm','-o',t/'decorators'])
        cmd('decorators-'+k,[t/'decorators'])
        if k!='base':assert (out/('decorators-'+k+'.log')).read_bytes()==(out/'decorators-base.log').read_bytes()
        if k=='indexed':
            cmd('register-static',['cmake','--build',b,'--target','capstone_static','--parallel','4'])
        if k=='indexed':
            names=['mcinst','aarch64_postprocess','aarch64_scan','mips_scan','mips_single','mips_msa_control','mips_reglist_offset','mips_register_names','x86_reg_access','x86_mapping_counts','x86_scan_batch']
            cmd('units-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static',*names])
            cmd('units-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(names)+')$'])
            cmd('generator',['python3','-B',s/'suite/synctools/alias_mnemonic_trie.py','--check'])
    assert len(set(ids.values()))==3
    imgs['copy']=imgs['base'];size=max(map(len,imgs.values()));imgs={k:v+bytes(size-len(v)) for k,v in imgs.items()}
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(imgs['base']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile-time',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(d/f,t/f)
    cmd('libmvec',['python3','-B',t/'libmvec.py'])
    cmd('build-public-states',['c++','-std=c++17','-O2','-I',s/'include',d/'public-records.cpp','-ldl','-o',t/'public-states'])
    libs={}
    for k in ('base','active','indexed'):
        libs[k]=t/(k+'.so');libs[k].write_bytes(imgs[k])
    states={}
    for k in ('base','active','indexed'):
        states[k]={}
        for label,bits,f in [('real-pe32',32,t/'putty-0.85-32.text'),('real-pe64',64,t/'putty-0.85-64.text'),('code16',16,t/'putty-0.85-32.text'),('simd64',64,t/'libmvec.text')]:
            z=json.loads(sp.check_output([t/'public-states',libs['base'],libs[k],f,str(bits)],text=True))
            assert z['complete_record_comparisons']>0 and z['batch_records']>0
            states[k][label]=z
    assert states['base']==states['active']==states['indexed']
    save('public-differential',states)
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name'] in ('arm-ls', 'arm64-ls', 'mips64el-ls', 'ppc64el-ls', 'riscv64-ls', 'sparc64-ls', 's390x-ls', 'loong64-ls')]
    from xtensa import get
    xfile,xsource=get(t,load(d/'xtensa-source.json'));save('xtensa-source',xsource);extra.append(dict(name='xtensa-picolibc',path=xfile))
    assert len(extra)==9
    selectors={'arm': 101, 'arm64': 102, 'mips64el': 103, 'ppc64el': 104, 'riscv64': 105, 'sparc64': 106, 's390x': 107, 'loong64': 108, 'xtensa': 109}
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(0,1,2))]
    panels.append(('libmvec-amd64',64,t/'libmvec.text',load(t/'libmvec.json')['address'],(0,1,2)))
    panels.extend((q['name'],selectors[q['name'].split('-')[0]],Path(q['path']),0x100000,(0,1,2))for q in extra)
    cmd('compile-records',['c++','-std=c++17','-O2','-I',s/'include',d/'raw.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'raw'])
    samples=[q for q in foreign if q['name'].split('-')[0] in selectors]+[extra[-1]]
    bystage={}
    for k in ('base','active','indexed'):
        target.write_bytes(imgs[k]);rows={}
        for q in samples:
            for opt in range(5):
                raw=list(map(int,sp.check_output([t/'raw',str(selectors[q['name'].split('-')[0]]),q['path'],str(opt)]).split()))
                assert len(raw)==4 and raw[0]>0
                rows[q['name']+'/'+str(opt)]=raw
        bystage[k]=rows
    assert bystage['base']==bystage['active']==bystage['indexed'] and len(bystage['base'])>=10
    save('raw-records',bystage)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rng=random.Random(1756);rows=[]
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),compiler=sp.check_output([cc,'--version'],text=True),images=ids,osrel=osrel,machine=platform.machine(),cc=cc))
    def invoke(k,arch,mode,path,ip,n):
        target.write_bytes(imgs[k]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time',str(arch),str(mode),path,str(ip),str(n)],text=True).split()))
    for name,arch,path,ip,modes in panels:
        for mode in modes:
            one=invoke('base',arch,mode,path,ip,1);n=max(1,round(65e6/one[0]));rows_=[]
            for i in range(15):
                order=list(imgs);rng.shuffle(order);cyc={k:[]for k in order}
                for k in order+order[::-1]:
                    v=invoke(k,arch,mode,path,ip,n)
                    expect=one[2]
                    assert v[2]==expect,(name,mode,k,v[2],expect);cyc[k].append(v[0])
                rows_.append(cyc)
            rows.append(dict(name=name,arch=arch,mode=mode,cycles=rows_,sha=sha(path),reps=n));save('timings',rows)
    save('complete',dict(done=True,panels=len(rows),revisions=meta,images=ids))
finally:
    count=sum(p.stat().st_size for p in t.rglob('*') if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=count))
