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
t=Path(tempfile.mkdtemp());b=t/'build';orig=g('rev-parse','HEAD');assert orig==meta['parent']
try:
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC','SYSTEMZ','LOONGARCH','SPARC','XTENSA')]])
    imgs={};ids={}
    for k in ('base','active','indexed'):
        if k!='base':
            g('restore','--source','HEAD','--staged','--worktree','--','.')
            selected=load(d/'active-tree.json') if k=='active' else meta
            patch=d/('active.patch' if k=='active' else 'candidate.patch')
            assert sha(patch)==selected['sha256'];g('apply','--index',str(patch));assert g('write-tree')==selected['tree']
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*') if not x.is_symlink()]
        names={'matchAliasPatterns','X86_disasmIter32','X86_disasmIter64','cs_disasm_iter','cs_decode_full_insn','AArch64_getInstruction','Mips_getInstruction','Mips_printInst','AArch64_printInst','Mips_reg_name','RISCV_getInstruction','RISCV_printInst','Sparc_getInstruction','Sparc_printInst','LoongArch_getInstruction','Xtensa_getInstruction','X86_disasmProjected32','X86_disasmProjected64','X86_decodeTextRecord32','X86_decodeTextRecord64','scanBatch32','scanBatch64','readFirst32','readFirst64'}
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
        for symbol in ('cs_disasm_iter','X86_disasmScanFallback','X86_disasmProjected32','X86_disasmProjected64','X86_decodeTextRecord32','X86_decodeTextRecord64','scanBatch32','scanBatch64'):
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
        command_line=sp.check_output(['ninja','-C',b,'-t','commands','capstone_static'],text=True)
        assert 'X86BatchScan.c' in command_line
        ids[k]=sha(so)
        imgs[k]=so.read_bytes()
    imgs['copy']=imgs['base']
    size=max(map(len,imgs.values()))
    imgs={key:raw+bytes(size-len(raw)) for key,raw in imgs.items()}
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6'
    target.write_bytes(imgs['base']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile-consumer',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args))
    panels=[(q['name'],sel,m,Path(q['path']),0x100000) for label,sel,m in [('arm64-ls',102,0),('arm-ls',101,0),('riscv64-ls',105,1),('riscv64-ls',105,2),('mips64el-ls',103,0)] for q in foreign if q['name']==label]
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    panels.append(('putty32',32,2,t/'putty-0.85-32.text',0x401000))
    assert len(panels)==6
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    stats={}
    for name,arch,mode,path,ip in panels:
        panel=name+'-'+str(mode)
        got={}
        for k in ('base','copy','active','indexed'):
            target.write_bytes(imgs[k]);f=t/'callgrind.out';cmdline=[t/'time',str(arch),str(mode),path,str(ip),'1']
            args=['setarch',platform.machine(),'-R','valgrind','--tool=callgrind','--instr-atstart=no','--branch-sim=yes','--cache-sim=yes','--callgrind-out-file='+str(f),'--log-file='+str(out/('sim-'+panel+'-'+k+'.log')),*cmdline]
            cmd('profile-'+panel+'-'+k,args)
            signature=list(map(int,(out/('profile-'+panel+'-'+k+'.log')).read_text().split()))
            assert len(signature)==4 and signature[-1]>0
            doc=f.read_text().splitlines();events=next(ln.split()[1:]for ln in doc if ln.startswith('events:'))
            totals=next(ln.split()[1:]for ln in doc if ln.startswith('totals:'))
            assert len(events)==len(totals) and 'Bim' in events
            got[k]=dict(events=dict(zip(events,map(int,totals))),score=signature[2],count=signature[3],sample=sha(path))
            cmd('functions-'+panel+'-'+k,['callgrind_annotate','--show=Ir,Dr,Dw,I1mr,D1mr,D1mw,Bc,Bcm,Bi,Bim','--show-percs=no','--auto=no','--threshold=99.99',f])
            f.unlink()
        assert len({(v['count'],v['score'])for v in got.values()})==1
        assert got['base']['events']['Ir']==got['copy']['events']['Ir']
        stats[panel]=got;save('profiles',stats)
    save('host',dict(compiler=sp.check_output([cc,'--version'],text=True),valgrind=sp.check_output(['valgrind','--version'],text=True),os=osrel))
    save('complete',dict(done=True,panels=len(stats),revisions=meta,images=ids))
finally:
    removed=sum(p.stat().st_size for p in t.rglob('*')if p.is_file() and not p.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=removed))
