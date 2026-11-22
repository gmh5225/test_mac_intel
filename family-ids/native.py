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
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC')]])
    imgs={};ids={}
    for k in ('base','indexed'):
        if k!='base':
            assert sha(d/'candidate.patch')==meta['sha256'];g('apply','--index',str(d/'candidate.patch'));assert g('write-tree')==meta['tree']
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*') if not x.is_symlink()]
        names={'matchAliasPatterns','X86_disasmIter32','X86_disasmIter64','cs_disasm_iter','cs_decode_full_insn','AArch64_getInstruction','Mips_getInstruction','Mips_printInst','AArch64_printInst','Mips_reg_name'}
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
        ids[k]=sha(so)
        imgs[k]=so.read_bytes()
        if cc=='clang':
            cmd('alias-static-'+k,['cmake','--build',b,'--target','capstone_static','--parallel','4'])
            cmd('alias-compile-'+k,[cc,'-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_HAS_AARCH64','-DCAPSTONE_HAS_MIPS','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include',d/'alias.c',b/'libcapstone.a','-o',t/'alias'])
            cmd('alias-oracle-'+k,[t/'alias'])
            assert int((out/('alias-oracle-'+k+'.log')).read_text())>500000
        if k=='indexed':
            names=['mcinst','aarch64_postprocess','aarch64_scan','mips_scan','mips_single','mips_msa_control','mips_reglist_offset','mips_register_names','x86_reg_access','x86_mapping_counts','x86_scan_batch']
            cmd('units-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static',*names])
            cmd('units-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(names)+')$'])
            cmd('generator',['python3','-B',s/'suite/synctools/alias_mnemonic_trie.py','--check'])
            cmd('index-check',['python3','-B',s/'suite/synctools/alias_pattern_rows.py','--check'])
    assert ids['base']!=ids['indexed']
    imgs['copy']=imgs['base'];size=max(map(len,imgs.values()));imgs={k:v+bytes(size-len(v)) for k,v in imgs.items()}
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(imgs['base']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile-time',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(d/f,t/f)
    cmd('libmvec',['python3','-B',t/'libmvec.py'])
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name']in ('arm-ls','riscv64-ls','mips64el-ls','arm64-ls')]
    assert len(extra)==4
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(1,2))]
    panels.append(('libmvec-amd64',64,t/'libmvec.text',load(t/'libmvec.json')['address'],(1,2)))
    panels.extend((q['name'],{'arm-ls':101,'riscv64-ls':105,'mips64el-ls':103,'arm64-ls':102}[q['name']],Path(q['path']),0x100000,(0,1,2))for q in extra)
    cmd('compile-records',['c++','-std=c++17','-O2','-I',s/'include',d/'raw.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'raw'])
    samples=[q for q in foreign if q['name'].startswith(('mips64el-','arm64-'))]
    bystage={}
    for k in ('base','indexed'):
        target.write_bytes(imgs[k]);rows={}
        for q in samples:
            for opt in range(5):
                raw=list(map(int,sp.check_output([t/'raw','arm'if q['name'].startswith('arm64-')else 'mips',q['path'],str(opt)]).split()))
                assert len(raw)==4 and raw[0]>0
                rows[q['name']+'/'+str(opt)]=raw
        bystage[k]=rows
    assert bystage['base']==bystage['indexed'] and len(bystage['base'])>=10
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
