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
meta=load(d/'revisions.json');ref=load(d/'reference.json');osrel='22.04'if '22.04' in Path('/etc/os-release').read_text() else '24.04'
t=Path(tempfile.mkdtemp());b=t/'build';orig=g('rev-parse','HEAD');assert orig==meta['fixed']['parent']==meta['mode']['parent']
try:
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC')]])
    imgs={};ids={}
    for k in ('base','mode','fixed'):
        if k!='base':
            if k=='fixed':g('restore','--source',orig,'--staged','--worktree','--','.')
            assert sha(d/(k+'.patch'))==meta[k]['sha256'];g('apply','--index',str(d/(k+'.patch')));assert g('write-tree')==meta[k]['tree']
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*') if not x.is_symlink()]
        ids[k]=sha(so)
        mapper,=b.rglob('X86Mapping.c.o')
        raw=t/'common.bin';cmd('text-'+k,['objcopy','--dump-section','.text='+str(raw),mapper,t/'copy.o'])
        syms={}
        for line in sp.check_output(['nm','-n','-S','--defined-only',so],text=True).splitlines():
            e=line.split()
            if len(e)==4 and e[3] in ('X86_get_insn_id','X86_map_full_register_bank','cs_disasm_iter','X86_getInstruction','RISCV_getInstruction','RISCV_LLVM_printInstruction','X86_Intel_printInst'):syms[e[3]]=[int(e[0],16),int(e[1],16)]
        assert 'cs_disasm_iter' in syms and 'X86_get_insn_id' in syms
        cmd('mapper-disassembly-'+k,['objdump','-d','--disassemble=X86_get_insn_id',so])
        save('layout-'+k,dict(symbols=syms,text_sha=sha(raw),size=raw.stat().st_size))
        cmd('build-tests-'+k,['cmake','--build',b,'--parallel','4','--target','x86_reg_access','x86_buffer_bounds','x86_scan_batch'])
        cmd('test-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_(x86_reg_access|x86_buffer_bounds|x86_scan_batch)$'])
        cmd('mapping-'+k,['python3','-B',s/'suite/synctools/x86_mapping_counts.py','--check'])
        imgs[k]=so.read_bytes()
    imgs['copy']=imgs['base'];size=max(map(len,imgs.values()));imgs={k:v+bytes(size-len(v)) for k,v in imgs.items()}
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(imgs['base']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile-time',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name']in ('riscv64-sort','mips64el-ls')]
    assert len(extra)==2
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(1,2))]
    panels.extend((q['name'],105 if q['name']=='riscv64-sort' else 103,Path(q['path']),0x100000,(0,1,2))for q in extra)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rng=random.Random(1756);rows=[]
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),compiler=sp.check_output(['clang','--version'],text=True),images=ids,osrel=osrel))
    def invoke(k,arch,mode,path,ip,n):
        target.write_bytes(imgs[k]);return list(map(int,sp.check_output(['setarch','x86_64','-R',t/'time',str(arch),str(mode),path,str(ip),str(n)],text=True).split()))
    for name,arch,path,ip,modes in panels:
        for mode in modes:
            one=invoke('base',arch,mode,path,ip,1);n=max(1,round(85e6/one[0]));rows_=[]
            for i in range(19):
                order=list(imgs);rng.shuffle(order);cyc={k:[]for k in order}
                for k in order+order[::-1]:
                    v=invoke(k,arch,mode,path,ip,n)
                    expect=one[2]-(ref['pe32-score'] if name=='putty32'and mode==3 and k in ('mode','fixed') else 0)
                    assert v[2]==expect,(name,mode,k,v[2],expect);cyc[k].append(v[0])
                rows_.append(cyc)
            rows.append(dict(name=name,arch=arch,mode=mode,cycles=rows_,sha=sha(path),reps=n));save('timings',rows)
    if os.environ['FLAVOR']=='first':
        stats={}
        for k in ('base','mode','fixed'):
            target.write_bytes(imgs[k]);f=t/'callgrind.out'
            args=['valgrind','--tool=callgrind','--branch-sim=yes','--cache-sim=yes','--callgrind-out-file='+str(f),t/'time','32','2',t/'putty-0.85-32.text',str(0x401000),'1']
            cmd('profile-'+k,args)
            docs=f.read_text(errors='replace').splitlines();events=next(x for x in docs if x.startswith('events:')).split()[1:];totals=next(x for x in docs if x.startswith('totals:')).split()[1:]
            assert len(totals)==len(events) and 'Ir' in events
            stats[k]=dict(zip(events,map(int,totals)))
            cmd('functions-'+k,['callgrind_annotate','--show=Ir,Bc,Bcm,D1mr,D1mw','--auto=no','--threshold=99.95',f])
            f.unlink()
        save('profile',stats)
    save('complete',dict(done=True,panels=len(rows),revisions=meta,images=ids))
finally:
    count=sum(p.stat().st_size for p in t.rglob('*') if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=count))
