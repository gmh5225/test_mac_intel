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
    cfg=['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC')]]
    # Compare the ordinary six-backend bytes separately from the five-backend
    # mixed configuration that uses the new stack operand table.
    broad=t/'six'
    fullcfg=[str(broad) if x==b else x for x in cfg]
    cmd('six-configure',fullcfg)
    cfg.remove('-DCAPSTONE_AARCH64_SUPPORT=ON')
    cmd('configure',cfg)

    imgs={};ids={}
    for k in ('base','stack'):
        if k!='base':
            assert sha(d/'candidate.patch')==meta['sha256'];g('apply','--index',str(d/'candidate.patch'));assert g('write-tree')==meta['tree']
        cmd('six-build-'+k,['cmake','--build',broad,'--parallel','4','--target','capstone_shared'])
        six,=[x for x in broad.glob('libcapstone.so.*') if not x.is_symlink()]
        if k=='base':original_six=sha(six)
        else:
            assert sha(six)==original_six
            save('six-identities',dict(base=original_six,candidate=sha(six)))
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*') if not x.is_symlink()]
        ids[k]=sha(so)
        imgs[k]=so.read_bytes()
        cmd('compile-riscv-'+k,['cc','-O2','-I',s/'include',d/'records.c','-L',b,'-Wl,-rpath,'+str(b),'-lcapstone','-o',t/'riscv-records'])
        hd=hashlib.sha256();length=0
        with (out/('riscv-'+k+'.log')).open('w')as log,sp.Popen([t/'riscv-records'],stdout=sp.PIPE,stderr=log)as cp:
            while buf:=cp.stdout.read(4194304):hd.update(buf);length+=len(buf)
            assert cp.wait()==0
        if k=='base':rv_reference=(hd.hexdigest(),length)
        else:assert rv_reference==(hd.hexdigest(),length)
        assert (out/('riscv-'+k+'.log')).read_text().startswith('262144 states, ')
        save('riscv-bytes-'+k,dict(bytes=length,sha256=hd.hexdigest()))
        if k=='stack':
            names=['x86_reg_access','x86_mapping_counts','x86_evex_detail','x86_scan_batch','riscv_op_count_iter','riscv_instruction_groups','riscv_mapping_index','riscv_reg_access','riscv_sysreg','riscv_insn_name_segv','riscv_writeback_postprocess','mips_single']
            cmd('units-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static',*names])
            cmd('units-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(names)+')$'])
            cmd('generator',['python3','-B',s/'suite/synctools/operand_writeback.py','--check'])
    active = cc=='clang' and osrel=='24.04' and platform.machine()=='x86_64'
    assert (ids['base']!=ids['stack'])==active,ids
    cmd('identity',['python3','-B',d/'identity.py'])
    imgs['copy']=imgs['base'];size=max(map(len,imgs.values()));imgs={k:v+bytes(size-len(v)) for k,v in imgs.items()}
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(imgs['base']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile-time',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(d/f,t/f)
    cmd('libmvec',['python3','-B',t/'libmvec.py'])
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name']in ('riscv64-sort','riscv64-cp','riscv64-ls','mips64el-ls','arm-ls')]
    assert len(extra)==5
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(1,2))]
    panels.append(('libmvec-amd64',64,t/'libmvec.text',load(t/'libmvec.json')['address'],(1,2)))
    panels.extend((q['name'],{'riscv64-sort':105,'riscv64-cp':105,'riscv64-ls':105,'mips64el-ls':103,'arm-ls':101}[q['name']],Path(q['path']),0x100000,(0,1,2))for q in extra)
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
