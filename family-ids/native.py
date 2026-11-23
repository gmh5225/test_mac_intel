from pathlib import Path
import hashlib,json,re,os,platform,random,shutil,subprocess as sp,tempfile
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
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC','SYSTEMZ','LOONGARCH','SPARC','XTENSA')]])
    imgs={};ids={};raw_bins={};probe_bins={};libs={}
    units=['x86_simple_output','x86_scan_batch','x86_buffer_bounds','x86_reg_access','aarch64_scan','aarch64_postprocess','mips_scan','mips_single','text_option','detail_option']
    linked_probes={}
    for k in ('base','candidate'):
        if k=='candidate':
            patch=d/'candidate.patch';assert sha(patch)==meta['sha256'];g('apply','--index',str(patch));assert g('write-tree')==meta['tree']
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static',*units])
        cmd('units-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','--parallel','3','-R','^unit_('+'|'.join(units)+')$'])
        lib=b/'libcapstone.a';order=sp.check_output(['ar','t',lib],text=True).splitlines()
        obj={n:hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in order}
        assert len(order)==len(obj)>55 and 'XtensaDisassembler.c.o' in order
        if k=='base':base_obj=obj;base_order=order
        else:
            assert {n for n in obj if base_obj.get(n)!=obj[n]}=={'X86PublicOutput.c.o','X86DisassemblerDecoder.c.o'}
            assert [n for n in obj if n in base_obj]==base_order
        save('objects-'+k,dict(members=obj,order=order))
        for case,store in [('time',probe_bins),('raw',raw_bins)]:
            exe=t/(case+'-'+k)
            cmd('compile-'+case+'-'+k,['c++','-std=c++17','-O3','-no-pie','-I',s/'include',d/(case+'.cpp'),lib,'-lm','-o',exe]);store[k]=exe
        linked=t/('linked-'+k)
        cmd('link-already-used-'+k,['c++','-std=c++17','-O3','-no-pie','-Wl,-u,X86_disasmIterText','-I',s/'include',d/'time.cpp',lib,'-lm','-o',linked])
        linked_probes[k]=linked.read_bytes()
        names={'cs_disasm_iter','X86_disasmIterText','X86_disasmIter32','X86_decodePublicRecord','cs_decode_full_insn','X86_scanNativeBatch','AArch64_getInstruction','Mips_getInstruction','RISCV_getInstruction','SystemZ_LLVM_getInstruction','Xtensa_getInstruction'}
        for label,exe in [('public',probe_bins[k]),('linked',linked)]:
            symbols={}
            for line in sp.check_output(['nm','-n','-S','--defined-only',exe],text=True).splitlines():
                z=line.split()
                if len(z)==4 and z[-1] in names:symbols[z[-1]]=[int(z[0],16),int(z[1],16)]
            assert 'cs_decode_full_insn' in symbols and 'cs_disasm_iter' in symbols
            assert ('X86_decodePublicRecord' in symbols)==(k=='candidate')
            if label=='linked' or k=='candidate':assert 'X86_disasmIterText' in symbols
            save('layout-'+label+'-'+k,symbols)
            cmd('iter-'+label+'-'+k,['objdump','-d','--disassemble=cs_disasm_iter',exe])
        imgs[k]=probe_bins[k].read_bytes();ids[k]=sha(probe_bins[k])
        so=t/(k+'.so')
        cmd('loadable-'+k,[cc,'-shared','-Wl,-Bsymbolic','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-lm','-o',so]);libs[k]=so
    assert ids['base']!=ids['candidate']
    imgs['copy']=imgs['base'];size=max(map(len,imgs.values()));imgs={k:v+bytes(size-len(v))for k,v in imgs.items()}
    target=t/'time';target.write_bytes(imgs['base']);target.chmod(0o755)
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(d/f,t/f)
    cmd('libmvec',['python3','-B',t/'libmvec.py'])
    cmd('build-public-states',['c++','-std=c++17','-O2','-I',s/'include',d/'public-records.cpp','-ldl','-o',t/'public-states'])
    states={}
    for label,bits,f in [('real-pe32',32,t/'putty-0.85-32.text'),('real-pe64',64,t/'putty-0.85-64.text'),('code16',16,t/'putty-0.85-32.text'),('simd64',64,t/'libmvec.text')]:
        result=json.loads(sp.check_output([t/'public-states',libs['base'],libs['candidate'],f,str(bits)],text=True))
        assert result['complete_record_comparisons']>0 and result['batch_records']>0
        states[label]=result
    save('public-differential',states)
    cmd('build-guard',['c++','-std=c++17','-O2','-I',s/'include',d/'primary-guard.cpp','-ldl','-o',t/'guard'])
    cmd('guard',[t/'guard',libs['base'],libs['candidate']]);assert (out/'guard.log').read_text().split()==['14255104','10945975']
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name'] in ('arm-ls', 'arm64-ls', 'mips64el-ls', 'ppc64el-ls', 'riscv64-ls', 'sparc64-ls', 's390x-ls', 'loong64-ls')]
    from xtensa import get
    xfile,xsource=get(t,load(d/'xtensa-source.json'));save('xtensa-source',xsource);extra.append(dict(name='xtensa-picolibc',path=xfile))
    assert len(extra)==9
    selectors={'arm': 101, 'arm64': 102, 'mips64el': 103, 'ppc64el': 104, 'riscv64': 105, 'sparc64': 106, 's390x': 107, 'loong64': 108, 'xtensa': 109}
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(0,1,2))]
    panels.append(('libmvec-amd64',64,t/'libmvec.text',load(t/'libmvec.json')['address'],(0,1,2)))
    panels.extend((q['name'],selectors[q['name'].split('-')[0]],Path(q['path']),0x100000,(0,1,2))for q in extra)
    samples=[q for q in foreign if q['name'].split('-')[0] in selectors]+[extra[-1]]
    bystage={}
    for k in ('base','candidate'):
        rows={}
        for q in samples:
            for opt in range(5):
                raw=list(map(int,sp.check_output([raw_bins[k],str(selectors[q['name'].split('-')[0]]),q['path'],str(opt)]).split()))
                assert len(raw)==4 and raw[0]>0
                rows[q['name']+'/'+str(opt)]=raw
        bystage[k]=rows
    assert bystage['base']==bystage['candidate'] and len(bystage['base'])>=10
    save('raw-records',bystage)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rng=random.Random(1756);rows=[]
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),compiler=sp.check_output([cc,'--version'],text=True),images=ids,osrel=osrel,machine=platform.machine(),cc=cc))
    def invoke(k,arch,mode,path,ip,n):
        target.write_bytes(imgs[k]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time',str(arch),str(mode),path,str(ip),str(n)],text=True).split()))
    for name,arch,path,ip,modes in panels:
        for mode in modes:
            one=invoke('base',arch,mode,path,ip,1);n=max(1,round(65e6/one[0]));rows_=[]
            for i in range(21):
                order=list(imgs);rng.shuffle(order);cyc={k:[]for k in order}
                for k in order+order[::-1]:
                    v=invoke(k,arch,mode,path,ip,n)
                    expect=one[2]
                    assert v[2]==expect,(name,mode,k,v[2],expect);cyc[k].append(v[0])
                rows_.append(cyc)
            rows.append(dict(name=name,arch=arch,mode=mode,cycles=rows_,sha=sha(path),reps=n));save('timings',rows)
    linked_probes['copy']=linked_probes['base'];size=max(map(len,linked_probes.values()))
    imgs={k:raw+bytes(size-len(raw))for k,raw in linked_probes.items()}
    probe_rows=[]
    for name,arch,path,ip,modes in panels:
        for mode in modes:
            if (name,mode) not in {('putty32',0),('putty32',1),('putty32',2),('putty64',0),('putty64',1),('putty64',2),('libmvec-amd64',1),('libmvec-amd64',2),('arm64-ls',1),('riscv64-ls',1),('mips64el-ls',2),('ppc64el-ls',0)}:continue
            one=invoke('base',arch,mode,path,ip,1);n=max(1,round(55e6/one[0]));cycles=[]
            for _ in range(13):
                order=list(imgs);rng.shuffle(order);cyc={k:[]for k in order}
                for k in order+order[::-1]:
                    v=invoke(k,arch,mode,path,ip,n);assert v[2]==one[2];cyc[k].append(v[0])
                cycles.append(cyc)
            probe_rows.append(dict(case=name,mode=mode,cycles=cycles,reps=n))
    assert len(probe_rows)==12
    save('linked-readers',probe_rows)
    save('complete',dict(done=True,panels=len(rows),revisions=meta,images=ids))
finally:
    count=sum(p.stat().st_size for p in t.rglob('*') if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=count))
