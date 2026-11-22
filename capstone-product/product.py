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
assert git(nd,'rev-parse','HEAD')==dev and git(cs,'rev-parse','HEAD')==m['official_capstone']
assert sha(r/'candidate.patch')==m['candidate']['sha256']
llvm=git(ll,'rev-parse','HEAD');remote=git(ll,'ls-remote','origin','refs/heads/main').split()[0];assert llvm==remote
save('source',dict(m,llvm=llvm,main_at_start=remote,prebuilt=False))
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    build=t/'build';cases=corpus.prepare(r,t,out,command)
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
    for variant in ('base','candidate'):
        if variant=='candidate':command(['git','apply','--index',r/'candidate.patch'],'apply-candidate',cs)
        actual=git(cs,'write-tree');assert actual==m[variant]['tree']
        decoder=nd/'lib/decode/X86/X86Decoder.cpp'
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+variant,nd)
        assert git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        assert git(cs,'write-tree')==actual and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        if variant=='base':
            command([sys.executable,nd/'scripts/build.py',build,'--target','capstone-count-clear','--parallel','4'],'build-reference-counter',nd)
            binary,=build.rglob('capstone-count-clear');counter=t/'count';shutil.copy2(binary,counter)
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(variant+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+variant)
        binary,=build.rglob('capstone-product');products[variant]=t/(variant+'-product');shutil.copy2(binary,products[variant])
        archive,=build.rglob('libcapstone.a')
        command(['clang','-O2','-I',cs/'include',r/'registers.c',archive,'-lm','-o',t/'verify'],'compile-records-'+variant)
        command([t/'verify'],'registers-'+variant)
        regs=[v.split() for v in (out/('registers-'+variant+'.log')).read_text().splitlines()]
        assert len(regs)==12 and all(int(v[3])==int(v[4])==(16 if variant=='base' or v[0]=='64' else 8) for v in regs)
        identities[variant]=dict(archive=sha(archive),binary=sha(binary),cap_tree=actual,llvm=llvm,decoder=sha(decoder),records=regs)
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
            n=max(1,round(65000/single[0]))
            expected=execute('base',c,mode,n)[1:];cycles=[]
            if c['name']=='jpeg-avx2-i386':assert expected[:2]==[7764*n,0],expected[:2]
            delta,occurrences=0,0
            if c['selector']==32 and mode==2:
                counted=list(map(int,sp.check_output([counter,c['path'],'32','2','1',*([c['intervals']]if 'intervals'in c else [])],text=True).split()))
                occurrences,delta=counted[:2]
                assert counted[3:]==single[1:]
                assert (occurrences==0)==(delta==0)
                if c['name']=='putty-32-0.85':assert occurrences==3
            for rep in range(17):
                keys=['base','copy','candidate'];rng.shuffle(keys);ticks={v:[] for v in keys}
                for k in keys+keys[::-1]:
                    sample=execute(k,c,mode,n)
                    wanted=expected.copy()
                    if k=='candidate':wanted[-1]-=delta*n
                    assert wanted==sample[1:],(c['name'],mode,k,wanted,sample)
                    ticks[k].append(sample[0])
                cycles.append(ticks)
            rows.append(dict(case=c['name'],mode=mode,sha=c['text_sha256'],counts=expected[:2],boundary=expected[2],score=expected[3],clears=occurrences,score_change_per_pass=delta,reps=n,cycles=cycles))
            save('timings',rows)
    save('complete',dict(done=True,pairs=17,panels=len(rows),source=llvm))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
