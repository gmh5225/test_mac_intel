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
assert sha(r/'writer.patch')==m['writer']['sha256']
llvm=git(ll,'rev-parse','HEAD');remote=git(ll,'ls-remote','origin','refs/heads/main').split()[0];assert llvm==remote
save('source',dict(m,llvm=llvm,main_at_start=remote,prebuilt=False))
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    build=t/'build';cases=corpus.prepare(r,t,out,command)
    pe,=[c for c in cases if c['name']=='putty-64-0.85'];meta=json.loads((r/'extents.json').read_text())
    assert pe['text_sha256']==meta['source']['text_sha256']
    for k,z in meta['checked'].items():assert sha(r/(k+'.tsv'))==z['sha256']
    shutil.copyfile(r/'attribution.cpp',nd/'attribution.cpp')
    shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp')
    with (nd/'CMakeLists.txt').open('a') as f:f.write('\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\nadd_executable(capstone-attribution attribution.cpp)\ntarget_link_libraries(capstone-attribution PRIVATE NeverDDecode)\n')
    command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
    assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF'in (build/'CMakeCache.txt').read_text()
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests'];products={};identities={}
    for variant in ('base','writer'):
        if variant=='writer':command(['git','apply','--index',r/'writer.patch'],'apply-writer',cs)
        actual=git(cs,'write-tree');assert actual==m[variant]['tree']
        decoder=nd/'lib/decode/X86/X86Decoder.cpp'
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product','capstone-attribution',*targets,'--parallel','4'],'build-'+variant,nd)
        assert git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        assert git(cs,'write-tree')==actual and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(variant+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+variant)
        products[variant]={};archive,=build.rglob('libcapstone.a')
        for surface in ('product','attribution'):
            binary,=build.rglob('capstone-'+surface)
            products[variant][surface]=t/(variant+'-'+surface);shutil.copy2(binary,products[variant][surface])
        identities[variant]=dict(archive=sha(archive),bins={k:sha(z)for k,z in products[variant].items()},cap_tree=actual,llvm=llvm,decoder=sha(decoder))
    save('products',identities)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cpu=sp.check_output(['lscpu'],text=True);save('host',dict(cpu=cpu,compiler=sp.check_output(['clang','--version'],text=True)))
    from random import Random
    surfaces=['product','attribution']
    exe=t/'selected';shutil.copy2(products['base']['product'],exe)
    payload={surface:{k:v[surface].read_bytes()for k,v in products.items()}for surface in surfaces}
    length=max(len(b) for variants in payload.values() for b in variants.values())
    for variants in payload.values():
        variants['copy']=variants['base']
        for k,raw in list(variants.items()):variants[k]=raw+bytes(length-len(raw))
    def once(surface,k,region,entry,repetitions):
        exe.write_bytes(payload[surface][k])
        path=r/(region+'.tsv')
        result=sp.check_output(['setarch','x86_64','-R',exe,pe['path'],'64',str(entry),str(repetitions),path],text=True)
        return list(map(int,result.split()))
    timings=[];rng=Random(1802)
    for region in meta['checked']:
        for surface in surfaces:
            if surface=='product' and region!='whole-low':continue
            for entry in ([1,2] if surface=='product' else [1,2,4,5]):
                first=once(surface,'base',region,entry,1);n=max(1,round(85000/first[0]))
                expect=once(surface,'base',region,entry,n)[1:];cycles=[]
                for i in range(17):
                    keys=['base','copy','writer'];rng.shuffle(keys);ticks={k:[]for k in keys}
                    for k in keys+keys[::-1]:
                        sample=once(surface,k,region,entry,n);assert sample[1:]==expect,(surface,region,entry,k)
                        ticks[k].append(sample[0])
                    cycles.append(ticks)
                timings.append(dict(surface=surface,region=region,entry=entry,reps=n,first=first[1:],score=expect,cycles=cycles));save('timings',timings)
    assert len(timings)==22
    save('complete',dict(done=True,panels=len(timings),raw=meta,host=cpu,source=llvm,pairs=17))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
