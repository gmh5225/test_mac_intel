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
assert sha(r/'candidate.patch')==m['candidate']['sha256']
assert git(cs,'write-tree')==git(cs,'rev-parse','HEAD^{tree}')
llvm=git(ll,'rev-parse','HEAD');remote=git(ll,'ls-remote','origin','refs/heads/main').split()[0];assert llvm==remote
save('source',dict(m,llvm=llvm,main_at_start=remote,prebuilt=False))
t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    build=t/'build';cases=corpus.prepare(r,t,out,command)
    foreign=[z for z in cases if z['name'].startswith(('arm64-','mips64el-'))]
    selected={'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','arm-ls','ppc64el-ls','riscv64-ls'}
    cases=[c for c in cases if c['name'] in selected]
    assert {c['name']for c in cases}==selected
    specs=json.loads((r/'mips-samples.json').read_text())['fixtures']
    ls=next(c for c in cases if c['name']=='mips64el-ls');pkg=t/'corpus'/ls['package_sha256']
    for name,spec in specs.items():
        assert sha(pkg)==spec['package'];elf=corpus.deb_binary(pkg,spec['command'])
        assert corpus.digest(elf)==spec['binary_sha256'];data=corpus.elf_text(elf)
        assert corpus.digest(data)==spec['sha256']
        if name==ls['name']:assert ls['text_sha256']==spec['sha256'];continue
        dest=t/(name+'.text');dest.write_bytes(data)
        case=dict(name=name,path=str(dest),selector=4,text_sha256=spec['sha256']);cases.append(case)
        if not any(x['name']==name for x in foreign):foreign.append(case)
    save('mips-inputs',specs)
    rv=next(c for c in cases if c['name']=='riscv64-ls')
    elf=corpus.deb_binary(t/'corpus'/rv['package_sha256'],'ls')
    assert corpus.digest(elf)==rv['binary_sha256'] and corpus.digest(corpus.elf_text(elf))==rv['text_sha256']
    assert elf[:6]==b'\x7fELF\x02\x01' and int.from_bytes(elf[48:52],'little')&1
    assert b'rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_' in elf
    save('new-architectures',dict(riscv=rv['binary_sha256'],ppc=next(c['binary_sha256'] for c in cases if c['name']=='ppc64el-ls')))
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
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests']
    identities={};results={}
    for stage in ('base','candidate'):
        if stage=='candidate':
            command(['git','apply','--index',r/'candidate.patch'],'apply',cs)
        assert git(cs,'write-tree')==m[stage]['tree']
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+stage,nd)
        assert git(cs,'write-tree')==m[stage]['tree'] and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm and not git(ll,'diff','HEAD','--name-only')
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(stage+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+stage)
        lib,=build.rglob('libcapstone.a');binary,=build.rglob('capstone-product')
        names=sp.check_output(['nm','--defined-only',binary],text=True)
        assert all(' '+sym in names for sym in ('X86_scanNativeBatch','X86_disasmIterText','RISCV_compact_operands','cs_disasm_iter'))
        objs={str(f.relative_to(build)):sha(f) for f in build.rglob('*.c.o') if '/capstone' in str(f.relative_to(build)) or f.name=='RISCVMapping.c.o'}
        assert len(objs)>=60 and any(k.endswith('RISCVMapping.c.o') for k in objs),list(objs)
        identities[stage]=dict(archive=sha(lib),exe=sha(binary),objects=objs,llvm=llvm,decoder=sha(nd/'lib/decode/Decoder.cpp'))
        rows={}
        for c in cases:
            sel=str(c['selector']) if c['selector'] in (32,64) else {0:'arm64',1:'arm',2:'riscv64',3:'ppc64el',4:'mips64el'}[c['selector']]
            for mode in (range(6) if c['selector'] in (32,64) else range(3)):
                args=[binary,c['path'],sel,str(mode),'1',*([c['intervals']] if 'intervals' in c else [])]
                values=list(map(int,sp.check_output(args,text=True).split()))
                assert len(values)==5 and values[0]>0 and values[1]>0,(c['name'],mode,values)
                rows[c['name']+'/'+str(mode)]=dict(text=c['text_sha256'],counts=values[1:3],boundary=values[3],score=values[4])
        assert len(rows)==60
        results[stage]=rows;save('products',identities);save('records',results)
    assert identities['candidate']==identities['base'] and results['base']==results['candidate']
    save('complete',dict(complete=True,inputs=len(cases),workloads=len(results['base']),llvm=llvm,dev=dev,source=m))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
