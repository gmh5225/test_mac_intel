from pathlib import Path
import hashlib,json,time,os,random,shutil,statistics,subprocess as sp,sys,tempfile
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
assert all(sha(r/(stage+'.patch'))==m[stage]['sha256'] for stage in ('base','mask'))
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
    for stage in ('shipping','base','mask'):
        git(cs,'restore','--source','HEAD','--worktree','--staged','--','.')
        patches={'shipping':[],'base':['base'],'mask':['mask']}
        for name in patches[stage]:
            command(['git','apply','--index',r/(name+'.patch')],'apply-'+stage+'-'+name,cs)
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
        from product_layout import record_layout
        save('elf-'+stage,record_layout(binary))
        if stage=='shipping':
            import frozen_ssl64
            name,bits,path,spans,metadata=next(iter(frozen_ssl64.prepare(t)));q=json.loads((r/'ssl64-extents.json').read_text())
            assert name=='libssl3t64-amd64' and bits==64 and len(spans)==q['input_functions'] and sha(path)==q['text_sha256']
            intervals=t/'openssl-amd64.tsv';intervals.write_text(''.join('%d %d %d\n'%s for s in spans))
            command(['clang++','-O2','-I',cs/'include',r/'vectors.cpp',lib,'-o',t/'vectors'],'vectors')
            views=[list(map(int,x.split()))for x in sp.check_output([t/'vectors','64',path,intervals],text=True).splitlines()]
            assert len(views)==len(spans)
            skip={tuple(s[:3]) for s in q['excluded_incompatible_extents']}
            chosen=[z for z,(total,vectors) in zip(spans,views)if tuple(z)not in skip and vectors>=8 and vectors>=.15*total]
            intervals.write_text(''.join('%d %d %d\n'%s for s in chosen));assert len(chosen)==320 and sha(intervals)==q['extent_sha256']
            cases.append(dict(name=name,selector=bits,path=str(path),intervals=str(intervals),text_sha256=q['text_sha256']))
            save('openssl64-input',dict(extents=len(chosen),bytes=sum(n for _,n,_ in chosen),input=q))

        assert len(cases)==14 and len({v['name'] for v in cases})==14
        assert sum(6 if c['selector'] in (32,64) else 3 for c in cases)==60
        shutil.copyfile(binary,t/(stage+'.exe'));(t/(stage+'.exe')).chmod(0o755)
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
    assert all(fields==results['shipping'] for fields in results.values())
    comparisons={}
    arm=os.uname().machine=='aarch64'
    first=set(['X86RegisterFallback32.c.o', 'X86Vex32Output.c.o']);second=set(first);between=set()
    for before,after,expected in [('shipping','base',set() if arm else first),
        ('shipping','mask',set() if arm else second),('base','mask',set() if arm else between)]:
        a,b=identities[before],identities[after]
        assert a['objects'].keys()==b['objects'].keys()
        delta={Path(k).name for k,v in a['objects'].items() if b['objects'][k]!=v}
        assert delta==expected,(before,after,delta)
        assert (a['exe']!=b['exe'])==bool(delta) and (a['archive']!=b['archive'])==bool(delta)
        comparisons[before+'/'+after]=sorted(delta)
    save('checked-objects',comparisons)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    image=t/'selected';shutil.copy2(t/'base.exe',image);ino=image.stat().st_ino
    blobs={k:(t/(k+'.exe')).read_bytes() for k in ('shipping','base','mask')}
    blobs['shipping_copy']=blobs['shipping'];blobs['mask_copy']=blobs['mask']
    total=max(map(len,blobs.values()));blobs={k:v+bytes(total-len(v)) for k,v in blobs.items()}
    block=4096;diff=[n for n in range(0,total,block) if len({v[n:n+block] for v in blobs.values()})>1]
    assert bool(diff)==(not arm);image.write_bytes(blobs['base']);checked={}
    def execute(k,c,mode,reps):
        with image.open('r+b',buffering=0) as f:
            for at in diff:
                f.seek(at);part=blobs[k][at:at+block];assert f.write(part)==len(part)
        assert image.stat().st_ino==ino and image.stat().st_size==total
        if k not in checked:
            checked[k]=sha(image);assert checked[k]==hashlib.sha256(blobs[k]).hexdigest()
        sel=str(c['selector']) if c['selector'] in (32,64) else {0:'arm64',1:'arm',2:'riscv64',3:'ppc64el',4:'mips64el'}[c['selector']]
        args=['setarch',os.uname().machine,'-R',image,c['path'],sel,str(mode),str(reps),*([c['intervals']] if 'intervals'in c else [])]
        start=time.perf_counter_ns();values=list(map(int,sp.check_output(args,text=True).split()));wall=time.perf_counter_ns()-start
        assert len(values)==5 and values[0]>0
        return values,wall
    rng=random.Random(3849);timings={}
    for c in cases:
        for mode in (range(6) if c['selector'] in (32,64) else range(3)):
            key=c['name']+'/'+str(mode);first,_=execute('base',c,mode,1)
            reps=max(1,round(30000/first[0]));expected=execute('base',c,mode,reps)[0][1:]
            focus=c['name'] in ('putty-64-0.85','putty-32-0.85','libssl3t64-i386')
            count=35 if focus else 17;cycles=[]
            for rep in range(count):
                order=list(blobs);rng.shuffle(order);trial={k:[]for k in order}
                for stage in order+order[::-1]:
                    sample,wall=execute(stage,c,mode,reps)
                    assert sample[1:]==expected,(key,stage,reps,sample,expected)
                    trial[stage].append([sample[0],wall])
                cycles.append(trial)
            timings[key]=dict(cycles=cycles,reps=reps,fields=expected,sha=c['text_sha256']);save('timings',timings)
    assert set(checked)==set(blobs) and checked['shipping']==checked['shipping_copy'] and checked['mask']==checked['mask_copy'] and (checked['shipping']==checked['mask'])==arm
    save('fixed-image',dict(inode=ino,verified=checked,bytes=total,blocks=len(diff)))
    save('complete',dict(complete=True,inputs=len(cases),workloads=len(timings),llvm=llvm,dev=dev,source=m,active=True))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
