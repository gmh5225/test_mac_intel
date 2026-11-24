from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==q['parent'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c','PPCMapping.c','RISCVMapping.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    from training import fetch,holdouts
    heldout=fetch(r,w);save('foreign-corpus',heldout)
    images={};objects={}
    run('clang++','-std=c++17','-O3','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')

    for label in ('base','candidate'):
        if label=='candidate':
            assert sha(r/'candidate.patch')==q['sha256']
            run('git','-C',base,'apply','--index',r/'candidate.patch');assert get('git','-C',base,'write-tree').strip()==q['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/label)
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        if sys.platform.startswith('linux'):
            run('clang','-O2','-I',base/'include','-c',r/'counter.c','-o',w/'counter.o')
            run('clang++',w/'driver.o',w/'counter.o','-Wl,--wrap=X86_getInstructionScanResult',lib,ice_lib,*flags,'-o',w/('counter-'+label))

        objects[label]={f.name:sha(f)for f in build.rglob('*.c.o')}
        run('clang++',w/'foreign.o',lib,'-o',w/('foreign-'+label))
        args=(['-dynamiclib','-Wl,-force_load,'+str(lib)] if sys.platform=='darwin' else ['-shared','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-lm'])
        run('clang',*args,'-o',w/(label+'.library'))
        if label=='candidate':
            affected=[k for k,h in objects[label].items()if h!=objects['base'][k]];assert affected==['X86BatchScan.c.o'],affected
            save('affected',dict(count=len(objects[label]),changed=affected))
    shutil.copy2(w/'foreign-base',w/'foreign-duplicate')
    run('clang++','-std=c++17','-O2','-I',base/'include',r/'states.cpp',*(['-ldl']if sys.platform!='darwin' else []),'-o',w/'states')
    v=sp.run([w/'states',w/'base.library',w/'candidate.library','2048'],capture_output=True,text=True)
    if v.returncode:print(v.stderr[-3000:],flush=True)
    v.check_returncode();save('states',dict(stdout=v.stdout,iterations=2048,settings=v.stderr.count('case arch=')))

    assert images['base']['exe']!=images['candidate']['exe']
    shutil.copy2(w/'base',w/'duplicate');assert sha(w/'duplicate')==images['base']['exe']
    cpu=(get('sysctl','-n','machdep.cpu.brand_string').strip() if sys.platform=='darwin' else get('lscpu'))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host=dict(capstone=m['checkout_commit'],neverd=dev,iced=m['iced_revision'],cpu=cpu,compiler=get('clang','--version').splitlines()[0],os=platform.platform(),images=images,driver_sha256=sha(w/'driver.cpp'),rust_sha256=sha(ad/'iced.rs'))
    save('host',host);observations={};summary={};audits={}
    for name,bits,f,spans,_ in itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)):
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit(v):path.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path)==spec['extent_sha256']
        def audit_engine(exe):
            rows=[list(map(int,z.split())) for z in get(w/exe,'audit','0','1',f,path,str(bits)).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            return rows
        assert audit_engine('base')==audit_engine('candidate')
        if sys.platform.startswith('linux'):
            counts={}
            for label in ('base','candidate'):
                rows=sp.run([w/('counter-'+label),'private','0','1',f,path,str(bits)],check=True,capture_output=True,text=True)
                vals=list(map(int,rows.stderr.split()))
                assert len(vals)==257 and all(x%2==0 for x in vals)
                counts[label]=[x//2 for x in vals]
            delta=[a-b for a,b in zip(counts['base'],counts['candidate'])]
            assert delta[0]==sum(delta[1:]) and all(i>=0 for i in delta)
            if bits==32:assert delta[0]==0
            if name=='libssl3t64-amd64':assert delta[0]>0
            save('scan-calls-'+name,dict(full=counts,avoided=delta[0],opcodes={str(i):n for i,n in enumerate(delta[1:])if n}))

        audits[name]=dict(functions=len(selected),bytes=spec['bytes'],extent_sha256=sha(path));save('audit',audits)
        def take(engine,mode,n):
            comparator=engine if engine in ('iced','fast') else 'private'
            exe=engine if engine in ('candidate','duplicate')else'base'
            return list(map(int,get(w/exe,comparator,str(mode),str(n),f,path,str(bits)).split()))
        for mode in (0,1,2):
            labels=['base','duplicate','candidate','iced']+(['fast']if mode else[])
            repeats=max(1,math.ceil(25e6/take('iced',mode,1)[0]))
            expected={k:take(k,mode,repeats)[2:]for k in labels}
            assert len({tuple(x[:3])for x in expected.values()})==1 and expected['base']==expected['duplicate']==expected['candidate']
            rows=[];rng=random.Random(name+'/immediate-byte-pairs/'+str(mode))
            for _ in range(13):
                rng.shuffle(labels);sample={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    row=take(k,mode,repeats);assert row[2:]==expected[k]
                    sample[k].append(row[:2])
                rows.append({k:[sum(a[i]for a in times)for i in (0,1)]for k,times in sample.items()})
            key=name+'/'+str(mode);observations[key]=dict(repeats=repeats,checks=expected,cycles=rows)
            summary[key]={label:{k:interval([x[k][i]/x['candidate'][i]for x in rows])for k in labels if k!='candidate'}for i,label in enumerate(('cpu','wall'))}
            save('effects',summary);save('observations',observations);print(key,summary[key]['cpu']['base'],flush=True)
    assert len(summary)==18
    holdouts(heldout,w,save)
    save('complete',dict(complete=True,source=q,host=host,images=images,pairs=13,samples=audits,unit='Paired throughput, X86_scanNativeBatch with cs_disasm_iter fallback on scan misses; X86_disasmIterText for text and details. Each executable links the current NeverD static Capstone configuration. iced Intel and Fast formatters run on the same accepted instruction spans; full native results are consumed and Capstone output checksums agree exactly.'))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
