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
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
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
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
# Inserted after the prepared production project, exact Rust/Capstone driver and source inputs.
    from instrument import instrument
    maps=rd(r/'source.json')
    path_src=base/'arch/X86/X86VexRegisterImmediate.c'
    for label,patch in [('base','reference.patch'),('outlined','outlined.patch')]:
        assert sha(r/patch)==maps[label]['sha256']
        run('git','-C',base,'apply','--index',r/patch)
        assert get('git','-C',base,'write-tree').strip()==maps[label]['tree']
        if label=='base':before=path_src.read_text()
    path_src.write_text(instrument(before,path_src.read_text()))
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    current=w/'fixed';run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',current)
    identity=(current.stat().st_ino,sha(current))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R',current]
    report={};addresses={}
    def panel(name,bits,f,span):
        for route in ('private','capstone'):
            for mode in (1,2):
                def sample(tag,n,probe=False):
                    env=dict(os.environ,ND_VEX_STAGE='b' if tag=='extended' else 'a')
                    if probe:env['ND_VEX_COUNT']='1'
                    v=sp.run([*invoke,route,str(mode),str(n),f,span,str(bits)],env=env,capture_output=True,check=True,text=True)
                    data=list(map(int,v.stdout.split()));assert len(data)==6
                    if not probe:
                        assert not v.stderr.strip(),v.stderr
                        return data
                    fields=v.stderr.strip().split();assert len(fields)==6 and fields[0]=='C4',v.stderr
                    addr=fields[3:]
                    assert addr[0]!=addr[1] and addr[2]==addr[int(tag=='extended')]
                    assert addresses.setdefault('choices',addr[:2])==addr[:2]
                    return data,list(map(int,fields[1:3]))
                ref,counts=sample('original',1,True);cand,new_counts=sample('extended',1,True)
                # The fast path can absorb records but cannot change how often its own entry is called.
                assert ref[2:]==cand[2:] and counts==new_counts,(name,route,mode,counts,new_counts)
                assert counts[bits==32]==0
                reps=max(1,math.ceil(16e6/ref[0]));labels=['original','duplicate','extended']
                checks={k:sample(k,reps)[2:] for k in labels}
                assert checks['original']==checks['extended']==checks['duplicate'] and ref[2]>0
                rng=random.Random(name+'/'+route+'/'+str(mode));blocks=[]
                for _ in range(25):
                    rng.shuffle(labels);times={k:[]for k in labels}
                    for k in labels+labels[::-1]:
                        val=sample(k,reps);assert val[2:]==checks[k];times[k].append(val[:2])
                    blocks.append({k:[a+b for a,b in zip(*v)]for k,v in times.items()})
                summary={other:[interval([b[other][i]/b['extended'][i]for b in blocks]) for i in (0,1)] for other in ('original','duplicate')}
                key='/'.join([name,route,str(mode)])
                report[key]=dict(bits=bits,extent=sha(span),checks=checks['original'],one_pass=ref[2:],entries=counts,pairs=blocks,repeats=reps,effects=summary)
                save('matrix',report);print(key,counts,summary['original'][0],flush=True)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
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
        panel(name,bits,f,path)
        if name=='libssl3t64-amd64':
            recovered=w/'recovered.tsv';targets=[s[:3]for s in spec['excluded_incompatible_extents']]
            assert len(targets)==6 and sum(n for _,n,_ in targets)==19594
            recovered.write_text(''.join('%d %d %d\n'%tuple(z) for z in targets))
            panel('openssl-ifma',64,f,recovered)
    assert len(report)==28 and identity==(current.stat().st_ino,sha(current))
    save('complete',dict(complete=True,source=maps,panels=len(report),sha256=identity[1],inode=identity[0],addresses=addresses,host=get('lscpu'),compiler=get('clang','--version').splitlines()[0],affinity=list(os.sched_getaffinity(0)),instrumented_source=sha(path_src),pairs=25))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
