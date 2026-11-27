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
    images={}
    maps=rd(r/'source.json')
    import shlex
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    entry=next(x for x in rd(build/'compile_commands.json') if x['file'].endswith('/SStream.c'))
    args=shlex.split(entry['command'])
    for option in ('-o','-c'):
        i=args.index(option)
        del args[i:i+2]
    names=('shipping','first','outlined','printable','control')
    objects=[]
    units={}
    for name in names:
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        tree=maps[name]
        if name!='shipping':
            patch=r/(name+'.patch')
            assert sha(patch)==tree['sha256']
            run('git','-C',base,'apply','--index',patch)
        assert get('git','-C',base,'write-tree').strip()==tree['tree']
        source=(base/'SStream.c').read_text()
        header=source.split('#ifndef CAPSTONE_DIET\nstatic size_t SStream_remaining',1)[0]
        assert len(header)<1500
        code=source.split('ss->index = kept_len + repl_len;\n}',1)[1].split('/// Extract the mnemonic',1)[0]
        assert code.count('void SStream_trimls(SStream *ss)')==1
        symbol='benchTrim_'+name
        src=w/(name+'.c')
        src.write_text(header+code.replace('void SStream_trimls(SStream *ss)','__attribute__((aligned(64),noinline)) void '+symbol+'(SStream *ss)'))
        obj=w/(name+'.o')
        run(*args,'-I',base,'-c',src,'-o',obj,cwd=entry['directory'])
        objects.append(obj)
        units[name]=dict(body=hashlib.sha256(code.encode()).hexdigest(),unit=sha(obj),symbol=symbol)
    run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    from training import fetch
    foreign_rows=fetch(r,w)
    save('foreign-corpus',foreign_rows)
    for label,extras in [('timed',[]),('counted',['-DCOUNT_CALLS'])]:
        shim=w/(label+'.o')
        run(*args,*extras,'-I',base,'-c',r/'select.c','-o',shim,cwd=entry['directory'])
        for engine,driver,libs in [('x86',w/'driver.o',[lib,ice_lib,*flags]),('foreign',w/'foreign.o',[lib,'-no-pie'])]:
            exe=w/(engine+'-'+label)
            run('clang++',driver,shim,*objects,*libs,'-Wl,--wrap=SStream_trimls','-o',exe)
            rows={v.split()[-1]:int(v.split()[0],16) for v in get('nm','-an',exe).splitlines() if v.split() and v.split()[-1] in {x['symbol'] for x in units.values()}}
            assert len(rows)==5 and len(set(rows.values()))==5 and all(x%64==0 for x in rows.values())
            images[exe.name]=dict(binary=sha(exe),inode=exe.stat().st_ino,code=rows,archive=sha(lib))
    run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/'x86-reference')
    run('clang++',w/'foreign.o',lib,'-no-pie','-o',w/'foreign-reference')
    run('clang','-O2','-std=c99','-I',base,r/'trim-domain.c',w/'timed.o',*objects,lib,'-Wl,--wrap=SStream_trimls','-o',w/'domain')
    checks=[int(get(w/'domain',env=dict(os.environ,CS_BENCH_TRIM=str(i)))) for i in range(6)]
    assert len(set(checks))==1 and checks[0]>221184
    save('images',images)
    save('units',dict(functions=units,domain=checks))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    observations={}
    def sample(key,kind,args_for):
        binary=w/(kind+'-timed')
        def launch(exe,sel,n):
            return sp.run(['setarch',os.uname().machine,'-R',exe,*args_for(n)],env=dict(os.environ,CS_BENCH_TRIM=str(sel)),check=True,capture_output=True,text=True)
        def take(i,n):return list(map(int,launch(binary,i,n).stdout.split()))
        ref=list(map(int,launch(w/(kind+'-reference'),0,1).stdout.split()))
        counted=launch(w/(kind+'-counted'),0,1)
        assert list(map(int,counted.stdout.split()))[2:]==ref[2:]
        calls,indented,high=map(int,counted.stderr.split())
        assert 0<=indented<=calls and 0<=high<=calls-indented
        reps=max(1,math.ceil(25e6/ref[0]));expected=take(0,reps)[2:]
        assert all(take(i,1)[2:]==ref[2:] for i in range(6))
        order=list(range(6));rng=random.Random('trim/'+key);blocks=[]
        for block in range(17):
            rng.shuffle(order);row=[[0,0] for _ in order]
            for i in order+order[::-1]:
                values=take(i,reps)
                assert values[2:]==expected and min(values[:2])>0
                for j in (0,1):row[i][j]+=values[j]
            blocks.append(row)
        assert images[binary.name]['inode']==binary.stat().st_ino and images[binary.name]['binary']==sha(binary)
        observations[key]=dict(reps=reps,fields=expected,reference=ref[2:],counts=[calls,indented,high],pairs=blocks)
        save('observations',observations)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    observations={}
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

        for mode in range(3):
            for route in ('private','capstone'):
                sample('/'.join((route,name,str(mode))),'x86',lambda n:[route,str(mode),str(n),f,path,str(bits)])
    for row in foreign_rows:
        if row['arch'] in ('i386','amd64'):continue
        for mode in range(3):
            sample('/'.join(('foreign',row['name'],str(mode))),'foreign',lambda n:[row['arch'],w/(row['name']+'.text'),str(mode),str(n)])
    assert len(observations)==51
    save('complete',dict(complete=True,source=maps,images=images,host=os.uname().machine,cpu=get('lscpu'),cases=len(observations)))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
