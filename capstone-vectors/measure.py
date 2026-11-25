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
    gas=w/'gas-adapter';gas.mkdir()
    assert {f:sha(r/f) for f in ('gas.rs','gas_driver.cpp','gas-Cargo.toml')}==rd(r/'gas-sources.json')
    shutil.copyfile(r/'Cargo.lock',gas/'Cargo.lock');shutil.copyfile(r/'gas.rs',gas/'iced.rs')
    (gas/'Cargo.toml').write_text((r/'gas-Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=gas)
    gas_lib=gas/'target/release/libiced_compare.a'
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',r/'gas_driver.cpp','-o',w/'att-bench.o')
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    candidate = rd(r/'source.json')['outlined']
    assert sha(r/'outlined.patch') == candidate['sha256'] and candidate['parent'] == m['checkout_commit']
    run('git','-C',base,'apply','--index',r/'outlined.patch')
    assert get('git','-C',base,'write-tree').strip() == candidate['tree']
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/'intel')
    run('clang++',w/'att-bench.o',lib,gas_lib,*flags,'-o',w/'att')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cohort = rd(r/'cohort.json')
    assert cohort['complete'] and cohort['source']==candidate
    host = dict(cpu=get('lscpu'),affinity=sorted(os.sched_getaffinity(0)),system=platform.platform(),compiler=get('clang','--version').splitlines()[0],images={s:sha(w/s) for s in ('intel','att')},archive=sha(lib),iced=m['iced_revision'],source=candidate,neverd=dev,drivers={**m['drivers'],**rd(r/'gas-sources.json')})
    save('host',host)
    policies = dict(intel=('capstone','private','iced','fast'),att=('capstone','private','iced'))
    sys.path.insert(0,str(w))
    import pe_panels
    run(sys.executable,'-B',w/'libmvec.py')
    meta = rd(w/'libmvec.json')
    pe = rd(w/'pe-images.json')
    (w/'pe-images.json').write_text(json.dumps([row for row in pe if row['bits']==32]))
    putty, = pe_panels.prepare(w)
    vec = ('libmvec-amd64',64,w/'libmvec.text',[(0,meta['bytes'],meta['address'])],meta)
    def bench_case(name,group,bits,blob,ranges,accepted,rejected):
        policy = policies if group=='whole' else {'att':('capstone','iced')}
        modes = (1,3,4,2)
        def take(syntax,engine,mode,repeats):
            value = list(map(int,get('setarch',os.uname().machine,'-R',w/syntax,engine,str(mode),str(repeats),blob,ranges,str(bits)).split()))
            assert len(value)==6 and value[2:4]==[accepted*repeats,rejected*repeats],(name,group,engine,mode,value)
            return value
        def call(label,n):
            dialect,engine,mode = label.split('/')
            return take(dialect,engine,int(mode),n)
        labels = [f'{dialect}/{engine}/{mode}' for dialect,engines in policy.items() for engine in engines for mode in modes]
        def audit(dialect):
            actual = [list(map(int,line.split())) for line in get('setarch',os.uname().machine,'-R',w/dialect,'audit','0','1',blob,ranges,str(bits)).splitlines()]
            assert len(actual)==len(ranges.read_text().splitlines()) and all(a[3]==a[4] and a[1]==a[5] for a in actual)
            assert sum(a[3] for a in actual)==accepted+rejected
            return actual
        audits = [audit(dialect) for dialect in policy]
        assert all(a==audits[0] for a in audits)
        n = max(1,math.ceil(15e6/min(call(label,1)[0] for label in labels)))
        expected = {label:call(label,n)[2:] for label in labels}
        assert len({tuple(z[:3]) for z in expected.values()})==1
        for dialect,engines in policy.items():
            for engine in engines:
                assert expected[f'{dialect}/{engine}/1']==expected[f'{dialect}/{engine}/3']
                if engine=='private':
                    assert all(expected[f'{dialect}/{engine}/{mode}']==expected[f'{dialect}/capstone/{mode}'] for mode in modes)
        cycles=[]
        rng=random.Random(name+'/'+group+'/stages')
        for j in range(17):
            order=labels.copy()
            rng.shuffle(order)
            clocks={label:[0,0] for label in order}
            for label in order+order[::-1]:
                value=call(label,n)
                assert value[2:]==expected[label],(name,group,label,j,value)
                for i in (0,1):clocks[label][i]+=value[i]
            cycles.append(clocks)
        return dict(accepted=accepted,rejected=rejected,spans=len(audits[0]),bytes=sum(a[1] for a in audits[0]),sha256=sha(blob),extents_sha256=sha(ranges),repeats=n,visits=2,checks=expected,cycles=cycles)
    panels={}
    for name,bits,blob,spans,_ in (vec,putty):
        expected=m['provenance'][name]
        assert sha(blob)==expected['text_sha256'] and len(spans)==1
        path=w/(name+'.tsv')
        path.write_text(''.join('%d %d %d\n'%tuple(row) for row in spans))
        assert sha(path)==expected['extent_sha256']
        accepted,rejected=(25021,0) if bits==64 else (282906,3)
        panels[name+'/whole']=bench_case(name,'whole',bits,blob,path,accepted,rejected)
        save('observations',panels)
        if bits==64:
            assert cohort['section_sha256']==sha(blob) and cohort['extents_sha256']==sha(path)
            for group,data in cohort['groups'].items():
                path=r/(group+'.tsv')
                assert sha(path)==data['sha256']
                result=bench_case(name,group,bits,blob,path,data['instructions'],0)
                assert (result['spans'],result['bytes'])==(data['spans'],data['bytes'])
                panels[name+'/'+group]=result
                save('observations',panels)
    save('complete',dict(complete=True,panels=sorted(panels),host=host))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink())
    shutil.rmtree(w)
    save('cleanup',dict(removed=not w.exists(),bytes=n))
