from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def once(s,a,b):assert s.count(a)==1,(a,s.count(a));return s.replace(a,b)
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
    f=ad/'iced.rs';v=f.read_text()
    start=v.index('                result.values = result.values.wrapping_add(\n                    state.text.len()')
    end=v.index('                );',start)+len('                );')
    original=v[start:end]
    v=v[:start]+'''                if state.mode & 7 == 5 {
                    std::hint::black_box(state.text.as_bytes());
                } else {
'''+original+'''
                }'''+v[end:]
    v=once(v,'if (state.mode & 7) >= 2 {','if (state.mode & 7) >= 2 && (state.mode & 7) != 5 {')
    f.write_text(v)
    f=w/'driver.cpp';v=once((r/'driver.cpp').read_text(),'if (mode>4 || !reps)','if (mode>5 || !reps)')
    v=once(v,'mode>=2 ? CS_OPT_ON','mode>=2 && mode!=5 ? CS_OPT_ON')
    v=once(v,'      if (mode) {','''      if (mode == 5) {
        asm volatile("" : : "r"(insn->mnemonic), "r"(insn->op_str) : "memory");
      } else if (mode) {''')
    f.write_text(v)
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    assert q['commit']==m['checkout_commit'] and q['tree']==m['checkout_tree']
    run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/'base')
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    audits={}; wanted={'putty-32-0.85','libmvec-amd64','jpeg-avx2-i386'}
    report={}
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    save('build',dict(capstone=q,neverd=dev,iced=m['iced_revision'],lib=sha(lib),exe=sha(w/'base'),host=platform.machine(),driver=sha(w/'driver.cpp'),adapter=sha(ad/'iced.rs'),inputs=m['drivers']))
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    for name,bits,f,spans,_ in itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)):
        if name not in wanted:continue
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
        traces=[list(map(int,line.split()))for line in get(w/'base','audit','0','1',f,path,str(bits)).splitlines()]
        assert len(traces)==len(selected) and all(x[3]==x[4] and x[1]==x[5]for x in traces)
        audits[name]=dict(extents=len(selected),boundaries=sum(x[3]for x in traces),extent_sha256=sha(path),text_sha256=sha(f))
        save('audit',audits)
        labels=('private/1','private/5','fast/1','fast/5')
        def read(label,reps):return list(map(int,get('setarch',os.uname().machine,'-R',w/'base',*label.split('/'),str(reps),f,path,str(bits)).split()))
        calibration={label:read(label,1)for label in labels}
        assert len({tuple(z[2:5])for z in calibration.values()})==1 and calibration['private/1'][2]>0
        reps=max(1,min(math.ceil(40e6/z[0])for z in calibration.values()))
        expected={label:read(label,reps)[2:] for label in labels}
        assert len({tuple(z[:3])for z in expected.values()})==1
        assert all(expected[e+'/5'][3]<expected[e+'/1'][3]for e in ('private','fast'))
        order=list(labels);rng=random.Random('consumer-'+name);cycles=[]
        for block in range(17):
            rng.shuffle(order);data={label:[] for label in labels}
            for label in order+order[::-1]:
                z=read(label,reps);assert z[2:]==expected[label];data[label].append(z[:2])
            cycles.append({k:[x+y for x,y in zip(*v)] for k,v in data.items()})
        def compare(a,b):
            values=[sorted(row[a][i]/row[b][i]for row in cycles) for i in (0,1)]
            return {clock:[statistics.median(v),v[4],v[-5]] for clock,v in zip(('cpu','wall'),values)}
        report[name]=dict(reps=reps,extent_sha256=sha(path),text_sha256=sha(f),expected=expected,ordinary_ratio=compare('fast/1','private/1'),materialized_ratio=compare('fast/5','private/5'),private_consumption=compare('private/1','private/5'),iced_consumption=compare('fast/1','fast/5'),cycles=cycles)
        save('results',report);print(name,report[name]['ordinary_ratio'],report[name]['materialized_ratio'],flush=True)
    assert len(report)==3
    save('complete',dict(complete=True,dev=dev,source=q,iced=m['iced_revision'],inputs=list(report),pairs=17,method='The same executable processes each span twice in a randomized forward/reverse list with both checksum policies and both engines. Mode 5 still invokes the formatter and passes full output to a compiler barrier. This is a consumer-cost diagnostic only.'))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
