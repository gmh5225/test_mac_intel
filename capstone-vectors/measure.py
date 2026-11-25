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
    driver=(r/'driver.cpp').read_text();marker='Result timed=run(reps);'
    assert driver.count(marker)==1
    wrapped='#include <valgrind/callgrind.h>\n'+driver.replace(marker,'CALLGRIND_ZERO_STATS; CALLGRIND_TOGGLE_COLLECT; '+marker+' CALLGRIND_TOGGLE_COLLECT;')
    (w/'driver.cpp').write_text(wrapped)
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    assert q['commit']==m['checkout_commit'] and q['tree']==m['checkout_tree']
    run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/'base')
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    audits={}; wanted={'libmvec-amd64'}
    from costs import profile
    from stage import recipe_values,variants
    source=rd(r/'merged.json');assert q['commit']==source['parent'] and sha(r/'candidate.patch')==source['sha256']
    generated=base/'arch/X86/X86GenPrinterQuick.inc';original=recipe_values(generated.read_text())
    run('git','-C',base,'apply','--index',r/'candidate.patch');assert get('git','-C',base,'write-tree').strip()==source['tree']
    run(sys.executable,'-B',base/'suite/synctools/x86_printer_dispatch.py','--check')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/'on')
    select,path_used,proof=variants(w,original,recipe_values(generated.read_text()));save('image',proof)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rows={};profiles=[]

    save('build',dict(capstone=q,neverd=dev,iced=m['iced_revision'],lib=sha(lib),exe=sha(w/'base'),host=platform.machine(),driver=sha(w/'driver.cpp'),inputs=m['drivers']))
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
        for mode in (1,2):
            def visit(tag,reps):
                select(tag)
                return list(map(int,get('setarch',os.uname().machine,'-R',path_used,'private',str(mode),str(reps),f,path,str(bits)).split()))
            reps=max(1,math.ceil(35e6/visit('base',1)[0]))
            expected=visit('base',reps)[2:];labels=['off','duplicate','on','base'];rng=random.Random(name+'/recipe-data/'+str(mode));cycles=[]
            for k in range(35):
                rng.shuffle(labels);times={tag:[] for tag in labels}
                for tag in labels+labels[::-1]:
                    v=visit(tag,reps);assert v[2:]==expected;times[tag].append(v[:2])
                cycles.append({t:[sum(v[i] for v in pairs)for i in (0,1)]for t,pairs in times.items()})
            rows[name+'/'+str(mode)]=dict(cycles=cycles,signature=expected,repeats=reps);save('observations',rows)
            from probe import hardware,record
            with hardware(r,w,save) as (groups,measure):
                if 'work' in groups:
                    summary=record(groups,measure,w,path_used,select,visit,f,path,bits,mode,reps,save)
                    assert set(summary)==set(groups)
    assert len(rows)==2 and set(audits)==wanted
    save('complete',dict(complete=True,source=q,merged=source,cases=len(rows),neverd=dev,inputs=audits))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
