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
    driver=(r/'driver.cpp').read_text();mark='Result timed=run(reps);';assert driver.count(mark)==1
    (w/'driver.cpp').write_text('#include <valgrind/callgrind.h>\n'+driver.replace(mark,'CALLGRIND_START_INSTRUMENTATION; CALLGRIND_ZERO_STATS; Result timed=run(reps); CALLGRIND_DUMP_STATS_AT("measure"); CALLGRIND_STOP_INSTRUMENTATION;'))

    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    trees=rd(r/'source.json');images={}
    for tag,entry in [('base','base'),('compact','prefix'),('word','outlined')]:
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
        if tag!='base':
            patch=r/(tag+'.patch');assert sha(patch)==trees[entry]['sha256']
            run('git','-C',base,'apply','--index',patch)
        assert get('git','-C',base,'write-tree').strip()==trees[entry]['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/tag)
        images[tag]=sha(w/tag)
    assert len(set(images.values()))==3
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    host={'compiler':get('clang','--version').splitlines()[0],'machine':os.uname().machine,'capstone':m['checkout_commit'],'iced':m['iced_revision'],'driver':sha(w/'driver.cpp'),'rust_driver':sha(ad/'iced.rs'),'valgrind':get('valgrind','--version').strip(),'images':images}
    rows={};save('host',host)
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        if name not in ('putty-32-0.85','jpeg-avx2-i386','libmvec-amd64'):continue
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
        variants=[(t,e,m)for t in images for e,m in [('private',0),('private',1),('private',2),('capstone',1)]]
        rows[name]={};boundary=None
        for tree,engine,mode in variants:
            key=tree+'/'+engine+'/'+str(mode)
            label=name+'-'+tree+'-'+engine+'-'+str(mode);raw=w/(label+'.epoch')
            cmd=[w/tree,engine,str(mode),'1',f,path,str(bits)]
            truth=list(map(int,get(*cmd).split()))[2:]
            result=list(map(int,get('valgrind','--tool=callgrind','--instr-atstart=no','--branch-sim=yes','--callgrind-out-file='+str(raw),'--log-file='+str(w/(label+'.log')),*cmd).split()))[2:]
            assert result==truth,(name,key,result,truth)
            if boundary is None:boundary=truth[:3]
            assert boundary==truth[:3] and truth[0]>0
            dumps=[u for u in w.glob(raw.name+'.*') if 'Client Request: measure' in u.read_text(errors='replace')]
            assert len(dumps)==1,(name,key,list(w.glob(raw.name+'*')))
            lines=dumps[0].read_text(errors='replace').splitlines()
            events=next(l.split()[1:] for l in lines if l.startswith('events:'))
            totals=next(list(map(int,l.split()[1:]))for l in lines if l.startswith('summary:'))
            assert events==['Ir','Bc','Bcm','Bi','Bim'] and len(totals)==5 and totals[0]>truth[0]
            for opt in ('yes','no'):
                anno=get('callgrind_annotate','--show=Ir,Bc,Bcm,Bi,Bim','--sort=Ir','--inclusive='+opt,'--threshold=99','--auto=no',dumps[0])
                (e/(label+'-inclusive-'+opt+'.txt')).write_text(anno)
            rows[name][key]={'codes':truth,'events':dict(zip(events,totals)),'per_record':{k:v/truth[0]for k,v in zip(events,totals)},'extent':sha(path),'text':sha(f)};save('rows',rows)
            raw.unlink();dumps[0].unlink()
    save('complete',dict(complete=True,source=m['checkout_commit'],host=host,cases=len(rows),checksum=sum(x['base/private/1']['codes'][0]for x in rows.values())))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
