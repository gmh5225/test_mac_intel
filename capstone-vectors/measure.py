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
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    from training import fetch
    foreign_rows=fetch(r,w);save('foreign-corpus',foreign_rows)
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    def link(label,reader):
        for kind,driver,libs in [('x86',w/'driver.o',[lib,ice_lib,*flags]),('foreign',w/'foreign.o',[lib,'-no-pie'])]:
            exe=w/(kind+'-'+label)
            run('clang++',driver,*libs,'-o',exe)
            if reader:
                lines=get('nm','-an',exe).splitlines()
                fn={z.split()[-1]:int(z.split()[0],16) for z in lines if z.split() and z.split()[-1].startswith('benchReader_')}
                assert len(fn)==5 and len(set(fn.values()))==5 and all(x%64==0 for x in fn.values()),fn
                images[exe.name]=dict(binary=sha(exe),inode=exe.stat().st_ino,code=fn,archive=sha(lib))
        run('clang','-O2','-I',base,'-I',base/'include',r/'raw-timing.c',lib,'-no-pie','-o',w/('raw-'+label))
    link('reference',False)
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    unit=base/'arch/X86/X86DisassemblerDecoder.c';lookup=unit.with_name('X86GenOperandRead.inc')
    parts=[];units={};start='static int readOperands(struct InternalInstruction *insn)\n{';end='/*\n * checkEVEX'
    for label in ('shipping','shift','triple','pair','both'):
        run('git','-C',base,'restore','--staged','--worktree','--source','HEAD','--','.')
        tree=maps[label]
        if label!='shipping':
            patch=r/(label+'.patch');assert sha(patch)==tree['sha256']
            run('git','-C',base,'apply','--index',patch)
        assert get('git','-C',base,'write-tree').strip()==tree['tree']
        source=unit.read_text();i=source.index(start);j=source.index(end,i)
        body=source[i:j].replace('#include "X86GenOperandRead.inc"',lookup.read_text())
        assert body.count(start)==1
        parts.append(body.replace(start,'static __attribute__((aligned(64),noinline)) int benchReader_'+label+'(struct InternalInstruction *insn)\n{'))
        units[label]=dict(body=hashlib.sha256(body.encode()).hexdigest(),source=tree)
    assert len({v['body'] for v in units.values()})==len(units)
    run('git','-C',base,'restore','--staged','--worktree','--source','HEAD','--','.')
    source=unit.read_text();i=source.index(start);j=source.index(end,i)
    new=source[:i]+'\n'.join(parts)+(r/'select.inc').read_text()+'\n'+source[j:]
    for label in ('timed','counted'):
        unit.write_text(('#define READER_COUNTS\n' if label=='counted' else '')+new)
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        link(label,True)
    save('images',images);save('units',units)
    raw_results={}
    def raw_samples(key,args_for):
        data=w/'capture.bin'
        exe=w/'x86-counted'
        run('setarch',os.uname().machine,'-R',exe,*args_for(1),env=dict(os.environ,CS_BENCH_READER='0',CS_BENCH_READ_TRACE=str(data)),capture_output=True)
        content=data.read_bytes();data.unlink()
        assert len(content)%40==0 and content[:len(content)//2]==content[len(content)//2:]
        rows={k:bytearray() for k in ('double-shift','other-three','untargeted')}
        for i in range(0,len(content)//2,20):
            row=content[i:i+20];sid=int.from_bytes(row[:2],'little')
            group='double-shift' if 196<=sid<=199 else 'other-three' if 44<=sid<=47 or 101<=sid<=106 or 192<=sid<=195 else 'untargeted'
            rows[group]+=row
        for group,region in rows.items():
            if not region:continue
            file=w/'cohort.bin';file.write_bytes(region);binary=w/'raw-timed'
            def take(exe,sel,n):
                return list(map(int,get('setarch',os.uname().machine,'-R',exe,file,str(n),env=dict(os.environ,CS_BENCH_READER=str(sel))).split()))
            one=take(w/'raw-reference',0,1)
            assert all(take(binary,j,1)[2:]==one[2:] for j in range(6))
            reps=max(1,math.ceil(12e6/one[0]))
            expected=take(w/'raw-reference',0,reps)[2:];order=list(range(6));rng=random.Random(key+group);blocks=[]
            for _ in range(17):
                rng.shuffle(order);row=[[0,0] for j in order]
                for j in order+order[::-1]:
                    v=take(binary,j,reps);assert v[2:]==expected and min(v[:2])>0
                    for c in (0,1):row[j][c]+=v[c]
                blocks.append(row)
            raw_results[key+'/'+group]=dict(count=len(region)//20,sha=sha(file),checks=one[2:],reps=reps,pairs=blocks)
            file.unlink();save('raw-cohorts',raw_results)
    observations={}
    def sample(key,kind,args_for):
        binary=w/(kind+'-timed')
        def launch(exe,sel,n):
            return sp.run(['setarch',os.uname().machine,'-R',exe,*args_for(n)],env=dict(os.environ,CS_BENCH_READER=str(sel)),check=True,capture_output=True,text=True)
        def take(i,n):return list(map(int,launch(binary,i,n).stdout.split()))
        ref=list(map(int,launch(w/(kind+'-reference'),0,1).stdout.split()))
        counted=launch(w/(kind+'-counted'),0,1)
        assert list(map(int,counted.stdout.split()))[2:]==ref[2:]
        calls,indented,high=map(int,counted.stderr.split())
        assert 0<=indented<=calls and 0<=high<=calls-indented
        reps=max(1,math.ceil(25e6/ref[0]));expected=take(0,reps)[2:]
        assert all(take(i,1)[2:]==ref[2:] for i in range(6))
        order=list(range(6));rng=random.Random('scalar-raw/'+key);blocks=[]
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

        if name in ('putty-32-0.85','libssl3t64-i386','libmvec-amd64'):
            raw_samples(name,lambda n:['private','1',str(n),f,path,str(bits)])
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
