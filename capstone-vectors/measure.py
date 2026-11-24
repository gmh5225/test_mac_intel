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
    import shlex
    original=sha(lib);db=rd(build/'compile_commands.json');row,=[x for x in db if Path(x['file']).name=='X86ImmediateOutput.c']
    argv=shlex.split(row['command']);f=Path(row['file']);src_index=argv.index(str(f));obj_index=argv.index('-o')+1
    def compile(source,output,extra):
        args=argv.copy();args[src_index]=str(source);args[obj_index]=str(output);run(*args,*extra,cwd=row['directory'])
    for name in ('digits','details'):
        patch=r/(name+'.patch');spec=m['variants'][name];assert sha(patch)==spec['sha256']
        run('git','-C',base,'apply','--index',patch);assert get('git','-C',base,'write-tree').strip()==spec['tree']
        compile(f,w/(name+'.o'),['-DX86_writeImmediateOutput=measure_'+name])
        run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','arch/X86')
    compile(r/'select.c',w/'select.o',['-I',str(base)])
    run('clang++',w/'driver.o',w/'select.o',w/'digits.o',w/'details.o','-Wl,--wrap=X86_writeImmediateOutput',lib,ice_lib,*flags,'-o',w/'image')
    images={'all':dict(exe=sha(w/'image'),archive=sha(lib))};assert sha(lib)==original
    symbols={}
    for line in get('nm','-S','-n',w/'image').splitlines():
        col=line.split()
        if len(col)==4 and col[3]in ('X86_writeImmediateOutput','measure_digits','measure_details','__wrap_X86_writeImmediateOutput','X86_scanNativeBatch','X86_disasmIterText','X86_disasmIter32'):symbols[col[3]]=[int(col[0],16),int(col[1],16)]
    assert len(symbols)==7;save('workers',dict(symbols=symbols,object_options=argv,images=images))
    run('setarch',platform.machine(),'-R','/bin/true')
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
            rows=[list(map(int,z.split())) for z in get('setarch',platform.machine(),'-R',w/'image','audit','0','1',f,path,str(bits),env=dict(os.environ,CS_IMMEDIATE_VARIANT={'digits':'1','details':'2'}.get(exe,'0'))).splitlines()]
            assert len(rows)==len(selected) and all(a[3]==a[4] and a[1]==a[5] for a in rows)
            return rows
        assert audit_engine('base')==audit_engine('digits')==audit_engine('details')
        audits[name]=dict(functions=len(selected),bytes=spec['bytes'],extent_sha256=sha(path));save('audit',audits)
        def take(engine,mode,n):
            comparator=engine if engine in ('iced','fast') else 'private'
            exe=engine if engine in ('candidate','duplicate')else'base'
            return list(map(int,get('setarch',platform.machine(),'-R',w/'image',comparator,str(mode),str(n),f,path,str(bits),env=dict(os.environ,CS_IMMEDIATE_VARIANT={'digits':'1','details':'2','trap':'3'}.get(engine,'0'))).split()))
        assert take('trap',0,1)[2:]==take('base',0,1)[2:]
        proc=sp.run(['setarch',platform.machine(),'-R',w/'image','private','1','1',f,path,str(bits)],env=dict(os.environ,CS_IMMEDIATE_VARIANT='3'))
        assert proc.returncode==73,(name,proc.returncode)

        for mode in (0,1,2):
            labels=['base','duplicate','digits','details','iced']+(['fast']if mode else[])
            repeats=max(1,math.ceil(25e6/take('iced',mode,1)[0]))
            expected={k:take(k,mode,repeats)[2:]for k in labels}
            assert len({tuple(x[:3])for x in expected.values()})==1 and expected['base']==expected['duplicate']==expected['digits']==expected['details']
            rows=[];rng=random.Random(name+'/same-image-immediate/'+str(mode))
            for _ in range(17):
                rng.shuffle(labels);sample={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    row=take(k,mode,repeats);assert row[2:]==expected[k]
                    sample[k].append(row[:2])
                rows.append({k:[sum(a[i]for a in times)for i in (0,1)]for k,times in sample.items()})
            key=name+'/'+str(mode);observations[key]=dict(repeats=repeats,checks=expected,cycles=rows)
            summary[key]={label:{k:interval([x[k][i]/x['digits'][i]for x in rows])for k in labels if k!='digits'}for i,label in enumerate(('cpu','wall'))}
            save('effects',summary);save('observations',observations);print(key,summary[key]['cpu']['base'],flush=True)
    assert len(summary)==18
    save('complete',dict(complete=True,source=q,host=host,images=images,pairs=17,samples=audits,unit='Paired throughput, X86_scanNativeBatch with cs_disasm_iter fallback on scan misses; X86_disasmIterText for text and details. Both algorithms use one fixed-address executable linked with the current NeverD static Capstone configuration. iced Intel and Fast formatters run on the same accepted instruction spans; full native results are consumed and Capstone output checksums agree exactly.'))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
