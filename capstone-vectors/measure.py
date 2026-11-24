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
    import shlex
    row,=[x for x in rd(build/'compile_commands.json')if Path(x['file']).name=='X86RegisterFallback32.c']
    argv=shlex.split(row['command']);source=Path(row['file'])
    def compile_one(name):
        args=argv.copy();args[args.index('-o')+1]=str(w/(name+'.o'))
        args+=['-DX86_decodeRegisterFallback32='+name]
        run(*args,cwd=row['directory'])
    original=sha(lib)
    for name in ('original_a','original_b'):compile_one(name)
    assert sha(r/'candidate.patch')==q['sha256']
    run('git','-C',base,'apply','--index',r/'candidate.patch')
    assert get('git','-C',base,'write-tree').strip()==q['tree']
    for name in ('late_a','late_b'):compile_one(name)
    src=source.read_text()
    def inject(a,b):
        global src
        assert src.count(a)==1,a
        src=src.replace(a,b)
    inject('const unsigned opcode = code[0];','extern unsigned long long reader_entries, admission_checks, group_ff, register_hits;\n\t++reader_entries;\n\tconst unsigned opcode = code[0];')
    inject('if (opcode == 0xff && size >= 2','++admission_checks;\n\tgroup_ff += opcode == 0xff;\n\tif (opcode == 0xff && size >= 2')
    inject('!X86_OUTPUT_UNSUPPORTED(handle, false))\n\t\t\treturn X86_writeIndirectRegister(', '!X86_OUTPUT_UNSUPPORTED(handle, false) && (++register_hits, true))\n\t\t\treturn X86_writeIndirectRegister(')
    source.write_text(src);compile_one('measured_probe')
    run('git','-C',base,'restore','--source','HEAD','--staged','--worktree','--','.')
    assert get('git','-C',base,'write-tree').strip()==m['checkout_tree'] and sha(lib)==original
    args=argv.copy();args[args.index(str(source))]=str(r/'select.c');args[args.index('-o')+1]=str(w/'choose.o')
    run(*args,'-I',str(base),cwd=row['directory'])
    order=['original_a','late_a','late_b','original_b','measured_probe']
    run('clang++',w/'driver.o',w/'choose.o',*[w/(n+'.o')for n in order],
        '-Wl,--wrap=X86_decodeRegisterFallback32',lib,ice_lib,*flags,'-o',w/'image')
    from elftools.elf.elffile import ELFFile
    with (w/'image').open('rb')as stream:
        elf=ELFFile(stream);assert elf.header['e_type']=='ET_EXEC'
        symbols={v.name: [v['st_value'],v['st_size']] for v in elf.get_section_by_name('.symtab').iter_symbols()if v.name in set(order)|{'__wrap_X86_decodeRegisterFallback32','X86_disasmIter32','X86_decodeOutputMiss32','tryOutput32','cs_decode_full_insn'}}
    assert set(order)<=set(symbols) and len({symbols[k][0]for k in order})==5
    assert symbols['original_a'][1]==symbols['original_b'][1]and symbols['late_a'][1]==symbols['late_b'][1]
    images=dict(archive=original,exe=sha(w/'image'),inode=(w/'image').stat().st_ino,symbols=symbols)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R',w/'image']
    save('image',images);counter={}
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
        if bits!=32:continue
        labels=['baseA','baseB','lateA','lateB'];index={k:str(i)for i,k in enumerate(labels+['probe'])}
        def take(label,mode,reps,route='private'):
            engine=label if label in ('iced','fast')else route
            result=sp.run([*invoke,engine,str(mode),str(reps),f,path,str(bits)],check=True,capture_output=True,text=True,
                          env=dict(os.environ,CS_READER=index.get(label,'0')))
            if label=='probe':
                counts=list(map(int,result.stderr.split()));assert len(counts)==4 and all(x%(reps+1)==0 for x in counts)
                counter[name+'/'+route+'/'+str(mode)]=[x//(reps+1) for x in counts]
                save('probe',counter)
            return list(map(int,result.stdout.split()))
        audits[name]=dict(extents=len(selected),extent_sha256=sha(path),sha256=sha(f))
        for mode in (0,1,2):
            for route in ('private','capstone'):
                assert take('probe',mode,1,route)[2:]==take('baseA',mode,1,route)[2:]
            presult=counter[name+'/private/'+str(mode)]
            ceiling=0 if mode==0 else {'putty-32-0.85':390,'libssl3t64-i386':1114,'jpeg-avx2-i386':0}[name]
            assert 0<=presult[-1]<=ceiling and presult[0]>=presult[1]>=presult[2]>=presult[3]
            if ceiling:assert presult[-1]>0
            if mode==0:continue
            repeats=max(1,math.ceil(26e6/take('baseA',mode,1)[0]))
            others=['iced','fast'];all_keys=labels+others
            expected={k:take(k,mode,repeats)[2:]for k in all_keys}
            assert all(v[:3]==expected['baseA'][:3] for v in expected.values()) and len({tuple(expected[k])for k in labels})==1
            key=name+'/'+str(mode);n=35 if name=='jpeg-avx2-i386' else 17
            rng=random.Random(key);cycles=[]
            for _ in range(n):
                rng.shuffle(all_keys);pair={k:[]for k in all_keys}
                for k in all_keys+all_keys[::-1]:
                    row=take(k,mode,repeats);assert row[2:]==expected[k];pair[k].append(row[:2])
                cycles.append({k:[sum(v[j]for v in a)for j in (0,1)]for k,a in pair.items()})
            observations[key]=dict(cycles=cycles,checks=expected,reps=repeats);save('observations',observations)
    assert len(audits)==3 and len(observations)==6 and len(counter)==18 and sha(w/'image')==images['exe']
    save('complete',dict(complete=True,source=q,host=host,audits=audits,columns=['fallback calls','reached FF check','FF opcode','admitted register CALL or JMP'],image=images))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
