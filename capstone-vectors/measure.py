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
# Keep the changed vector writer and the existing i386 readers in paired section slots.
    from elf_slots import plan,symbols
    from elftools.elf.elffile import ELFFile
    protocol=rd(r/'protocol.json');machine=platform.machine()
    reference=protocol['images'][machine]
    assert protocol['source']==q
    members=['X86VectorOutput.c.o','X86Vex32Output.c.o','X86MemoryFallback32.c.o','X86RegisterFallback32.c.o','X86BatchScan.c.o']
    archives={};versions={};obj={}
    ar=shutil.which('llvm-ar') or shutil.which('ar')
    objcopy=shutil.which('llvm-objcopy') or shutil.which('objcopy')
    for tag in ('base','candidate'):
        if tag=='candidate':
            patch=r/'candidate.patch';assert sha(patch)==q['sha256']
            run('git','-C',base,'apply','--index',patch)
            assert get('git','-C',base,'write-tree').strip()==q['tree']
            run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        dest=w/('objects-'+tag);dest.mkdir();versions[tag]=dest
        archive=archives[tag]=dest/'libcapstone.a';shutil.copyfile(lib,archive)
        assert sha(archive)==reference[tag]['archive']
        obj[tag]={str(x.relative_to(build)):sha(x) for x in build.rglob('*.c.o')}
        for member in members:
            (dest/member).write_bytes(sp.check_output([ar,'p',archive,member]))
            path,=build.rglob(member);assert (dest/member).read_bytes()==path.read_bytes()
    changes=[Path(f).name for f,h in obj['base'].items() if obj['candidate'][f]!=h]
    assert changes==['X86VectorOutput.c.o']
    links={'regular':(archives,None)}
    for label,groups in [('code',{'exec'}),('constants',{'const'}),('both',{'exec','const'})]:
        wd=w/label;wd.mkdir();libs,ld=plan(versions,archives,wd,ar,objcopy,[members[0]],groups)
        links[label]=libs,ld
        (e/(label+'.ld')).write_bytes(ld.read_bytes())
    layouts={};files={}
    interest=['X86_disasmIter32','X86_decodeOutputMiss32','X86_decodeRegisterFallback32','X86_scanNativeBatch',
              'X86_disasmIterText','cs_decode_full_insn','X86_writeVectorOutput','cs_disasm_iter','X86_reg_access']
    for group,(libs,script) in links.items():
        for tag,archive in libs.items():
            label=group+'-'+tag;exe=w/label
            link=['clang++',w/'driver.o',archive,ice_lib,*flags]
            if script is not None:link+=['-fuse-ld=bfd','-Wl,-T,'+str(script)]
            run(*link,'-o',exe)
            digest=sha(exe)
            if group=='regular':assert digest==reference[tag]['exe']
            sy,sections=symbols(exe)
            with exe.open('rb') as f:
                elf=ELFFile(f);sym=elf.get_section_by_name('.symtab')
                slots={x.name:x['st_value'] for x in sym.iter_symbols() if x.name.startswith('csprobe_') and x.name.endswith(('_start','_end'))}
            layouts[label]=dict(digest=digest,functions={k:sy[k] for k in interest if k in sy},sections=sections,slots=slots)
            files[label]=exe.read_bytes()
        files[group+'-copy']=files[group+'-base']
    for group in ('code','constants','both'):
        x,y=(layouts[group+'-'+tag] for tag in ('base','candidate'))
        assert set(x['slots'])==set(y['slots']) and len(x['slots'])>=2
        sections={kind:'.csprobe_'+kind for kind in ('exec','const')}
        for kind,section in sections.items():
            if section not in x['sections']:continue
            assert x['sections'][section][1]==y['sections'][section][1]
    save('links',dict(layout=layouts,members=[members[0]],changed=changes,scripts={k:sha(ld) for k,(_,ld) in links.items() if ld}))
    length=max(map(len,files.values()));files={k:v.ljust(length,b'\0') for k,v in files.items()}
    path=w/'selected';previous='regular-base';path.write_bytes(files[previous]);path.chmod(0o755)
    inode=path.stat().st_ino;verified={}
    diffs={(a,b):[j for j in range(0,length,16384) if x[j:j+16384]!=y[j:j+16384]] for a,x in files.items() for b,y in files.items()}
    def select(k):
        global previous
        if k!=previous:
            with path.open('r+b',buffering=0) as f:
                for j in diffs[previous,k]:
                    f.seek(j);chunk=files[k][j:j+16384];assert f.write(chunk)==len(chunk)
            previous=k
        assert path.stat().st_ino==inode
        if k not in verified:
            assert path.read_bytes()==files[k]
            verified[k]=sha(path)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',machine,'-R',path];results={};random_input=platform.node()
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path_to_spans=w/(name+'.tsv')
        def emit(v):path_to_spans.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path_to_spans).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path_to_spans)==spec['extent_sha256']
        for key in protocol['keys']:
            engine,program,mode=key.split('/')
            if program!=name:continue
            def trial(tag,reps):
                select(tag)
                return list(map(int,get(*invoke,engine,mode,str(reps),f,path_to_spans,str(bits)).split()))
            path_to_spans=w/(name+'.tsv')
            reps=max(1,math.ceil(protocol['duration_ns']/trial('regular-base',1)[0]))
            expected=trial('regular-base',reps)[2:]
            assert all(trial(t,reps)[2:]==expected for t in files)
            order=list(files);rng=random.Random(key+'/'+random_input);blocks=[]
            for _ in range(protocol['iterations']):
                rng.shuffle(order);times={k:[] for k in files}
                for k in order+order[::-1]:
                    got=trial(k,reps);assert got[2:]==expected;times[k].append(got[:2])
                blocks.append({k:[a+b for a,b in zip(*v)]for k,v in times.items()})
            results[key]=dict(reps=reps,expected=expected,pairs=blocks);save('observations',results)
    assert set(results)==set(protocol['keys']) and len(verified)==12
    save('complete',dict(complete=True,protocol=protocol,source=q,verified=verified,machine=machine,compiler=get('clang','--version'),node=random_input))
finally:
    size=sum(p.stat().st_size for p in w.rglob('*') if p.is_file() and not p.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
