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
    from elftools.elf.elffile import ELFFile
    from fixed_image import FixedImage
    from verify_fixed import run_test
    maps=rd(r/'source.json')
    assert maps['base']['commit']==q['patch_base']
    def link(output,*objects):
        run('clang++',w/'driver.o',*objects,ice_lib,*flags,'-o',w/output)
    link('base',lib)
    assert sha(r/'candidate.patch')==q['sha256']
    run('git','-C',base,'apply','--index',r/'candidate.patch')
    assert get('git','-C',base,'write-tree').strip()==q['tree']
    source=base/'arch/X86/X86BatchScan.c'
    command,=[i for i in rd(build/'compile_commands.json') if Path(i['file'])==source or Path(i['file']).resolve()==source.resolve()]
    args=shlex.split(command['command'])
    args[args.index('-o')+1]=str(w/'alternate.o')
    run(*args,'-DX86_scanNativeBatch=X86_scanAlternateBatch',cwd=command['directory'])
    includes=['-I',base,'-I',base/'include']
    for tag,extra in [('switch',[]),('count',['-DCOUNT_BATCH_CALLS'])]:
        run('clang','-O3',*includes,*extra,'-c',r/'select.c','-o',w/'select.o')
        link(tag,w/'select.o',w/'alternate.o',lib,'-Wl,--wrap=X86_scanNativeBatch')
        nm=get('nm',w/tag)
        assert all(' '+n+'\n' in nm for n in ['X86_scanNativeBatch','X86_scanAlternateBatch','__wrap_X86_scanNativeBatch'])
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    link('candidate',lib)
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    layouts={}
    for tag in ('base','candidate','switch'):
        with (w/tag).open('rb') as f:
            elf=ELFFile(f);sections={k.name:[k['sh_addr'],k['sh_size'],hashlib.sha256(k.data()).hexdigest()]for k in elf.iter_sections()if k.name in ['.cs_x86_batch32_text','.cs_x86_batch64_text','.cs_x86_i386_text']}
            assert len(sections)==3
            layouts[tag]=dict(sections=sections,sha256=sha(w/tag))
    save('layouts',layouts)
    image=FixedImage(w/'selected',{tag:(w/tag).read_bytes()for tag in layouts},executable=True)
    cases={}
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
        for mode in (0,1,2):
            if name in ('putty-32-0.85','libssl3t64-i386') or (name=='libmvec-amd64' and mode in (0,1)):
                cases[name+'/'+str(mode)]=(str(mode),f,path,str(bits))
    assert len(cases)==8
    run_test(w,image,cases,save,layouts)
    save('complete',dict(complete=True,source=q,compiler=get('clang','--version').splitlines()[0],cpu=get('lscpu'),controls=image.receipt()))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
