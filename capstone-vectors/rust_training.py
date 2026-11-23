from pathlib import Path
import hashlib,json,os,re,shutil,subprocess as sp
def rust_triple():
    version=sp.check_output(['rustc','-vV'],text=True)
    return next(line.split(': ',1)[1]for line in version.splitlines()if line.startswith('host: '))
def fork_profdata(w,out):
    src=w/'llvm-profdata-source';build=w/'llvm-profdata-build'
    uri='https://github.com/NeverSight/llvm-project.git'
    sp.run(['git','clone','--quiet','--filter=blob:none','--no-checkout','--depth','1','--branch','main',uri,src],check=True)
    sp.run(['git','-C',src,'sparse-checkout','init','--no-cone'],check=True)
    sp.run(['git','-C',src,'sparse-checkout','set','--no-cone','/llvm/','!/llvm/test/','!/llvm/unittests/','/cmake/','/third-party/'],check=True)
    sp.run(['git','-C',src,'checkout','--quiet','--detach','HEAD'],check=True)
    head=sp.check_output(['git','-C',src,'rev-parse','HEAD'],text=True).strip()
    (out/'llvm-source-at-configure.json').write_text(json.dumps(dict(repository=uri,branch='main',commit=head))+'\n')
    try:
        sp.run(['cmake','-S',src/'llvm','-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DLLVM_TARGETS_TO_BUILD=Native','-DLLVM_ENABLE_RTTI=ON','-DLLVM_INCLUDE_TESTS=OFF','-DLLVM_INCLUDE_EXAMPLES=OFF','-DLLVM_INCLUDE_BENCHMARKS=OFF','-DLLVM_BUILD_TOOLS=ON','-DLLVM_ENABLE_PROJECTS=','-DLLVM_ENABLE_TERMINFO=OFF'],check=True)
    except sp.CalledProcessError:
        for name in ('CMakeConfigureLog.yaml','CMakeError.log'):
            log=build/'CMakeFiles'/name
            if log.is_file():
                import gzip
                (out/(name+'.gz')).write_bytes(gzip.compress(log.read_bytes(),mtime=0))
        raise
    sp.run(['cmake','--build',build,'--target','llvm-profdata','--parallel','4'],check=True)
    tool=w/'fork-llvm-profdata';shutil.copy2(build/'bin/llvm-profdata',tool)
    version=sp.check_output([tool,'--version'],text=True)
    size=sum(f.stat().st_size for t in (src,build)for f in t.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(src);shutil.rmtree(build)
    (out/'llvm-profdata-source.json').write_text(json.dumps(dict(repository=uri,branch='main',commit=head,version=version,built_from_source=True,removed_bytes=size,cleaned=not src.exists()and not build.exists()),indent=2)+'\n');return tool
def rust_build(ad,w,out,arg):
    env=dict(os.environ);env['RUSTFLAGS']=(env.get('RUSTFLAGS','')+' '+arg).strip()
    triple=rust_triple();td=w/'rust-pgo-target'
    with (out/('rust-generate.log' if 'generate='in arg else 'rust-use.log')).open('w') as log:
        sp.run(['cargo','build','--locked','--release','--target',triple,'--target-dir',td],cwd=ad,env=env,stdout=log,stderr=sp.STDOUT,check=True)
    return td/triple/'release/libiced_compare.a'
def instrument(ad,w,out,flags,capstone,syslibs):
    raw=w/'rust-raw';raw.mkdir()
    lib=rust_build(ad,w,out,'-Cprofile-generate='+str(raw))
    libdir=Path(sp.check_output(['rustc','--print','target-libdir'],text=True).strip())
    rt,=libdir.glob('libprofiler_builtins-*.rlib')
    exe=w/'rust-training-runner'
    wrapper=w/'profile_driver.o'
    sp.run(['clang','-O2','-c',Path(__file__).with_name('profile_driver.c'),'-o',wrapper],check=True)
    with (out/'rust-instrumented-link.log').open('w')as log:
        sp.run(['clang++','-Wl,--wrap=main',w/'driver.o',wrapper,*flags,capstone,lib,rt,*syslibs,'-o',exe],stdout=log,stderr=sp.STDOUT,check=True)
    return exe
def optimize(ad,w,out,counts):
    raw=w/'rust-raw';frozen=sorted(raw.glob('training-*.profraw'));assert len(frozen)==36 and all(f.stat().st_size>128 for f in frozen),(len(frozen),[f.stat().st_size for f in frozen])
    import struct
    versions={struct.unpack_from('<Q',f.read_bytes(),8)[0]&0xffffffff for f in frozen}
    if versions!={10}:raise RuntimeError(('unexpected raw profile versions',versions))
    (out/'input-counter-files.json').write_text(json.dumps({f.name:{'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in frozen},indent=2)+'\n')
    tool=fork_profdata(w,out);merged=w/'iced.profdata';sp.run([tool,'merge','-o',merged,*frozen],check=True)
    shown=sp.check_output([tool,'show','--all-functions','--counts',merged],text=True)
    import gzip
    (out/'iced-counter-functions.txt.gz').write_bytes(gzip.compress(shown.encode(),mtime=0))
    groups=dict(decoder={},formatter={},info={},adapter={})
    symbols=re.findall(r'^  (\S[^\n]*):\n((?:    [^\n]+\n)+)',shown,re.M)
    for name,data in symbols:
        keys=[x for x in ('decoder','formatter','info')if x in name.lower()]
        if name=='iced_run':keys+=['adapter']
        if not keys:continue
        hits=[int(v)for l in data.splitlines()if 'Block counts:'in l or 'Function count:'in l for v in re.findall(r'[0-9]+',l.split(':',1)[1])]
        if hits and max(hits)>0:
            for k in keys:groups[k][name]=max(hits)
    assert all(groups.values()),[(k,len(v))for k,v in groups.items()]
    keep={k:dict(sorted(z.items(),key=lambda t:-t[1])[:5])for k,z in groups.items()}
    trained=rust_build(ad,w,out,'-Cprofile-use='+str(merged))
    (out/'rust-profile.json').write_text(json.dumps(dict(rust=sp.check_output(['rustc','-vV'],text=True),training=counts,active_functions=keep,raw_files=len(frozen),profile_sha256=hashlib.sha256(merged.read_bytes()).hexdigest(),library_sha256=hashlib.sha256(trained.read_bytes()).hexdigest()),indent=2)+'\n')
    usage=(out/'rust-use.log').read_text(errors='replace')
    assert not any(z in usage.lower() for z in ('invalid instrumentation profile','malformed instrumentation profile','unsupported instrumentation profile','failed to load profile'))
    assert 'release: 1.97.1' in sp.check_output(['rustc','-vV'],text=True)
    return trained
