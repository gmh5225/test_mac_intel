from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent;s=p/'source';nd=p/'neverd-config';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def get(*a):return sp.check_output(a,text=True)
def run(*a,cwd=None,log=None):
    if log:
        with log.open('wb')as output:out=sp.run(a,cwd=cwd,stdout=output,stderr=sp.STDOUT,env=dict(os.environ,ZERO_AR_DATE='1',SOURCE_DATE_EPOCH='1735689600'))
        if out.returncode:print(log.read_text(errors='replace')[-4000:],flush=True)
        out.check_returncode()
    else:sp.run(a,cwd=cwd,check=True)
q=rd(r/'source.json');assert get('git','-C',s,'rev-parse','HEAD').strip()==q['base'] and get('git','-C',nd,'rev-parse','HEAD').strip()==q['dev']
t=Path(tempfile.mkdtemp());project=t/'project';b=t/'cmake-build';obj=t/'make-build'
arch=platform.machine().lower();enabled=sys.platform=='darwin' or arch in ('arm64','aarch64');before=None
images={};bins={};cost=0
def bytes_used(d):return sum(f.stat().st_size for f in d.rglob('*') if f.is_file() and not f.is_symlink())
def attest(file):
    return dict(sha256=sha(file),bytes=file.stat().st_size)
def archive(lib):
    members=get('ar','t',lib).splitlines()
    assert ('MCInstStorage.c.o' in members or 'MCInstStorage.o' in members)==enabled,(lib,members,enabled)
    return dict(file=attest(lib),members=members,contents={m:hashlib.sha256(sp.check_output(['ar','p',lib,m])).hexdigest() for m in members if not m.startswith('__.SYMDEF')})
try:
    run('clang++','-std=c++17','-O2','-I',s/'include',r/'states.cpp',*(['-ldl'] if sys.platform=='linux' else []),'-o',t/'states')
    for label,tree in [('reference',before),('final',q['final'])]:
        run('git','-C',s,'restore','--staged','--worktree','--source=HEAD','--','.')
        if tree is not None:
            patch=r/('original.patch' if label=='reference' else 'candidate.patch')
            assert sha(patch)==tree['sha256'];run('git','-C',s,'apply','--index',patch);assert get('git','-C',s,'write-tree').strip()==tree['tree']
        else:assert get('git','-C',s,'write-tree').strip()==q['base_tree']
        images[label]={}
        for cfg in ('static-only','static-shared'):
            directory=t/'make-build'
            args=['make','-j4','V=1','CC=clang','AR=ar','BUILDDIR='+str(directory),'CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_BUILD_MACOS_THIN=yes','CAPSTONE_ARCHS=aarch64 arm mips powerpc riscv x86','CAPSTONE_STATIC=yes','CAPSTONE_SHARED='+('no' if cfg=='static-only' else 'yes')]
            log=e/(label+'-'+cfg+'.log');run(*args,cwd=s,log=log);lines=log.read_text(errors='replace')
            active=label=='final' and sys.platform=='darwin' and cfg=='static-only'
            assert ('-DCAPSTONE_STATIC_X86_READERS' in lines)==active
            assert not any('__cs_mcinst' in line and 'not a code section' in line for line in lines.splitlines())
            lib,=[f for f in directory.rglob('libcapstone.a') if not f.is_symlink()]
            row=images[label][cfg]=dict(archive=archive(lib))
            libs=[f for f in directory.rglob('libcapstone*') if f.is_file() and not f.is_symlink() and ('.so' in f.name or f.name.endswith('.dylib'))]
            assert len(libs)==int(cfg=='static-shared')
            if libs:row['shared']=attest(libs[0])
            for name in ('x86_buffer_bounds','x86_simple_output'):
                exe=t/name;run('clang','-O2','-I',s/'include',s/('tests/unit/'+name+'.c'),lib,'-o',exe);run(exe,log=e/(label+'-'+cfg+'-'+name+'.log'))
            wrapper=t/(label+'-'+cfg+'.library')
            opts=['-dynamiclib','-Wl,-force_load,'+str(lib)] if sys.platform=='darwin' else ['-shared','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-lm']
            run('clang',*opts,'-o',wrapper);bins[label,cfg]=wrapper
            save('images',images);cost+=bytes_used(directory);shutil.rmtree(directory)
    states={}
    for cfg in ('static-only','static-shared'):
        a=images['reference'][cfg];z=images['final'][cfg]
        assert a['archive']['members']==z['archive']['members']
        changed=sorted(n for n,digest in a['archive']['contents'].items() if z['archive']['contents'][n]!=digest)
        if sys.platform=='darwin' and cfg=='static-only':
            assert set(changed)=={'cs.o','X86Vex32Output.o','X86Sse64Output.o','X86DisassemblerDecoder.o'},changed
        else:assert a==z,(cfg,changed)
        ptest=sp.run([t/'states',bins['reference',cfg],bins['final',cfg],'2048'],text=True,capture_output=True)
        if ptest.returncode:print(ptest.stderr[-1500:])
        ptest.check_returncode();assert ptest.stderr.count('case arch=')==464
        states[cfg]=dict(objects=changed,equal_records=ptest.stdout.strip(),settings=464,archive=z['archive']['file'],shared=z.get('shared'))
    save('complete',dict(complete=True,source=q,host=arch,system=sys.platform,states=states))
finally:
    cost+=bytes_used(t);shutil.rmtree(t);save('cleanup',dict(bytes=cost,removed=not t.exists()))
