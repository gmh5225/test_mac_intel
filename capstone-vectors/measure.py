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
arch=platform.machine().lower();enabled=sys.platform=='darwin' or arch in ('arm64','aarch64');before=q['original'] if enabled else None
images={};bins={};cost=0
def bytes_used(d):return sum(f.stat().st_size for f in d.rglob('*') if f.is_file() and not f.is_symlink())
def attest(file):
    return dict(sha256=sha(file),bytes=file.stat().st_size)
def archive(lib):
    members=get('ar','t',lib).splitlines()
    assert ('MCInstStorage.c.o' in members or 'MCInstStorage.o' in members)==enabled,(lib,members,enabled)
    return dict(file=attest(lib),members=members,contents={m:hashlib.sha256(sp.check_output(['ar','p',lib,m])).hexdigest() for m in members if not m.startswith('__.SYMDEF')})
try:
    (project/'cmake').mkdir(parents=True);(project/'third_party').mkdir();(project/'third_party/capstone').symlink_to(s)
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes((nd/cm).read_bytes());menu=(nd/'CMakeLists.txt').read_text()
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Identity LANGUAGES C CXX)\n'+menu[menu.index('# --- Capstone (our fork'):menu.index('# --- NeverD CMake helpers')])
    for label,tree in [('reference',before),('final',q['final'])]:
        run('git','-C',s,'restore','--staged','--worktree','--source=HEAD','--','.')
        if tree is not None:
            patch=r/('original.patch' if label=='reference' else 'candidate.patch')
            assert sha(patch)==tree['sha256'];run('git','-C',s,'apply','--index',patch);assert get('git','-C',s,'write-tree').strip()==tree['tree']
        else:assert get('git','-C',s,'write-tree').strip()==q['base_tree']
        run('cmake','-G','Ninja','-S',project,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++',log=e/(label+'-configure.log'))
        run('cmake','--build',b,'--target','capstone_static','--parallel','4',log=e/(label+'-cmake.log'))
        units=rd(b/'compile_commands.json');assert any('MCInstStorage.c' in f['file'] for f in units)==enabled
        assert ('CAPSTONE_MIXED_CONSTRUCTED_OPERANDS' in next(f['command'] for f in units if Path(f['file']).name=='cs.c'))==enabled
        lib,=b.rglob('libcapstone.a');cmake=archive(lib)
        args=['make','-j4','V=1','CC=clang','AR=ar','BUILDDIR='+str(obj),'CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_BUILD_MACOS_THIN=yes','CAPSTONE_ARCHS=aarch64 arm mips powerpc riscv x86','CAPSTONE_STATIC=yes','CAPSTONE_SHARED=yes']
        make_log=e/(label+'-make.log');run(*args,cwd=s,log=make_log)
        log=make_log.read_text(errors='replace');assert ('-DCAPSTONE_MIXED_CONSTRUCTED_OPERANDS' in log)==enabled
        assert not any('__cs_mcinst' in l and 'not a code section' in l for l in log.splitlines())
        lib,=[x for x in obj.rglob('libcapstone.a') if not x.is_symlink()]
        dynamic,=[x for x in obj.rglob('libcapstone*') if x.is_file() and not x.is_symlink() and ('.so' in x.name or x.name.endswith('.dylib'))]
        make=archive(lib);images[label]=dict(cmake=cmake,make=make,shared=attest(dynamic))
        wrapper=t/(label+'.library')
        opts=['-dynamiclib','-Wl,-force_load,'+str(lib)] if sys.platform=='darwin' else ['-shared','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-lm']
        run('clang',*opts,'-o',wrapper);bins[label]=wrapper
        for name in ('x86_buffer_bounds','x86_simple_output'):
            exe=t/name;run('clang','-O2','-I',s/'include',s/('tests/unit/'+name+'.c'),lib,'-o',exe);run(exe,log=e/(label+'-'+name+'.log'))
        save('images',images)
        for bed in (b,obj):
            cost+=bytes_used(bed);shutil.rmtree(bed)
    for system in ('cmake','make'):
        a=images['reference'][system];z=images['final'][system]
        assert a['members']==z['members'] and a['contents']==z['contents'],(arch,system,[m for m in a['contents'] if a['contents'][m]!=z['contents'].get(m)])
        assert a['file']==z['file'],(arch,system,a['file'],z['file'])
    assert images['reference']['shared']==images['final']['shared'],(arch,images['reference']['shared'],images['final']['shared'])
    run('clang++','-std=c++17','-O2','-I',s/'include',r/'states.cpp',*(['-ldl'] if sys.platform=='linux' else []),'-o',t/'states')
    ptest=sp.run([t/'states',bins['reference'],bins['final'],'2048'],text=True,capture_output=True)
    if ptest.returncode:print(ptest.stderr[-1500:])
    ptest.check_returncode();assert ptest.stderr.count('case arch=')==464
    save('complete',dict(complete=True,source=q,host=arch,system=sys.platform,enabled=enabled,compared_to=before['commit'] if before else q['base'],settings=464,checks=ptest.stdout.strip(),images={k:{'cmake':a['cmake']['file'],'make':a['make']['file'],'shared':a['shared']}for k,a in images.items()}))
finally:
    cost+=bytes_used(t);shutil.rmtree(t);save('cleanup',dict(bytes=cost,removed=not t.exists()))
