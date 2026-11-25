from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
from training import fetch
from extra_mips_time import measure
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir(exist_ok=True);src=r.parent/'source';nd=r.parent/'neverd-config'
rd=lambda f:json.loads(f.read_text())
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a,**kw):sp.run(a,check=True,**kw)
def out(*a):return sp.check_output(a,text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
q=rd(r/'source.json');w=Path(tempfile.mkdtemp());mix=w/'mixed';one=w/'standalone';project=w/'project'
try:
    assert out('git','-C',src,'rev-parse','HEAD')==q['base']['commit'] and out('git','-C',nd,'rev-parse','HEAD')==q['neverd']
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(src);cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/'cmake').mkdir();(project/cm).write_bytes((nd/cm).read_bytes())
    v=(nd/'CMakeLists.txt').read_text()
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Mixed LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    run('cmake','-G','Ninja','-S',project,'-B',mix,*flags)
    run('cmake','-G','Ninja','-S',src,'-B',one,*flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF')
    singlecmd=next(z['command'] for z in rd(one/'compile_commands.json')if z['file'].endswith('/MipsInstPrinter.c'))
    mixcmd=next(z['command'] for z in rd(mix/'compile_commands.json')if z['file'].endswith('/MipsInstPrinter.c'))
    assert '-DCAPSTONE_MIPS_ONLY' in singlecmd and '-DCAPSTONE_MIPS_ONLY' not in mixcmd
    mixed={};products={};domain={};streams={}
    shutil.copyfile(r/'public-compare.cpp',w/'trial-compare.cpp');shutil.copyfile(r/'mips-domain.cpp',w/'mips-domain.cpp')
    run('clang++','-O2','-std=c++17','-I',src/'include',w/'mips-domain.cpp','-ldl','-o',w/'domain')
    corpus=fetch(r,w);manifest=rd(r/'mips-samples.json')['fixtures'];assert len(corpus)==4
    assert all(a['binary_sha256']==manifest[a['name']]['binary_sha256'] and a['text_sha256']==manifest[a['name']]['sha256']for a in corpus);save('mips-corpus',corpus)
    for v in ('base','candidate','outlined'):
        run('git','-C',src,'restore','--source=HEAD','--staged','--worktree','--','.')
        if v!='base':
            patch=r/(v+'.patch');assert sha(patch)==q[v]['sha256'];run('git','-C',src,'apply','--index',patch)
        assert out('git','-C',src,'write-tree')==q[v]['tree']
        run('cmake','--build',mix,'--target','capstone_static','--parallel','4')
        archive,=mix.rglob('libcapstone.a');objects={str(obj.relative_to(mix)):sha(obj)for obj in mix.rglob('*.c.o')}
        assert len(objects)>40;mixed[v]=dict(objects=objects,archive=sha(archive));assert mixed[v]==mixed['base'];save('mixed',mixed)
        run('cmake','--build',one,'--target','capstone_static','capstone_shared','--parallel','4')
        lib,=one.rglob('libcapstone.a');shared,=one.rglob('libcapstone.so');output=w/(v+'.so');shutil.copy2(shared,output)
        run('clang++','-O3','-std=c++17','-no-pie','-I',src/'include',r/'foreign.cpp',lib,'-o',w/('foreign-'+v))
        products[v]=dict(archive=sha(lib),shared=sha(output),program=sha(w/('foreign-'+v)));save('products',products)
        if v!='base':
            code=(src/'arch/Mips/MipsInstPrinter.c').read_text()
            helper=(r/(v+'.inc')).read_text()
            assert helper.split('#define MEASURE_WRITE')[0].strip() in code
            (w/'alias-writer.inc').write_text(helper)
            run('clang','-O2','-std=gnu99','-DCAPSTONE_MIPS_ONLY','-DCAPSTONE_USE_SYS_DYN_MEM','-I',w,'-I',src,'-I',src/'include',r/'stream-guard.c',lib,'-o',w/'guard')
            streams[v]=int(out(w/'guard'));assert streams[v]==458752
            domain[v]=json.loads(out(w/'domain',w/'base.so',output));assert domain[v]['trials']==5242880 and 0<domain[v]['accepted']<5242880
    assert domain['candidate']==domain['outlined'];save('guards',dict(domain=domain,streams=streams))
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});save('host',dict(cpu=out('lscpu'),compiler=out('clang','--version')))
    measure(corpus,w,save)
    save('complete',dict(complete=True,source=q,hosts=1,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
