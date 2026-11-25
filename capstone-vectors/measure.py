from pathlib import Path
import hashlib,json,os,shlex,shutil,subprocess as sp,tempfile
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
    run('cmake','-G','Ninja','-S',src,'-B',one,*flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF')
    singlecmd=next(z['command'] for z in rd(one/'compile_commands.json')if z['file'].endswith('/MipsInstPrinter.c'))
    mixcmd=next(z['command'] for z in rd(mix/'compile_commands.json')if z['file'].endswith('/MipsInstPrinter.c'))
    assert '-DCAPSTONE_MIPS_ONLY' in singlecmd and '-DCAPSTONE_MIPS_ONLY' not in mixcmd
    mixed={};products={};domain={};streams={};real={}
    shutil.copyfile(r/'public-compare.cpp',w/'trial-compare.cpp');shutil.copyfile(r/'mips-domain.cpp',w/'mips-domain.cpp')
    run('clang++','-O2','-std=c++17','-I',src/'include',w/'mips-domain.cpp','-ldl','-o',w/'domain')
    run('clang++','-O2','-std=c++17','-I',w,'-I',src/'include',r/'real.cpp','-ldl','-o',w/'real')
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
        run('python3','-B',src/'suite/synctools/mips_register_names.py','--check')
        units=['mips_register_names','mips_scan','mips_reglist_offset','mips_msa_control','mips16_word_order','mips16_immediates','mips16_memory_calls','mips16_shifts_hilo','mips16_frames','mips16e2']
        run('cmake','--build',one,'--target',*units,'--parallel','4')
        report=out('ctest','--test-dir',one,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units+['mips_register_names_generator'])+')$')
        assert '100% tests passed' in report
        (e/(v+'-units.log')).write_text(report+'\n')

        args=shlex.split(singlecmd);slot=args.index('-o')
        run(*args[:slot],'-I',src,r/'stream.c',lib,'-o',w/'guard')
        streams[v]=list(map(int,out(w/'guard').split()))
        assert streams[v]==[1136128,0]
        run(*args[:slot],'-I',src,r/'comments.c',lib,'-o',w/'comment-guard')
        checked=int(out(w/'comment-guard'));assert checked==512*513*4+1
        save('comment-'+v,dict(checked=checked))
        if os.uname().machine=='x86_64' and v=='outlined':
            run(*args[:slot],'-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',src,r/'comments.c',lib,'-o',w/'comment-instrumented')
            assert int(out(w/'comment-instrumented'))==checked

        if v!='base':
            domain[v]=json.loads(out(w/'domain',w/'base.so',output));assert domain[v]['trials']==20971520 and domain[v]['accepted']==15190912
            real[v]={row['name']:list(map(int,out(w/'real',w/'base.so',output,w/(row['name']+'.text')).split())) for row in corpus}
    if os.uname().machine=='aarch64':
        assert products['base']==products['candidate']==products['outlined']
    else:
        assert all(products[tag]['shared']!=products['base']['shared'] for tag in ('candidate','outlined'))
    assert domain['candidate']==domain['outlined'] and real['candidate']==real['outlined']
    save('guards',dict(domain=domain,streams=streams,real=real))
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});save('host',dict(cpu=out('lscpu'),compiler=out('clang','--version')))
    measure(corpus,w,save)
    save('complete',dict(complete=True,source=q,hosts=1,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
