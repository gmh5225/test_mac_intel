"""Compile the pinned public sources, preserve main code, then test its library host."""
from pathlib import Path
from private_symbols import isolate
import argparse, gzip, hashlib, json, os, resource, shutil, subprocess

ap=argparse.ArgumentParser();ap.add_argument('--arch',choices=['x64','arm64'],required=True);args=ap.parse_args()
out=Path('/output');source=out/'sources';logs=out/'diagnostics';prefix=out/'dependencies';prefix.mkdir()
home=out/'home';home.mkdir();empty=out/'no-host-pkgconfig';empty.mkdir()
sysroot='/opt/linux-sysroot-glibc'+('-arm64' if args.arch=='arm64' else '')
triple='x86_64-linux-gnu' if args.arch=='x64' else 'aarch64-linux-gnu'
compiler='/usr/lib/llvm-23/bin/clang';cxx=compiler+'++';toolbin=Path(compiler).parent
ccflags=f'--target={triple} --sysroot={sysroot}'
env=dict(PATH=os.environ['PATH'],HOME=str(home),LANG='C.UTF-8',LC_ALL='C.UTF-8',
    CC=compiler+' '+ccflags,CXX=cxx+' '+ccflags,AR=str(toolbin/'llvm-ar'),RANLIB=str(toolbin/'llvm-ranlib'),
    CFLAGS='-O2 -fPIC -ffunction-sections -fdata-sections',CXXFLAGS='-O2 -fPIC -ffunction-sections -fdata-sections',
    CPPFLAGS='-I'+str(prefix/'include'),LDFLAGS='-L'+str(prefix/'lib'),
    PKG_CONFIG_LIBDIR=str(prefix/'lib/pkgconfig'),GIT_CEILING_DIRECTORIES=str(out))
commands=[]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(label,argv,cwd=None,data=None,environment=None):
    commands.append(dict(label=label,argv=list(map(str,argv)),cwd=str(cwd) if cwd else None))
    result=subprocess.run(list(map(str,argv)),cwd=cwd,env=environment or env,input=data,capture_output=True,timeout=1200)
    (logs/(label+'.stdout')).write_bytes(result.stdout);(logs/(label+'.stderr')).write_bytes(result.stderr)
    assert result.returncode==0,(label,result.returncode)
    return result
def make(label,path,*targets):return run(label,['make','-j2',*targets],path)
def cmake(name,path,*options):
    build=out/(name+'-build')
    run(name+'-configure',['cmake','-S',path,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX='+str(prefix),
        '-DCMAKE_INSTALL_LIBDIR=lib','-DBUILD_SHARED_LIBS=OFF','-DCMAKE_POSITION_INDEPENDENT_CODE=ON',*options])
    run(name+'-build',['cmake','--build',build,'--parallel','2']);run(name+'-install',['cmake','--install',build]);return build

run('compiler-version',[compiler,'--version']);run('cxx-version',[cxx,'--version'])
pthread_link=['-Wl,--whole-archive','-lpthread','-Wl,--no-whole-archive']
thread_control=logs/'pthread-link-control.cc'
thread_control.write_text('#include <condition_variable>\n#include <thread>\nint main() { std::mutex mutex; std::condition_variable condition; bool ready=false; std::thread worker([&] { { std::lock_guard<std::mutex> lock(mutex); ready=true; } condition.notify_one(); }); { std::unique_lock<std::mutex> lock(mutex); condition.wait(lock,[&] { return ready; }); } worker.join(); }\n')
run('pthread-link-control-build',[cxx,*ccflags.split(),'-O2','-static',thread_control,*pthread_link,'-o',logs/'pthread-link-control'])
run('pthread-link-control',[logs/'pthread-link-control'])
run('pthread-link-control-symbols',[toolbin/'llvm-nm','--defined-only',logs/'pthread-link-control'])
thread_symbols={line.split()[-1] for line in (logs/'pthread-link-control-symbols.stdout').read_text().splitlines() if line.split()}
assert {'pthread_cond_destroy','pthread_cond_wait','pthread_cond_signal','pthread_create','pthread_join'} <= thread_symbols
compat=out/'compat'
run('compile-bun-compat',[cxx,*ccflags.split(),'-std=c++20',*env['CXXFLAGS'].split(),'-c',compat/'compat.cpp','-o',compat/'compat.o'])
outer_flags=['-Wl,--wrap=fcntl64','-Wl,--wrap=statx','-Wl,--gc-sections','-static-libstdc++','-static-libgcc','-Wl,--no-as-needed','-pthread','-ldl','-lm']
for variant in ['native','fallback']:
    extra=['-DRECOVERY_FORCE_OLD_FCNTL=1'] if variant=='fallback' else []
    run('compile-compat-probe-'+variant,[compiler,*ccflags.split(),'-std=c11','-O2',*extra,'-c',compat/'compat-probe.c','-o',compat/('probe-'+variant+'.o')])
    run('link-compat-probe-'+variant,[cxx,*ccflags.split(),compat/('probe-'+variant+'.o'),compat/'compat.o',*outer_flags,'-Wl,--wrap=dlsym','-o',compat/('probe-'+variant)])
    run('compat-probe-'+variant,[compat/('probe-'+variant)])
z=source/'zlib';run('zlib-configure',[z/'configure','--static','--prefix='+str(prefix)],z);make('zlib-build',z);make('zlib-check',z,'check');make('zlib-install',z,'install')
b=source/'bzip2';make('bzip2-build',b,'libbz2.a','bzip2','bzip2recover','CC='+env['CC'],'AR='+env['AR'],'RANLIB='+env['RANLIB'],'CFLAGS='+env['CFLAGS']);make('bzip2-check',b,'test');make('bzip2-install',b,'install','PREFIX='+str(prefix))
cmake('zstd',source/'zstd/build/cmake','-DZSTD_BUILD_SHARED=OFF','-DZSTD_BUILD_STATIC=ON','-DZSTD_BUILD_PROGRAMS=ON','-DZSTD_BUILD_TESTS=OFF','-DZSTD_ZLIB_SUPPORT=OFF','-DZSTD_LZMA_SUPPORT=OFF','-DZSTD_LZ4_SUPPORT=OFF')
brotli=cmake('brotli',source/'brotli');run('brotli-check',['ctest','--test-dir',brotli,'--output-on-failure'])
p=source/'pcre2';run('pcre2-configure',[p/'configure','--prefix='+str(prefix),'--enable-static','--disable-shared','--enable-jit','--disable-pcre2-16','--disable-pcre2-32'],p);make('pcre2-build',p);make('pcre2-check',p,'check');make('pcre2-install',p,'install')
# libstdc++ condition-variable calls are weak on the pinned focal sysroot.
# A plain -lpthread leaves the corresponding static objects unselected, and
# lld resolves their tail branches to fall-through instructions. Retain the
# real pthread implementation before testing the upstream static executable.
ug=source/'ugrep';ugenv=dict(env,LIBS='-lbrotlicommon -lm',
    PTHREAD_LIBS=' '.join(pthread_link),PTHREAD_CFLAGS='-pthread')
options=['--enable-static','--without-lzma','--without-lz4',*['--with-'+flag+'='+str(prefix) for flag in ['pcre2','zlib','bzlib','zstd','brotli']]]
if args.arch=='x64':options.append('--disable-avx2')
run('ugrep-configure',[ug/'configure',*options],ug,environment=ugenv)
run('ugrep-build',['make','-j2'],ug,environment=ugenv)
shutil.copyfile(ug/'bin/ugrep',logs/'public-ugrep-candidate')
shutil.copyfile(ug/'config.h',logs/'ugrep-config.h')
probes=[]
for label,argv in [('version',['--version']),('config-search',['-Fq','HAVE_PCRE2 1',str(ug/'config.h')]),('no-config-search',['--no-config','-Fq','HAVE_PCRE2 1',str(ug/'config.h')])]:
    result=subprocess.run([str(ug/'bin/ugrep'),*argv],env=ugenv,capture_output=True,timeout=10)
    for field in ['stdout','stderr']:(logs/('candidate-'+label+'.'+field)).write_bytes(getattr(result,field))
    probes.append(dict(case=label,argv=argv,exit_code=result.returncode))
    (logs/'candidate-probes.json').write_text(json.dumps(probes,indent=2)+'\n')
run('ugrep-check',['make','-j2','check'],ug,environment=ugenv)
library=out/'native-library';library.mkdir();objects=library/'objects';objects.mkdir()
names=['ugrep','cnf','glob','output','query','screen','stats','vkey','zopen']
paths=[]
for name in names:
    original=ug/'src'/('ugrep-'+name+'.o');assert original.is_file();destination=objects/original.name;shutil.copyfile(original,destination);paths.append(destination)
main=objects/'ugrep-ugrep.o'
run('main-symbols',[toolbin/'llvm-nm','--defined-only',main])
assert sum(line.split()[-1]=='main' for line in (logs/'main-symbols.stdout').read_text().splitlines() if line.split())==1
before=library/'main-text-before.bin';after=library/'main-text-after.bin'
original_main_hash=sha(main)
run('main-text-before',[toolbin/'llvm-objcopy','--dump-section','.text.main='+str(before),main,logs/'main-readback-before.o'])
assert sha(main)==original_main_hash,'Section readback modified the compiler object'
assert before.is_file() and before.stat().st_size>0
run('rename-main',[toolbin/'llvm-objcopy','--redefine-sym','main=neverd_recovered_ugrep_main',main])
renamed_main_hash=sha(main)
run('main-text-after',[toolbin/'llvm-objcopy','--dump-section','.text.main='+str(after),main,logs/'main-readback-after.o'])
assert sha(main)==renamed_main_hash,'Section readback modified the renamed compiler object'
assert before.read_bytes()==after.read_bytes()
dependencies=['reflex','viiz','pcre2-8','z','bz2','zstd','brotlidec','brotlicommon']
for name in dependencies:
    if name=='reflex':original=ug/'lib/libreflex.a'
    elif name=='viiz':original=ug/'lzma/C/libviiz.a'
    else:original=prefix/'lib'/('lib'+name+'.a')
    assert original.is_file();shutil.copyfile(original,library/('lib'+name+'.a'))
private=isolate(library,paths,[library/('lib'+name+'.a') for name in dependencies],toolbin,run,logs)
private_main=library/'main-text-private.bin'
run('private-main-text',[toolbin/'llvm-objcopy','--dump-section','.text.main='+str(private_main),main,logs/'main-readback-private.o'])
assert private_main.read_bytes()==before.read_bytes(),'Private symbol names changed main code bytes'
archive=library/'librecovered_ugrep.a';run('export-library',[toolbin/'llvm-ar','rcs',archive,*paths])
host_source=library/'ugrep-library-host.c';host_source.write_text('extern int neverd_recovered_ugrep_main(int, char **);\nint main(int argc, char **argv) { return neverd_recovered_ugrep_main(argc, argv); }\n')
run('compile-host',[compiler,*ccflags.split(),'-O2','-c',host_source,'-o',library/'host.o'])
host=library/'ugrep-library-host'
run('link-host',[cxx,*ccflags.split(),library/'host.o',compat/'compat.o','-Wl,--start-group',archive,*[library/('lib'+name+'.a') for name in dependencies],'-Wl,--end-group',*outer_flags,'-o',host])
fixture=library/'input.txt';fixture.write_bytes(b'first\nNEEDLE\npreneedle\n');compressed=library/'input.gz';compressed.write_bytes(gzip.compress(fixture.read_bytes(),mtime=0))
def limits():resource.setrlimit(resource.RLIMIT_FSIZE,(0,0));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
controls=[]
for label,argv,wanted in [('version',['--version'],None),('literal',['--no-config','-n','NEEDLE',str(fixture)],b'2:NEEDLE\n'),('pcre',['--no-config','-P','-o','(?<=pre)needle',str(fixture)],b'needle\n'),('gzip',['--no-config','-z','-n','NEEDLE',str(compressed)],b'2:NEEDLE\n')]:
    r=subprocess.run([str(host),*argv],env=env,capture_output=True,timeout=10,preexec_fn=limits)
    for field in ['stdout','stderr']:(library/(label+'.'+field)).write_bytes(getattr(r,field))
    controls.append(dict(case=label,argv=argv,exit_code=r.returncode,stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),rlimit_fsize=0))
    assert r.returncode==0 and not r.stderr and (wanted is None or r.stdout==wanted)
# The top-level all target always copies src/ugrep into bin/ugrep before
# invoking the test scripts. Install the fresh host at both locations so the
# upstream suite cannot silently revert to the standalone executable.
for destination in [ug/'src/ugrep',ug/'bin/ugrep']:
    shutil.copyfile(host,destination);assert sha(destination)==sha(host)
run('library-host-upstream-check',['make','-j2','check'],ug,environment=ugenv)
assert all(sha(p)==sha(host) for p in [ug/'src/ugrep',ug/'bin/ugrep']),'Upstream checks replaced the library host'
receipt=dict(status='ugrep_source_library_host_and_upstream_checks_passed',entry_symbol='neverd_recovered_ugrep_main',source_objects=len(paths),
    main_text_unchanged=True,main_text_sha256=sha(before),library_sha256=sha(archive),host_sha256=sha(host),controls=controls,commands=commands,
    original_binary_reused=False,dependency_archives={name:sha(library/('lib'+name+'.a')) for name in dependencies},zstd_upstream_suite_run=False,
    static_pthread_condition_variable_control_passed=True,public_bun_compatibility_controls_passed=True,private_c_symbols=private)
(library/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
