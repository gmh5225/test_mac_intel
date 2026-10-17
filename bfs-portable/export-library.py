"""Own fresh Bfs objects, rename only its C entry symbol, and check the host."""
from pathlib import Path
import hashlib,json,os,resource,shutil,subprocess,sys
sys.dont_write_bytecode=True
work=Path('/tmpfs/bun');bfs=work/'embedded/bfs';out=work/'native-library';out.mkdir()
llvm=Path('/usr/lib/llvm-23/bin')
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(args):
    subprocess.run(list(map(str,args)),check=True)
objects=sorted((bfs/'obj/src').glob('*.o'));assert objects and len({p.name for p in objects})==len(objects)
assert sum(p.name=='main.o' for p in objects)==1
owned=out/'objects';owned.mkdir();rows=[]
for source in objects:
    target=owned/source.name;shutil.copyfile(source,target)
    if source.name=='main.o':
        before=out/'main-text-before';after=out/'main-text-after'
        original_sha256=sha(source)
        run([llvm/'llvm-objcopy','--dump-section',f'.text={before}',source,out/'dump-source.o'])
        assert sha(source)==original_sha256
        run([llvm/'llvm-objcopy','--redefine-sym=main=neverd_recovered_bfs_main',target])
        renamed_sha256=sha(target)
        run([llvm/'llvm-objcopy','--dump-section',f'.text={after}',target,out/'dump-renamed.o'])
        assert sha(target)==renamed_sha256
        (out/'dump-source.o').unlink();(out/'dump-renamed.o').unlink()
        assert before.read_bytes()==after.read_bytes() and before.stat().st_size>0
    rows.append(dict(file=target.name,source_sha256=sha(source),library_object_sha256=sha(target),entry_symbol_renamed=source.name=='main.o'))
archive=out/'librecovered_bfs.a';run([llvm/'llvm-ar','crsD',archive,*sorted(owned.glob('*.o'))])
members=subprocess.check_output([llvm/'llvm-ar','t',archive],text=True).splitlines();assert members==[p.name for p in sorted(owned.glob('*.o'))]
nm=subprocess.check_output([llvm/'llvm-nm','--defined-only',archive],text=True);assert ' T neverd_recovered_bfs_main' in nm and not any(line.endswith(' T main') for line in nm.splitlines())
onig=work/'build/release/deps/oniguruma/libonig.a';assert onig.is_file();shutil.copyfile(onig,out/'libonig.a')
arch=os.environ['RECOVERY_ARCH'];triple={'x64':'x86_64-linux-gnu','arm64':'aarch64-linux-gnu'}[arch];sysroot='/opt/linux-sysroot-glibc'+('-arm64' if arch=='arm64' else '')
run([llvm/'clang','--target='+triple,'--sysroot='+sysroot,'-std=c11','-O2','-c','/recipes/bfs-library-host.c','-o',out/'host.o'])
host=out/'bfs-library-host'
run([llvm/'clang++','--target='+triple,'--sysroot='+sysroot,out/'host.o',archive,out/'libonig.a',work/'standalone/compat.o','-Wl,-z,now','-no-pie','-Wl,--wrap=fcntl64','-Wl,--wrap=statx','-Wl,--gc-sections','-static-libstdc++','-static-libgcc','-pthread','-ldl','-lrt','-o',host])
fixture=out/'fixture';fixture.mkdir();(fixture/'owned-猫.txt').write_bytes(b'owned fixture\n')
def no_file_writes():
    resource.setrlimit(resource.RLIMIT_FSIZE,(0,0));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
controls=[]
for case,args,code,expected in [
    ('version',['--version'],0,Path('/recipes/expected-version-'+arch+'.txt').read_bytes()),
    ('name',[str(fixture),'-name','*.txt','-printf','%f\n'],0,'owned-猫.txt\n'.encode()),
    ('regex',[str(fixture),'-regex','.*[.]txt','-printf','%f\n'],0,'owned-猫.txt\n'.encode()),
    ('absent',[str(fixture),'-name','absent-value','-print'],0,b'')]:
    p=subprocess.run(['bfs',*args],executable=host,capture_output=True,timeout=15,preexec_fn=no_file_writes,env=dict(PATH='/unavailable',LANG='C',LC_ALL='C'))
    (out/(case+'.stdout')).write_bytes(p.stdout);(out/(case+'.stderr')).write_bytes(p.stderr)
    assert p.returncode==code and p.stdout==expected and not p.stderr,case
    controls.append(dict(case=case,exit_code=p.returncode,rlimit_fsize=0,stdout_sha256=hashlib.sha256(p.stdout).hexdigest()))
receipt=dict(status='fresh_bfs_library_host_passes_zero_file_budget_controls',arch=arch,entry_symbol='neverd_recovered_bfs_main',main_text_unchanged_sha256=sha(out/'main-text-before'),objects=rows,archive_sha256=sha(archive),oniguruma_archive_sha256=sha(out/'libonig.a'),host_sha256=sha(host),controls=controls,original_binary_reused=False,whole_bun_integration=False)
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(dict(status=receipt['status'],objects=len(rows),controls=len(controls))))
