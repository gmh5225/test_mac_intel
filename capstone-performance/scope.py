from pathlib import Path
import json,os,shutil,subprocess as s,tempfile,sys,hashlib
d=Path(__file__).resolve().parent;e=Path('capstone-evidence').resolve();e.mkdir(exist_ok=True)
crt=sys.argv[1];assert crt in ('MD','MT')
def run(cmd,cwd,env=None):s.run(cmd,cwd=cwd,env=env,check=True)
def write(k,v):(e/k).write_text(json.dumps(v,indent=2)+'\n')
def digest(b):return hashlib.sha256(b).hexdigest()
def main(tmp):
    source=tmp/'src';source.mkdir();b=tmp/'build'
    run(['git','init','-q'],source);run(['git','config','core.autocrlf','false'],source)
    ref='c3fd1f110810201fa4d82a2d057ed82f5b08d5b1'
    run(['git','fetch','-q','--depth=1','https://github.com/NeverSight/capstone',ref],source);run(['git','checkout','-q','--detach','FETCH_HEAD'],source)
    env=dict(os.environ,CL='/Brepro')
    run(['cmake','-G','Visual Studio 17 2022','-A','x64','-S',source,'-B',b,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF')],tmp,env)
    hashes={}
    for label in ('reference','scoped'):
        if label=='scoped':
            run(['git','restore','--source=HEAD','--','arch','suite','cs_disasm_internal.h'],source)
        f=d/(label+'.patch')
        h=digest(f.read_bytes());assert h==(d/(f.name+'.sha256')).read_text().strip()
        run(['git','apply',f],source)
        run(['cmake','--build',b,'--config','Release','--target','capstone_static','--parallel','4'],tmp,env)
        tool=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
        records={}
        # Include machine code, relocation annotations and read-only data.
        for obj in (b/'capstone.dir/Release').rglob('*.obj'):
            records[obj.name]=digest(obj.read_bytes())
        assert 'X86Disassembler.obj'in records and 'cs.obj' in records
        hashes[label]=records
    write('objects.json',hashes)
    assert hashes['reference'].keys()==hashes['scoped'].keys()
    differing=[k for k,v in hashes['reference'].items() if v != hashes['scoped'][k]]
    write('comparison.json',dict(crt=crt,differing=differing,objects=len(hashes['reference'])))
    assert not differing,differing
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as work:
    root=Path(work)
    try:main(root)
    finally:size=sum(f.stat().st_size for f in root.rglob('*') if f.is_file())
write('cleanup.json',dict(removed=not root.exists(),bytes=size))
