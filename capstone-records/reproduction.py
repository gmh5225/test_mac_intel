from pathlib import Path
import gzip
import hashlib
import json
import os
import platform
import shutil
import subprocess as sp
import tempfile
import corpus
from arm_cost import cost_probe

r=Path(__file__).resolve().parent
s=r.parent/'source'
e=r.parent/'evidence'
e.mkdir()
meta=json.loads((r/'candidates.json').read_text())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def save(name,value):
    (e/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args,label,cwd=None):
    print(label,flush=True)
    with (e/(label+'.log')).open('wb') as log:
        result=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((label,(e/(label+'.log')).read_text(errors='replace')[-2000:]))
assert platform.machine()=='aarch64'
assert sp.check_output(['git','rev-parse','HEAD'],cwd=s,text=True).strip()==meta['scan']['parent']
assert meta['dispatch']['parent']==meta['scan']['parent']
save('environment',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output(['clang','--version'],text=True),
                        valgrind=sp.check_output(['valgrind','--version'],text=True),
                        platform=platform.platform()))
w=Path(tempfile.mkdtemp(prefix='capstone-output-observer-'))
try:
    cases=corpus.prepare(r,w,e,run)
    run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include',
         '-c',r/'single.cpp','-o',w/'single.o'],'consumer')
    save('consumer',dict(source_sha256=sha(r/'single.cpp'),object_sha256=sha(w/'single.o'),shared_by_all_variants=True))
    b=w/'build'
    run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers',
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ('ARM','AARCH64','MIPS','X86')],
         '-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON',
         '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
    binaries,objects={},{ }
    for key in ('base','scan'):
        patch=r/(key+'.patch')
        if key!='base':
            assert sha(patch)==meta[key]['sha256']
            run(['git','apply','--index',patch],'apply-'+key,s)
            assert sp.check_output(['git','write-tree'],cwd=s,text=True).strip()==meta[key]['tree']
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+key)
        binary=w/key
        run(['clang++',w/'single.o',b/'libcapstone.a','-lm','-o',binary],'link-'+key)
        binaries[key]=binary
        root=b/'CMakeFiles/capstone.dir'
        objects[key]={str(f.relative_to(root)):sha(f)for f in root.rglob('*.o')}
        if key!='base':
            assert objects['base'].keys()==objects[key].keys()
            changed=[n for n,v in objects['base'].items()if objects[key][n]!=v]
            assert set(changed)<={'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o','arch/X86/X86ImmediateOutput.c.o'}
            assert {'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o'}<=set(changed)
            save(key+'-objects',dict(changed=changed,identical=len(objects[key])-len(changed),source=meta[key]))
        (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',binary]))
        with gzip.open(e/(key+'-linked-assembly.gz'),'wb')as stream:
            stream.write(sp.check_output(['objdump','-dr',binary]))
        if key!='base':
            run(['git','apply','--index','-R',patch],'restore-'+key,s)
        assert not sp.check_output(['git','status','--porcelain'],cwd=s,text=True)
    binaries['aa']=w/'aa'
    shutil.copy2(binaries['base'],binaries['aa'])
    payloads={k:v.read_bytes()for k,v in binaries.items()}
    maximum=max(map(len,payloads.values()))
    image=w/'same-image'
    image.write_bytes(payloads['base']+bytes(maximum-len(payloads['base'])))
    image.chmod(0o755)
    probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
    assert probe.returncode==0,probe.stderr
    save('launch-controls',dict(aslr_disable_returncode=0,inode=image.stat().st_ino,fixed_size=maximum,
                               original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()}))
    if hasattr(os,'sched_getaffinity'):
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cost_probe(binaries,cases,w,e,run)
    save('complete',dict(complete=True,variants=['base','aa','scan'],source=meta,
                         native_timing=True,scope='Diagnostic observer interaction only. The modified consumer binary retains full library format/detail work; a runtime flag controls only NUL-terminated string observation. Exact baseline and tagged-plan sources are unchanged. Not a frozen-consumer performance qualification or a NeverD product measurement.'))
finally:
    amount=sum(f.stat().st_size for f in w.rglob('*')if f.is_file())
    shutil.rmtree(w)
    save('cleanup',dict(bytes=amount,removed=not w.exists()))
