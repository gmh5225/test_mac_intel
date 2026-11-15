from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
source = r.parent/'source'
evidence = r.parent/'evidence'
evidence.mkdir()
meta = json.loads((r/'candidate.json').read_text())


def save(name, data):
    (evidence/(name+'.json')).write_text(json.dumps(data, indent=2)+'\n')


def run(name, args, check=True):
    with (evidence/(name+'.log')).open('wb') as out:
        return sp.run(list(map(str,args)), cwd=source, stdout=out, stderr=sp.STDOUT, check=check)


w = Path(tempfile.mkdtemp(prefix='capstone-cstool-bitmanip-'))
try:
    assert sp.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip() == meta['parent']
    assert not sp.check_output(['git','status','--porcelain'],cwd=source)
    run('canonical-config',['git','config','core.autocrlf','false'])
    run('canonical-checkout',['git','checkout-index','-a','-f'])
    patch = sp.check_output(['git','show','HEAD:capstone-records/candidate.patch'],cwd=r.parent)
    assert hashlib.sha256(patch).hexdigest() == meta['sha256']
    (w/'candidate.patch').write_bytes(patch)
    compiler, diet = os.environ['TOOLCHAIN'], os.environ['DIET'] == 'ON'
    options = ['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
               '-DCAPSTONE_RISCV_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON',
               '-DCAPSTONE_BUILD_CSTOOL=ON','-DCAPSTONE_BUILD_CSTEST=ON',
               '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_DIET='+('ON' if diet else 'OFF')]
    if os.name == 'nt':
        options += ['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4',
                    '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if compiler == 'MT' else 'OFF')]
    else:
        options += ['-G','Ninja','-DCMAKE_C_COMPILER='+compiler]
        if compiler == 'gcc':
            options += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    b = w/'build'
    run('configure',['cmake','-S',source,'-B',b,*options])
    run('base-build',['cmake','--build',b,'--config','Release','--target','cstool','--parallel','4'])
    exe = b/'Release/cstool.exe' if os.name == 'nt' else b/'cstool'
    def objects():
        files = [f for f in b.rglob('*') if f.suffix in ('.o','.obj') and 'capstone.dir' in f.parts]
        return {str(f.relative_to(b)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    before = objects()
    assert before
    bad = run('base-bitmanip',[exe,'riscv64+bitmanip','b3227320'],check=False)
    assert bad.returncode != 0
    assert 'CS_ERR_MODE' in (evidence/'base-bitmanip.log').read_text()
    run('base-unintended-a',[exe,'riscv64+zba','af227300'])
    run('apply',['git','apply','--index',w/'candidate.patch'])
    tree = sp.check_output(['git','write-tree'],cwd=source,text=True).strip()
    assert tree == meta['tree']
    run('candidate-build',['cmake','--build',b,'--config','Release','--parallel','4'])
    after = objects()
    assert before == after
    run('tests',['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_'])
    for bits in (32,64):
        run(f'candidate-bitmanip-{bits}',[exe,f'riscv{bits}+bitmanip','b3227320'])
        rejected = run(f'candidate-isolated-a-{bits}',[exe,f'riscv{bits}+bitmanip','af227300'],check=False)
        assert rejected.returncode != 0
        run(f'candidate-explicit-a-{bits}',[exe,f'riscv{bits}+bitmanip+a','af227300'])
    save('objects',dict(identical=True,total=len(before),baseline=before,candidate=after))
    save('complete',dict(candidate=meta,tree=tree,compiler=compiler,diet=diet,success=True))
finally:
    amount = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    def remove_readonly(fn,path,exc):
        os.chmod(path,0o700)
        fn(path)
    shutil.rmtree(w,onerror=remove_readonly)
    save('cleanup',dict(removed=not w.exists(),bytes=amount))
