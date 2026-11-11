import json
import os
from pathlib import Path
import shutil
import subprocess as sp
import sys
import tempfile

d=Path(__file__).resolve().parent
e=d.parent/'capstone-evidence'
e.mkdir(exist_ok=True)
target=sys.argv[1]
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as tmp:
    root=Path(tmp)
    src=root/'source'
    build=root/'build'
    def run(cmd, log, cwd=root, check=True):
        with (e/(log+'.log')).open('w') as out:
            p=sp.run(list(map(str,cmd)),cwd=cwd,stdout=out,stderr=sp.STDOUT)
        if check and p.returncode:
            print((e/(log+'.log')).read_text(errors='replace')[-4000:])
            p.check_returncode()
        return p.returncode
    try:
        ref='5b9cbe48b46842e70a4ce8dcfafcb3f35c2f34cd'
        run(['git','init','-q',src],'init')
        run(['git','config','core.autocrlf','false'],'line-endings',src)
        run(['git','remote','add','origin','https://github.com/NeverSight/capstone.git'],'origin',src)
        run(['git','fetch','-q','--depth','1','origin',ref],'fetch',src)
        run(['git','checkout','-q','--detach','FETCH_HEAD'],'checkout',src)
        assert sp.check_output(['git','rev-parse','HEAD'],cwd=src,text=True).strip()==ref
        opts=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_USE_DEFAULT_ALLOC=OFF']
        if target=='diet': opts.append('-DCAPSTONE_BUILD_DIET=ON')
        if target=='reduced': opts.append('-DCAPSTONE_X86_REDUCE=ON')
        generator=['-G','Visual Studio 17 2022','-A','x64'] if os.name=='nt' else ['-G','Ninja']
        run(['cmake','-S',src,'-B',build,*generator,*opts],'configure')
        cmd=['cmake','--build',build,'--config','Release','--parallel','4','--target','x86_encoding_accuracy','x86_mapping_counts']
        test=['ctest','--test-dir',build,'-C','Release','-R','^(unit_x86_encoding_accuracy|unit_x86_mapping_counts)$','--no-tests=error','--output-on-failure']
        run(cmd,'build-original')
        assert run(test,'before',check=False)!=0 and 'unit_x86_encoding_accuracy (Failed)' in (e/'before.log').read_text()
        run(['git','apply',d/'allocator.patch'],'apply',src)
        run(cmd,'build-fixed')
        run(test,'after')
        print((e/'after.log').read_text(),flush=True)
    finally:
        size=sum(f.stat().st_size for f in root.rglob('*') if f.is_file())
        shutil.rmtree(root)
        (e/'cleanup.json').write_text(json.dumps(dict(bytes=size,removed=not root.exists()))+'\n')
