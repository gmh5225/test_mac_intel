from pathlib import Path
import hashlib, json, os, shutil, subprocess as sp, tempfile
r=Path(__file__).resolve().parent
source=r.parent/'source'
evidence=r.parent/'evidence';evidence.mkdir()
meta=json.loads((r/'candidate.json').read_text())
profile=os.environ['PROFILE'];compiler=os.environ['TOOLCHAIN'];forms=os.environ['FORMS']
def save(name,value):(evidence/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args,name):
    print(name,flush=True)
    with (evidence/(name+'.log')).open('wb') as log:
        result=sp.run(list(map(str,args)),cwd=source,stdout=log,stderr=sp.STDOUT)
    if result.returncode:raise RuntimeError((name,(evidence/(name+'.log')).read_text(errors='replace')[-3500:]))
def clean_error(fn,path,exc):
    os.chmod(path,0o700);fn(path)
w=Path(tempfile.mkdtemp(prefix='capstone-arm-constructed-profile-'));b=w/'build'
try:
    assert sp.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==meta['parent']
    run(['git','config','core.autocrlf','false'],'canonical-config')
    archive=w/'canonical-source.tar'
    run(['git','archive','--format=tar','-o',archive,'HEAD'],'canonical-archive')
    save('canonical-archive',dict(bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    run(['tar','-xf',archive,'-C',source],'canonical-extract')
    archive.unlink()
    assert not sp.check_output(['git','status','--porcelain'],cwd=source)

    patch=w/'candidate.patch'
    canonical=sp.check_output(['git','show','HEAD:capstone-output-release/'+forms+'.patch'],cwd=r.parent)
    assert hashlib.sha256(canonical).hexdigest()==meta['sha256']
    patch.write_bytes(canonical)
    opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if os.name=='nt':
        opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if compiler=='MT' else 'OFF')]
    else:
        opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+compiler]
        if compiler=='gcc':opts+=['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    if profile=='diet':opts+=['-DCAPSTONE_BUILD_DIET=ON']
    if profile=='sanitize':opts+=['-DENABLE_ASAN=ON','-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
    run(['cmake','-S',source,'-B',b,*opts],'configure')
    units=['api','sstream','instruction_bytes']
    if profile!='diet':units+=['arm_post_index','arm_private_stream']
    targets=['capstone_static',*units,*(['cstest'] if profile!='diet' else [])]
    header=source/'MCInst.h';core=source/'cs.c'
    for phase in ('base','candidate','observer'):
        if phase=='candidate':
            raw=(source/'cs.c').read_bytes()
            head=sp.check_output(['git','show','HEAD:cs.c'],cwd=source)
            index=sp.check_output(['git','show',':cs.c'],cwd=source)
            status=sp.check_output(['git','status','--porcelain'],cwd=source,text=True)
            save('pre-apply-source',dict(worktree_sha256=hashlib.sha256(raw).hexdigest(),head_sha256=hashlib.sha256(head).hexdigest(),index_sha256=hashlib.sha256(index).hexdigest(),status=status))
            assert raw==head==index and not status
            run(['git','apply',patch],'apply')
            run(['git','add','-A'],'stage-tested-source')
            tree=sp.check_output(['git','write-tree'],cwd=source,text=True).strip()
            assert tree==meta['tree']
        if phase=='observer':
            text=header.read_text();needle='assert(i < MAX_MC_OPS);';assert text.count(needle)==1
            text=text.replace(needle,'if (i >= inst->size) { fprintf(stderr, "ARM operand read before construction: opcode=%u size=%u index=%u\\n", inst->Opcode, inst->size, i); abort(); }')
            text=text.replace('#include <assert.h>','#include <assert.h>\n#include <stdio.h>\n#include <stdlib.h>');header.write_text(text)
            text=core.read_text();assert text.count('MCInst mci;')==1
            core.write_text(text.replace('MCInst mci;','MCInst mci;\nmemset(&mci, 0xa5, sizeof(mci));'))
        run(['cmake','--build',b,'--config','Release','--target',*targets,'--parallel','4'],phase+'-build')
        run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],phase+'-tests')
        if profile!='diet':
            binary=b/'suite/cstest'/('Release/cstest.exe' if os.name=='nt' else 'cstest')
            run([binary,source/'tests/MC/ARM'],phase+'-arm-fixtures')
        names=[phase+'-tests',*([phase+'-arm-fixtures'] if profile!='diet' else [])]
        for name in names:
            text=(evidence/(name+'.log')).read_text(errors='replace')
            assert 'runtime error:' not in text and 'ERROR: AddressSanitizer' not in text
    save('complete',dict(forms=forms,profile=profile,compiler=compiler,units=units,tested_tree=tree,operand_observer_passed=True))
finally:
    amount=sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w,onerror=clean_error);save('cleanup',dict(bytes=amount,removed=not w.exists()))
