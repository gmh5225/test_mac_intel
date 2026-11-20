"""Compare integrated Capstone outputs under the product's real CMake configuration."""
from pathlib import Path
import hashlib
import json
import os
import subprocess as sp
import sys
r=Path(__file__).resolve().parent
root=r.parent
nd=root/'neverd'
ev=root/'evidence'
ev.mkdir(exist_ok=True)
cs=nd/'third_party/capstone'
llvm=nd/'third_party/llvm-project'
target=Path(os.environ['RUNNER_TEMP'])/'capstone-product'
spec=json.loads((r/'integrated-inputs.json').read_text())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def git(repo,*args):
    return sp.check_output(['git','-C',repo,*args],text=True).strip()
def exact(label):
    commit,tree,capstone=spec[label]
    git(cs,'checkout','--detach',capstone)
    git(nd,'update-index','--cacheinfo','160000,'+capstone+',third_party/capstone')
    assert git(nd,'write-tree')==tree
    assert git(nd,'hash-object','-t','commit','-w',str(r/(label+'-nd.txt')))==commit
    git(nd,'checkout','--detach',commit)
    assert git(nd,'rev-parse','HEAD')==commit and git(cs,'rev-parse','HEAD')==capstone
def build(label,command):
    print(label,flush=True)
    with (ev/(label+'.log')).open('w') as f:
        status=sp.run(list(map(str,command)),cwd=nd,stdout=f,stderr=sp.STDOUT).returncode
    if status:
        raise RuntimeError(label+'\n'+(ev/(label+'.log')).read_text(errors='replace')[-3000:])
def records():
    roots=[b for b in target.rglob('capstone.dir') if any(b.rglob('X86DisassemblerDecoder.c.o'))]
    assert len(roots)==1
    objects={str(f.relative_to(roots[0])):sha(f) for f in roots[0].rglob('*.o')}
    archives=[f for f in target.rglob('libcapstone.a') if f.is_file()]
    assert len(objects)>30 and len(archives)==1
    return dict(objects=objects,archive=sha(archives[0]))
if sys.argv[1]=='compare':
    assert git(nd,'rev-parse','HEAD')==spec['parent']
    commit=git(llvm,'rev-parse','HEAD')
    git(cs,'fetch','--depth','2','origin',spec['candidate'][2])
    exact('control')
    build('configure',['cmake','-S',nd,'-B',target,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DBUILD_TESTING=ON','-DCMAKE_LINKER_TYPE=LLD','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DNEVERD_LLVM_PREBUILT=OFF','-DNEVERD_ENABLE_SEMANTIC_TESTS=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_BINARY_CORPUS_TESTS=OFF','-DNEVERD_BUILD_GUI=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF'])
    build('control',[sys.executable,'scripts/build.py',target,'--target','capstone_static','--parallel','4'])
    assert git(cs,'rev-parse','HEAD')==spec['control'][2]
    control=records()
    exact('candidate')
    build('candidate',['cmake','--build',target,'--target','capstone_static','--parallel','4'])
    candidate=records()
    assert commit==git(llvm,'rev-parse','HEAD') and not git(llvm,'diff','--name-only','HEAD')
    data=dict(complete=True,source=spec,llvm=commit,control=control,candidate=candidate,identical=control==candidate)
    (ev/'objects.json').write_text(json.dumps(data,indent=2)+'\n')
    assert data['identical']
    print('Byte-identical archive and objects:',len(control['objects']),control['archive'],flush=True)
else:
    assert sys.argv[1]=='contracts'
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests']
    build('dependent-build',['cmake','--build',target,'--parallel','4','--target',*targets])
    build('contracts',['ctest','--test-dir',target,'--no-tests=error','--output-on-failure','-j4','-L','^('+'|'.join(targets)+')$','--output-junit',ev/'contracts.xml'])
    assert git(nd,'rev-parse','HEAD')==spec['candidate'][0] and git(cs,'rev-parse','HEAD')==spec['candidate'][2]
    assert git(llvm,'rev-parse','HEAD')==json.loads((ev/'objects.json').read_text())['llvm']
