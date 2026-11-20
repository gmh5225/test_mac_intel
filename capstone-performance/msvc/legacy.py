"""Measure both compilable MSVC inlining choices on one machine and consumer."""
from pathlib import Path
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess as sp
import run as tool

source, work = tool.source, tool.work
manifest = json.loads((source / 'legacy-inputs.json').read_text())

def git(repo, *args):
    return sp.check_output(['git', '-C', repo, *args], text=True).strip()

def main():
    current = tool.fetch('source', 'capstone', manifest['capstone'])
    tool.fetch('iced', 'iced', manifest['iced'])
    compiler = sp.run(['cl'], capture_output=True, text=True)
    version, = re.findall(r'Version (\d+\.\d+\.\d+)', compiler.stderr)
    modern = tuple(map(int, version.split('.')[:2])) >= (19, 52)
    variants = ['readers','terminal'] if modern else ['base','readers','terminal']
    tool.write('inputs.json',dict(**manifest, native_compiler=version, variants=variants, image=os.environ.get('ImageVersion')))
    adapter = work / 'adapter'
    adapter.mkdir()
    for name in ('iced.rs','Cargo.lock'):
        shutil.copyfile(source/name,adapter/name)
    (adapter/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}\n[profile.release]\nopt-level=3\npanic="abort"\n')
    tool.run(['cargo','build','--release','--locked','--manifest-path',adapter/'Cargo.toml'],'iced')
    build = work/'build'
    tool.run(['cmake','-G','Ninja','-S',current,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS')]],'configure')
    for name, path in [('compare',source/'msvc/compare.cpp'),('snapshot',source/'snapshot.cpp')]:
        tool.run(['cl','/nologo','/MD','/O2','/DNDEBUG','/EHsc','/std:c++17','/I'+str(current/'include'),'/Fo'+str(work/(name+'.obj')),'/c',path], 'consumer-'+name)
    programs = {}
    objects = {}
    for label in variants:
        if label != 'base':
            path = work/'input.patch'
            path.write_bytes(sp.check_output(['git','-C',source,'show','HEAD:capstone-performance/'+label+'.patch']))
            assert tool.digest(path.read_bytes()) == manifest[label]['sha256']
            git(current,'apply','--index',str(path))
        assert git(current,'write-tree') == manifest[label]['tree']
        tool.run(['cmake','--build',build,'--target','capstone_static','--parallel','1'],'build-'+label)
        libs=list(build.rglob('capstone.lib')) or list(build.rglob('capstone_static.lib'))
        assert len(libs)==1,libs
        root = build/'CMakeFiles/capstone.dir'
        objects[label] = {str(f.relative_to(root)):tool.digest(f.read_bytes()) for f in root.rglob('*.obj')}
        assert len(objects[label])>25
        programs[label] = {}
        for name in ('compare','snapshot'):
            exe = work/(label+'-'+name+'.exe')
            args = [work/(name+'.obj'),libs[0]]
            if name=='compare':
                args.extend([work/'cargo-target/release/iced_compare.lib','advapi32.lib','bcrypt.lib','ntdll.lib','userenv.lib','ws2_32.lib'])
            tool.run(['link','/nologo','/incremental:no','/fixed','/dynamicbase:no','/out:'+str(exe),*args], 'link-'+label+'-'+name)
            programs[label][name] = exe
        git(current,'reset','--hard',manifest['capstone'])
        assert not git(current,'status','--porcelain')
    first = variants[0]
    differences = {v:[f for f in objects[first] if objects[v].get(f)!=objects[first][f]] for v in variants}
    assert all(set(z)==set(objects[first]) for z in objects.values())
    tool.write('objects.json',dict(differences=differences, hashes=objects))
    cases = tool.get_cases()
    assert {'putty-32-0.85','putty-64-0.85','scalar32','scalar64','simd64'} <= {c['name'] for c in cases}
    tool.snapshot(programs,cases)
    blobs={label:programs[label]['compare'].read_bytes() for label in variants}
    blobs['copy']=blobs['iced']=blobs[first]
    maximum=max(map(len,blobs.values()))
    padded={k:v+bytes(maximum-len(v)) for k,v in blobs.items()}
    tool.write('controls.json', dict(first=first, exe_sha256={k:tool.digest(v) for k,v in blobs.items()},equal_size=maximum,aslr=False,cycles=8))
    shared=work/'same-image.exe'
    shared.write_bytes(padded[first])
    def sample(label,case,mode,n):
        with shared.open('r+b') as stream:
            assert stream.write(padded[label])==maximum
        return json.loads(sp.check_output([shared,'iced' if label=='iced' else 'capstone',mode,str(case['bits']),str(n),case['path']]))
    results=[]
    for case in cases:
        for mode in ('scan','format','detail'):
            probe=sample(first,case,mode,1)
            n=max(1,math.ceil(60e6/max(probe['wall_ns'],1)))
            labels=[*variants,'copy','iced']
            cycles=[]
            same=True
            for i in range(8):
                order=labels[i%len(labels):]+labels[:i%len(labels)]
                obs=[(k,sample(k,case,mode,n)) for k in order+order[::-1]]
                def signatures(keys, engines):
                    return {tuple(row[x] for x in keys) for name,row in obs if name in engines}
                boundary=('instructions','rejected','boundary_hash')
                assert len(signatures((*boundary,'value_hash'),variants+['copy']))==1
                same &= len(signatures(boundary,labels))==1
                cycles.append({k:{field:statistics.mean(row[field] for name,row in obs if k==name) for field in ('thread_cycles','wall_ns','cpu_ns')} for k in labels})
            results.append(dict(case=case['name'],mode=mode,repeats=n,iced_equal_boundaries=same,cycles=cycles))
            tool.write('timings.json',results)
    tool.write('complete.json',dict(rows=len(results),cases=len(cases),variants=variants))

try:
    main()
finally:
    size=sum(p.stat().st_size for p in work.rglob('*') if p.is_file())
    def writable(fn,path,error):
        os.chmod(path,0o700)
        fn(path)
    shutil.rmtree(work,onerror=writable)
    tool.write('cleanup.json',dict(bytes=size,removed=not work.exists()))
