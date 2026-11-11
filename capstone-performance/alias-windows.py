"""Measure alias substring writers on native MSVC for both CRT linkage modes."""
import io
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tarfile

from corpus import digest, elf_text, pe_text
from run import WORK, EVIDENCE, SOURCE, cleanup, command, fetch, write

crt = sys.argv[1]
manifest = json.loads((SOURCE/'manifest.json').read_text())
assert crt in ('MD','MT')


def fixture(row, packages):
    key = row['package_sha256']
    if key not in packages:
        p = WORK/(key + '.pkg')
        command(['curl.exe','-fsSL','--retry','3',row['url'],'-o',p], 'fetch-'+key[:10])
        package = p.read_bytes()
        assert digest(package) == key
        if row['kind'] == 'pe':
            packages[key] = package
        else:
            assert package[:8] == b'!<arch>\n'
            i = 8
            while i < len(package):
                header = package[i:i+60]
                assert header[58:] == b'`\n'
                size = int(header[48:58])
                i += 60
                if header[:16].strip().rstrip(b'/').startswith(b'data.tar'):
                    packages[key] = package[i:i+size]
                    break
                i += size + size % 2
    payload = packages[key]
    if row['kind'] == 'pe':
        data = pe_text(payload)
    else:
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            allowed = (row['member'],) if 'member' in row else ('usr/bin/'+row['command'],'bin/'+row['command'])
            entry, = [m for m in archive if m.name.lstrip('./') in allowed and m.isfile()]
            data = elf_text(archive.extractfile(entry).read())
    if 'text_sha256' in row: assert digest(data) == row['text_sha256']
    dst = WORK/(row['name']+'.text')
    dst.write_bytes(data)
    return dict(row, path=str(dst), sha256=digest(data), size=len(data))


def main():
    WORK.mkdir(); EVIDENCE.mkdir()
    command(['git','config','--global','core.autocrlf','false'],'lf')
    base = fetch('base','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'])
    exports=('X86_getInstructionScan','X86_getInstructionScanResult','X86_scanBatch','X86_scanCallTarget','cs_disasm_iter','decodeInstruction','decodeInstructionFull','decodeInstructionScan')
    for label in ('live','isolated'):
        tree=WORK/label
        patch=SOURCE/(label+'.patch')
        assert digest(patch.read_bytes())==manifest['source_lineage'][patch.name]['sha256']
        command(['git','worktree','add','--detach',tree,'HEAD'],label+'-tree',base)
        command(['git','apply',patch],label+'-apply',tree)
        impl=(tree/'arch/X86/X86DisassemblerDecoder.c').as_posix()
        h=''.join('#define '+name+' '+label+'_'+name+'\n' for name in exports)
        (base/'arch/X86'/('Bench'+label+'.c')).write_text(h+'#include "'+impl+'"\n')
    with (base/'CMakeLists.txt').open('a') as f:
        f.write('\ntarget_sources(capstone PRIVATE arch/X86/Benchlive.c arch/X86/Benchisolated.c)\nadd_executable(native_single "'+(SOURCE/'single-msvc.cpp').as_posix()+'")\ntarget_compile_features(native_single PRIVATE cxx_std_17)\ntarget_link_libraries(native_single PRIVATE capstone_static)\n')
    build=WORK/'build'
    command(['cmake','-S',base,'-B',build,'-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF')],'configure')
    command(['cmake','--build',build,'--config','Release','--parallel','4','--target','native_single'],'build')
    exe=build/'Release/native_single.exe'
    write('inputs.json',dict(manifest=manifest,crt=crt,image=digest(exe.read_bytes())))
    selected = {r['name']:r for r in manifest['inputs'] if r['name'] in (
        'arm-ls','arm64-ls','ppc64el-ls','loong64-ls','putty-32-0.85')}
    assert len(selected)==5
    cache={};cases=[fixture(r,cache) for r in selected.values()]
    write('cases.json',cases)
    snapshots=[]; measurements=[]
    for case in cases:
        for mode in (1,2):
            args=[str(case['selector']),str(mode),case['path']]
            labels=('base','live','isolated')
            def sample(label,n):
                env=dict(os.environ,CAPSTONE_BENCH_ITER=str(labels.index(label)))
                return json.loads(subprocess.check_output([exe,*args,str(n)],env=env))
            n=1
            while (probe:=sample('base',n))['wall_ns']<10_000_000:n*=4
            repeats=max(1,math.ceil(n*75_000_000/probe['wall_ns']))
            pairs=[]
            for cycle in range(6):
                order=labels[cycle%3:]+labels[:cycle%3]
                raw=[(label,sample(label,repeats))for label in order+order[::-1]]
                assert all(row['result']==raw[0][1]['result']for _,row in raw)
                v={label:[a['thread_cycles']for k,a in raw if k==label]for label in labels}
                pairs.append(dict(raw=raw,gain={k:statistics.mean(v['base'])/statistics.mean(a)for k,a in v.items()},aa={k:a[0]/a[1]for k,a in v.items()}))
            measurements.append(dict(case=case['name'],mode=mode,pairs=pairs))
            write('measurement.json',measurements)
    write('complete.json',dict(complete=True))

if __name__=='__main__':
    try: main()
    finally: cleanup()
