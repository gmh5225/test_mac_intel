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
    assert digest((SOURCE/'msvc-alias.patch').read_bytes()) == manifest['source_lineage']['msvc-alias.patch']['sha256']
    new = WORK/'new'
    command(['git','worktree','add','--detach',new,'HEAD'],'worktree',base)
    command(['git','apply',SOURCE/'msvc-alias.patch'],'apply',new)
    write('inputs.json',dict(ref=manifest['capstone_revision'],crt=crt,patch=digest((SOURCE/'msvc-alias.patch').read_bytes()),image=os.environ['ImageVersion']))
    write('processor.json',json.loads(subprocess.check_output(['powershell','-NoProfile','-Command','Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'],text=True)))
    programs = {}; compiled = {}
    for label,tree in [('base',base),('new',new)]:
        build = WORK/(label+'-build')
        targets = '''
add_executable(native_single "${SOURCE}/single-msvc.cpp")
target_compile_features(native_single PRIVATE cxx_std_17)
target_link_libraries(native_single PRIVATE capstone_static)
add_executable(native_snapshot "${SOURCE}/alias-snapshot.cpp")
target_compile_features(native_snapshot PRIVATE cxx_std_17)
target_link_libraries(native_snapshot PRIVATE capstone_static bcrypt)
add_executable(native_sstream "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/sstream.c")
target_include_directories(native_sstream PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/include")
target_link_libraries(native_sstream PRIVATE capstone_static)
'''
        with (tree/'CMakeLists.txt').open('a') as f: f.write('\n'+targets)
        command(['cmake','-S',tree,'-B',build,'-G','Visual Studio 17 2022','-A','x64',
                 '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MSVC_NATIVE_DECODER='+('ON' if label=='new' else 'OFF'),'-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCMAKE_C_FLAGS=/MP4','-DSOURCE='+SOURCE.as_posix(),'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                 '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF')], label+'-configure')
        def build_targets(step,*names):
            command(['cmake','--build',build,'--config','Release','--parallel','4','--target',*names],label+step)
        build_targets('-timed','native_single','native_sstream')
        timed=build/'Release/native_single.exe'
        command([build/'Release/native_sstream.exe'],label+'-sstream')
        compiled[label]=digest(timed.read_bytes())
        programs[label]=timed
    write('binaries.json',compiled)
    selected = {r['name']:r for r in manifest['inputs'] if r['name'] in ('arm-ls','arm-cp','arm-sort','thumb-ls','thumb-cp','thumb-sort','putty-32-0.85')}
    assert len(selected)==7
    cache={};cases=[fixture(r,cache) for r in selected.values()]
    write('cases.json',cases)
    snapshots=[]; measurements=[]
    for case in (cases if sys.argv[2]=='first' else list(reversed(cases))):
        for mode in (1,2):
            args=[str(case['selector']), str(mode), case['path']]
            def sample(label,n):
                return json.loads(subprocess.check_output([programs[label],*args,str(n)]))
            n=1
            while (probe:=sample('base',n))['wall_ns'] < 10000000: n *= 4
            repeats=max(1,math.ceil(n*220000000/probe['wall_ns']))
            pairs=[]
            for cycle in range(15):
                order=['base','new','new','base'] if cycle%2==(0 if sys.argv[2]=='first' else 1) else ['new','base','base','new']
                rows=[(label,sample(label,repeats)) for label in order]
                assert all(row['result']==rows[0][1]['result'] for _,row in rows)
                a,b=([row['thread_cycles'] for label,row in rows if label==variant] for variant in ('base','new'))
                pairs.append(dict(raw=rows,gain=statistics.mean(a)/statistics.mean(b),base_aa=a[0]/a[1],new_aa=b[0]/b[1]))
            measurements.append(dict(case=case['name'],mode=mode,pairs=pairs,gain=statistics.median(p['gain'] for p in pairs)))
            write('measurement.json',measurements)
    write('complete.json',dict(complete=True))

if __name__=='__main__':
    try: main()
    finally: cleanup()
