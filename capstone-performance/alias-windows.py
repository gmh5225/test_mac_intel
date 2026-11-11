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
                 '-DCMAKE_C_FLAGS=/MP4','-DSOURCE='+SOURCE.as_posix(),'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                 '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF')], label+'-configure')
        def build_targets(step,*names):
            command(['cmake','--build',build,'--config','Release','--parallel','4','--target',*names],label+step)
        build_targets('-timed','native_single','native_sstream')
        objdump=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
        compiled[label]={}
        for stem in ('cs','SStream','Mapping','AArch64Mapping','ARMMapping','MipsMapping','SparcMapping','PPCMapping','RISCVMapping','LoongArchMapping','SystemZMapping'):
            obj,=(build/'capstone.dir'/'Release').rglob(stem+'.obj')
            listing=subprocess.check_output([objdump,'-dr','--no-show-raw-insn',obj],text=True,errors='replace')
            contents='\n'.join(line for line in listing.splitlines() if 'file format' not in line and line.strip()).encode()
            compiled[label][stem]=digest(contents)
        write('release-code.json',compiled)
        timed=build/'Release/native_single.exe'
        before = digest(timed.read_bytes())
        command([build/'Release/native_sstream.exe'],label+'-sstream')
        p=tree/'SStream.c';t=p.read_text()
        start=t.index('CAPSTONE_INTERNAL void SStream_concat0_substr(')
        t=t[:start]+'unsigned long long alias_direct_count, alias_heap_count;\n'+t[start:]
        start=t.index('CAPSTONE_INTERNAL void SStream_concat0_substr(')
        end=t.index('char *substr = cs_mem_malloc',start)
        t=t[:start]+t[start:end].replace('assert(ss && s);','++alias_direct_count;\n\t\tassert(ss && s);')+'++alias_heap_count;\n\t'+t[end:]
        p.write_text(t)
        build_targets('-instrumented','native_snapshot')
        assert digest(timed.read_bytes()) == before
        programs[label] = (timed,build/'Release/native_snapshot.exe')
    selected = {r['name']:r for r in manifest['inputs'] if r['name'] in (
        'arm-ls','arm-cp','arm64-ls','ppc64el-ls','ppc64el-sort','mips64el-ls','sparc64-ls','loong64-ls','loong64-sort','putty-32-0.85')}
    assert len(selected) == 10, selected.keys()
    cache={};cases=[fixture(r,cache) for r in selected.values()]
    write('cases.json',cases)
    snapshots=[]; measurements=[]
    for case in cases:
        for mode in (1,2):
            args=[str(case['selector']), str(mode), case['path']]
            copies={k:json.loads(subprocess.check_output([progs[1],*args])) for k,progs in programs.items()}
            snapshots.append(dict(case=case['name'],mode=mode,results=copies));write('snapshots.json',snapshots)
            assert copies['base']['sha256']==copies['new']['sha256'] and copies['base']['records']==copies['new']['records']
            def sample(label,n):
                return json.loads(subprocess.check_output([programs[label][0],*args,str(n)]))
            n=1
            while (probe:=sample('base',n))['wall_ns'] < 10000000: n *= 4
            repeats=max(1,math.ceil(n*130000000/probe['wall_ns']))
            pairs=[]
            for cycle in range(6):
                order=['base','new','new','base'] if cycle%2==0 else ['new','base','base','new']
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
