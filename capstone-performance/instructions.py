"""Attribute the same warmed Capstone workload to backend work or linked code layout."""
from pathlib import Path
import gzip, hashlib, json, os, shutil, subprocess
import run
import corpus

def main():
    run.WORK.mkdir()
    run.EVIDENCE.mkdir()
    manifest=json.loads((run.SOURCE/'manifest.json').read_text())
    base=run.fetch('base','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'])
    source=(run.SOURCE/'single.cpp').read_text()
    source='#include <valgrind/callgrind.h>\n'+source
    source=source.replace('    const Result expected =','    CALLGRIND_START_INSTRUMENTATION;\n    const Result expected =')
    source=source.replace('    const Result measured =','    CALLGRIND_ZERO_STATS;\n    const Result measured =')
    source=source.replace('    cpu = process_cpu_ns() - cpu;', '    CALLGRIND_STOP_INSTRUMENTATION;\n    cpu = process_cpu_ns() - cpu;')
    assert source.count('CALLGRIND_')==3
    (run.WORK/'roi.cpp').write_text(source)
    run.command(['clang++','-std=c++17','-O3','-DNDEBUG','-I',base/'include','-c',run.WORK/'roi.cpp','-o',run.WORK/'roi.o'],'consumer')
    run.command(['valgrind','--version'],'valgrind-version')
    run.command(['lscpu'],'cpu')
    by_case={}
    fixtures=corpus.prepare(run.SOURCE,run.WORK,run.EVIDENCE,run.command)
    selected={(n,m) for n in ('putty-32-0.85','scalar32','simd64','mips64el-ls','sparc64-ls') for m in (1,2)}
    results=[]
    for tag in ('base','terminal','printer'):
        if tag!='base':
            tree=run.WORK/tag
            run.command(['git','worktree','add','--detach',tree,'HEAD'],'tree-'+tag,base)
            patch=run.SOURCE/(tag+'.patch')
            assert run.sha(patch)==manifest['source_lineage'][patch.name]['sha256']
            run.command(['git','apply',patch],'apply-'+tag,tree)
        build=run.build(tag)
        exe=run.WORK/(tag+'-roi')
        run.command(['clang++',run.WORK/'roi.o',build/'libcapstone.a','-lm','-o',exe],tag+'-link')
        for case in fixtures:
            for mode in (1,2):
                if (case['name'],mode) not in selected:continue
                label=tag+'-'+case['name']+'-'+str(mode)
                path=run.WORK/(label+'.out')
                run.command(['valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes',
                             '--callgrind-out-file='+str(path),exe,case['selector'],mode,case['path'],1],label)
                lines=(run.EVIDENCE/(label+'.log')).read_text().splitlines()
                row=next(json.loads(v)for v in lines if v.startswith('{'))
                key=(case['name'],mode)
                assert row['result']==by_case.setdefault(key,row['result'])
                profile=path.read_bytes()
                events=next(line.split()[1:] for line in profile.splitlines() if line.startswith(b'events:'))
                totals=next(line.split()[1:] for line in profile.splitlines() if line.startswith(b'totals:'))
                counters={event.decode():int(count) for event,count in zip(events,totals)}
                assert counters['Ir']>row['result']['instructions']*50 and len(counters)>=9
                results.append(dict(variant=tag,case=case['name'],mode=mode,counters=counters,public=row['result']))
                run.write('counters.json',results)
                (run.EVIDENCE/(label+'.callgrind.gz')).write_bytes(gzip.compress(profile))
    assert len(results)==3*len(selected),(len(results),selected,set(by_case))
    run.write('complete.json',dict(sources=manifest['source_lineage'],revision=manifest['capstone_revision'],rows=len(results)))
if __name__=='__main__':
    try:main()
    finally:
        if run.EVIDENCE.exists():run.cleanup()
