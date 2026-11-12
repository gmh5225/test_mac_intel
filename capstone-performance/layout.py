from pathlib import Path
import hashlib,json,math,os,re,statistics,subprocess,shutil
import run,corpus

def main():
    w,e=run.WORK,run.EVIDENCE
    w.mkdir();e.mkdir()
    manifest=json.loads((run.SOURCE/'manifest.json').read_text())
    rev=manifest['capstone_revision']
    base=run.fetch('base','https://github.com/NeverSight/capstone.git',rev)
    source=(run.SOURCE/'single.cpp').read_text()
    source='#include <valgrind/callgrind.h>\n'+source
    source=source.replace('    const Result expected =','    CALLGRIND_START_INSTRUMENTATION;\n    const Result expected =').replace('    const Result measured =','    CALLGRIND_ZERO_STATS;\n    const Result measured =').replace('    cpu = process_cpu_ns() - cpu;', '    CALLGRIND_STOP_INSTRUMENTATION;\n    cpu = process_cpu_ns() - cpu;')
    (w/'roi.cpp').write_text(source)
    run.command(['clang++','-std=c++17','-O3','-DNDEBUG','-I',base/'include','-c',w/'roi.cpp','-o',w/'roi.o'],'consumer')
    run.command(['clang','-O3','-fno-builtin-memset','-I',base,'-I',base/'include','-c',run.SOURCE/'layout.c','-o',w/'wrap.o'],'wrapper')
    fixtures=corpus.prepare(run.SOURCE,w,e,run.command)
    active={'mips64el-ls','sparc64-ls','putty-32-0.85','scalar32','simd64'}
    cases=[v for v in fixtures if v['name'] in active]
    assert len(cases)==len(active)
    allowed=os.sched_getaffinity(0);os.sched_setaffinity(0,{min(allowed)})
    run.command(['lscpu'],'cpu');run.write('inputs.json',dict(source=rev,lineage=manifest['source_lineage'],affinity=list(os.sched_getaffinity(0))))
    variants=('base','terminal','entry','aligned','entryaligned')
    progs={};digests={};signatures={};measurements=[];hist=[];counts=[]
    for tag in variants:
        root=w/tag
        if tag!='base':
            run.command(['git','worktree','add','--detach',root,'HEAD'],'tree-'+tag,base)
            patch='terminal' if tag=='terminal' else 'entry' if tag.startswith('entry') else None
            if patch:
                f=run.SOURCE/(patch+'.patch');assert run.sha(f)==manifest['source_lineage'][f.name]['sha256'];run.command(['git','apply',f],'apply-'+tag,root)
            if tag.endswith('aligned'):
                f=root/'cs.c';s=f.read_text();start=s.index('cs_decode_full_insn(cs_struct');j=s.index('MCInst mci;',start)
                f.write_text(s[:j]+s[j:].replace('MCInst mci;', 'MCInst mci __attribute__((aligned(64)));',1))
        b=run.build(tag)
        exe=w/(tag+'-roi');wrapped=w/(tag+'-wrap');progs[tag]=exe
        for target,extra in [(exe,[]),(wrapped,[w/'wrap.o','-Wl,--wrap=memset'])]:
            run.command(['clang++','-no-pie',w/'roi.o',*extra,b/'libcapstone.a','-lm','-o',target],target.name+'-link')
        digests[tag]=dict(exe=run.sha(exe),object=run.sha(w/'roi.o'))
        for f in ('MCInst_Init','cs_disasm_iter','cs_decode_full_insn'):
            run.command(['objdump','-d','--disassemble='+f,exe],tag+'-'+f+'-assembly')
        for case in cases:
            for mode in ((1,2) if case['selector']>=16 else (2,)):
                args=[str(case['selector']),str(mode),case['path'],'1'];key=(case['name'],mode)
                native=json.loads(subprocess.check_output([exe,*args]));assert native['result']==signatures.setdefault(key,native['result'])
                if case['selector']>=16:continue
                def dump(probe,log):
                    lines=log.splitlines()
                    for line in lines:
                        if not line.startswith('mcinst '):continue
                        _,pc,n,offset,calls=line.split();owner=subprocess.check_output(['addr2line','-fe',wrapped,hex(int(pc,16)-1)],text=True).splitlines()[0]
                        hist.append(dict(tag=tag,case=case['name'],probe=probe,site=owner,size=int(n),offset=int(offset),calls=int(calls)))
                    assert any(x['tag']==tag and x['case']==case['name'] and x['probe']==probe and x['site']=='MCInst_Init' for x in hist)
                for i in range(6):
                    v=subprocess.run([wrapped,*args],capture_output=True,text=True,check=True);dump('native'+str(i),v.stderr)
                for machine,binary in [('plain',exe),('wrapped',wrapped)]:
                    profile=w/'cache.out'
                    name=tag+'-'+case['name']+'-'+machine
                    run.command(['valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(profile),binary,*args],name)
                    report=(e/(name+'.log')).read_text()
                    if machine=='wrapped':dump('callgrind',report)
                    data=profile.read_text().splitlines();events=next(t for t in data if t.startswith('events:')).split()[1:];totals=next(t for t in data if t.startswith('totals:')).split()[1:]
                    counts.append(dict(tag=tag,case=case['name'],machine=machine,events=dict(zip(events,map(int,totals)))))
                    profile.unlink()
                run.write('offsets.json',hist);run.write('counts.json',counts)
    run.write('binaries.json',digests)
    for case in cases:
        for mode in ((0,1,2) if case['selector']>=16 else (1,2)):
            args=[str(case['selector']),str(mode),case['path']]
            n=1
            while (v:=json.loads(subprocess.check_output([progs['base'],*args,str(n)])))['cpu_ns']<8000000:n*=3
            n=max(1,math.ceil(n*80000000/v['cpu_ns']))
            cycles=[]
            for i in range(10):
                order=list(variants[i%len(variants):]+variants[:i%len(variants)])
                if i%2:order.reverse()
                raw=[(k,json.loads(subprocess.check_output([progs[k],*args,str(n)])))for k in order+order[::-1]]
                assert all(row['result']==raw[0][1]['result'] for _,row in raw)
                times={k:[v['cpu_ns'] for name,v in raw if name==k]for k in variants}
                cycles.append(dict(times=times,relative={k:statistics.mean(times['base'])/statistics.mean(v)for k,v in times.items()}))
            measurements.append(dict(case=case['name'],mode=mode,cycles=cycles));run.write('measurement.json',measurements)
    run.write('complete.json',dict(complete=True,rows=len(measurements)))
if __name__=='__main__':
    try:main()
    finally:
        if run.EVIDENCE.exists():run.cleanup()
