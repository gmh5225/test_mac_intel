import itertools,json,math,os,platform,shutil,statistics as st,subprocess as sp
from pathlib import Path
def inspect(t,bins,cases,e):
    def write(key,j):(e/(key+'.json')).write_text(json.dumps(j,indent=2)+'\n')
    cpu=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
    names=('cs_disasm_iter','cs_decode_full_insn','ARM_getInstruction','Mips_getInstruction','Mips_LLVM_getInstruction','Mips_set_instr_map_data','Mips_init_cs_detail','Mips_printer','ARM_LLVM_getInstruction','map_cs_id','find_cs_id')
    write('machine',dict(cpu=cpu,uname=platform.uname()._asdict(),detail=sp.check_output(['lscpu'],text=True)))
    symbols={};counts={};cross={};obs={}
    for side in ('base','indexed'):
        symbols[side]={}
        for ln in sp.check_output(['nm','-nS',bins[side]],text=True).splitlines():
            q=ln.split()
            if len(q)==4 and q[-1] in names:symbols[side][q[-1]]=dict(address=q[0],size=q[1])
    write('symbols',symbols)
    samples=[(x,m)for x in cases for m in (0,1,2) if x['name']=='mips64el-ls' or x['name']=='arm-ls' and not m]
    slots=[t/('slot'+str(i)) for i in range(2)]
    for x,m in samples:
        data=[]
        key=x['name']+'-'+str(m)
        def run(path,reps):return json.loads(sp.check_output([path,str(x['selector']),str(m),x['path'],str(reps)]))
        warm=run(bins['base'],2)
        reps=max(2,min(2000,round(2*120e6/warm['cpu_ns'])))
        for side in ('base','indexed'):
            trace=t/'counter.out';log=t/'valgrind.log'
            args=['valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(trace),str(bins[side]),str(x['selector']),str(m),x['path'],'1']
            with log.open('w')as f:record=json.loads(sp.check_output(args,stderr=f))
            assert record['first']==warm['first']
            rows=trace.read_text().splitlines();events=next(ln[8:].split()for ln in rows if ln.startswith('events: '));total=list(map(int,next(ln[8:].split()for ln in rows if ln.startswith('totals: '))));counts[key+'-'+side]=dict(zip(events,total));assert counts[key+'-'+side]['Ir']>0;trace.unlink();log.unlink()
        write('counters',counts)
        expected=None
        for cycle in range(19):
            timed={}
            for swap in (cycle%2,1-cycle%2):
                sets=('base','indexed') if swap==0 else ('indexed','base')
                for i,side in enumerate(sets):shutil.copyfile(bins[side],slots[i]);slots[i].chmod(0o755)
                ino=[os.stat(z).st_ino for z in slots]
                if 'inodes' in obs:assert obs['inodes']==ino
                obs['inodes']=ino
                for i in ((0,1,1,0) if cycle%2==0 else (1,0,0,1)):
                    v=run(slots[i],reps);result=(v['first'],v['result'])
                    if expected is None:expected=result
                    assert result==expected;timed.setdefault((sets[i],i),[]).append(v['cpu_ns'])
            time={k:st.geometric_mean(v)for k,v in timed.items()}
            def g(a,b):return time[a]/time[b]
            data.append(dict(image=math.sqrt(g(('base',0),('indexed',0))*g(('base',1),('indexed',1))),slot=math.sqrt(g(('base',0),('base',1))*g(('indexed',0),('indexed',1))),slot0=g(('base',0),('indexed',0)),slot1=g(('base',1),('indexed',1))))
        cross[key]=dict(pairs=data,median={z:st.median(row[z]for row in data)for z in data[0]},public=warm['first'],cycles=len(data));write('image-crossover',cross)
    write('attribution-complete',dict(cases=len(samples),counter_variants=len(counts),same_inodes=obs['inodes']))
