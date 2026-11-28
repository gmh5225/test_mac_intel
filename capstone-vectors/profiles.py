from pathlib import Path
import os,re,subprocess as sp
from self_cost import read
from sites import parse
import json
def set_sites(s):
    global source_sites
    source_sites=s
def measure(exe,mode,bits,path,spans,tagfile,counts,work,out,case):
    selected={}
    for engine in ('x86_all_','fast____'):
        argv=[exe,engine,str(mode),'1',path,spans,str(bits)]
        ref=list(map(int,sp.check_output(argv).split()))[2:]
        assert ref[0]==sum(counts[1:]) and ref[1]==counts[0],(case,engine,ref,counts)
        rows={}
        for bucket,count in [(3,sum(counts)),*enumerate(counts)]:
            if not count:continue
            profile=work/'current.callgrind';env=dict(os.environ,CG_COHORT=str(bucket),CG_COHORT_FILE=str(tagfile))
            job=sp.run(['valgrind','--tool=callgrind','--collect-atstart=no','--dump-instr=yes','--compress-strings=no','--compress-pos=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(profile),*argv],capture_output=True,text=True,env=env)
            (out/(case+'-'+str(mode)+'-'+engine+'-'+str(bucket)+'.log')).write_text(job.stderr)
            job.check_returncode()
            assert list(map(int,job.stdout.split()))[2:]==ref
            visits=re.search(r'^cohort-visits (\d+) (\d+)$',job.stderr,re.M)
            assert visits and list(map(int,visits.groups()))==[sum(counts),count],(case,engine,bucket,job.stderr[-1000:])
            events=[];values=[]
            with profile.open()as f:
                for line in f:
                    if line.startswith('events:'):events=line.split()[1:]
                    if line.startswith('totals:'):values=list(map(int,line.split()[1:]))
            self=read(profile,out,case+'-'+str(mode)+'-'+engine+'-'+str(bucket))
            if engine=='x86_all_' and bucket==2:
                exact=parse(profile,source_sites)
                (out/(case+'-'+str(mode)+'-cost-sites.json')).write_text(json.dumps(dict(records=count,functions=exact),indent=1)+'\n')
            profile.unlink()
            values+= [0]*(len(events)-len(values));totals=dict(zip(events,values))
            assert {'Ir','Dr','Dw','Bc','Bcm','Bi','Bim'}<=totals.keys() and totals['Ir']>0
            rows[bucket]=dict(visits=count,events=totals,exclusive=self)
        selected[engine]=dict(checksum=ref,cohorts=rows)
    assert selected['x86_all_']['checksum'][:3]==selected['fast____']['checksum'][:3]
    return selected
