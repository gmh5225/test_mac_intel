from pathlib import Path
import os,re,subprocess as sp
def measure(exe,mode,bits,path,spans,tagfile,counts,work,out,case):
    selected={}
    for engine in ('x86_all_','fast____'):
        argv=[exe,engine,str(mode),'1',path,spans,str(bits)]
        ref=list(map(int,sp.check_output(argv).split()))[2:]
        assert ref[0]==sum(counts[1:]) and ref[1]==counts[0],(case,engine,ref,counts)
        rows={}
        for bucket,count in [(10,sum(counts)),*enumerate(counts)]:
            if not count:continue
            profile=work/'current.callgrind';env=dict(os.environ,CG_COHORT=str(bucket),CG_COHORT_FILE=str(tagfile))
            job=sp.run(['valgrind','--tool=callgrind','--collect-atstart=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(profile),*argv],capture_output=True,text=True,env=env)
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
            annotated=sp.check_output(['callgrind_annotate','--show=Ir','--threshold=90','--auto=no','--inclusive=no','--show-percs=no',profile],text=True)
            (out/(case+'-'+str(mode)+'-'+engine+'-'+str(bucket)+'-self.log')).write_text(annotated)
            functions=[]
            for line in annotated.splitlines():
                match=re.match(r'^\s*([0-9][0-9,]*)\s+(.+\S)$',line)
                if match and 'PROGRAM ' not in match[2]:
                    functions.append([int(match[1].replace(',','')),match[2]])
            functions.sort(reverse=True)
            assert functions,(case,mode,engine,bucket,annotated[-1200:])
            profile.unlink()
            values+= [0]*(len(events)-len(values));totals=dict(zip(events,values))
            assert {'Ir','Dr','Dw','Bc','Bcm','Bi','Bim'}<=totals.keys() and totals['Ir']>0
            rows[bucket]=dict(visits=count,events=totals,top_self_instructions=functions[:20])
        selected[engine]=dict(checksum=ref,cohorts=rows)
    assert selected['x86_all_']['checksum'][:3]==selected['fast____']['checksum'][:3]
    return selected
