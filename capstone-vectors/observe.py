import math,os,random
import subprocess as sp
from probe import hardware

def measure_all(r,w,cases,save):
 exe=w/'runner';isa=os.uname().machine;prefix=['setarch',isa,'-R'];all_times={};all_counts={}
 def args(case,label,n):
  mode,blob,path,bits=case
  return [exe,label.partition('+')[0],str(mode),str(n),blob,path,str(bits)]
 def visit(case,label,n):return list(map(int,sp.check_output(prefix+args(case,label,n),text=True).split()))
 with hardware(r,w,save) as (groups,pmu):
  for name,case in cases.items():
   mode=case[0];tags=['capstone','private','iced','iced+copy'] if mode==0 else ['capstone','private','private+copy','iced','fast','fast+copy']
   warm={t:visit(case,t,1)for t in tags};assert all(len(v)==6 and v[2:5]==warm['private'][2:5] for v in warm.values())
   n=max(1,math.ceil(15e6/min(v[0]for v in warm.values())));signatures={t:visit(case,t,n)[2:]for t in tags}
   def blocks(labels,count,reader,seed):
    series=[];order=list(labels);rng=random.Random(name+'/'+seed)
    for _ in range(count):
     rng.shuffle(order);block={}
     for t in order+order[::-1]:
      v=reader(t)
      if t in block:
       for k,value in v.items():block[t][k]+=value
      else:block[t]=v
     series.append(block)
    return series
   def time(t):
    got=visit(case,t,n);assert got[2:]==signatures[t];return dict(cpu=got[0],wall=got[1])
   tm=blocks(tags,17,time,'elapsed')
   all_times[name]=dict(reps=n,attempts=sum(warm['private'][2:4]),checks=signatures,blocks=tm);save('real-times',all_times)
   if mode and name.split('/')[0]in ('putty-32-0.85','libmvec-amd64'):
    data={}
    for group,events in groups.items():
     def read(t):
      ok,counts,stdout,diag=pmu(events,args(case,t,n));assert ok and list(map(int,stdout.split()))[2:]==signatures[t],(name,t,group,diag)
      return counts
     data[group]=blocks(['private','capstone','fast','fast+copy'],13,read,group)
    all_counts[name]=dict(reps=n,attempts=all_times[name]['attempts'],events=data);save('hardware-events',all_counts)
 assert len(all_times)==18 and len(all_counts)==4
