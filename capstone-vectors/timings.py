from pathlib import Path
import math,os,random,subprocess as sp
def measure(w,cases,images,save):
 data={};window=w/'selected';isa=os.uname().machine
 for name,(mode,blob,ext,bits)in cases.items():
  for route in ('private','capstone'):
   rival='iced' if not mode else 'fast';tags=['stock','control','control+copy','placed','placed+copy','shuffled',rival]
   def visit(t,n):
    o=t.partition('+')[0];exe=images['stock' if o==rival else o];window.unlink(missing_ok=True);window.symlink_to(exe)
    return list(map(int,sp.check_output(['setarch',isa,'-R',window,rival if o==rival else route,str(mode),str(n),blob,ext,str(bits)],text=True).split()))
   warm={t:visit(t,1)for t in tags};assert all(z[2:5]==warm['stock'][2:5] for z in warm.values())
   reps=max(1,math.ceil(12e6/min(z[0]for z in warm.values())));checks={t:visit(t,reps)[2:]for t in tags};assert all(z==checks['stock'] for t,z in checks.items()if t!=rival)
   blocks=[];rng=random.Random(name+'/'+route);order=tags[:]
   for block in range(17):
    rng.shuffle(order);times={}
    for t in order+order[::-1]:
     z=visit(t,reps);assert z[2:]==checks[t];x=times.setdefault(t,[0,0]);x[0]+=z[0];x[1]+=z[1]
    blocks.append(times)
   data[route+'/'+name]=dict(cycles=blocks,reps=reps,checks=checks);save('timings',data)
 assert len(data)==36

