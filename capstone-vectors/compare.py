import hashlib,json,math,os,random,subprocess as sp
from pathlib import Path
def run_programs(r,w,cases,foreign,save):
 def measure(name,cmd,visits):
  tags={'base':'base','base+copy':'base','fixed':'fixed','fixed+copy':'fixed'}
  def run(t,n):return list(map(int,sp.check_output(['setarch',os.uname().machine,'-R',*cmd(tags[t],n)],text=True).split()))
  warm={t:run(t,1)for t in tags};assert all(x[2:-1]==warm['base'][2:-1]for x in warm.values())
  n=max(1,math.ceil(15e6/min(v[0]for v in warm.values())));checks={t:run(t,n)[2:]for t in tags}
  assert checks['fixed']==checks['fixed+copy'] and checks['base']==checks['base+copy']
  rng=random.Random('segments/'+name);order=list(tags);blocks=[]
  for _ in range(visits):
   rng.shuffle(order);b={}
   for t in order+order[::-1]:
    v=run(t,n);assert v[2:]==checks[t];row=b.setdefault(t,[0,0]);row[0]+=v[0];row[1]+=v[1]
   blocks.append(b)
  return dict(n=n,checks=checks,blocks=blocks)
 timing={};records={}
 for key,case in cases.items():
  mode,blob,ext,bits=case;name=key.split('/')[0]
  if mode==0:
   records[name]={}
   for route in ('public','fixed'):
    lines=[list(map(int,x.split()))for x in sp.check_output([w/('records-'+route),w/'base.so',w/'fixed.so',blob,ext,str(bits)],text=True).splitlines()]
    assert len(lines)==8 and all(z==lines[4]for z in lines[4:]);records[name][route]=dict(corrections=lines[:4],counts=lines[4]);save('string-records',records)
  if name not in ('putty-32-0.85','libmvec-amd64','libssl3t64-i386'):continue
  for route in ('private','capstone'):
   args=lambda t,n:[w/('x86-'+t),route,str(mode),str(n),blob,ext,str(bits)]
   freq=35 if name in ('libmvec-amd64','putty-32-0.85','jpeg-avx2-i386')else 17
   row=measure(route+'/'+key,args,freq)
   if mode!=2:assert row['checks']['base']==row['checks']['fixed']
   if row['checks']['base']!=row['checks']['fixed']:
    assert any(records[name]['fixed'if route=='private'else'public']['corrections'][1][:2])
   timing['natural/'+route+'/'+key]=row
   frozen=lambda t,n:[w/('x86-frozen-'+t),route,str(mode),str(n),blob,ext,str(bits)]
   ctrl=measure(route+'/'+key,frozen,freq)
   for t in ('base','fixed'):assert list(map(int,sp.check_output(frozen(t,1),text=True).split()))[2:]==list(map(int,sp.check_output(args(t,1),text=True).split()))[2:]
   timing['fixed-address/'+route+'/'+key]=ctrl;save('timings',timing)
 for f in foreign:
  for mode in (0,1,2):
   name='foreign/'+f['name']+'/'+str(mode);args=lambda t,n:[w/('foreign-'+t),f['arch'],w/(f['name']+'.text'),str(mode),str(n)]
   row=measure(name,args,17);assert row['checks']['base']==row['checks']['fixed']
   timing['natural/'+name]=row
   frozen=lambda t,n:[w/('foreign-frozen-'+t),f['arch'],w/(f['name']+'.text'),str(mode),str(n)]
   ctrl=measure(name,frozen,17);assert ctrl['checks']['base']==ctrl['checks']['fixed']
   assert list(map(int,sp.check_output(frozen('base',1),text=True).split()))[2:]==list(map(int,sp.check_output(args('base',1),text=True).split()))[2:]
   timing['fixed-address/'+name]=ctrl;save('timings',timing)
 assert len(timing)==66
