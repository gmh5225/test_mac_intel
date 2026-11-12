from pathlib import Path
import hashlib,json,os,random,shutil,statistics,subprocess as sp,sys,tempfile
import corpus
r=Path(__file__).resolve().parent;root=r.parent;nd=root/'neverd';out=root/'product-evidence';out.mkdir(exist_ok=True)
def write(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
 print(label,flush=True)
 with (out/(label+'.log')).open('w') as log:rv=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT).returncode
 if rv:print((out/(label+'.log')).read_text(errors='replace')[-4000:],flush=True);raise RuntimeError(label)
def rev(d):return sp.check_output(['git','-C',d,'rev-parse','HEAD'],text=True).strip()
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project'
expected=json.loads((r/'inputs.json').read_text())
assert rev(nd)==expected['neverd'] and rev(cs)==expected['capstone']
write('sources',dict(neverd=rev(nd),capstone=rev(cs),llvm_fork=rev(ll),llvm_source=str(ll)))
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
 t=Path(temp);build=t/'build'
 try:
  cases=corpus.prepare(r,t,out,command)
  cases=[v for v in cases if v['name'] in ('putty-32-0.85','putty-64-0.85','amd64-ls','arm64-ls','scalar32','simd64','arm-cp','mips64el-ls','arm64-sort')]
  assert len(cases)==9
  shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp');cm=nd/'CMakeLists.txt'
  cm.write_text(cm.read_text()+'\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'route.cpp',nd/'capstone-route.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-route capstone-route.cpp)\ntarget_link_libraries(capstone-route PRIVATE NeverDDecode)\n')
  command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld','-DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=OFF','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
  assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in (build/'CMakeCache.txt').read_text()
  products={}
  import struct,collections
  def compare(left,right,label):
   with left.open('rb') as a,right.open('rb')as b:
    fmt=struct.Struct('=9I');head=a.read(fmt.size);assert head==b.read(fmt.size);layout=fmt.unpack(head);result={};counts=collections.Counter();samples=0
    length=32+layout[0]+layout[1]
    while True:
     x=a.read(length);y=b.read(length);assert len(x)==len(y)
     if not x:break
     assert len(x)==length
     samples+=1
     if x==y:continue
     ctx=struct.unpack('=8I',x[:32]);which=(ctx[0],ctx[4],ctx[1]);counts[which]+=1
     if which not in result:
      diffs=[(i-32,x[i],y[i])for i in range(length)if x[i]!=y[i]]
      result[which]=dict(context=ctx,number=len(diffs),ranges=diffs[:160])
    write('record-difference-'+label,dict(layout=layout,states=samples,changed=sum(counts.values()),classes=[dict(count=counts[k],**v)for k,v in result.items()]))
  for label in ('base','direct','forward','arch'):
   if label!='base':
    command(['git','apply',r/(label+'.patch')],'select-'+label,nd)
   command([sys.executable,nd/'scripts/build.py',build,'--target','capstone-product','capstone-route','--parallel','4'],'product-'+label,nd)
   tool=next(build.rglob('capstone-route'));trace=t/(label+'.trace')
   signature=sp.check_output([tool,trace],text=True).strip();write(label+'-public-state',signature)
   if label=='base':
    rep=t/'repeat.trace';again=sp.check_output([tool,rep],text=True).strip();write('base-repeat-state',again);compare(trace,rep,'base-repeat');rep.unlink()
   else:
    compare(t/'base.trace',trace,label);trace.unlink()
   bins=list(build.rglob('capstone-product'));assert len(bins)==1,bins
   prod=t/label;shutil.copy2(bins[0],prod);products[label]=prod
   deps=sp.check_output(['ldd',prod],text=True);(out/(label+'-linked.txt')).write_text(deps)
   assert not any(key in deps for key in ('libcapstone','libneverd','libNeverD','not found')),deps
   if label!='base':
    command(['git','apply','-R',r/(label+'.patch')],'restore-client-'+label,nd)
   snapshot=json.loads((build/'.neverd-deps/snapshot.json').read_text())
   write(label+'-snapshot',snapshot)
   roots=list(build.rglob('CMakeFiles/capstone.dir')); assert len(roots)==1,roots
   objects={str(f.relative_to(roots[0])):hashlib.sha256(f.read_bytes()).hexdigest() for f in roots[0].rglob('*.o')};write(label+'-objects',objects)
   if label!='base':
    base_objects=json.loads((out/'base-objects.json').read_text());assert objects==base_objects
   source_receipt=build/'neverd-dependency-inputs.json'
   if source_receipt.exists():shutil.copyfile(source_receipt,out/(label+'-dependencies.json'))
  identities={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in products.items()}
  write('products',identities);assert len(set(identities.values()))==4
  products['base-copy']=t/'base-copy';shutil.copy2(products['base'],products['base-copy'])
  os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def measure(name,case,mode,reps):
   sel=case['selector'] if case['selector'] in (32,64) else {0:'arm64',1:'arm',4:'mips64el'}[case['selector']]
   ticks,*signature=map(int,sp.check_output(list(map(str,[products[name],case['path'],sel,mode,reps])),text=True).split())
   assert ticks>0 and signature[0]>0
   return ticks,signature
  results=[]
  for case in cases:
   for mode in (0,1,2):
    cases_of_interest={'arm-cp':(0,1,2),'arm64-ls':(0,2),'arm64-sort':(0,),'mips64el-ls':(0,1),'putty-32-0.85':(0,1,2),'simd64':(2,)}
    if mode not in cases_of_interest.get(case['name'],()):continue
    # A long full text and a tiny compiler fixture have very different costs.
    start,_=measure('base',case,mode,1);reps=max(1,min(20000,round(230000/start)))
    row=dict(case=case['name'],mode=mode,reps=reps,pairs={});oracle=None
    for idx,label in enumerate(('base-copy','direct','forward','arch')):
     plans=[]
     for cycle in range(13):
      order=('base',label,label,'base') if (cycle+idx)%2==0 else (label,'base','base',label)
      times={'base':[],label:[]}
      for who in order:
       ticks,sig=measure(who,case,mode,reps);times[who].append(ticks)
       if oracle is None:oracle=sig
       assert oracle==sig,(case['name'],mode,who,oracle,sig)
      plans.append(dict(ticks=times,gain=sum(times['base'])/sum(times[label])))
     row['pairs'][label]=dict(plans=plans,median=statistics.median(q['gain'] for q in plans))
    row['signature']=oracle;results.append(row);write('timings',results)
  assert len(results)==12;write('complete',dict(cases=len(results),entrypoints=['Decoder::decodeOneLight','Decoder::decodeOne']))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
