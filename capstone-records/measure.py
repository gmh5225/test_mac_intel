from pathlib import Path
import hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-loongarch-rows-') as tmp:
 t=Path(tmp);b=t/'build'
 try:
  import re
  mapping=(s/'arch/LoongArch/LoongArchGenCSMappingInsn.inc').read_text()
  rows=re.findall(r'^\s*(LoongArch_[\w]+) /\* (\d+) \*/, (LOONGARCH_INS_[\w]+)',mapping,re.M)
  enums=dict(re.findall(r'^\s*(LoongArch_[\w]+)\s*=\s*(\d+)',(s/'arch/LoongArch/LoongArchGenInstrInfo.inc').read_text(),re.M))
  assert [int(row[1]) for row in rows]==list(range(2397)) and all(enums[name]==idx for name,idx,_ in rows)
  write('mapping',dict(rows=len(rows),sha256=hashlib.sha256(mapping.encode()).hexdigest()))
  mixed=os.environ['BUILD_ARCHS']=='four'
  all_inputs=corpus.prepare(r,t,e,run)
  choices={'loong64-ls','loong64-sort','loong64-cp'} | ({'putty-32-0.85','putty-64-0.85','arm64-ls','arm-ls','amd64-ls'} if mixed else set())
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_LOONGARCH_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={}
  active=platform.system()=='Linux' and platform.machine()=='aarch64'
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','indexed'):
   if key!='base':run(['git','apply',r/(key+'.patch')],'apply-'+key,s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'],'build-'+key)
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   objdir=b/'CMakeFiles/capstone.dir'
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o')}
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':
    run(['cmake','--build',b,'--target','mapping','--parallel','4'],'build-test-'+key)
    run(['ctest','--test-dir',b,'-R','^unit_mapping$','--no-tests=error','--output-on-failure'],'owner-test-'+key)
   if key!='base':run(['git','apply','-R',r/(key+'.patch')],'restore-'+key,s)
  (t/'loongarch.bin').write_bytes(b''.join(Path(q['path']).read_bytes()for q in cases if q['name'].startswith('loong64-')))
  run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-loongarch.cpp',*(['-ldl'] if platform.system()=='Linux' else []),'-o',t/'verify'],'build-differential')
  for key in ('indexed',):
   changed=[k for k,h in objects['base'].items() if objects[key][k]!=h]
   assert changed==['arch/LoongArch/LoongArchMapping.c.o'],changed
   write('objects-'+key,dict(changed=changed,identical=len(objects['base'])-len(changed)))
   run([t/'verify',libs['base'],libs[key],16384,t],'differential-'+key)
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==2;write('binaries',digests)
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def sample(key,x,mode,reps):
   return json.loads(sp.check_output(list(map(str,[bins[key],x['selector'],mode,x['path'],reps])),text=True))
  data=[]
  for x in cases:
   for mode in (0,1,2):
    warm=sample('base',x,mode,2);n=max(2,min(4000,round(2*160e6/warm['cpu_ns'])))
    runs=[];reference=None;keys=['base','indexed','aa']
    for k in range(19):
     seq=keys[k%len(keys):]+keys[:k%len(keys)];ticks={v:[] for v in keys}
     for v in seq+seq[::-1]:
      vout=sample(v,x,mode,n)
      if reference is None:reference=(vout['first'],vout['result'])
      assert reference==(vout['first'],vout['result'])
      ticks[v].append(vout['cpu_ns'])
     runs.append({v:sum(ticks['base'])/sum(ticks[v]) for v in keys})
    data.append(dict(case=x['name'],mode=mode,pairs=runs,median={v:st.median(c[v]for c in runs)for v in keys},result=reference));write('timings',data)
  write('complete',dict(cases=len(data),cc=cc,host=platform.platform()))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
