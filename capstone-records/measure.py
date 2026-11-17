from pathlib import Path
import hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
from layout import object_proof, linked_layout
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-evex-prechecked-dispatch-mixed-') as tmp:
 t=Path(tmp);b=t/'build'
 try:
  import re
  mapping=(s/'arch/ARM/ARMGenCSMappingInsn.inc').read_text()
  rows=re.findall(r'^\s*(ARM_[\w]+) /\* (\d+) \*/, (ARM_INS_[\w]+)',mapping,re.M)
  enums=dict(re.findall(r'^\s*(ARM_[\w]+)\s*=\s*(\d+)',(s/'arch/ARM/ARMGenInstrInfo.inc').read_text(),re.M))
  assert [int(row[1]) for row in rows]==list(range(4465)) and all(enums[name]==idx for name,idx,_ in rows)
  write('mapping',dict(rows=len(rows),sha256=hashlib.sha256(mapping.encode()).hexdigest()))
  if Path('/proc/cpuinfo').exists():
   write('cpu',{'model':next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith(('model name','CPU part')))})
  mixed=os.environ['BUILD_ARCHS']=='four';assert mixed
  all_inputs=corpus.prepare(r,t,e,run)
  choices={'arm-ls','arm-sort','arm-cp'} | ({'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','amd64-ls'} if mixed else set())
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={};ownedlibs={}
  write('compiler',dict(compiler=sp.check_output([cc,'--version'],text=True)))
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','output'):
   variant=r/(key+'.patch')
   if key!='base':
    run(['git','apply',variant],'apply-'+key,s)
    run(['git','add','-A'],'stage-tested-source',s)
    tested=sp.check_output(['git','write-tree'],cwd=s,text=True).strip()
    assert tested==json.loads((r/'inputs.json').read_text())['variants'][key]['tree'],tested
    write(key+'-tested-source',dict(tree=tested,patch_sha256=sha(variant)))
    run(['git','reset','-q'],'unstage-tested-source',s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'],'build-'+key)
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',f]))
   (e/(key+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',f]))
   objdir=b/'CMakeFiles/capstone.dir'
   members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines();assert len(set(members))==len(members)
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o') if v.name in members};assert len(objects[key])==len(members)
   if key=='base':shutil.copyfile(objdir/'arch/X86/X86VectorOutput.c.o',t/'baseline-plan.o')
   if key!='base':
    write(key+'-object-proof',object_proof(key,t/'baseline-plan.o',objdir/'arch/X86/X86VectorOutput.c.o',objdir/'arch/X86/X86EvexMemoryOutput.c.o'))
    write(key+'-linked-layout',linked_layout(e/'base-symbols.txt',e/(key+'-symbols.txt'),key))
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('output',):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert added=={'arch/X86/X86EvexMemoryOutput.c.o'},added
   assert set(objects['base']) <= set(objects[key])
   assert set(changed) == {'arch/X86/X86VectorOutput.c.o'},changed
   active=bool(changed)
   write('scope',dict(active=active,source_applies=True,policy='Prechecked memory dispatch; all unmodified runtime objects are preserved and every symbol relocation is recorded for native comparison; identical lowering is retained as an object and binary identity control'))
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==2;write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,active=False,identical_binary=True));raise SystemExit(0)
  payloads={key:path.read_bytes()for key,path in bins.items()}
  assert payloads['base']==payloads['aa']
  maximum=max(map(len,payloads.values()));padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
  image=t/'same-image';image.write_bytes(padded['base']);image.chmod(0o755);inode=image.stat().st_ino
  probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
  launches=['images']
  if probe.returncode==0:launches.append('same-file-fixed')
  write('launch-controls',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,inode=inode,fixed_size=maximum,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},semantic_qualification='Prechecked memory dispatch; all unmodified runtime objects are preserved and every symbol relocation is recorded for native comparison; preserve complete records, original images and controlled-image timing panels.'))
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def sample(key,x,mode,reps,launch):
   tail=list(map(str,[x['selector'],mode,x['path'],reps]))
   if launch=='images':args=[str(bins[key]),*tail]
   else:
    with image.open('r+b')as stream:assert stream.write(padded[key])==maximum
    assert image.stat().st_ino==inode and image.stat().st_size==maximum
    args=['setarch',platform.machine(),'-R',str(image),*tail]
   return json.loads(sp.check_output(args,text=True))
  data=[]
  for x in cases:
   for mode in (0,1,2):
    for launch in launches:
     warm=sample('base',x,mode,2,launch);n=max(2,min(4000,round(2*80e6/warm['cpu_ns'])))
     runs=[];reference=None;keys=['base','aa','output']
     for k in range(32):
      seq=keys[k%len(keys):]+keys[:k%len(keys)];ticks={v:[] for v in keys}
      for v in seq+seq[::-1]:
       vout=sample(v,x,mode,n,launch)
       if reference is None:reference=(vout['first'],vout['result'])
       assert reference==(vout['first'],vout['result'])
       ticks[v].append(vout['cpu_ns'])
      runs.append({v:sum(ticks['base'])/sum(ticks[v]) for v in keys})
     data.append(dict(case=x['name'],mode=mode,launch=launch,pairs=runs,median={v:st.median(c[v]for c in runs)for v in keys},result=reference));write('timings',data)
  write('complete',dict(cases=len(data),cc=cc,host=platform.platform(),launches=launches,active=active,native_qualification=False))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
