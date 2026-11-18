from pathlib import Path
import gzip,hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-arm-lazy-predicate-descriptor-') as tmp:
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
  choices={'arm-ls','arm-sort','arm-cp'} | ({'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','amd64-ls','scalar32','scalar64','simd64'} if mixed else set())
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17',*(['-DCAPSTONE_PERF_ARM_ONLY'] if not mixed else []),'-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  consumer_symbols=sp.check_output(['nm','-u',t/'single.o'],text=True)
  if not mixed:assert 'X86_disasmIter' not in consumer_symbols
  write('consumer-scope',dict(arm_only=not mixed,source_sha256=sha(r/'single.cpp'),x86_iterator_reference='X86_disasmIter' in consumer_symbols))
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in (['X86','MIPS','AARCH64','PPC','RISCV','LOONGARCH','ARC','TRICORE'] if os.environ['BUILD_ARCHS']=='extra' else ['X86','MIPS','AARCH64'])] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={};ownedlibs={}
  active=mixed
  write('scope',dict(active=active,policy='Demand-driven ARM predicate descriptor lookup',inactive_requirement='All runtime objects and linked consumer must be byte-identical'))
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','scan'):
   variant=r/('baseline.patch' if key=='base' else key+'.patch')
   if key!='base':
    run(['git','apply',variant],'apply-'+key,s)
    run(['git','add','-A'],'stage-tested-source',s)
    tested=sp.check_output(['git','write-tree'],cwd=s,text=True).strip()
    assert tested==json.loads((r/'candidate.json').read_text())['tree'],tested
    write('tested-source',dict(tree=tested,patch_sha256=sha(variant)))
    run(['git','reset','-q'],'unstage-tested-source',s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'],'build-'+key)
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',f]))
   (e/(key+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',f]))
   objdir=b/'CMakeFiles/capstone.dir'
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o')}
   if active:
    with gzip.open(e/(key+'-cs-object-assembly.gz'),'wb') as stream:stream.write(sp.check_output(['objdump','-dr',objdir/'cs.c.o']))
    with gzip.open(e/(key+'-linked-assembly.gz'),'wb') as stream:stream.write(sp.check_output(['objdump','-dr',f]))
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':
    run(['cmake','--build',b,'--target','arm_private_stream','arm_post_index','mapping','mcinst','x86_simple_output','--parallel','4'],'callback-build')
    run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_(arm_private_stream|arm_post_index|mapping|mcinst|x86_simple_output)$'],'callback-contract')
    if active:
     run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-arm.cpp','-ldl','-o',t/'verify-arm'],'records-link')
     run([t/'verify-arm',libs['base'],libs['scan']],'records')
     run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-aarch64.cpp','-ldl','-o',t/'verify-aarch64'],'records-aarch64-link')
     run([t/'verify-aarch64',libs['base'],libs['scan']],'records-aarch64')
    run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('scan',):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert not added,added
   expected={'arch/ARM/ARMDisassembler.c.o'} if active else set()
   assert set(changed)==expected,(key,changed,expected)
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==(2 if active else 1);write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,active=False,identical_binary=True));raise SystemExit(0)
  payloads={key:path.read_bytes()for key,path in bins.items()}
  assert payloads['base']==payloads['aa']
  maximum=max(map(len,payloads.values()));padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
  image=t/'same-image';image.write_bytes(padded['base']);image.chmod(0o755);inode=image.stat().st_ino
  probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
  launches=['images']
  if probe.returncode==0:launches.append('same-file-fixed')
  write('launch-controls',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,inode=inode,fixed_size=maximum,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},semantic_qualification='Demand-driven ARM predicate descriptor lookup; preserve complete records, original images and controlled-image timing panels.'))
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def sample(key,x,mode,reps,launch):
   tail=list(map(str,[x['selector'],mode,x['path'],reps]))
   if launch=='images':args=[str(bins[key]),*tail]
   else:
    with image.open('r+b')as stream:assert stream.write(padded[key])==maximum
    assert image.stat().st_ino==inode and image.stat().st_size==maximum
    args=['setarch',platform.machine(),'-R',str(image),*tail]
   return json.loads(sp.check_output(args,text=True))
  from mixed_cost import cost_probe
  cost_probe(bins,cases,t,e,run)
  protocol=json.loads((e/'cost-protocol.json').read_text())
  gate=dict(available=protocol['available'],passive_counts_not_increased=None,rows=[])
  if protocol['available']:
   costs=json.loads((e/'instruction-costs.json').read_text())
   for case,mode in sorted({(x['case'],x['mode']) for x in costs if x['case']!='arm-ls'}):
    pair={x['variant']:x for x in costs if (x['case'],x['mode'])==(case,mode)}
    gate['rows'].append(dict(case=case,mode=mode,ir_delta=pair['scan']['events']['Ir']-pair['base']['events']['Ir']))
   gate['passive_counts_not_increased']=all(x['ir_delta']<=0 for x in gate['rows'])
  write('codegen-gate',gate)
  gate['native_timing_policy']='Screen all real and synthetic cases; event counts diagnose admission and lowering, native timing decides benefit.'
  write('codegen-gate',gate)
  data=[]
  for x in cases:
   for mode in (0,1,2):
    for launch in launches:
     warm=sample('base',x,mode,2,launch);n=max(2,min(4000,round(2*40e6/warm['cpu_ns'])))
     runs=[];reference=None;keys=['base','aa','scan']
     for k in range(21):
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
