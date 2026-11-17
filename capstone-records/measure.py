from pathlib import Path
import gzip,hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
from data_identity import section_proof
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-evex-extension-small-entry-mixed-') as tmp:
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
  for key in ('base','previous','data','scan'):
   variant=r/({'base':'baseline.patch','data':'data-control.patch'}.get(key,key+'.patch'))
   if key!='base':
    run(['git','apply',variant],'apply-'+key,s)
    run(['git','add','-A'],'stage-tested-source',s)
    tested=sp.check_output(['git','write-tree'],cwd=s,text=True).strip()
    assert tested==json.loads((r/({'previous':'previous.json','data':'data-control.json'}.get(key,'candidate.json'))).read_text())['tree'],tested
    write({'previous':'previous-source','data':'data-source'}.get(key,'tested-source'),dict(tree=tested,patch_sha256=sha(variant)))
    run(['git','reset','-q'],'unstage-tested-source',s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'],'build-'+key)
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',f]))
   (e/(key+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',f]))
   objdir=b/'CMakeFiles/capstone.dir'
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o')}
   if key=='previous':shutil.copyfile(objdir/'arch/X86/X86Mapping.c.o',t/'previous-mapping.o')
   if key=='data':write('data-identity',section_proof(t/'previous-mapping.o',objdir/'arch/X86/X86Mapping.c.o',objects['previous'],objects['data']))
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('previous','data','scan'):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert not added,added
   assert set(objects['base']) <= set(objects[key])
   assert set(changed) == ({'arch/X86/X86Mapping.c.o'} if key=='scan' else {'arch/X86/X86Mapping.c.o','arch/X86/X86Disassembler.c.o','arch/X86/X86DisassemblerDecoder.c.o'}),changed
   active=bool(changed)
   write('scope',dict(active=active,source_applies=True,policy='Small EVEX entry with separate selector and data placement controls; identical lowering is retained as an object and binary identity control'))
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==4;write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,active=False,identical_binary=True));raise SystemExit(0)
  payloads={key:path.read_bytes()for key,path in bins.items()}
  maximum=max(map(len,payloads.values()));padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
  image=t/'cost-image';image.write_bytes(padded['base']);image.chmod(0o755);inode=image.stat().st_ino
  probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True);assert probe.returncode==0
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  costs=[]
  targets=[('putty-32-0.85',0),('arm-ls',2),('mips64el-ls',1)]
  for name,mode in targets:
   x=next(v for v in cases if v['name']==name);reference=None
   for label in ('base','previous','data','scan'):
    with image.open('r+b')as stream:assert stream.write(padded[label])==maximum
    assert image.stat().st_ino==inode and image.stat().st_size==maximum
    raw=t/(name+'-'+label+'.callgrind');logname='cost-'+name+'-'+label
    run(['setarch',platform.machine(),'-R','valgrind','--tool=callgrind','--demangle=no','--collect-atstart=no',
         '--toggle-collect=_ZL3runR7SessionRKSt6vectorIhSaIhEEj','--cache-sim=yes','--branch-sim=yes',
         '--dump-instr=yes','--collect-jumps=yes','--callgrind-out-file='+str(raw),image,
         str(x['selector']),str(mode),x['path'],'1'],logname)
    value=json.loads(next(line for line in (e/(logname+'.log')).read_text().splitlines() if line.startswith('{')))
    result={k:value[k]for k in ('first','result')}
    if reference is None:reference=result
    else:assert result==reference,(name,label)
    content=raw.read_text();events=next(line[8:].split()for line in content.splitlines()if line.startswith('events: '))
    counts=list(map(int,next(line[8:].split()for line in content.splitlines()if line.startswith('totals: '))))
    assert len(events)==len(counts) and counts[0]>0
    costs.append(dict(case=name,mode=mode,variant=label,events=dict(zip(events,counts)),result=result,collected_traversals=2))
    with gzip.open(e/(name+'-'+label+'.callgrind.gz'),'wb')as stream:stream.write(raw.read_bytes())
    raw.unlink();write('instruction-costs',costs)
  assert len(costs)==12
  write('cost-protocol',dict(consumer_unchanged=True,symbol='_ZL3runR7SessionRKSt6vectorIhSaIhEEj',traversals=2,same_inode=True,padded_size=maximum,aslr_disabled=True,scope='Original warmed mixed consumer, one warm and one measured traversal. Counts and simulated cache events are separate from native timing.'))
  write('complete',dict(success=True,cases=len(costs),cc=cc,host=platform.platform(),active=True,native_qualification=False,cost_only=True))

 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
