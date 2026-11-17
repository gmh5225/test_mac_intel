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
with tempfile.TemporaryDirectory(prefix='capstone-evex-extension-isolated-entry-mixed-') as tmp:
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
  choices={'arm-ls','arm-sort','arm-cp','putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','amd64-ls'}
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)
  write('host',dict(platform=platform.platform(),machine=platform.machine(),cpu=sp.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip(),consumer_source_sha256=sha(r/'single.cpp')))
  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={};ownedlibs={}
  write('compiler',dict(compiler=sp.check_output([cc,'--version'],text=True)))
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','scan'):
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
   (e/(key+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n',f]))
   objdir=b/'CMakeFiles/capstone.dir'
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o')}
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('scan',):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert not added,added
   assert set(objects['base']) <= set(objects[key])
   assert set(changed) == {'arch/X86/X86Mapping.c.o'},changed
   active=bool(changed)
   write('scope',dict(active=active,source_applies=True,policy='Isolated EVEX entry with original section bytes and linked symbol positions verified; identical lowering is retained as an object and binary identity control'))
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==2;write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,active=False,identical_binary=True));raise SystemExit(0)
  write('layout-scope',dict(ELF_isolation=False,object_scope_verified=True,linked_positions_verified=False,launches=['images'],note='Darwin compilation and native performance guard; ELF section-placement proof does not apply.'))
  data=[]
  for x in cases:
   for mode in range(3):
    def sample(key,n):return json.loads(sp.check_output(list(map(str,[bins[key],x['selector'],mode,x['path'],n])),text=True))
    warm=sample('base',2);n=max(2,min(4000,round(2*80e6/warm['cpu_ns'])))
    pairs=[];reference=None;keys=['base','aa','scan']
    for cycle in range(24):
     order=keys[cycle%3:]+keys[:cycle%3];ticks={v:[] for v in keys}
     for key in order+order[::-1]:
      value=sample(key,n)
      signature=value['first'],value['result']
      if reference is None:reference=signature
      assert reference==signature
      ticks[key].append(value['cpu_ns'])
     pairs.append({key:sum(ticks['base'])/sum(ticks[key])for key in keys})
    data.append(dict(case=x['name'],mode=mode,launch='images',pairs=pairs,median={key:st.median(v[key]for v in pairs)for key in keys},result=reference))
    write('timings',data);print(x['name'],mode,data[-1]['median'],flush=True)
  assert len(data)==24
  write('complete',dict(success=True,cases=len(data),cc=cc,host=platform.platform(),active=True,macos_native_guard=True,source_unchanged=not sp.check_output(['git','-C',s,'status','--porcelain'])))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
