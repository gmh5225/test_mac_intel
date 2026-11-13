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
  for key in ('base','indexed','shipping'):
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
  reference='base' if mixed else 'indexed'
  unequal=[k for k in objects[reference] if objects['shipping'][k]!=objects[reference][k]]
  assert objects['shipping']==objects[reference],(reference,unequal)
  assert sha(bins['shipping'])==sha(bins[reference]) and sha(libs['shipping'])==sha(libs[reference]),reference
  run([t/'verify',libs['base'],libs['shipping'],16384,t],'shipping-differential')
  if not mixed:
   diet=t/'diet'
   run(['cmake','-S',s,'-B',diet,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_LOONGARCH_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_DIET=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'diet-configure')
   for key in ('base','shipping'):
    if key=='shipping':run(['git','apply',r/'shipping.patch'],'diet-apply',s)
    run(['cmake','--build',diet,'--target','capstone_shared','--parallel','4'],'diet-build-'+key)
    shutil.copy2(diet/libname,t/('diet-'+key))
   run([t/'verify',t/'diet-base',t/'diet-shipping',16384,t],'diet-differential')
  write('complete',dict(compared=reference,objects=len(objects[reference]),binary=sha(bins['shipping']),library=sha(libs['shipping']),host=platform.platform(),cc=cc))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
