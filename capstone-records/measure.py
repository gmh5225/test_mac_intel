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
with tempfile.TemporaryDirectory(prefix='capstone-arm-branches-') as tmp:
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
  choices={'arm64-ls','arm64-sort','arm64-cp','putty-32-0.85','mips64el-ls'}
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
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
    run(['cmake','--build',b,'--target','arm_post_index','mips_scan','--parallel','4'],'build-test-'+key)
    target='arch/X86/X86VectorOutput.o'
    for archs,qualified in (('x86',True),('mips x86',True),('x86 arm mips aarch64',True),('arm x86',False),('mips arm x86',False),('mips aarch64 arm x86 riscv',False)):
     env={**os.environ,'CAPSTONE_ARCHS':archs,'CC':cc,'CXX':'g++' if cc=='gcc' else 'clang++','CAPSTONE_STATIC':'yes','CAPSTONE_SHARED':'no'}
     dry=sp.check_output(['make','-Bn',target],env=env,cwd=s,text=True)
     compile=next(line for line in dry.splitlines() if ' -c ' in line and 'X86VectorOutput.c' in line)
     assert ('-mstringop-strategy=libcall' in compile)==(qualified and cc=='gcc' and platform.machine()=='x86_64'),(archs,cc,compile)
     assert ('-DCAPSTONE_ARM_AARCH64_MIPS_X86' in compile)==(len(archs.split())==4)
    write('make-profiles',dict(architecture_sets=6,cc=cc,target=target))
    run(['ctest','--test-dir',b,'-R','^unit_(arm_post_index|mips_scan|aarch64_register_names_generator|arm_register_names_generator|fixed_len_decoder|fixed_len_decoder_newlines)$','--no-tests=error','--output-on-failure'],'owner-test-'+key)
    run(['cmake','--build',b,'--target','x86_simple_output','x86_scan_batch','x86_encoding_accuracy','detail_option','--parallel','4'],'x86-test-build')
    run(['ctest','--test-dir',b,'-R','^unit_(x86_simple_output|x86_scan_batch|x86_encoding_accuracy|detail_option)$','--no-tests=error','--output-on-failure'],'x86-tests')
   if key!='base':run(['git','apply','-R',r/(key+'.patch')],'restore-'+key,s)
  run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify.cpp',*(['-ldl'] if platform.system()=='Linux' else []),'-o',t/'verify'],'build-differential')
  for key in ('indexed',):
   changed=[k for k,h in objects['base'].items() if objects[key][k]!=h]
   active=cc=='gcc' and platform.machine()=='x86_64'
   expected={'arch/AArch64/AArch64Mapping.c.o','arch/ARM/ARMInstPrinter.c.o','arch/Mips/MipsDisassembler.c.o','arch/ARM/ARMMapping.c.o','arch/Mips/MipsMapping.c.o','arch/X86/X86DisassemblerDecoder.c.o',*('arch/X86/'+x+'.c.o' for x in ('X86ImmediateOutput','X86MemoryOutput','X86OutputIterator','X86VectorOutput'))} if active else set()
   assert set(changed)==expected,(changed,expected)
   write('objects-'+key,dict(changed=changed,identical=len(objects['base'])-len(changed)))
   run([t/'verify',libs['base'],libs[key]],'differential-'+key)
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-x86.cpp','-ldl','-o',t/'verify-x86'],'build-x86-differential')
   run([t/'verify-x86',libs['base'],libs[key]],'x86-differential')
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-mips.cpp','-ldl','-o',t/'verify-mips'],'build-mips-differential')
   run([t/'verify-mips',libs['base'],libs[key]],'mips-differential')
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-a64.cpp','-ldl','-o',t/'verify-a64'],'build-a64-differential')
   run([t/'verify-a64',libs['base'],libs[key]],'a64-differential')
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==(2 if active else 1);write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,identical_binary=True));raise SystemExit(0)
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def sample(key,x,mode,reps):
   return json.loads(sp.check_output(list(map(str,[bins[key],x['selector'],mode,x['path'],reps])),text=True))
  data=[]
  for x in cases:
   for mode in (0,1,2):
    warm=sample('base',x,mode,2);n=max(2,min(4000,round(2*210e6/warm['cpu_ns'])))
    runs=[];reference=None;keys=['base','indexed','aa']
    for k in range(25):
     seq=keys[k%len(keys):]+keys[:k%len(keys)];ticks={v:[] for v in keys}
     for v in ((seq+seq[::-1]) if (k//3)%2==0 else (seq[::-1]+seq)):
      vout=sample(v,x,mode,n)
      if reference is None:reference=(vout['first'],vout['result'])
      assert reference==(vout['first'],vout['result'])
      ticks[v].append(vout['cpu_ns'])
     runs.append({v:sum(ticks['base'])/sum(ticks[v]) for v in keys})
    data.append(dict(case=x['name'],mode=mode,pairs=runs,median={v:st.median(c[v]for c in runs)for v in keys},result=reference));write('timings',data)
  write('complete',dict(cases=len(data),cc=cc,host=platform.platform()))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
