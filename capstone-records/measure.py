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
  choices={'arm-ls','arm-sort','arm-cp'} | ({'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','amd64-ls'} if mixed else set())
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={}
  active=platform.system()=='Linux' and platform.machine()=='aarch64'
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','indexed'):
   variant=r/('baseline.patch' if key=='base' else key+'.patch')
   if key!='base':run(['git','apply',variant],'apply-'+key,s)
   run(['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'],'build-'+key)
   link=t/'single';run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-Wl,-Map='+str(e/(key+'-link.map')),'-o',link],'link-'+key);f=t/key;link.rename(f);bins[key]=f
   whole=t/('ordered-'+key)
   members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines()
   paths={file.name:file for file in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
   assert len(members)==len(set(members)) and set(members)<=paths.keys()
   ordered=list(members)
   for prefix in ('ARM','AArch64','Mips'):
    group=[name for name in members if name.startswith(prefix)]
    if prefix=='ARM':
     sequence=['ARMModule.c.o','ARMMapping.c.o','ARMDisassembler.c.o','ARMDisassemblerExtension.c.o','ARMInstPrinter.c.o','ARMBaseInfo.c.o']
    elif prefix=='AArch64':
     sequence=['AArch64Module.c.o','AArch64Mapping.c.o','AArch64Disassembler.c.o','AArch64DisassemblerExtension.c.o','AArch64InstPrinter.c.o','AArch64BaseInfo.c.o']
    else:
     sequence=['MipsModule.c.o','MipsMapping.c.o','MipsDisassembler.c.o','MipsInstPrinter.c.o']
    assert set(group)==set(sequence)
    offset=min(ordered.index(name) for name in group)
    ordered=[name for name in ordered if name not in group]
    ordered[offset:offset]=sequence
   archive=t/('ordered-'+key+'.a')
   run(['ar','qc',archive,*[paths[name] for name in ordered]],'archive-'+key)
   run(['ranlib',archive],'archive-index-'+key)
   write('archive-'+key,dict(original=members,ordered=ordered))
   run(['clang++',t/'single.o',archive,'-lm','-Wl,-Map='+str(e/('ordered-'+key+'-link.map')),'-o',whole],'link-ordered-'+key)
   bins['ordered-'+key]=whole
   for layout,executable in ((key,f),('ordered-'+key,whole)):
    symbols=sp.check_output(['nm','-n','-S','--defined-only',executable],text=True)
    (e/(layout+'-symbols.txt')).write_text(symbols)
    sections=sp.check_output(['objdump','-h',executable],text=True)
    (e/(layout+'-sections.txt')).write_text(sections)
    section=next(line.split() for line in sections.splitlines() if len(line.split())>=7 and line.split()[1]=='.text')
    vma,offset=int(section[3],16),int(section[5],16)
    image=executable.read_bytes()
    functions=[]
    for line in symbols.splitlines():
     fields=line.split()
     if len(fields)!=4 or fields[2] not in ('t','T'):continue
     address,size=int(fields[0],16),int(fields[1],16)
     content=image[offset+address-vma:offset+address-vma+size]
     assert len(content)==size
     functions.append(dict(name=fields[3],address=address,size=size,sha256=hashlib.sha256(content).hexdigest()))
    write(layout+'-functions',functions)
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
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify.cpp',*(['-ldl'] if platform.system()=='Linux' else []),'-o',t/'verify'],'build-differential')
  for key in ('indexed',):
   changed=[k for k,h in objects['base'].items() if objects[key][k]!=h]
   active=True
   expected={'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o','arch/X86/X86ImmediateOutput.c.o'}
   assert {'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o'} <= set(changed) <= expected,(changed,expected)
   write('objects-'+key,dict(changed=changed,identical=len(objects['base'])-len(changed)))
   run([t/'verify',libs['base'],libs[key]],'differential-'+key)
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-x86.cpp','-ldl','-o',t/'verify-x86'],'build-x86-differential')
   run([t/'verify-x86',libs['base'],libs[key]],'x86-differential')
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-mips.cpp','-ldl','-o',t/'verify-mips'],'build-mips-differential')
   run([t/'verify-mips',libs['base'],libs[key]],'mips-differential')
   run(['clang++','-O2','-std=c++17','-I',s/'include',r/'verify-a64.cpp','-ldl','-o',t/'verify-a64'],'build-a64-differential')
   run([t/'verify-a64',libs['base'],libs[key]],'a64-differential')
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==(4 if active else 2);write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,identical_binary=True));raise SystemExit(0)
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  cases=[x for x in cases if x['name']in ('putty-32-0.85','arm64-ls','mips64el-ls')]
  def sample(key,x,mode,reps):
   return json.loads(sp.check_output(list(map(str,[bins[key],x['selector'],mode,x['path'],reps])),text=True))
  data=[]
  for x in cases:
   for mode in (0,1,2):
    warm=sample('base',x,mode,2);n=max(2,min(4000,round(2*160e6/warm['cpu_ns'])))
    runs=[];reference=None;keys=['base','indexed','ordered-base','ordered-indexed','aa']
    for k in range(21):
     seq=keys[k%len(keys):]+keys[:k%len(keys)];ticks={v:[] for v in keys}
     for v in seq+seq[::-1]:
      vout=sample(v,x,mode,n)
      if reference is None:reference=(vout['first'],vout['result'])
      assert reference==(vout['first'],vout['result'])
      ticks[v].append(vout['cpu_ns'])
     runs.append({v:sum(ticks['base'])/sum(ticks[v]) for v in keys})
     runs[-1]['ordered-gain']=sum(ticks['ordered-base'])/sum(ticks['ordered-indexed'])
    data.append(dict(case=x['name'],mode=mode,pairs=runs,median={v:st.median(c[v]for c in runs)for v in keys+['ordered-gain']},result=reference));write('timings',data)
  profiles=[]
  for x in cases:
   for mode in (0,1,2):
    if (x['name'],mode) not in (('mips64el-ls',0),('arm64-ls',1)):continue
    for key in ('base','indexed','ordered-base','ordered-indexed'):
     ident=x['name']+'-'+str(mode)+'-'+key
     raw=t/(ident+'.callgrind')
     run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes',
          '--collect-atstart=no','--toggle-collect=cs_disasm_iter',
          '--callgrind-out-file='+str(raw),bins[key],x['selector'],mode,x['path'],1],
          'profile-'+ident)
     payload=raw.read_text()
     lines=payload.splitlines()
     events=next(line.split()[1:] for line in lines if line.startswith('events:'))
     totals=next(line.split()[1:] for line in lines if line.startswith('summary:'))
     profiles.append(dict(case=x['name'],mode=mode,variant=key,counts=dict(zip(events,map(int,totals)))))
     for inclusive in ('yes','no'):
      report=sp.check_output(['callgrind_annotate','--inclusive='+inclusive,'--tree=both','--threshold=99.5','--auto=no',raw])
      (e/(ident+'-'+inclusive+'.txt')).write_bytes(report)
     with gzip.open(e/(ident+'.callgrind.gz'),'wb') as stream:stream.write(payload.encode())
     raw.unlink()
     write('dynamic-costs',profiles)
  write('complete',dict(cases=len(data),cc=cc,host=platform.platform()))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
