from pathlib import Path
import gzip,hashlib,json,os,platform,re,shutil,statistics,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as out:result=sp.run(list(map(str,args)),cwd=cwd,stdout=out,stderr=sp.STDOUT).returncode
 if result:raise RuntimeError((label,(e/(label+'.log')).read_text()[-2000:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
write('compiler',dict(cc=sp.check_output([cc,'--version'],text=True),clang=sp.check_output(['clang','--version'],text=True),host=platform.platform()))
write('cpu',dict(cpu=Path('/proc/cpuinfo').read_text()))
with tempfile.TemporaryDirectory(prefix='capstone-simd-work-') as tmp:
 t=Path(tmp);b=t/'build'
 try:
  run(['clang','-target','x86_64-unknown-linux-gnu','-O3','-ffreestanding','-mavx2','-mfma','-c',r/'simd.c','-o',t/'simd.o'],'fixture')
  fixture=corpus.elf_text((t/'simd.o').read_bytes());(t/'simd.text').write_bytes(fixture)
  write('fixture',dict(bytes=len(fixture),sha256=hashlib.sha256(fixture).hexdigest(),source_sha256=sha(r/'simd.c')))
  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={}
  for key in ('base','combined','shift','joined'):
   if key!='base':run(['git','apply',r/(key+'.patch')],'apply-'+key,s)
   run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+key)
   f=t/key;run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-Wl,-Map='+str(e/(key+'-link.map')),'-o',f],'link-'+key);bins[key]=f
   symbols=sp.check_output(['nm','-n','-S','--defined-only',f],text=True);(e/(key+'-symbols.txt')).write_text(symbols)
   sections=sp.check_output(['objdump','-h',f],text=True)
   section=next(line.split() for line in sections.splitlines() if len(line.split())>=7 and line.split()[1]=='.text')
   vma,offset=int(section[3],16),int(section[5],16);image=f.read_bytes();functions=[]
   for line in symbols.splitlines():
    fields=line.split()
    if len(fields)!=4 or fields[2] not in ('t','T'):continue
    address,size=int(fields[0],16),int(fields[1],16);data=image[offset+address-vma:offset+address-vma+size]
    assert len(data)==size
    functions.append(dict(name=fields[3],address=address,size=size,sha256=hashlib.sha256(data).hexdigest()))
   write(key+'-functions',functions)
   with gzip.open(e/(key+'-assembly.gz'),'wb') as out:out.write(sp.check_output(['objdump','-dr',f]))
   objdir=b/'CMakeFiles/capstone.dir';objects[key]={str(q.relative_to(objdir)):sha(q) for q in objdir.rglob('*.o')}
   if key=='joined':
    changed={name for name in objects[key] if objects[key][name]!=objects['combined'][name]}
    assert changed=={'arch/X86/X86OutputIterator.c.o','arch/X86/X86ImmediateOutput.c.o','arch/X86/X86VectorOutput.c.o'},changed
   if key!='base':run(['git','apply','-R',r/(key+'.patch')],'restore-'+key,s)
  write('objects',objects)
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa'])
  os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def sample(k,mode,reps):return json.loads(sp.check_output(list(map(str,[bins[k],64,mode,t/'simd.text',reps])),text=True))
  results=[]
  for mode in (0,1,2):
   warm=sample('base',mode,2);reps=max(2,min(4000,round(2*160e6/warm['cpu_ns'])));rows=[];reference=None;keys=list(bins)
   for cycle in range(21):
    order=keys[cycle%len(keys):]+keys[:cycle%len(keys)];ticks={k:[]for k in keys}
    for key in order+order[::-1]:
     measured=sample(key,mode,reps)
     if reference is None:reference=(measured['first'],measured['result'])
     assert reference==(measured['first'],measured['result'])
     ticks[key].append(measured['cpu_ns'])
    rows.append({k:sum(ticks['base'])/sum(ticks[k])for k in keys})
   results.append(dict(mode=mode,repeats=reps,pairs=rows,median={k:statistics.median(v[k]for v in rows)for k in keys},result=reference));write('timings',results)
  profiles=[]
  for mode in (0,1,2):
   for key in ('base','combined','shift','joined'):
    ident=str(mode)+'-'+key;raw=t/(ident+'.callgrind')
    run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--collect-atstart=no','--toggle-collect=capstone_measure_run','--callgrind-out-file='+str(raw),bins[key],64,mode,t/'simd.text',1],'profile-'+ident)
    payload=raw.read_bytes();lines=payload.decode().splitlines();events=next(v.split()[1:]for v in lines if v.startswith('events:'));totals=next(v.split()[1:]for v in lines if v.startswith('summary:'))
    counts=dict(zip(events,map(int,totals)));assert counts['Ir']>0
    profiles.append(dict(mode=mode,variant=key,counts=counts))
    for inclusive in ('yes','no'):
     (e/(ident+'-'+inclusive+'.txt')).write_bytes(sp.check_output(['callgrind_annotate','--inclusive='+inclusive,'--tree=both','--threshold=99.9','--auto=no',raw]))
    with gzip.open(e/(ident+'.callgrind.gz'),'wb') as out:out.write(payload)
    raw.unlink();write('dynamic-costs',profiles)
  write('complete',dict(variants=5,modes=3,fixture_sha256=hashlib.sha256(fixture).hexdigest()))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
