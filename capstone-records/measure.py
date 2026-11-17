from pathlib import Path
import hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
import gzip
from layout import object_proof, linked_layout
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
protocol=json.loads((r/'image-protocol.json').read_text());focus=protocol['focus'];replica=int(os.environ['REPLICA'])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-evex-image-identity-') as tmp:
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
  if json.loads((e/'cpu.json').read_text())['model'] != protocol['requested_cpu']:
   write('complete',dict(selected=False,cases=0,reason='Requested original CPU model unavailable',protocol=protocol))
   raise SystemExit(0)
  mixed=os.environ['BUILD_ARCHS']=='four';assert mixed
  all_inputs=corpus.prepare(r,t,e,run)
  choices={'arm-ls','arm-sort','arm-cp'} | ({'putty-32-0.85','putty-64-0.85','arm64-ls','mips64el-ls','amd64-ls'} if mixed else set())
  cases=[x for x in all_inputs if x['name'] in choices];assert len(cases)==len(choices)

  run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON',*(['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON'] if mixed else []),'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
  bins={};objects={};libs={};ownedlibs={}
  write('compiler',dict(compiler=sp.check_output([cc,'--version'],text=True)))
  libname='libcapstone.dylib' if platform.system()=='Darwin' else 'libcapstone.so'
  for key in ('base','merge'):
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
   with gzip.open(e/(key+'-linked-disassembly.gz'),'wb')as out:out.write(sp.check_output(['objdump','-d',f]))
   objdir=b/'CMakeFiles/capstone.dir'
   members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines();assert len(set(members))==len(members)
   objects[key]={str(v.relative_to(objdir)):sha(v) for v in objdir.rglob('*.o') if v.name in members};assert len(objects[key])==len(members)
   if key=='base':shutil.copyfile(objdir/'arch/X86/X86EvexScan.c.o',t/'baseline-plan.o')
   if key!='base':
    write(key+'-object-proof',object_proof(key,t/'baseline-plan.o',objdir/'arch/X86/X86EvexScan.c.o',objdir/'arch/X86/X86EvexTransferScan.c.o'))
    write(key+'-linked-layout',linked_layout(e/'base-symbols.txt',e/(key+'-symbols.txt'),key))
   libs[key]=t/(key+'-'+libname);shutil.copy2(b/libname,libs[key])
   if key!='base':run(['git','apply','-R',variant],'restore-'+key,s)
  for key in ('merge',):
   changed=[k for k,h in objects['base'].items()if objects[key].get(k)!=h]
   added=set(objects[key])-set(objects['base'])
   assert added==({'arch/X86/X86EvexTransferScan.c.o'} if key=='scan' else set()),added
   assert set(objects['base']) <= set(objects[key])
   assert set(changed) == {'arch/X86/X86EvexScan.c.o'},changed
   active=bool(changed)
   write('scope',dict(active=active,source_applies=True,policy='Two predeclared canonical EVEX transfer implementations; all unmodified runtime objects and instruction semantics are preserved, while data relocation is recorded and measured; identical lowering is retained as an object and binary identity control'))
   write('objects-'+key,dict(changed=changed,added=sorted(added),identical=len(objects['base'])-len(changed)))
  bins['aa']=t/'aa';shutil.copy2(bins['base'],bins['aa']);digests={k:sha(v)for k,v in bins.items()};assert len(set(digests.values()))==2;write('binaries',digests)
  if not active:
   write('complete',dict(cc=cc,host=platform.platform(),cases=0,active=False,identical_binary=True));raise SystemExit(0)
  payloads={key:path.read_bytes()for key,path in bins.items()}
  assert payloads['base']==payloads['aa']
  maximum=max(map(len,payloads.values()));padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
  image=t/'slot_';image.write_bytes(payloads['base']);image.chmod(0o755);inode=image.stat().st_ino
  aliases={}
  for key,path in bins.items():
   alias=t/key.ljust(5,'_')
   if alias!=path:os.link(path,alias)
   aliases[key]=alias
   assert alias.stat().st_ino==path.stat().st_ino
  assert len({len(str(path))for path in aliases.values()}|{len(str(image))})==1
  probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
  assert probe.returncode==0
  launches=[family+'-'+aslr for family in protocol['image_controls']for aslr in protocol['aslr_controls']]
  rotate=(replica-1)*2;launches=launches[rotate:]+launches[:rotate]
  if replica%2==0:launches=launches[::-1]
  identities={key:dict(original=str(path),alias=str(aliases[key]),inode=path.stat().st_ino,size=len(payloads[key]))for key,path in bins.items()}
  write('launch-controls',dict(launches=launches,aslr_disable_returncode=probe.returncode,identities=identities,shared_path=str(image),shared_inode=inode,padded_size=maximum,replica=replica,original_sha256={key:hashlib.sha256(v).hexdigest()for key,v in payloads.items()},protocol=protocol))
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  prepared_launch=None
  def materialize(path,content):
   before=path.stat().st_ino
   with path.open('r+b')as stream:
    assert stream.write(content)==len(content)
    stream.truncate(len(content))
   assert path.stat().st_ino==before and path.stat().st_size==len(content)
  def prepare_launch(launch):
   global prepared_launch
   if prepared_launch==launch:return
   family=launch.rsplit('-',1)[0]
   for key,path in bins.items():
    materialize(path,padded[key]if family=='equal-padded'else payloads[key])
    assert path.read_bytes()==(padded[key]if family=='equal-padded'else payloads[key])
   prepared_launch=launch
  def selected_image(key,launch):
   family=launch.rsplit('-',1)[0]
   prepare_launch(launch)
   if family=='images':return bins[key]
   if family in ('equal-names','equal-padded'):return aliases[key]
   assert family in ('shared-variable','shared-padded')
   materialize(image,padded[key]if family=='shared-padded'else payloads[key])
   assert image.stat().st_ino==inode
   return image
  def sample(key,x,mode,reps,launch):
   target=selected_image(key,launch)
   args=[str(target),*map(str,[x['selector'],mode,x['path'],reps])]
   if launch.endswith('-fixed'):args=['setarch',platform.machine(),'-R',*args]
   return json.loads(sp.check_output(args,text=True))
  data=[]
  for x in cases:
   for mode in (0,1,2):
    if [x['name'],mode] not in focus:continue
    for launch in launches:
     warm=sample('base',x,mode,2,launch);n=max(2,min(4000,round(2*protocol['target_ms']*1e6/warm['cpu_ns'])))
     runs=[];reference=None;keys=['base','aa','merge']
     for k in range(protocol['cycles']):
      seq=keys[k%len(keys):]+keys[:k%len(keys)];ticks={v:[] for v in keys}
      for v in seq+seq[::-1]:
       vout=sample(v,x,mode,n,launch)
       if reference is None:reference=(vout['first'],vout['result'])
       assert reference==(vout['first'],vout['result'])
       ticks[v].append(vout['cpu_ns'])
      runs.append({v:sum(ticks['base'])/sum(ticks[v]) for v in keys})
     data.append(dict(case=x['name'],mode=mode,launch=launch,pairs=runs,median={v:st.median(c[v]for c in runs)for v in keys},result=reference));write('timings',data)
  prepare_launch('images-fixed')
  costs=[]
  for x in cases:
   for mode in (0,1,2):
    if [x['name'],mode] not in focus:continue
    signatures={}
    for label in ('base','merge'):
     ident=x['name']+'-'+str(mode)+'-'+label
     raw=t/(ident+'.callgrind')
     args=[bins[label],str(x['selector']),str(mode),x['path'],'1']
     run(['valgrind','--tool=callgrind','--demangle=no','--collect-atstart=no','--toggle-collect=_ZL3runR7SessionRKSt6vectorIhSaIhEEj','--dump-instr=yes','--collect-jumps=yes','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(raw),*args],'cost-'+ident)
     log=(e/('cost-'+ident+'.log')).read_text()
     result=json.loads(next(line for line in log.splitlines() if line.startswith('{')))
     signatures[label]=(result['first'],result['result'])
     assert signatures[label]==signatures['base']
     content=raw.read_text()
     events=next(line[8:].split()for line in content.splitlines()if line.startswith('events: '))
     counts=list(map(int,next(line[8:].split()for line in content.splitlines()if line.startswith('totals: '))))
     assert len(events)==len(counts) and counts[0]>0
     costs.append(dict(case=x['name'],mode=mode,variant=label,events=dict(zip(events,counts)),result=signatures[label],collected_traversals=3))
     with gzip.open(e/(ident+'.callgrind.gz'),'wb')as out:out.write(raw.read_bytes())
     raw.unlink()
     write('instruction-costs',costs)
  assert len(costs)==len(focus)*2

  assert len(data)==len(focus)*len(launches)
  x,= [x for x in cases if x['name']=='arm64-ls']
  debug=[]
  for family in protocol['image_controls']:
   for key in ('base','aa','merge'):
    target=selected_image(key,family+'-fixed')
    name='entry-'+family+'-'+key
    args=['gdb','-q','-nx','--batch','-ex','set pagination off','-ex','set startup-with-shell off','-ex','set disable-randomization on','-ex','break cs_disasm_iter','-ex','run','-ex','printf "ENTRY sp=%#lx insn=%#lx codeptr=%#lx sizeptr=%#lx\\n", (unsigned long)$rsp, (unsigned long)$r8, (unsigned long)$rsi, (unsigned long)$rdx','--args',str(target),str(x['selector']),'0',str(x['path']),'1']
    result=sp.run(args,stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
    (e/(name+'.log')).write_text(result.stdout)
    observed=re.findall(r'ENTRY sp=(0x[0-9a-f]+) insn=(0x[0-9a-f]+) codeptr=(0x[0-9a-f]+) sizeptr=(0x[0-9a-f]+)',result.stdout)
    debug.append(dict(family=family,variant=key,returncode=result.returncode,entries=[dict(zip(('sp','insn','codeptr','sizeptr'),v))for v in observed],timing=False))
  write('debug-entries',debug)

  write('complete',dict(selected=True,protocol=protocol,cases=len(data),cc=cc,host=platform.platform(),launches=launches,active=active,native_qualification=False))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
