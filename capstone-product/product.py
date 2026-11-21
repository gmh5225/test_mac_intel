from pathlib import Path
import hashlib,json,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
import corpus
import avx_corpus
r=Path(__file__).resolve().parent;root=r.parent;nd=root/'neverd';out=root/'product-evidence';out.mkdir(exist_ok=True)
def write(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
 print(label,flush=True)
 with (out/(label+'.log')).open('w') as log:rv=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT).returncode
 if rv:print((out/(label+'.log')).read_text(errors='replace')[-4000:],flush=True);raise RuntimeError(label)
def rev(d):return sp.check_output(['git','-C',d,'rev-parse','HEAD'],text=True).strip()
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project'
cc=os.environ['CC']
assert cc == 'clang' and platform.machine()=='x86_64'
feature_active = True
write('scope',dict(active=feature_active,policy='Test the ordinary NeverD C++ Decoder entry on PE32, PE64, ELF scalar and vector data with the shipping static iterators. Measure scan, text, detail and batch using the production backend.'))
expected=json.loads((r/'inputs.json').read_text())
variants=expected['variants']
write('inputs',expected)
assert rev(nd)==expected['neverd'] and rev(cs)==expected['capstone']
write('sources',dict(neverd=rev(nd),capstone=rev(cs),llvm_fork=rev(ll),llvm_source=str(ll)))
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
 t=Path(temp);build=t/'build'
 try:
  write('llvm_source_build',dict(revision=rev(ll),compiler='clang++',prebuilt=False,unmodified_latest_fork=True))
  cases=corpus.prepare(r,t,out,command)
  cases=[v for v in cases if v['name'] in ('putty-32-0.85','putty-64-0.85','amd64-ls','arm64-ls','scalar32','scalar64','simd64','arm-cp','mips64el-ls','arm64-sort','arm64-cp','libjpeg-arm64','libssl3t64-amd64','libjpeg62-turbo-i386','libssl3t64-i386','libzstd1-i386')]
  assert len(cases)==16
  original_cases=list(cases)
  cases.append(avx_corpus.prepare(r,t,out,command))
  assert len(cases)==17
  shutil.copy(r/'libmvec.py',t);shutil.copy(r/'libmvec.json',t)
  command([sys.executable,t/'libmvec.py'],'glibc-vector-math')
  glibc=json.loads((t/'libmvec.json').read_text())
  cases.append(dict(name='libmvec-amd64',selector=64,path=str(t/'libmvec.text'),bytes=glibc['bytes'],text_sha256=glibc['text_sha256']))
  write('libmvec',glibc)
  shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp');cm=nd/'CMakeLists.txt'
  cm.write_text(cm.read_text()+'\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'original-probe.cpp',nd/'capstone-product-legacy.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-product-legacy capstone-product-legacy.cpp)\ntarget_link_libraries(capstone-product-legacy PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'route.cpp',nd/'capstone-route.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-route capstone-route.cpp)\ntarget_link_libraries(capstone-route PRIVATE NeverDDecode)\n')
  with cm.open('a') as f:f.write('target_link_options(capstone-product PRIVATE "LINKER:-Map,${CMAKE_BINARY_DIR}/capstone-product.map")'+chr(10))
  command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCMAKE_CXX_COMPILER=clang++','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
  assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in (build/'CMakeCache.txt').read_text()
  write('compiler',dict(c=sp.check_output([cc,'--version'],text=True).splitlines()[0],cxx=sp.check_output(['clang++','--version'],text=True).splitlines()[0],cpu=Path('/proc/cpuinfo').read_text(),host=platform.machine()))
  command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','--parallel','4'],'swift-demangle-from-source',nd)
  def llvm_identity():
   modified=sp.check_output(['git','-C',ll,'diff','--binary','HEAD'])
   untracked=sp.check_output(['git','-C',ll,'ls-files','--others','--exclude-standard','-z']).split(b'\0')
   extras={os.fsdecode(name):hashlib.sha256((ll/os.fsdecode(name)).read_bytes()).hexdigest() for name in untracked if name}
   return dict(revision=rev(ll),tracked_diff_sha256=hashlib.sha256(modified).hexdigest(),untracked=extras)
  llvm_reference=llvm_identity()
  write('llvm-baseline-identity',llvm_reference)
  products={};canonical_signatures={}
  import struct,collections
  def compare(left,right,label):
   with left.open('rb') as a,right.open('rb')as b:
    fmt=struct.Struct('=9I');head=a.read(fmt.size);assert head==b.read(fmt.size);layout=fmt.unpack(head);result={};counts=collections.Counter();samples=0
    length=32+layout[0]+layout[1]
    while True:
     x=a.read(length);y=b.read(length);assert len(x)==len(y)
     if not x:break
     assert len(x)==length
     samples+=1
     if x==y:continue
     ctx=struct.unpack('=8I',x[:32]);which=(ctx[0],ctx[4],ctx[1]);counts[which]+=1
     if which not in result:
      diffs=[(i-32,x[i],y[i])for i in range(length)if x[i]!=y[i]]
      result[which]=dict(context=ctx,number=len(diffs),ranges=diffs[:160])
    write('record-difference-'+label,dict(layout=layout,states=samples,changed=sum(counts.values()),classes=[dict(count=counts[k],**v)for k,v in result.items()]))
  for label in ['base',*variants]:
   ref=expected['capstone']
   assert rev(cs)==ref
   assert rev(nd)==expected['neverd']
   write(label+'-neverd-head',rev(nd))
   if label!='base':
    capfix=r/variants[label]['capstone_patch'];assert hashlib.sha256(capfix.read_bytes()).hexdigest()==variants[label]['capstone_sha256']
    if capfix.stat().st_size:command(['git','apply',capfix],'apply-capstone-'+label,cs)
   if 'patch' in variants.get(label,{}):
    change=r/variants[label]['patch']
    assert hashlib.sha256(change.read_bytes()).hexdigest()==variants[label]['patch_sha256']
    command(['git','apply',change],'apply-neverd-'+label,nd)
   policy=cm.read_text().split('\nadd_executable(capstone-product capstone-product.cpp)',1)[0]
   assert sp.check_output(['git','hash-object','--stdin'],input=policy.encode()).decode().strip()==(expected['build_blob'] if label=='base' else variants[label]['build_blob'])
   live={p:sp.check_output(['git','hash-object',nd/p],text=True).strip() for p in expected['base_blobs']}
   assert live==(expected['base_blobs'] if label=='base' else variants[label]['blobs'])
   write(label+'-decoder-source',dict(blobs=live,blob=live['lib/decode/Decoder.cpp']))
   targets=['capstone-product','capstone-route','NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests']
   if label=='base':targets.append('capstone-product-legacy')
   command([sys.executable,nd/'scripts/build.py',build,'--target',*targets,'--parallel','4'],'product-'+label,nd)
   import shlex
   compile_database=json.loads((build/'compile_commands.json').read_text())
   policies={}
   for name in ('X86OutputIterator.c','X86Vex32Output.c','X86Sse64Output.c'):
    entries=[c for c in compile_database if c['file'].endswith('/arch/X86/'+name)]
    entry,=entries
    args=shlex.split(entry['command'])
    policies[name]=[a for a in args if a in ('-fomit-frame-pointer','-O3','-DNDEBUG') or 'discard' in a]
   mips_command,=[c['command'] for c in compile_database if c['file'].endswith('/arch/Mips/MipsMapping.c')]
   alias_precheck='-DCAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS' in shlex.split(mips_command)
   assert alias_precheck
   selected={'CAPSTONE_MIPS_FINAL_OUTPUT_TRIM':'MipsInstPrinter.c','CAPSTONE_X86_NEAR_INDIRECT_OUTPUT':'X86Sse64Output.c'}
   flags={flag:[Path(c['file']).name for c in compile_database if '-D'+flag in shlex.split(c['command'])]for flag in selected}
   assert all(flags[k]==[v]for k,v in selected.items()),flags
   write(label+'-retained-options',flags)
   write(label+'-alias-compile-policy',dict(mips_precheck=alias_precheck))
   assert len(policies)==3
   for opts in policies.values():assert '-O3' in opts and '-DNDEBUG' in opts and '-fomit-frame-pointer' in opts
   assert all(v==policies['X86OutputIterator.c'] for v in policies.values())
   write(label+'-compile-policy',policies)
   import struct
   target=build/'lib/decode/CMakeFiles/NeverDDecode.dir/Decoder.cpp.o'
   obj=target.read_bytes();header=struct.unpack_from('<16sHHIQQQIHHHHHH',obj)
   assert obj[:6]==b'\x7fELF\x02\x01'
   secs=[struct.unpack_from('<IIQQQQIIQQ',obj,header[6]+j*header[11])for j in range(header[12])]
   st=secs[header[13]];names=obj[st[4]:st[4]+st[5]]
   text={}
   for no,ty,flags,addr,offset,size,*_ in secs:
    if flags&4:
     name=names[no:names.index(0,no)].decode()
     text[name]=dict(size=size,sha256=hashlib.sha256(obj[offset:offset+size]).hexdigest())
   rel=[line.strip() for line in sp.check_output(['readelf','-Wr',target],text=True).splitlines() if 'X86_disasmIter' in line]
   assert text and rel
   write(label+'-caller-object',dict(sections=text,iterator_relocations=rel))
   if label!='base':
    baseline=json.loads((out/'base-caller-object.json').read_text())
    assert text==baseline['sections']
    assert rel==baseline['iterator_relocations'] and all('X86_disasmIterText' in v for v in rel)

   llvm_current=llvm_identity();write(label+'-llvm-identity',llvm_current)
   assert llvm_current==llvm_reference,(label,'LLVM source changed during comparison',llvm_reference,llvm_current)
   command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',str(out/('tests-'+label+'.xml')),'-L','^(NeverDX86DecodeDetailTests|NeverDX86MpxEncodingTests|NeverDX86NoIndexAddressTests)$'],'tests-'+label)
   tool=next(build.rglob('capstone-route'))
   command([tool,'--xbegin'],'exhaustive-xbegin-'+label)
   command([tool,'--rendered-xbegin'],'rendered-xbegin-'+label)
   command(['objdump','-dC','--disassemble=neverd::Decoder::decodeOneLight(unsigned char const*, unsigned long, unsigned long, neverd::DecodedInsn&)',tool],'linked-light-'+label)
   command(['nm','-S','-C',tool],'symbols-'+label)
   trace=t/(label+'.trace')
   signature=sp.check_output([tool,trace],text=True).strip();write(label+'-public-state',signature)
   if label=='base':
    rep=t/'repeat.trace';again=sp.check_output([tool,rep],text=True).strip();write('base-repeat-state',again);compare(trace,rep,'base-repeat');rep.unlink()
   else:
    compare(t/'base.trace',trace,label);trace.unlink()
   bins=list(build.rglob('capstone-product'));assert len(bins)==1,bins
   prod=t/label;shutil.copy2(bins[0],prod);products[label]=prod
   if label=='base':
    legacy,=list(build.rglob('capstone-product-legacy'));checks=[]
    for case in cases:
     sel=case['selector'] if case['selector'] in (32,64) else {0:'arm64',1:'arm',4:'mips64el'}[case['selector']]
     for mode in (0,1,2):
      tail=list(map(str,[case['path'],sel,mode,1]))
      if 'intervals' in case:tail.append(case['intervals'])
      old=list(map(int,sp.check_output([legacy,*tail],text=True).split()))[1:]
      new=list(map(int,sp.check_output([prod,*tail],text=True).split()))[1:]
      assert old==new,(case['name'],mode,old,new)
      checks.append(dict(case=case['name'],mode=mode,signature=new))
    write('original-probe-equivalence',dict(checks=checks,unchanged=True))
    batch_checks=[]
    for case in cases:
     if case['selector'] not in (32,64):continue
     signatures={}
     for mode in (0,3):
      tail=list(map(str,[case['path'],case['selector'],mode,1]))
      if 'intervals' in case:tail.append(case['intervals'])
      signatures[mode]=list(map(int,sp.check_output([prod,*tail],text=True).split()))[1:]
     assert signatures[0]==signatures[3],(case['name'],signatures)
     batch_checks.append(dict(case=case['name'],signature=signatures[3]))
    write('batch-probe-equivalence',dict(checks=batch_checks,unchanged=True,capacity=64,fallback='Decoder::decodeOneLight'))

   signatures={}
   for case in cases:
    x86=case['selector'] in (32,64)
    sel=case['selector'] if x86 else {0:'arm64',1:'arm',4:'mips64el'}[case['selector']]
    for mode in range(4 if x86 else 3):
     tail=list(map(str,[case['path'],sel,mode,1]))
     if 'intervals' in case:tail.append(case['intervals'])
     raw=list(map(int,sp.check_output([prod,*tail],text=True).split()))[1:]
     key=case['name']+'/'+str(mode)
     signatures[key]=raw
     if label=='base':canonical_signatures[key]=raw
     assert canonical_signatures[key]==raw,(label,key,canonical_signatures[key],raw)
   write('public-checksums-'+label,dict(raw=signatures))
   command(['nm','-S','-C',prod],'timed-symbols-'+label)
   command(['readelf','-W','-S','-l',prod],'linked-sections-'+label)
   lines=(build/'capstone-product.map').read_text().splitlines()
   inclusions=[v for v in lines if 'libcapstone.a(' in v or ' X86_disasmIter' in v]
   assert inclusions and any('X86OutputIterator.c.o' in v for v in inclusions)
   (out/('capstone-link-map-'+label+'.log')).write_text(chr(10).join(inclusions)+chr(10))
   command_line=sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'],text=True).splitlines()[-1]
   assert '--undefined=X86_disasmIter' in command_line and '--undefined=X86_disasmIter32' in command_line
   write(label+'-link-options',dict(force_fallback='--undefined=X86_disasmIter' in command_line,linker_map=True,i386_first=True))
   deps=sp.check_output(['ldd',prod],text=True);(out/(label+'-linked.txt')).write_text(deps)
   assert not any(key in deps for key in ('libcapstone','libneverd','libNeverD','not found')),deps
   assert rev(cs)==ref
   snapshot=json.loads((build/'.neverd-deps/snapshot.json').read_text())
   write(label+'-snapshot',snapshot)
   identities={name:{key:value[key] for key in ('repository','branch','commit','sha256')} for name,value in snapshot['sources'].items()}
   write(label+'-managed-source-identity',identities)
   if label=='base':managed_reference=identities
   else:assert identities==managed_reference,(label,'Managed dependency source changed during comparison')
   roots=list(build.rglob('CMakeFiles/capstone.dir')); assert len(roots)==1,roots
   archives=list(build.rglob('libcapstone.a'));assert len(archives)==1,archives
   members=[name for name in sp.check_output(['ar','t',archives[0]],text=True).splitlines() if name not in ('__.SYMDEF','__.SYMDEF SORTED')]
   assert len(set(members))==len(members),members
   object_roots=[roots[0],roots[0].parent/'capstone_x86_iter32.dir',roots[0].parent/'capstone_x86_iter64.dir']
   disk={str(f.relative_to(parent)):f for parent in object_roots for f in parent.rglob('*.o')}
   assert sum(len(list(parent.rglob('*.o'))) for parent in object_roots)==len(disk)
   active={key:path for key,path in disk.items() if path.name in members}
   assert len(active)==len(members) and {path.name for path in active.values()}==set(members),(members,list(active))
   write(label+'-archive-members',dict(members=members,ignored_orphan_objects=sorted(set(disk)-set(active))))
   objects={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in active.items()};write(label+'-objects',objects)
   if label!='base':
    prior=json.loads((out/'base-objects.json').read_text())
    assert prior.keys()==objects.keys()
    assert {Path(k).name for k in prior if prior[k]!=objects[k]}==set(expected['changed_members'][label])
   assert len(objects)==42
   assert 'X86Vex32Output.c.o' in members
   sym=(out/('timed-symbols-'+label+'.log')).read_text().splitlines()
   assert any(line.endswith(' X86_disasmIter') for line in sym)
   assert any(line.endswith(' X86_disasmIter32') for line in sym)
   assert any(line.endswith(' X86_disasmIterText') for line in sym)
   source_receipt=build/'neverd-dependency-inputs.json'
   if source_receipt.exists():shutil.copyfile(source_receipt,out/(label+'-dependencies.json'))
   command(['git','add','-A'],'stage-receipt-'+label,cs)
   source_tree=sp.check_output(['git','write-tree'],cwd=cs,text=True).strip()
   write(label+'-source-tree',dict(tree=source_tree,parent=ref))
   if label!='base':
    assert source_tree==variants[label]['tree'],(label,source_tree,variants[label]['tree'])
   command(['git','reset','--hard',ref],'restore-'+label,cs)
   assert not sp.check_output(['git','status','--porcelain'],cwd=cs)
   if 'patch' in variants.get(label,{}):
    command(['git','apply','-R',r/variants[label]['patch']],'restore-neverd-'+label,nd)

  identities={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in products.items()}
  write('products',identities)
  if not feature_active:
   remaining={q.stem:json.loads(q.read_text())['changed']for q in out.glob('record-difference-*.json')};write('residual',remaining);assert not any(remaining.values()),remaining
   write('complete',dict(cases=0,active=False,identical_product=True,variants=list(variants),entrypoints=['Decoder::decodeOneLight','Decoder::decodeOne','Decoder::classifyX86Prefix']))
   raise SystemExit(0)
  products['base-copy']=t/'base-copy';shutil.copy2(products['base'],products['base-copy'])
  payloads={key:path.read_bytes() for key,path in products.items()}
  assert payloads['base']==payloads['base-copy']
  image=t/'same-image';maximum=max(map(len,payloads.values()))
  padded={key:value+bytes(maximum-len(value)) for key,value in payloads.items()}
  image.write_bytes(padded['base']);image.chmod(0o755);inode=image.stat().st_ino
  probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
  launches=['images','same-file-fixed']
  write('launch-controls',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,inode=inode,fixed_size=maximum,original_sha256={k:hashlib.sha256(v).hexdigest() for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest() for k,v in padded.items()}))
  assert probe.returncode==0,probe.stderr
  os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  def measure(name,case,mode,reps,launch):
   sel=case['selector'] if case['selector'] in (32,64) else {0:'arm64',1:'arm',4:'mips64el'}[case['selector']]
   tail=list(map(str,[case['path'],sel,mode,reps]))
   if 'intervals' in case:tail.append(case['intervals'])
   if launch=='images':args=[str(products[name]),*tail]
   else:
    with image.open('r+b')as stream:assert stream.write(padded[name])==maximum
    assert image.stat().st_ino==inode and image.stat().st_size==maximum
    args=['setarch',platform.machine(),'-R',str(image),*tail]
   ticks,*signature=map(int,sp.check_output(args,text=True).split())
   assert ticks>0 and signature[0]>0
   if 'expected_instructions' in case:
    assert signature[:2]==[case['expected_instructions']*reps,0],(case['name'],mode,reps,signature)
   return ticks,signature
  results=[]
  cases_of_interest={k:(0,1,2)for k in ('arm-cp','mips64el-ls','libssl3t64-i386',*expected['extra_arm64_samples'])}
  for k in ('jpeg-avx2-i386','libzstd1-i386','libssl3t64-amd64','putty-32-0.85','putty-64-0.85','libmvec-amd64'):
   cases_of_interest[k]=(0,1,2,3)
  clk=t/'ticks.c';clk.write_text('#include <stdio.h>\n#include <time.h>\nint main(void){printf("%ld\\n",(long)CLOCKS_PER_SEC);return 0;}\n')
  command(['cc',clk,'-o',t/'clock-scale'],'compile-clock-scale')
  scale=int(sp.check_output([t/'clock-scale'],text=True));assert scale>0
  write('clock-scale',dict(ticks_per_second=scale,calibration_cpu_ms=expected['timing_protocol']['calibration_cpu_ms']))
  for case in sorted(cases,key=lambda c:c['name'] not in ('arm-cp','mips64el-ls')):
   for mode in (0,1,2,3):
    if mode not in cases_of_interest.get(case['name'],()):continue
    for launch in launches:
     # A long full text and a tiny compiler fixture have very different costs.
     start,_=measure('base',case,mode,1,launch);reps=max(1,min(20000,round(expected['timing_protocol']['calibration_cpu_ms']*scale/1000/start)))
     row=dict(case=case['name'],mode=mode,launch=launch,reps=reps,pairs={});oracle=None
     labels=['base','base-copy',*variants]
     plans={label:[] for label in labels[1:]}
     for cycle in range(expected['timing_protocol']['cycles']):
      order=labels[cycle%len(labels):]+labels[:cycle%len(labels)]
      times={label:[] for label in labels}
      for who in order+order[::-1]:
       ticks,sig=measure(who,case,mode,reps,launch);times[who].append(ticks)
       if oracle is None:oracle=sig
       assert oracle==sig,(case['name'],mode,who,oracle,sig)
      for label in labels[1:]:
       plans[label].append(dict(ticks={who:times[who] for who in ('base',label)},gain=sum(times['base'])/sum(times[label])))
     for label in labels[1:]:
      row['pairs'][label]=dict(plans=plans[label],median=statistics.median(q['gain'] for q in plans[label]))
     row['signature']=oracle;results.append(row);write('timings',results);print(case['name'],mode,{who:round(v['median'],4) for who,v in row['pairs'].items()},flush=True)
  remaining={q.stem:json.loads(q.read_text())['changed']for q in out.glob('record-difference-*.json')};write('residual',remaining);assert not any(remaining.values()),remaining
  assert {(row["case"],row["mode"]) for row in results}=={(name,mode) for name,modes in cases_of_interest.items() for mode in modes};assert len(results)==sum(map(len,cases_of_interest.values()))*len(launches);write('complete',dict(active=feature_active,launches=launches,cases=len(results),entrypoints=['Decoder::decodeOneLight','Decoder::decodeOne','Decoder::classifyX86Prefix'],variants=list(variants)))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
