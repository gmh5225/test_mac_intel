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
assert cc == 'clang'
feature_active = True
write('scope',dict(active=feature_active,policy='Isolated EVEX extension entry, original decoder semantics retained'))
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
  cases=[v for v in cases if v['name'] in ('putty-32-0.85','putty-64-0.85','amd64-ls','arm64-ls','scalar32','scalar64','simd64','arm-cp','mips64el-ls','arm64-sort','libssl3t64-amd64','libjpeg62-turbo-i386','libssl3t64-i386','libzstd1-i386')]
  assert len(cases)==14
  original_cases=list(cases)
  cases.append(avx_corpus.prepare(r,t,out,command))
  assert len(cases)==15
  shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp');cm=nd/'CMakeLists.txt'
  cm.write_text(cm.read_text()+'\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'original-probe.cpp',nd/'capstone-product-legacy.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-product-legacy capstone-product-legacy.cpp)\ntarget_link_libraries(capstone-product-legacy PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'route.cpp',nd/'capstone-route.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-route capstone-route.cpp)\ntarget_link_libraries(capstone-route PRIVATE NeverDDecode)\n')
  command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCMAKE_CXX_COMPILER=clang++','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
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
  products={}
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
   if label!='base':
    change=r/variants[label]['patch']
    assert hashlib.sha256(change.read_bytes()).hexdigest()==variants[label]['patch_sha256']
    command(['git','apply',change],'apply-'+label,cs)
   targets=['capstone-product','capstone-route','NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests']
   if label=='base':targets.append('capstone-product-legacy')
   command([sys.executable,nd/'scripts/build.py',build,'--target',*targets,'--parallel','4'],'product-'+label,nd)
   llvm_current=llvm_identity();write(label+'-llvm-identity',llvm_current)
   assert llvm_current==llvm_reference,(label,'LLVM source changed during comparison',llvm_reference,llvm_current)
   command(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-L','^(NeverDX86DecodeDetailTests|NeverDX86MpxEncodingTests)$'],'tests-'+label)
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

   command(['nm','-S','-C',prod],'timed-symbols-'+label)
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
   disk={str(f.relative_to(roots[0])):f for f in roots[0].rglob('*.o')}
   active={key:path for key,path in disk.items() if path.name in members}
   assert len(active)==len(members) and {path.name for path in active.values()}==set(members),(members,list(active))
   write(label+'-archive-members',dict(members=members,ignored_orphan_objects=sorted(set(disk)-set(active))))
   objects={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in active.items()};write(label+'-objects',objects)
   if label!='base':
    base_objects=json.loads((out/'base-objects.json').read_text())
    new_files=sorted(set(objects)-set(base_objects))
    changed=sorted(k for k in base_objects if objects.get(k)!=base_objects[k])
    write(label+'-capstone-objects',dict(added=new_files,changed=changed))
    assert {Path(k).name for k in new_files}==set(variants[label]['added']),new_files
    assert {Path(k).name for k in changed}==(set(variants[label]['changed']) if feature_active else set()),changed
   source_receipt=build/'neverd-dependency-inputs.json'
   if source_receipt.exists():shutil.copyfile(source_receipt,out/(label+'-dependencies.json'))
   command(['git','add','-A'],'stage-receipt-'+label,cs)
   source_tree=sp.check_output(['git','write-tree'],cwd=cs,text=True).strip()
   write(label+'-source-tree',dict(tree=source_tree,parent=ref))
   if label!='base':
    assert source_tree==variants[label]['tree'],(label,source_tree,variants[label]['tree'])
   command(['git','reset','--hard',ref],'restore-'+label,cs)
   assert not sp.check_output(['git','status','--porcelain'],cwd=cs)

  identities={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in products.items()}
  write('products',identities);assert len(set(identities.values()))==(1+len(variants) if feature_active else 1)
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
  cases_of_interest={'jpeg-avx2-i386':(0,1,2),'libssl3t64-i386':(0,1,2),'libzstd1-i386':(0,1,2),'libssl3t64-amd64':(0,1,2),'libjpeg62-turbo-i386':(0,1,2),'arm-cp':(0,1,2),'arm64-ls':(0,1,2),'arm64-sort':(0,),'mips64el-ls':(0,1,2),'putty-32-0.85':(0,1,2),'simd64':(0,1,2),'putty-64-0.85':(0,1,2),'amd64-ls':(1,2),'scalar32':(1,2),'scalar64':(1,2)}
  batch_cases=('jpeg-avx2-i386','libssl3t64-i386','libzstd1-i386','libssl3t64-amd64','libjpeg62-turbo-i386','putty-32-0.85','putty-64-0.85','amd64-ls')
  for name in batch_cases:cases_of_interest[name]=(*cases_of_interest[name],3)
  for case in sorted(cases,key=lambda c:c['name'] not in ('arm-cp','mips64el-ls')):
   for mode in (0,1,2,3):
    if mode not in cases_of_interest.get(case['name'],()):continue
    for launch in launches:
     # A long full text and a tiny compiler fixture have very different costs.
     start,_=measure('base',case,mode,1,launch);reps=max(1,min(20000,round(100000/start)))
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
  assert {(row["case"],row["mode"]) for row in results}=={(name,mode) for name,modes in cases_of_interest.items() for mode in modes};assert len(results)==48*len(launches);write('complete',dict(active=feature_active,launches=launches,cases=len(results),entrypoints=['Decoder::decodeOneLight','Decoder::decodeOne','Decoder::classifyX86Prefix'],variants=list(variants)))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
