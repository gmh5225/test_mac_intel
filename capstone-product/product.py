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
write('scope',dict(active=feature_active,policy='Canonical EVEX register scan plans, complete output and callback semantics retained'))
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

  checks=[]
  for case in cases:
   sel=case['selector'] if case['selector'] in (32,64) else {0:'arm64',1:'arm',4:'mips64el'}[case['selector']]
   for mode in ((0,1,2,3) if case['selector'] in (32,64) else (0,1,2)):
    tail=list(map(str,[case['path'],sel,mode,1]))
    if 'intervals' in case:tail.append(case['intervals'])
    signatures={label:list(map(int,sp.check_output([path,*tail],text=True).split()))[1:]for label,path in products.items()}
    assert all(value==signatures['base'] for value in signatures.values()),(case['name'],mode,signatures)
    checks.append(dict(case=case['name'],mode=mode,signatures=signatures))
  assert len(checks)==56
  write('integration-case-equivalence',dict(checks=checks,unchanged=True))
  remaining={q.stem:json.loads(q.read_text())['changed']for q in out.glob('record-difference-*.json')};write('residual',remaining);assert not any(remaining.values()),remaining
  write('complete',dict(active=True,integration_only=True,cases=len(checks),variants=list(variants),native_timing=False,neverd=rev(nd)))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
