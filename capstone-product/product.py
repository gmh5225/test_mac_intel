from pathlib import Path
import hashlib,json,os,random,shutil,statistics,subprocess as sp,sys,tempfile

r=Path(__file__).resolve().parent;root=r.parent;nd=root/'neverd';out=root/'product-evidence';out.mkdir(exist_ok=True)
def write(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
 print(label,flush=True)
 with (out/(label+'.log')).open('w') as log:rv=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT).returncode
 if rv:print((out/(label+'.log')).read_text(errors='replace')[-4000:],flush=True);raise RuntimeError(label)
def rev(d):return sp.check_output(['git','-C',d,'rev-parse','HEAD'],text=True).strip()
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project'
expected=json.loads((r/'inputs.json').read_text())
assert rev(nd)==expected['neverd'] and rev(cs)==expected['capstone']
write('sources',dict(neverd=rev(nd),capstone=rev(cs),llvm_fork=rev(ll),llvm_source=str(ll)))
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
 t=Path(temp);build=t/'build'
 try:
  candidates=()
  shutil.copyfile(r/'route.cpp',nd/'capstone-product.cpp');cm=nd/'CMakeLists.txt'
  cm.write_text(cm.read_text()+'\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
  command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld','-DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
  assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in (build/'CMakeCache.txt').read_text()
  products={}
  for label in ('base','direct','cached','forward'):
   if label!='base':
    command(['git','apply',r/'memory.patch'],'apply-output-'+label,cs)
    command(['git','apply',r/(label+'.patch')],'select-'+label,nd)
   targets=['capstone-product','NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests']
   command([sys.executable,nd/'scripts/build.py',build,'--target',*targets,'--parallel','4'],'product-'+label,nd)
   command(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-L','^(NeverDX86DecodeDetailTests|NeverDX86MpxEncodingTests)$'],'tests-'+label)
   bins=list(build.rglob('capstone-product'));assert len(bins)==1,bins
   prod=t/label;shutil.copy2(bins[0],prod);products[label]=prod
   deps=sp.check_output(['ldd',prod],text=True);(out/(label+'-linked.txt')).write_text(deps)
   assert not any(key in deps for key in ('libcapstone','libneverd','libNeverD','not found')),deps
   if label!='base':
    command(['git','apply','-R',r/'memory.patch'],'restore-'+label,cs)
    command(['git','apply','-R',r/(label+'.patch')],'restore-client-'+label,nd)
   snapshot=json.loads((build/'.neverd-deps/snapshot.json').read_text())
   write(label+'-snapshot',snapshot)
   roots=list(build.rglob('CMakeFiles/capstone.dir')); assert len(roots)==1,roots
   objects={str(f.relative_to(roots[0])):hashlib.sha256(f.read_bytes()).hexdigest() for f in roots[0].rglob('*.o')};write(label+'-objects',objects)
   if label!='base':
    base_objects=json.loads((out/'base-objects.json').read_text());assert all(objects[k]==v for k,v in base_objects.items()) and len(objects)==len(base_objects)+1
   source_receipt=build/'neverd-dependency-inputs.json'
   if source_receipt.exists():shutil.copyfile(source_receipt,out/(label+'-dependencies.json'))
  signatures={label:sp.check_output([prod],text=True).strip()for label,prod in products.items()}
  write('signatures',signatures);assert len(set(signatures.values()))==1,signatures
  write('complete',dict(routes=3,variants=list(products),signature=signatures['base'],tests=targets[1:]))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
