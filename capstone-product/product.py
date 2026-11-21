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
write('scope',dict(active=feature_active,policy='Test the i386 VEX2 scan reader through decodeOneLight and decodeOne, including scalar PE, ELF, other architectures and batch behavior.'))
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
  from factors import measure_layout
  measure_layout(r,t,build,nd,cs,out,cases,expected,command,write,rev,llvm_identity,llvm_reference)

 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
