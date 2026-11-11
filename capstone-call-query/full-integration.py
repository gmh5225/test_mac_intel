from pathlib import Path
import hashlib,json,os,shutil,statistics,subprocess as sp,sys,tempfile,urllib.request
here=Path(__file__).resolve().parent;root=Path.cwd();nd=root/'neverd';b=root/'call-product-build';e=root/'product-evidence';e.mkdir(exist_ok=True)
def call(args,cwd=None):sp.run(list(map(str,args)),cwd=cwd,check=True)
def capture(args,cwd):return sp.check_output(list(map(str,args)),cwd=cwd,text=True).strip()
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project';orig=capture(['git','rev-parse','HEAD'],nd);expected=(here/'neverd-base.txt').read_text().strip();assert orig==expected
code='lib/ir/low/X86/FuncDetectorX86.cpp';call(['git','apply','--check',here/'neverd.patch'],nd);call(['git','apply',here/'neverd.patch'],nd);call(['git','apply','--check',here/'release.patch'],cs);call(['git','apply',here/'release.patch'],cs)
assert capture(['git','rev-parse','HEAD'],cs)=='f2f50b8fab856b374daf0e76dc3054f25de65ac9';llvm=capture(['git','rev-parse','HEAD'],ll);save('inputs',dict(neverd=orig,llvm=llvm,neverd_patch=sha(here/'neverd.patch'),capstone_patch=sha(here/'release.patch')))
shutil.copyfile(here/'walk.cpp',nd/'walk.cpp');f=nd/'CMakeLists.txt';f.write_text(f.read_text()+'\nadd_executable(callwalk walk.cpp)\ntarget_include_directories(callwalk PRIVATE lib/ir/low)\ntarget_link_libraries(callwalk PRIVATE NeverDIRLow NeverDDecode NeverDLoader)\n');args=['cmake','-S',nd,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_BINARY_CORPUS_TESTS=OFF','-DNEVERD_BUILD_SHARED=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF'];call(args)
# The first build runs the candidate on the current pipeline and tests it normally.
def build(targets):call([sys.executable,nd/'scripts/build.py',b,'--target',*targets,'--parallel','4'])
products={}
try:
 build(['NeverDFunctionAdmissionTests','callwalk']);call(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-L','^NeverDFunctionAdmissionTests$']);save('tests',dict(target='NeverDFunctionAdmissionTests',passed=True));shutil.copyfile(b/'neverd-build-receipt.json',e/'build-receipt.json');shutil.copyfile(b/'neverd-dependency-inputs.json',e/'dependency-inputs.json')
 exe=b/'bin/callwalk';products['new']=root/'new-walk';shutil.copy2(exe,products['new']);old=sp.check_output(['git','show','HEAD:'+code],cwd=nd);(nd/code).write_bytes(old);build(['callwalk']);products['base']=root/'old-walk';shutil.copy2(exe,products['base']);assert sha(products['base'])!=sha(products['new'])
 rows=[]
 with tempfile.TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as temp:
  cases=[]
  for v in json.loads((here/'corpus.json').read_text()):
   with urllib.request.urlopen(v['source'],timeout=60) as res:bin=res.read()
   assert hashlib.sha256(bin).hexdigest()==v['executable_sha256'];f=Path(temp)/v['executable'];f.write_bytes(bin);cases.append((v['name'],f))
  cases+= [('ls',Path('/usr/bin/ls')),('sort',Path('/usr/bin/sort'))]
  if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  for name,path in cases:
   pairs=[];oracle=None
   for i in range(12):
    order=('base','new','new','base') if i%2==0 else ('new','base','base','new');t={k:[] for k in products}
    for k in order:
     v=list(map(int,capture([products[k],path,8],root).split()));assert len(v)==6 and v[0]>0
     if oracle is None:oracle=v[1:]
     assert v[1:]==oracle;t[k].append(v[0])
    pairs.append(dict(ticks=t,gain=statistics.mean(t['base'])/statistics.mean(t['new'])))
   rows.append(dict(case=name,oracle=oracle,median=statistics.median(v['gain'] for v in pairs),pairs=pairs));save('measurement',rows)
 save('complete',dict(complete=True))
finally:
 for f in products.values():f.unlink(missing_ok=True)
 if b.exists():shutil.rmtree(b)
 save('cleanup',dict(build_removed=not b.exists()))
