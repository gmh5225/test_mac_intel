from pathlib import Path
import json,shutil,subprocess as sp,sys
root=Path.cwd();nd=root/'neverd';b=root/'published-product-build';e=root/'product-evidence';e.mkdir(exist_ok=True)
def run(args,cwd=None):sp.run(list(map(str,args)),cwd=cwd,check=True)
def sha(path):return sp.check_output(['git','-C',path,'rev-parse','HEAD'],text=True).strip()
def save(name,data):(e/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
assert sha(nd)=='bc9659da5d4e3df7bdfe32bcf8b8f855547b7d67' and sha(nd/'third_party/capstone')=='ed8c4b4f7eeb9b31b1899f61d7249062077d0d4e'
inputs=dict(neverd=sha(nd),capstone=sha(nd/'third_party/capstone'),llvm=sha(nd/'third_party/llvm-project'));save('inputs',inputs)
args=['cmake','-S',nd,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_BINARY_CORPUS_TESTS=OFF','-DNEVERD_BUILD_SHARED=ON','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF']
targets=['NeverDFunctionAdmissionTests','NeverDX86DecodeDetailTests','NeverDARM32InterworkingTests','NeverDX86APXEVEXExistingGprTests','NeverDLocalTypesDebugContextTests']
try:
 run(args)
 run([sys.executable,nd/'scripts/build.py',b,'--target','intrinsics_gen','--parallel','4'],nd)
 import shlex
 rel='lib/sdk/capi/NeverDCAPILocalTypes.cpp'
 entry=next(x for x in json.loads((b/'compile_commands.json').read_text()) if x['file'].endswith('/'+rel) and 'neverd_shared.dir' in x['command'])
 argv=shlex.split(entry['command']);start=argv.index('-o');del argv[start:start+2];argv[argv.index('-c')]='-fsyntax-only'
 old=sp.run(argv,cwd=entry['directory'],stdout=sp.PIPE,stderr=sp.STDOUT,text=True);(e/'before.log').write_text(old.stdout)
 run(['git','apply','--check',root/'capstone-call-query/sdk.patch'],nd)
 run(['git','apply',root/'capstone-call-query/sdk.patch'],nd)
 new=sp.run(argv,cwd=entry['directory'],stdout=sp.PIPE,stderr=sp.STDOUT,text=True);(e/'after.log').write_text(new.stdout)
 save('sdk-tu',dict(before=old.returncode,after=new.returncode,reproduced='no matching member function' in old.stdout and 'emplace' in old.stdout))
 # The full build also provides target-specific generated headers if the standalone check needs any.
 if new.returncode:print(new.stdout,flush=True)
 run([sys.executable,nd/'scripts/build.py',b,'--target',*targets,'--parallel','4'],nd)
 cache=(b/'CMakeCache.txt').read_text();assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in cache and sha(nd/'third_party/capstone')==inputs['capstone']
 groups='^('+'|'.join(targets[:3])+')$'
 run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--output-junit',e/'public-api-tests.xml','-L',groups])
 run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--output-junit',e/'masked-load.xml','-R','FloatingClassTestUsesExtendedAddressAndMaskedLoads'])
 run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--output-junit',e/'local-types.xml','-L','^NeverDLocalTypesDebugContextTests$'])
 save('complete',dict(complete=True,targets=targets,llvm_after_build=sha(nd/'third_party/llvm-project')))
finally:
 if b.exists():shutil.rmtree(b)
 save('cleanup',dict(build_removed=not b.exists()))
