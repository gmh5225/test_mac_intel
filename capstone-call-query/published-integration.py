from pathlib import Path
import json,shutil,subprocess as sp,sys
root=Path.cwd();nd=root/'neverd';b=root/'published-product-build';e=root/'product-evidence';e.mkdir(exist_ok=True)
def run(args,cwd=None):sp.run(list(map(str,args)),cwd=cwd,check=True)
def sha(path):return sp.check_output(['git','-C',path,'rev-parse','HEAD'],text=True).strip()
def save(name,data):(e/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
assert sha(nd)=='3b335bad27cccc12120bee50a66d68e99a4f6f67' and sha(nd/'third_party/capstone')=='76d4a75f7bb38db42df1f780fc65248dc560b3b5'
inputs=dict(neverd=sha(nd),capstone=sha(nd/'third_party/capstone'),llvm=sha(nd/'third_party/llvm-project'));save('inputs',inputs)
args=['cmake','-S',nd,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_BINARY_CORPUS_TESTS=OFF','-DNEVERD_BUILD_SHARED=ON','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF']
targets=['NeverDFunctionAdmissionTests','NeverDX86DecodeDetailTests','NeverDARM32InterworkingTests','NeverDX86APXEVEXExistingGprTests']
try:
 run(args)
 run([sys.executable,nd/'scripts/build.py',b,'--target',*targets,'--parallel','4'],nd)
 cache=(b/'CMakeCache.txt').read_text();assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in cache and sha(nd/'third_party/capstone')==inputs['capstone']
 groups='^('+'|'.join(targets[:3])+')$'
 run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--output-junit',e/'public-api-tests.xml','-L',groups])
 run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--output-junit',e/'masked-load.xml','-R','FloatingClassTestUsesExtendedAddressAndMaskedLoads'])
 save('complete',dict(complete=True,targets=targets,llvm_after_build=sha(nd/'third_party/llvm-project')))
finally:
 if b.exists():shutil.rmtree(b)
 save('cleanup',dict(build_removed=not b.exists()))
