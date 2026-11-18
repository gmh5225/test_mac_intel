from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
r=Path(__file__).resolve().parent
checkout=r.parent/'source'
e=r.parent/'evidence';e.mkdir()
meta=json.loads((r/'candidate.json').read_text())
profile=os.environ['PROFILE'];cc=os.environ['TOOLCHAIN'];archs=os.environ['BUILD_ARCHS']
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,name):
 print(name,flush=True)
 with (e/(name+'.log')).open('wb') as log:
  result=sp.run(list(map(str,args)),cwd=s,stdout=log,stderr=sp.STDOUT)
 if result.returncode:raise RuntimeError((name,(e/(name+'.log')).read_text(errors='replace')[-2500:]))
def cleanup_error(fn,path,exc):os.chmod(path,0o700);fn(path)
w=Path(tempfile.mkdtemp(prefix='capstone-arm-mixed-profile-'));s=w/'source';b=w/'build'
try:
 assert sp.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()==meta['parent']
 sp.run(['git','clone','-q','--shared','--no-checkout','--config','core.autocrlf=false',checkout,s],check=True)
 run(['git','checkout','-q','--detach',meta['parent']],'checkout')
 canonical=sp.check_output(['git','show','HEAD:capstone-output-release/combined.patch'],cwd=r.parent)
 assert hashlib.sha256(canonical).hexdigest()==meta['sha256']
 patch=w/'candidate.patch';patch.write_bytes(canonical)
 architectures={'four':['ARM','AARCH64','MIPS','X86'],'extra':['ARM','AARCH64','MIPS','X86','PPC','RISCV','LOONGARCH','ARC','TRICORE'],'mips':['MIPS'],'arm':['ARM'],'x86':['X86']}[archs]
 active=archs=='four'
 opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in architectures],'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 if os.name=='nt':opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if cc=='MT' else 'OFF')]
 else:
  opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+cc]
  if cc=='gcc':opts+=['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
 if profile=='diet':opts+=['-DCAPSTONE_BUILD_DIET=ON']
 if profile=='sanitize':opts+=['-DENABLE_ASAN=ON','-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
 run(['cmake','-S',s,'-B',b,*opts],'configure')
 objects={};tests={}
 for phase in ('base','candidate','observer') if active else ('base','candidate'):
  if phase=='candidate':
   assert not sp.check_output(['git','status','--porcelain'],cwd=s,text=True)
   run(['git','apply',patch],'apply')
   run(['git','add','-A'],'stage')
   tree=sp.check_output(['git','write-tree'],cwd=s,text=True).strip();assert tree==meta['tree']
  if phase=='observer':
   h=s/'MCInst.h';text=h.read_text();needle='assert(i < MAX_MC_OPS);';assert text.count(needle)==1
   text=text.replace(needle,'if (i >= inst->size) { fprintf(stderr, "ARM operand read before construction: opcode=%u size=%u index=%u\\n", inst->Opcode, inst->size, i); abort(); }')
   if profile=='diet':
    text=text.replace('static inline MCOperand *MCInst_getOperand', 'bool cs_test_arm_mcinst(const MCInst *inst);\nstatic inline MCOperand *MCInst_getOperand')
    text=text.replace('if (i >= inst->size)', 'if (cs_test_arm_mcinst(inst) && i >= inst->size)')
    owner=s/'MCInst.c'
    owner.write_text(owner.read_text()+'\n#include "cs_priv.h"\nbool cs_test_arm_mcinst(const MCInst *inst) { return inst->csh && inst->csh->arch == CS_ARCH_ARM; }\n')
   text=text.replace('#include <assert.h>','#include <assert.h>\n#include <stdio.h>\n#include <stdlib.h>');h.write_text(text)
   core=s/'cs.c';text=core.read_text();assert text.count('MCInst mci;')==1
   core.write_text(text.replace('MCInst mci;','MCInst mci;\nif (handle->arch == CS_ARCH_ARM) memset(&mci, 0xa5, sizeof(mci));'))
  targets=[] if phase!='observer' else ['--target','capstone_static',*(['arm_post_index','arm_private_stream','arm_reg_access','cstest'] if profile!='diet' else ['api','instruction_bytes','sstream'])]
  run(['cmake','--build',b,'--config','Release',*targets,'--parallel','4'],phase+'-build')
  extra=['-R',('^unit_arm_(post_index|private_stream|reg_access)$' if profile!='diet' else '^unit_(api|instruction_bytes|sstream)$')] if phase=='observer' else []
  run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--parallel','4',*extra],phase+'-tests')
  tests[phase]=(e/(phase+'-tests.log')).read_text(errors='replace')
  if 'ARM' in architectures and profile!='diet':
   binary=b/'suite/cstest'/('Release/cstest.exe' if os.name=='nt' else 'cstest')
   run([binary,s/'tests/MC/ARM'],phase+'-arm-fixtures')
  if phase!='observer' and os.name!='nt':
   objects[phase]={str(f.relative_to(b/'CMakeFiles/capstone.dir')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
  for name in [phase+'-tests',phase+'-arm-fixtures']:
   f=e/(name+'.log')
   if f.exists():
    log=f.read_text(errors='replace');assert 'runtime error:' not in log and 'ERROR: AddressSanitizer' not in log
 if objects:
  assert objects['base'].keys()==objects['candidate'].keys()
  changed=[k for k,v in objects['base'].items() if objects['candidate'][k]!=v]
  assert changed==(['cs.c.o'] if active else []),changed
  save('runtime-objects',dict(changed=changed,identical=len(objects['base'])-len(changed),active=active))
 save('complete',dict(profile=profile,compiler=cc,archs=archs,active=active,tested_tree=tree,phases=list(tests),observer_executed=active,observer_arm_owner_filtered=active and profile=='diet',test_summaries={k:[line for line in v.splitlines() if 'tests passed' in line] for k,v in tests.items()}))
finally:
 amount=sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
 shutil.rmtree(w,onerror=cleanup_error);save('cleanup',dict(bytes=amount,removed=not w.exists()))
