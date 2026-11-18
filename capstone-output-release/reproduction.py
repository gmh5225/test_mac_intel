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
w=Path(tempfile.mkdtemp(prefix='capstone-init-domain-profile-'));s=w/'source';b=w/'build'
try:
 assert sp.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()==meta['parent']
 sp.run(['git','clone','-q','--shared','--no-checkout','--config','core.autocrlf=false',checkout,s],check=True)
 run(['git','checkout','-q','--detach',meta['parent']],'checkout')
 canonical=sp.check_output(['git','show','HEAD:capstone-output-release/combined.patch'],cwd=r.parent)
 assert hashlib.sha256(canonical).hexdigest()==meta['sha256']
 patch=w/'candidate.patch';patch.write_bytes(canonical)
 architectures={'four':['ARM','AARCH64','MIPS','X86'],'extra':['ARM','AARCH64','MIPS','X86','PPC','RISCV','LOONGARCH','ARC','TRICORE'],'mips':['MIPS'],'arm':['ARM'],'x86':['X86'],'aarch64':['AARCH64'],'riscv':['RISCV']}[archs]
 arm_policy_active=archs=='four'
 opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in architectures],'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 if os.name=='nt':opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if cc=='MT' else 'OFF')]
 else:
  opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+cc]
  if cc=='gcc':opts+=['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
 if profile=='diet':opts+=['-DCAPSTONE_BUILD_DIET=ON']
 if profile=='sanitize':opts+=['-DENABLE_ASAN=ON','-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
 run(['cmake','-S',s,'-B',b,*opts],'configure')
 objects={};tests={}
 for phase in ('base','candidate','observer') if arm_policy_active else ('base','candidate'):
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
  diet_units=['api','utils','mapping','register_descriptors','sstream','instruction_bytes','mcinst','feature_mode',
              'arm_writeback_postprocess','aarch64_postprocess','aarch64_scan','mips_scan',
              'x86_reg_access','detail_option','text_option','x86_encoding_accuracy','x86_scan_batch','x86_buffer_bounds','x86_memory_scale']
  pattern='^unit_('+'|'.join(diet_units)+')$' if profile=='diet' else '^unit_'
  if phase=='observer':pattern='^unit_arm_(post_index|private_stream|reg_access)$' if profile!='diet' else '^unit_(api|instruction_bytes|sstream)$'
  extra=['-R',pattern]
  run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--parallel','4',*extra],phase+'-tests')
  tests[phase]=(e/(phase+'-tests.log')).read_text(errors='replace')
  if profile!='diet':
   binary=b/'suite/cstest'/('Release/cstest.exe' if os.name=='nt' else 'cstest')
   fixture_archs=['ARM'] if phase=='observer' else [a for a in ('ARM','AARCH64','MIPS','RISCV') if a in architectures]
   folders={'ARM':'ARM','AARCH64':'AArch64','MIPS':'Mips','RISCV':'RISCV'}
   for arch in fixture_archs:run([binary,s/'tests/MC'/folders[arch]],phase+'-'+arch.lower()+'-fixtures')
  if phase!='observer' and os.name!='nt':
   objects[phase]={str(f.relative_to(b/'CMakeFiles/capstone.dir')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
  for name in [phase+'-tests',*[phase+'-'+a+'-fixtures' for a in ('arm','aarch64','mips','riscv')]]:
   f=e/(name+'.log')
   if f.exists():
    log=f.read_text(errors='replace');assert 'runtime error:' not in log and 'ERROR: AddressSanitizer' not in log
 if objects:
  assert objects['base'].keys()==objects['candidate'].keys()
  changed=[k for k,v in objects['base'].items() if objects['candidate'][k]!=v]
  raw_changed=changed[:]
  save('raw-runtime-objects',dict(changed=raw_changed))
  location_control=None
  if profile=='sanitize':
   run(['git','restore','--worktree','--','MCInst.h','cs.c'],'restore-semantic-candidate')
   header=s/'MCInst.h';candidate_header=header.read_text()
   original_header=sp.check_output(['git','show',meta['parent']+':MCInst.h'],cwd=s,text=True)
   marker='\t/* All zero-valued defaults are established by the clear above. */'
   assert candidate_header.count(marker)==original_header.count(marker)==1
   original_line=original_header[:original_header.index(marker)].count('\n')+1
   candidate_line=candidate_header[:candidate_header.index(marker)].count('\n')+1
   directive='#line '+str(original_line)+'\n'
   adjusted=candidate_header.replace(marker,directive+marker)
   assert adjusted.replace(directive,'',1)==candidate_header
   header.write_text(adjusted)
   location_control=dict(original_line=original_line,candidate_line=candidate_line,directive=directive.strip(),
      original_header_sha256=hashlib.sha256(original_header.encode()).hexdigest(),
      candidate_header_sha256=hashlib.sha256(candidate_header.encode()).hexdigest(),
      control_header_sha256=hashlib.sha256(adjusted.encode()).hexdigest(),
      semantic_tests_source='Unmodified candidate patch before this diagnostic-only line directive')
   save('source-location-control',location_control)
   run(['cmake','--build',b,'--config','Release','--target','capstone_static','--parallel','4'],'location-control-build')
   normalized={str(f.relative_to(b/'CMakeFiles/capstone.dir')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
   assert normalized.keys()==objects['base'].keys()
   changed=[key for key,h in objects['base'].items() if normalized[key]!=h]
   save('source-location-object-proof',dict(raw_changed=raw_changed,location_control_changed=changed,
       all_nonowner_objects_identical=set(changed)<={'cs.c.o'},total=len(normalized)))
  allowed={'cs.c.o'} if archs!='x86' else set()
  if 'RISCV' in architectures:allowed.add('arch/RISCV/RISCVInstPrinter.c.o')
  assert set(changed)<=allowed,changed
  if arm_policy_active:assert 'cs.c.o' in changed
  save('runtime-objects',dict(changed=changed,raw_changed=raw_changed,source_location_control=location_control,allowed=sorted(allowed),identical=len(objects['base'])-len(changed),arm_policy_active=arm_policy_active))
 save('complete',dict(profile=profile,compiler=cc,archs=archs,arm_policy_active=arm_policy_active,architectures=architectures,tested_tree=tree,phases=list(tests),observer_executed=arm_policy_active,observer_arm_owner_filtered=arm_policy_active and profile=='diet',test_summaries={k:[line for line in v.splitlines() if 'tests passed' in line] for k,v in tests.items()}))
finally:
 amount=sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
 shutil.rmtree(w,onerror=cleanup_error);save('cleanup',dict(bytes=amount,removed=not w.exists()))
