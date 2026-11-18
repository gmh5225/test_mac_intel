from pathlib import Path
import hashlib
import gzip
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
w=Path(tempfile.mkdtemp(prefix='capstone-coalesced-tags-profile-'));s=w/'source';b=w/'build'
try:
 assert sp.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()==meta['parent']
 sp.run(['git','clone','-q','--shared','--no-checkout','--config','core.autocrlf=false',checkout,s],check=True)
 run(['git','checkout','-q','--detach',meta['parent']],'checkout')
 canonical=sp.check_output(['git','show','HEAD:capstone-output-release/combined.patch'],cwd=r.parent)
 assert hashlib.sha256(canonical).hexdigest()==meta['sha256']
 patch=w/'candidate.patch';patch.write_bytes(canonical)
 architectures={'all':['ARM', 'AARCH64', 'M68K', 'MIPS', 'PPC', 'SPARC', 'SYSTEMZ', 'XCORE', 'X86', 'TMS320C64X', 'M680X', 'EVM', 'MOS65XX', 'WASM', 'BPF', 'RISCV', 'SH', 'TRICORE', 'ALPHA', 'HPPA', 'LOONGARCH', 'XTENSA', 'ARC'],'four':['ARM','AARCH64','MIPS','X86'],'extra':['ARM','AARCH64','MIPS','X86','PPC','RISCV','LOONGARCH','ARC','TRICORE'],'mips':['MIPS'],'arm':['ARM'],'x86':['X86'],'aarch64':['AARCH64'],'riscv':['RISCV'],'affected':['ARM','AARCH64','MIPS','X86','PPC','RISCV','LOONGARCH','ARC','TRICORE','BPF','SPARC','SYSTEMZ','XTENSA']}[archs]
 arm_policy_active=False
 opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in architectures],'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 if os.name=='nt':opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if cc=='MT' else 'OFF')]
 else:
  opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+cc]
  if cc=='gcc':opts+=['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
 if profile=='diet':opts+=['-DCAPSTONE_BUILD_DIET=ON']
 if profile=='reduce':opts+=['-DCAPSTONE_X86_REDUCE=ON']
 if profile=='sanitize':opts+=['-DENABLE_ASAN=ON','-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
 run(['cmake','-S',s,'-B',b,*opts],'configure')
 objects={};tests={}
 for phase in ('base','candidate','observer') if arm_policy_active else ('base','candidate'):
  if phase=='candidate':
   assert not sp.check_output(['git','status','--porcelain'],cwd=s,text=True)
   run(['git','apply',patch],'apply')
   run(['git','add','-A'],'stage')
   tree=sp.check_output(['git','write-tree'],cwd=s,text=True).strip();assert tree==meta['tree']
  targets=[] if phase!='observer' else ['--target','capstone_static',*(['arm_post_index','arm_private_stream','arm_reg_access','cstest'] if profile!='diet' else ['api','instruction_bytes','sstream'])]
  run(['cmake','--build',b,'--config','Release',*targets,'--parallel','4'],phase+'-build')
  diet_units=['api','utils','mapping','register_descriptors','sstream','instruction_bytes','mcinst','feature_mode',
              'arm_writeback_postprocess','aarch64_postprocess','aarch64_scan','mips_scan',
              'x86_reg_access','detail_option','text_option','x86_encoding_accuracy','x86_scan_batch','x86_buffer_bounds','x86_memory_scale']
  pattern='^unit_('+'|'.join(diet_units)+')$' if profile in ('diet','reduce') else '^unit_'
  if phase=='observer':pattern='^unit_arm_(post_index|private_stream|reg_access)$' if profile!='diet' else '^unit_(api|instruction_bytes|sstream)$'
  extra=['-R',pattern]
  run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','--parallel','4',*extra],phase+'-tests')
  tests[phase]=(e/(phase+'-tests.log')).read_text(errors='replace')
  if profile!='diet':
   binary=b/'suite/cstest'/('Release/cstest.exe' if os.name=='nt' else 'cstest')
   fixture_archs=[]
   folders={'ARM':'ARM','AARCH64':'AArch64','MIPS':'Mips','RISCV':'RISCV','PPC':'PowerPC','LOONGARCH':'LoongArch','ARC':'ARC','TRICORE':'TriCore','BPF':'BPF','SPARC':'Sparc','SYSTEMZ':'SystemZ','XTENSA':'Xtensa','ALPHA':'Alpha','HPPA':'HPPA'}
   fixture_archs=[a for a in architectures if a in folders]
   save('fixture-coverage',dict(tested=fixture_archs,without_MC_directory=[a for a in architectures if a not in folders and a!='X86'],x86='Unit tests include generated-output, bounds, encoding and option suites'))
   for arch in fixture_archs:run([binary,s/'tests/MC'/folders[arch]],phase+'-'+arch.lower()+'-fixtures')
  if phase!='observer' and os.name!='nt':
   objects[phase]={str(f.relative_to(b/'CMakeFiles/capstone.dir')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
  for name in [phase+'-tests',*[phase+'-'+a+'-fixtures' for a in ('arm','aarch64','mips','riscv','ppc','loongarch','arc','tricore','bpf','sparc','systemz','xtensa')]]:
   f=e/(name+'.log')
   if f.exists():
    log=f.read_text(errors='replace');assert 'runtime error:' not in log and 'ERROR: AddressSanitizer' not in log
    if f.stat().st_size>1000000:
     raw=f.read_bytes();z=f.with_suffix(f.suffix+'.gz');z.write_bytes(gzip.compress(raw,mtime=0));assert gzip.decompress(z.read_bytes())==raw;f.unlink()
 if objects:
  assert objects['base'].keys()==objects['candidate'].keys()
  changed=[k for k,v in objects['base'].items() if objects['candidate'][k]!=v]
  active='X86' in architectures and profile not in ('diet','reduce')
  raw_changed=changed[:]
  save('raw-runtime-objects',dict(changed=raw_changed))
  location_control=None
  allowed = set(['MCInst.c.o', 'arch/AArch64/AArch64Disassembler.c.o', 'arch/ARC/ARCDisassembler.c.o', 'arch/ARM/ARMDisassembler.c.o', 'arch/ARM/ARMInstPrinter.c.o', 'arch/ARM/ARMMapping.c.o', 'arch/Alpha/AlphaDisassembler.c.o', 'arch/BPF/BPFDisassembler.c.o', 'arch/HPPA/HPPADisassembler.c.o', 'arch/LoongArch/LoongArchDisassembler.c.o', 'arch/MOS65XX/MOS65XXDisassembler.c.o', 'arch/Mips/MipsDisassembler.c.o', 'arch/PowerPC/PPCDisassembler.c.o', 'arch/RISCV/RISCVDisassembler.c.o', 'arch/Sparc/SparcDisassembler.c.o', 'arch/SystemZ/SystemZDisassembler.c.o', 'arch/TMS320C64x/TMS320C64xDisassembler.c.o', 'arch/TriCore/TriCoreDisassembler.c.o', 'arch/X86/X86Disassembler.c.o', 'arch/X86/X86DisassemblerDecoder.c.o', 'arch/X86/X86Mapping.c.o', 'arch/XCore/XCoreDisassembler.c.o', 'arch/Xtensa/XtensaDisassembler.c.o'])
  identity_gate = profile != 'sanitize'
  if identity_gate:
   assert set(changed) <= allowed, changed
  assert 'MCInst.c.o' in changed
  if not identity_gate:
   save('instrumentation-scope',dict(object_identity_gate=False,reason='ASan/UBSan embeds source locations from the shared header. Exact candidate source was used for all semantic tests; raw object changes are preserved without claiming unaffected-object identity.'))
  save('runtime-objects',dict(changed=changed,raw_changed=raw_changed,source_location_control=location_control,allowed=sorted(allowed),object_identity_gate=identity_gate,identical=len(objects['base'])-len(changed),arm_policy_active=arm_policy_active))
 save('complete',dict(profile=profile,compiler=cc,archs=archs,arm_policy_active=arm_policy_active,architectures=architectures,tested_tree=tree,phases=list(tests),observer_executed=arm_policy_active,observer_arm_owner_filtered=arm_policy_active and profile=='diet',test_summaries={k:[line for line in v.splitlines() if 'tests passed' in line] for k,v in tests.items()}))
finally:
 amount=sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
 shutil.rmtree(w,onerror=cleanup_error);save('cleanup',dict(bytes=amount,removed=not w.exists()))
