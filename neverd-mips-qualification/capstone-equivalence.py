"""Compare the C compiled for NeverD's multiarchitecture Capstone profile."""
import hashlib, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path
old='6977f9ad6412b1ed3a4431700ebdb989580efe46';new='6fbeffec215f3c7c79169c655b0928c616b46152'
source=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]).resolve()
def git(*args):return subprocess.check_output(['git',*args],cwd=source,text=True).strip()
def sha(b):return hashlib.sha256(b).hexdigest()
compiler=shutil.which('clang');assert compiler
assert git('rev-parse',new+'^')==old
units=['cs.c',*git('ls-files','arch/Mips/*.c').splitlines()]
defines=['CAPSTONE_ARM_AARCH64_MIPS_X86','CAPSTONE_HAS_AARCH64','CAPSTONE_HAS_ARM','CAPSTONE_HAS_MIPS','CAPSTONE_HAS_X86','CAPSTONE_USE_SYS_DYN_MEM']
changed=git('diff','--name-only',old,new).splitlines()
assert set(units)&set(changed)=={'cs.c'}
assert all(p in ('CMakeLists.txt','Makefile','cs.c') or p.startswith(('arch/RISCV/','suite/','tests/')) for p in changed)
cpp=['-std=c11','-O3','-DNDEBUG','-I.','-Iinclude',*['-D'+v for v in defines]]
if sys.platform=='win32':cpp+=['-D_CRT_SECURE_NO_WARNINGS']
before=git('rev-parse','HEAD'); all_rows={}
try:
 with tempfile.TemporaryDirectory() as td:
  ts=Path(td);obj=ts/'capstone.o'
  for rev in [old,new]:
   subprocess.run(['git','checkout','--quiet','--detach',rev],cwd=source,check=True)
   rows={}
   for u in units:
    text=subprocess.check_output([compiler,*cpp,'-E','-P',u],cwd=source)
    subprocess.run([compiler,*cpp,'-c',u,'-o',str(obj)],check=True,cwd=source,stdout=subprocess.PIPE)
    compiled=bytearray(obj.read_bytes())
    # COFF's file-header timestamp is independent of the instruction bytes.
    if sys.platform=='win32':
      assert len(compiled)>20 and compiled[:2]==b'\x64\x86';compiled[4:8]=b'\0'*4
    rows[u]={'preprocessed':sha(text),'object':sha(compiled)}
   all_rows[rev]=rows
  assert all_rows[old]==all_rows[new],all_rows
finally:
 subprocess.run(['git','checkout','--quiet','--detach',before],cwd=source,check=True)
out.write_text(json.dumps(dict(host=platform.platform(),compiler=subprocess.check_output([compiler,'--version'],text=True).splitlines()[0],old=old,new=new,defines=defines,units=all_rows,changed_paths=changed),indent=2)+'\n')
print('Identical preprocessed sources and native objects:',', '.join(units))
