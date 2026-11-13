from pathlib import Path
import hashlib,itertools,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-arm-branches-') as tmp:
 t=Path(tmp);b=t/'build'
 try:
  import re
  mapping=(s/'arch/ARM/ARMGenCSMappingInsn.inc').read_text()
  rows=re.findall(r'^\s*(ARM_[\w]+) /\* (\d+) \*/, (ARM_INS_[\w]+)',mapping,re.M)
  enums=dict(re.findall(r'^\s*(ARM_[\w]+)\s*=\s*(\d+)',(s/'arch/ARM/ARMGenInstrInfo.inc').read_text(),re.M))
  assert [int(row[1]) for row in rows]==list(range(4465)) and all(enums[name]==idx for name,idx,_ in rows)
  write('mapping',dict(rows=len(rows),sha256=hashlib.sha256(mapping.encode()).hexdigest()))
  if Path('/proc/cpuinfo').exists():
   write('cpu',{'model':next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith(('model name','CPU part')))})
  opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',*opts],'configure')
  libs={};base=sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()
  for key in ('base','prior','indexed','no-primary','map-only','identical'):
   if key not in ('base','identical'):
    patch=r/('prior.patch' if key=='prior' else 'indexed.patch');run(['git','apply',patch],'apply-'+key,s)
    if key in ('no-primary','map-only'):
     run(['git','restore','--source='+base,'--','arch/Mips/MipsDisassembler.c'],'restore-primary-'+key,s)
    if key=='map-only':run(['git','restore','--source='+base,'--','arch/Mips/MipsGenDirectDecoder.inc'],'restore-generated-'+key,s)
   run(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+key);lib=t/(key+'.so');shutil.copy2(b/'libcapstone.so',lib);libs[key]=lib
   if key not in ('base','identical'):run(['git','restore','.'],'restore-'+key,s)
  run(['clang++','-std=c++17','-O2','-I',s/'include',r/'diagnose.cpp','-ldl','-o',t/'probe'],'compile-probe')
  for key in [k for k in libs if k!='base']:run([t/'probe',libs['base'],libs[key]],'probe-'+key)
  run(['clang++','-std=c++17','-O2','-I',s/'include',r/'verify-mips.cpp','-ldl','-o',t/'sweep'],'build-sweep')
  for k in ('prior','indexed','no-primary','identical'):
   with(e/('sweep-'+k+'.log')).open('w')as out:rc=sp.run([t/'sweep',libs['base'],libs[k]],stdout=out,stderr=sp.STDOUT).returncode
   print(k,rc,flush=True)
  write('complete',dict(source=base,variants=list(libs)))
 finally:
  n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
