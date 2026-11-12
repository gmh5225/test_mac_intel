from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';out=root/'abi-evidence';out.mkdir();target=os.environ['TARGET_TRIPLE'];runner=os.environ['EMULATOR'];compiler=target+'-gcc';cxx=target+'-g++';done=[]
def save(name,obj):(out/(name+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,tag,cwd=None):
 with (out/(tag+'.log')).open('w') as f:p=sp.run(list(map(str,args)),stdout=f,stderr=sp.STDOUT,cwd=cwd)
 if p.returncode:raise RuntimeError((tag,(out/(tag+'.log')).read_text(errors='replace')[-1000:]))
t=Path(tempfile.mkdtemp(prefix='capstone-output-abi-'))
try:
 for name in ('integer','relative','memory'):
  run(['git','apply',r/(name+'.patch')],'apply-'+name,s);b=t/'build'
  run(['cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_SYSTEM_NAME=Linux','-DCMAKE_SYSTEM_PROCESSOR='+target.split('-')[0],'-DCMAKE_C_COMPILER='+compiler,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure-'+name)
  run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+name)
  unit=t/'unit';run([compiler,'-O2','-static','-I',s/'include',s/'tests/unit/x86_simple_output.c',b/'libcapstone.a','-lm','-o',unit],'unit-build-'+name);run([runner,unit],'unit-'+name)
  gen=t/'generate';run([cxx,'-std=c++17','-O2','-static','-I',s/'include',s/'suite/synctools/x86_simple_output.cpp',b/'libcapstone.a','-lm','-o',gen],'gen-build-'+name)
  v=sp.run([runner,gen],capture_output=True,check=True);assert v.stdout==(s/'arch/X86/X86GenSimpleOutput.inc').read_bytes();done.append(dict(candidate=name,elf=sp.check_output(['file',unit],text=True).strip(),table_sha256=hashlib.sha256(v.stdout).hexdigest(),generator=v.stderr.decode().strip()));save('verified',done);run(['git','apply','-R',r/(name+'.patch')],'restore-'+name,s)
 save('complete',dict(target=target,model=runner,checks=done))
finally:
 n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
