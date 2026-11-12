"""Verify the release against both the shipping library and the isolated mixed-ISA iterator."""
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['TOOLCHAIN'];win=os.name=='nt'
def write(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True);log=e/(label+'.log')
 with log.open('w')as f:rv=sp.run([str(x)for x in args],cwd=cwd,stdout=f,stderr=sp.STDOUT)
 if rv.returncode:raise RuntimeError((label,log.read_text(errors='replace')[-1800:]))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def clean(path):
 def writable(fn,v,exc):os.chmod(v,0o700);fn(v)
 shutil.rmtree(path,onerror=writable)
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()=='e2bfdc5ca6c847404c2c60e24fcb2567ac835ec6'
t=Path(tempfile.mkdtemp(prefix='capstone-x86-record-release-'));done={}
try:
 configs={'four':(['X86','ARM','AARCH64','MIPS'],[]),'dedicated':(['X86'],[]),'diet':(['X86'],['-DCAPSTONE_BUILD_DIET=ON']),'reduced':(['X86'],['-DCAPSTONE_X86_REDUCE=ON']),'intel':(['X86'],['-DCAPSTONE_X86_ATT_DISABLE=ON']),'seven':(['X86','ARM','AARCH64','MIPS','SPARC','RISCV','LOONGARCH'],[])}
 configs['aarch64']=(['AARCH64'],[]);configs['arm64-diet']=(['AARCH64'],['-DCAPSTONE_BUILD_DIET=ON'])
 if win:configs={os.environ['PROFILE']:configs[os.environ['PROFILE']]}
 if not win:configs['arm-only']=(['AARCH64'],[])
 for label in ('release',):
  if label!='base':run(['git','-c','core.autocrlf=false','apply',r/(os.environ['FORMS']+'.patch')],'apply-'+label,s)
  if os.environ['FORMS']=='vector':
   unit=s/'tests/unit/x86_simple_output.c';v=unit.read_text();unit.write_text(v[:v.index('int main(void)')]+(r/'checked-evex.cfrag').read_text())
  for name,(arches,opts) in configs.items():
   b=t/name
   args=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if cc=='MT' else 'OFF')]if win else ['-G','Ninja','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_BUILD_MACOS_THIN=ON']
   run(['cmake','-S',s,'-B',b,*args,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches],*opts],'configure-'+label+'-'+name)
   targets=['capstone_static']
   if label=='release' and name!='arm-only':targets+=['api','x86_encoding_accuracy','x86_relative_jump','x86_printer_prechecked','sstream','detail_option']+(['x86_simple_output']if name not in ('diet','reduced')else [])
   if os.environ['FORMS']=='arm64':targets=['capstone_static','aarch64_scan']
   run(['cmake','--build',b,'--config','Release','--target',*targets,'--parallel','4'],'build-'+label+'-'+name)
   key=label+'-'+name
   if not win:
    root=b/'CMakeFiles/capstone.dir';objs={str(f.relative_to(root)):digest(f)for f in root.rglob('*.o') if f.name!='X86OutputIterator.c.o' or label!='base'};assert len(objs)>8;write('objects-'+key,objs)
    if label=='release':
     original=json.loads((e/('objects-base-'+name+'.json')).read_text());owned=json.loads((e/('objects-owned-'+name+'.json')).read_text());member='arch/X86/X86OutputIterator.c.o';expected_public=name in ('dedicated','intel') and platform.system()=='Linux';changed=[k for k in original if objs[k]!=original[k]];assert changed==(['cs.c.o'] if expected_public else []),(key,changed);extra=set(objs)-set(original);assert extra==({member} if 'X86'in arches else set()),(name,extra)
     if not expected_public:assert objs==owned,(name,[k for k in objs if owned[k]!=objs[k]])
     done[name]=dict(original_objects=len(original),changed=changed,extra=sorted(extra),matches_verified_private=not expected_public)
   if label=='release' and len(targets)>1:
    run(['ctest','--test-dir',b,'--build-config','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(targets[1:])+')$'],'tests-'+name)
    if win:done[name]=dict(tests=targets[1:])
   write('progress',done)

 write('complete',dict(host=platform.platform(),compiler=cc,configs=done))
finally:
 n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());clean(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
