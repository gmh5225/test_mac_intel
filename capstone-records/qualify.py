from pathlib import Path
import hashlib,json,os,platform,re,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source';cc=os.environ['MEASURE_CC']
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True);log=e/(label+'.log')
 with log.open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,log.read_text()[-1300:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
with tempfile.TemporaryDirectory(prefix='capstone-qualified-a64-') as tmp:
 t=Path(tmp); rec={}; host=platform.machine().lower()
 try:
  configs={'dedicated':['AARCH64'],'diet':['AARCH64'],'four':['X86','AARCH64','ARM','MIPS'],'seven':['X86','AARCH64','ARM','MIPS','LOONGARCH','RISCV','SPARC']}
  if cc=='gcc' and host=='x86_64':configs['x86']=['X86']
  for label in ('base','inline','release'):
   if label!='base':run(['git','apply',r/(label+'.patch')],'apply-'+label,s)
   rec[label]={}
   for kind,arches in configs.items():
    b=t/kind;run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_DIET='+('ON' if kind=='diet' else 'OFF'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in arches]],'configure-'+label+'-'+kind)
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label+'-'+kind)
    objs={str(x.relative_to(b)):hashlib.sha256(x.read_bytes()).hexdigest()for x in (b/'CMakeFiles/capstone.dir').rglob('*.o')};assert len(objs)>9
    rec[label][kind]=objs;write('objects',rec)
    if label=='release':
     expected=('inline' if kind in ('diet','dedicated') and (cc=='clang' or host in ('aarch64','arm64')) else 'base')
     assert objs==rec[expected][kind],(kind,expected,[k for k in objs if objs[k]!=rec[expected][kind][k]])
     if expected=='inline':assert objs!=rec['base'][kind]
     if kind in ('dedicated','diet'):
      run(['cmake','--build',b,'--target','mcinst','aarch64_postprocess',*(['cstest'] if kind=='dedicated' else []),'--parallel','4'],'build-units-'+kind)
      run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_(mcinst|aarch64_postprocess)$'],'run-units-'+kind)
      if kind=='dedicated':
       exe=next(x for x in b.rglob('cstest')if x.is_file());run([exe,s/'tests/MC/AArch64'],'aarch64-mc');f=e/'aarch64-mc.log';z=f.read_bytes();f.unlink();assert b'Failed: 0' in z;write('mc',dict(digest=hashlib.sha256(z).hexdigest(),summary=z[-600:].decode()))
   if label!='base':run(['git','apply','-R',r/(label+'.patch')],'restore-'+label,s)
  write('complete',dict(configs=list(configs),compiler=cc,host=host))
 finally:
  n=sum(x.stat().st_size for x in t.rglob('*')if x.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=n,removed=not t.exists()))
