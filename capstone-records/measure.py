from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent
out=r.parent/'evidence';out.mkdir()
cc=os.environ['MEASURE_CC']
meta=json.loads((r/'candidate.json').read_text())
control_name='gnu' if cc=='gcc' else 'clang'
control=json.loads((r/(control_name+'.json')).read_text())
work=Path(tempfile.mkdtemp(prefix='capstone-gnu-constant-identity-'))
s,b=work/'source',work/'build'
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(n,args,cwd=None):
 print(n,flush=True)
 with (out/(n+'.log')).open('wb') as f:
  q=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT)
 if q.returncode:raise RuntimeError((n,(out/(n+'.log')).read_text(errors='replace')[-1800:]))
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
try:
 run('clone',['git','clone','-q','--shared','--no-checkout',r.parent/'source',s]);git('checkout','-q','--detach',meta['parent'])
 options=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS')],'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
 run('configure',['cmake','-S',s,'-B',b,*options])
 run('consumer',['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',work/'single.o'])
 objects={};binaries={};shared={}
 for label,source,patch in [('control',control,r/(control_name+'.patch')),('candidate',meta,r/'candidate.patch')]:
  assert sha(patch)==source['sha256'];git('apply','--index',str(patch));assert git('write-tree')==source['tree']
  run('build-'+label,['cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4'])
  root=b/'CMakeFiles/capstone.dir';objects[label]={str(f.relative_to(root)):sha(f) for f in root.rglob('*.o')}
  run('link-'+label,['clang++',work/'single.o',b/'libcapstone.a','-lm','-o',work/label])
  binaries[label]=sha(work/label);shared[label]=sha(b/'libcapstone.so')
  git('reset','--hard',meta['parent']);git('clean','-fdx');assert not git('status','--porcelain')
 save('objects',objects);save('binaries',binaries);save('shared-libraries',shared)
 assert len(objects['candidate'])==38 and objects['control']==objects['candidate']
 assert binaries['control']==binaries['candidate'] and shared['control']==shared['candidate']
 save('complete',dict(success=True,source=meta,control=control,control_family=control_name,compiler=sp.check_output([cc,'--version'],text=True),runtime_objects=38,all_runtime_objects_identical=True,linked_consumer_identical=True,shared_library_identical=True,native_timing='Not repeated for byte-identical binaries. Source workload evidence is inherited with its existing limitations.'))
finally:
 size=sum(f.stat().st_size for f in work.rglob('*') if f.is_file());shutil.rmtree(work);save('cleanup',dict(bytes=size,removed=not work.exists()))
