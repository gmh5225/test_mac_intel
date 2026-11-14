from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
import corpus
from layout import Layouts
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir()
def save(name,value):(e/name).write_text(json.dumps(value,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as log:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1500:]))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
reference='729680277dd762704ea3270291b7a75318f51583'
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==reference
w=Path(tempfile.mkdtemp(prefix='capstone-cross-arch-layout-'))
try:
 cc=os.environ['MEASURE_CC'];b=w/'build'
 save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([cc,'--version'],text=True)))
 all_cases=corpus.prepare(r,w,e,lambda args,label:run(args,label))
 cases=[x for x in all_cases if x['name'] in ('mips64el-ls','arm64-ls','putty-32-0.85')];assert len(cases)==3
 consumer=w/'single.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',consumer],'consumer')
 run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ('X86','ARM','AARCH64','MIPS')],'-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
 layouts=Layouts(w,e,save,run);objects={}
 for label in ('integer','scan'):
  if label=='scan':run(['git','apply',r/'scan.patch'],'apply-scan',s)
  run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
  objdir=b/'CMakeFiles/capstone.dir';objects[label]={str(o.relative_to(objdir)):sha(o)for o in objdir.rglob('*.o')}
  if label=='scan':
   changed=[k for k,v in objects[label].items()if v!=objects['integer'][k]]
   assert changed==['arch/X86/X86DisassemblerDecoder.c.o'],changed
   save('objects-scan.json',dict(changed=changed,identical=len(objects[label])-len(changed)))
  executable=w/('original-'+label);linkmap=w/(label+'.map')
  run(['clang++',consumer,b/'libcapstone.a','-lm','-Wl,-Map='+str(linkmap),'-o',executable],'link-'+label)
  layouts.capture(label,objdir,linkmap,b/'libcapstone.a',consumer,executable)
  if label=='scan':run(['git','apply','-R',r/'scan.patch'],'restore-scan',s)
 layouts.prepare(consumer,None)
 os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 for case in cases:
  for mode in (0,1,2):layouts.measure_mixed(case,mode)
 assert len(layouts.rows)==27
 save('complete.json',dict(cases=27,success=True,native_qualification=False,scope='Original archive, equal text extent, equal text and rodata extent; frozen machine code across MIPS64, AArch64, PE32'))
finally:
 files=[p for p in w.rglob('*')if p.is_file()];amount=sum(p.stat().st_size for p in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),files=len(files),bytes=amount))
