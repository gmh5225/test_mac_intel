from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;src=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True);q=json.loads((r/'tree.json').read_text());t=Path(tempfile.mkdtemp())
def save(n,z):(out/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(name,args,ok=True):
 with (out/(name+'.log')).open('w')as f:p=sp.run(args,stdout=f,stderr=sp.STDOUT)
 if ok and p.returncode:print((out/(name+'.log')).read_text()[-4500:]);p.check_returncode()
 return p.returncode
def git(*a):return sp.check_output(['git','-C',src,*a],text=True).strip()
try:
 assert git('rev-parse','HEAD')==q['parent'];patch=r/'candidate.patch';assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256']
 assert run('original',['gcc','-O3','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I'+str(src/'include'),'-Wall','-Werror','-Wshadow=local','-c',src/'arch/X86/X86BatchScan.c','-o',t/'o'],False)!=0
 msg=(out/'original.log').read_text();assert 'shadow' in msg and 'plan' in msg
 git('apply','--index',str(patch));assert git('write-tree')==q['tree']
 prof=os.environ['PROFILE'];b=t/'build';cfg=['cmake','-S',src,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 cfg+=dict(full=[],diet=['-DCAPSTONE_BUILD_DIET=ON'],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[prof]
 run('configure',cfg);names={z['name']for z in json.loads(sp.check_output(['ctest','--test-dir',b,'--show-only=json-v1']))['tests']}
 check=[n for n in ['x86_scan_batch','x86_simple_output','x86_reg_access','x86_buffer_bounds','x86_exchange_access','x86_encoding_accuracy'] if 'unit_'+n in names]
 assert len(check)>=4 and 'x86_scan_batch' in check
 run('build',['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*check])
 run('units',['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(check)+')$'])
 save('complete',dict(complete=True,source=q,compiler=sp.check_output(['gcc','--version'],text=True).splitlines()[0],tests=check,profile=prof))
finally:
 amount=sum(x.stat().st_size for x in t.rglob('*')if x.is_file()and not x.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=amount))
