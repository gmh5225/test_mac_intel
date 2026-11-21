from pathlib import Path
import hashlib,json,os,re,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;p=r.parent;s=p/'source';out=p/'evidence';out.mkdir(exist_ok=True)
def record(k,v):(out/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(name,argv,cwd=None):
 with(out/(name+'.log')).open('w')as f:z=sp.run(argv,cwd=cwd,stdout=f,stderr=sp.STDOUT)
 if z.returncode:print((out/(name+'.log')).read_text()[-3500:]);z.check_returncode()
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
m=json.loads((r/'tree.json').read_text());assert git('rev-parse','HEAD')==m['parent'] and hashlib.sha256((r/'candidate.patch').read_bytes()).hexdigest()==m['sha256']
run('apply',['git','-C',s,'apply','--index',r/'candidate.patch']);assert git('write-tree')==m['tree']
t=Path(tempfile.mkdtemp());kind=os.environ['GUARD_KIND'];flags=['-fsanitize=address','-fno-omit-frame-pointer']if kind=='asan'else[]
try:
 run('cmake',['cmake','-G','Ninja','-S',s,'-B',t/'b','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS='+' '.join(flags),'-DCMAKE_EXE_LINKER_FLAGS='+' '.join(flags),'-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'])
 units=['x86_buffer_bounds','x86_x87_environment','x86_x87_environment_hardware'] if kind=='release' else ['x86_buffer_bounds']
 run('build',['cmake','--build',t/'b','--parallel','4','--target','capstone_static',*units])
 run('unit',['ctest','--test-dir',t/'b','--no-tests=error','--output-on-failure','-V','-R','^unit_('+'|'.join(units)+')$'])
 run('link',['clang++','-std=c++17','-O2',*flags,'-I',s/'include','-I',s,r/'guard.cpp',t/'b/libcapstone.a','-o',t/'guard'])
 run('guard',[t/'guard'])
 n=int(re.search(r'for (\d+) protected-page', (out/'guard.log').read_text())[1]);assert n==3*8*8192*16
 record('complete',dict(tree=m['tree'],kind=kind,states=n,tests=units,cpu=[l for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith(('model name','vendor_id'))][:2],hardware_executed=kind=='release'and 'Skipped'not in (out/'unit.log').read_text()))
finally:
 total=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);record('cleanup',dict(bytes=total,removed=not t.exists()))
