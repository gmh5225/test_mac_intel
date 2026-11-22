from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;meta=json.loads((r/'tree.json').read_text());old=json.loads((r/'previous.json').read_text());out=Path(sys.argv[2]).resolve();out.mkdir(exist_ok=True);repo=sys.argv[1];t=Path(tempfile.mkdtemp(dir=out));s=t/'src';b=t/'build';env=dict(os.environ,ZERO_AR_DATE='1')
def run(a):sp.run(a,env=env,check=True)
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def record(f,j):(out/(f+'.json')).write_text(json.dumps(j,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
try:
 run(['git','init','-q',s]);g('fetch','--depth=1',repo,meta['parent']);g('checkout','--quiet','--detach','FETCH_HEAD')
 cfg=['cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers']
 cfg.extend('-DCAPSTONE_'+k+'_SUPPORT=ON'for k in ('X86','AARCH64','ARM','MIPS'));units=['x86_simple_output','x86_scan_batch','x86_reg_access','x86_buffer_bounds','aarch64_scan','mips_scan','text_option','detail_option']
 evidence={}
 for k,z in [('tested',old),('release',meta)]:
  g('restore','--source','HEAD','--staged','--worktree','--','.');f=r/(k+'.patch');assert sha(f)==z['sha256'];g('apply','--index',str(f));assert g('write-tree')==z['tree']
  run(cfg);run(['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units])
  run(['ctest','--test-dir',b,'--no-tests=error','--parallel','2','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
  a=b/'libcapstone.a';members=sp.check_output(['ar','t',a],text=True).splitlines();assert len(members)==len(set(members)) and any('AliasPatternLookup' in n for n in members)
  record_members={n:hashlib.sha256(sp.check_output(['ar','p',a,n])).hexdigest()for n in members}
  linked=[i for i in b.glob('libcapstone*')if not i.is_symlink() and (i.suffix=='.dylib' or '.so.' in i.name)];assert len(linked)==1
  evidence[k]=dict(tree=z['tree'],archive=sha(a),library=sha(linked[0]),members=record_members,order=members,tests=units)
  if k=='release':
   for f_ in ('alias_pattern_rows','x86_mapping_counts','x86_operand_specializations'):run(['python3','-B',s/('suite/synctools/'+f_+'.py'),'--check'])
 for key in ('members','order','library','archive'):
  assert evidence['tested'][key]==evidence['release'][key],key
 record('checked',dict(complete=True,compiler=sp.check_output(['clang','--version'],text=True).splitlines()[0],arch=platform.machine(),source=meta,results=evidence))
finally:
 count=sum(p.stat().st_size for p in t.rglob('*')if p.is_file()and not p.is_symlink());shutil.rmtree(t);record('cleanup',dict(removed=not t.exists(),bytes=count))
