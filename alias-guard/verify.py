from pathlib import Path
import hashlib,json,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;q=json.loads((r/'tree.json').read_text());output=Path(sys.argv[2]).resolve();output.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp(dir=output));s=t/'source';b=t/'build';repo=sys.argv[1]
def put(f,v):(output/(f+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(a,cwd=None):sp.run(a,cwd=cwd,check=True)
def val(a,cwd=None):return sp.check_output(a,cwd=cwd,text=True).strip()
try:
 run(['git','init','-q',s]);run(['git','-C',s,'fetch','--quiet','--depth=1',repo,q['parent']]);run(['git','-C',s,'checkout','-q','--detach','FETCH_HEAD'])
 assert val(['git','-C',s,'rev-parse','HEAD'])==q['parent']
 paths={'x86':['X86'],'systemz':['SYSTEMZ'],'xtensa':['XTENSA'],'diet-x86':['X86','DIET'],'diet-all':['AARCH64','ARM','MIPS','POWERPC','RISCV','SPARC','LOONGARCH','DIET']}
 for arch in ('AARCH64','ARM','MIPS','POWERPC','RISCV','SPARC','LOONGARCH'):paths[arch.lower()]=[arch]
 paths['all-aliases']=['AARCH64','ARM','MIPS','POWERPC','RISCV','SPARC','LOONGARCH']
 objects={};failures={}
 for stage in ('parent','commit'):
  if stage=='commit':
   patch=r/'candidate.patch';assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];run(['git','-C',s,'apply','--index',patch]);assert val(['git','-C',s,'write-tree'])==q['tree']
  symbols={}
  for name,arch in paths.items():
   obj=t/'alias.o';args=['clang','-std=c99','-Werror=unused-function','-O3','-g0','-DNDEBUG','-DCAPSTONE_USE_SYS_DYN_MEM','-I.','-Iinclude']
   args.extend('-DCAPSTONE_DIET' if a=='DIET' else '-DCAPSTONE_HAS_'+a for a in arch)
   p=sp.run(args+['-c','AliasPatternLookup.c','-o',obj],cwd=s,capture_output=True,text=True)
   if stage=='parent' and name in ('x86','systemz','xtensa'):
    assert p.returncode and "unused function 'matchAliasBlock'" in p.stderr,(name,p.stderr);failures[name]=p.stderr
   else:
    if p.returncode:print(p.stderr,flush=True);p.check_returncode()
    symbols[name]=hashlib.sha256(obj.read_bytes()).hexdigest()
  objects[stage]=symbols
 previous=objects['parent'];fixed=objects['commit'];assert all(fixed[k]==v for k,v in previous.items()) and len(failures)==3 and len(fixed)==len(paths)
 put('objects',dict(hashes=objects,reproduced=failures))
 cfg=['cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'];run(cfg)
 tests=['x86_simple_output','x86_scan_batch','x86_buffer_bounds','x86_reg_access','x86_exchange_access']
 run(['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*tests]);run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(tests)+')$'])
 put('checked',dict(complete=True,tests=tests,tree=q,arch=platform.machine(),compiler=val(['clang','--version']).splitlines()[0],profiles=len(paths)))
finally:
 size=sum(i.stat().st_size for i in t.rglob('*') if i.is_file() and not i.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
