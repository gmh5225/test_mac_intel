from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';out=root/'evidence';out.mkdir(exist_ok=True);metadata=json.loads((r/'compositions.json').read_text());fam=os.environ['FAMILY']
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(n,o):(out/(n+'.json')).write_text(json.dumps(o,indent=2)+'\n')
def run(n,*cmd):
 with (out/(n+'.log')).open('w') as f:v=sp.run(cmd,stdout=f,stderr=sp.STDOUT)
 if v.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2200:],flush=True);v.check_returncode()
def members(archive):
 names=sp.check_output(['ar','t',archive],text=True).splitlines();assert len(names)==len(set(names));return {n:hashlib.sha256(sp.check_output(['ar','p',archive,n])).hexdigest()for n in names}
def sha(x):return hashlib.sha256(x.read_bytes()).hexdigest()
t=Path(tempfile.mkdtemp());results={};summary={}
try:
 nd=root/'neverd-config';assert sp.check_output(['git','-C',nd,'rev-parse','HEAD'],text=True).strip()==metadata['dev']
 for f,b in metadata['blobs'].items():assert sp.check_output(['git','-C',nd,'hash-object',f],text=True).strip()==b
 txt=(nd/'CMakeLists.txt').read_text();a=txt.index('# --- Capstone (our fork');z=txt.index('# --- NeverD CMake helpers',a)
 h=t/'project';(h/'third_party').mkdir(parents=True);(h/'cmake').mkdir();(h/'third_party/capstone').symlink_to(s,target_is_directory=True);shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',h/'cmake')
 (h/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Native LANGUAGES C CXX)\n'+txt[a:z])
 flags=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
 for key,item in metadata['groups'][fam].items():
  summary[key]={}
  for which in ('before','after'):
   k=key+'-'+which;spec=item[which];assert g('rev-parse','HEAD')==metadata['checkout']
   g('restore','--source','HEAD','--staged','--worktree','--','.');df=r/(k+'.patch');assert sha(df)==spec['sha256']
   if df.stat().st_size:g('apply','--index',str(df))
   assert g('write-tree')==spec['tree'];result={}
   for profile,project in [('project',h),('x86',s)]:
    b=t/profile if profile=='x86' else t/'profile-build'
    target=['capstone_static'];units=['x86_simple_output','x86_reg_access','x86_buffer_bounds','x86_scan_batch']
    run('configure-'+k+'-'+profile,'cmake','-S',project,'-B',b,*flags,'-DCAPSTONE_BUILD_CSTEST='+('OFF' if profile=='project' else 'ON'))
    db=json.loads((b/'compile_commands.json').read_text());names={Path(x['file']).name for x in db};near={Path(x['file']).name for x in db if '-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT' in x['command'].split()};assert near==({'X86Sse64Output.c'} if profile=='project' else set())
    assert ('AArch64InstPrinter.c' in names)==('MipsMapping.c' in names)==(profile=='project')
    run('build-'+k+'-'+profile,'cmake','--build',b,'--parallel','4','--target',*target,*(units if profile=='x86' and which=='after' else []))
    archive,=list(b.rglob('libcapstone.a'));result[profile]=members(archive)
    if which=='after' and profile=='x86':
     run('units-'+key,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
     if key.startswith('mixed'):
      for test in ('mixed',):
       o=t/'wrap.o';exe=t/'oracle';run('wrapper-'+k+test,'clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include','-c',r/(test+'.c'),'-o',o);run('link-'+k+test,'clang++','-O2','-I',s/'include',r/(test+'.cpp'),o,archive,'-o',exe);run('guard-'+k+test,exe)
     if 'indexed' in key:
      o=t/'wrap.o';exe=t/'oracle';run('wrapper-'+k+'indexed','clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include','-c',r/'indexed.c','-o',o);run('link-'+k+'indexed','clang++','-O2','-I',s/'include',r/'indexed.cpp',o,archive,'-o',exe);run('guard-'+k+'indexed',exe)
   if which=='before':prev=result
   else:
    assert prev['project']==result['project'] and len(prev['project'])>=45
    assert set(prev['x86'])==set(result['x86']);diff=sorted(n for n in prev['x86']if prev['x86'][n]!=result['x86'][n]);assert set(diff)=={'cs.c.o','X86VectorFallback64.c.o'},diff
    summary[key]=dict(project_members=len(result['project']),x86_members=len(result['x86']),changed_x86=diff)
   results[k]=result;save('members-'+k,result)
 save('pass',dict(complete=True,family=fam,source=metadata['groups'][fam],summary=summary,compiler=sp.check_output(['clang','--version'],text=True)))
finally:
 n=sum(p.stat().st_size for p in t.rglob('*')if p.is_file() and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
