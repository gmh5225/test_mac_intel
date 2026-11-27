"""Verify the shipping and i386-based ARM changes in complete library builds."""
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;src=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);q=json.loads((r/'source.json').read_bytes())
def put(name,data):(e/(name+'.json')).write_text(json.dumps(data,indent=1)+'\n')
def run(*args,**kw):sp.run(args,check=True,**kw)
def out(*args,**kw):return sp.check_output(args,text=True,**kw).strip()
def dig(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def switch(stage):
 run('git','-C',src,'restore','--source','HEAD','--staged','--worktree','--','.')
 p=r/(stage+'.patch');assert dig(p)==q[stage]['patch'];run('git','-C',src,'apply','--index',p);assert out('git','-C',src,'write-tree')==q[stage]['tree']
def verify_unit(lib,b,stage,profile):
 exe=b/'test-detail-views';run('cc','-std=c11','-I',src/'include',src/'tests/unit/detail_views.c',lib,'-o',exe);run(exe,env=dict(os.environ,LD_LIBRARY_PATH=str(lib.parent),DYLD_LIBRARY_PATH=str(lib.parent)))
def only(xs):
 xs=list(xs);assert len(xs)==1,xs;return xs[0]
w=Path(tempfile.mkdtemp());os.environ['ZERO_AR_DATE']='1';darwin=platform.system()=='Darwin';isa=platform.machine()
try:
 assert out('git','-C',src,'rev-parse','HEAD')==q['checkout']
 proj=w/'product';(proj/'third_party').mkdir(parents=True);(proj/'third_party/capstone').symlink_to(src);(proj/'cmake').mkdir()
 for a,b in [('CMakeLists.txt','consumer.cmake'),('cmake/NeverDCapstoneCompilerOptions.inc','consumer-options.inc')]:
  assert dig(r/b)==q['recipe'][b];shutil.copyfile(r/b,proj/a)
 results={};stages=('ship','group','arm','combined','reference')
 profiles=['product','arm-both','arm-static','arm-shared','arm-diet','arm-debug','make']
 for profile in profiles:
  results[profile]={};b=w/'build';b.mkdir()
  measured=(*stages[:2],'makeShip','makeGroup',*stages[2:4]) if profile in ('product','make') else None
  for stage in (measured if measured else stages if profile.startswith('arm') and profile not in ('arm-debug','arm-diet') else stages[:-1]):
   switch(stage)
   active=profile in ('arm-both','arm-static','arm-shared') and stage in ('arm','combined','reference') and not darwin
   if profile=='make':
    run('make','-C',src,'-j4','CC=clang','CAPSTONE_ARCHS=arm','CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_SHARED=no','CAPSTONE_STATIC=yes','BUILDDIR='+str(b))
    lib=b/'libcapstone.a';verify_unit(lib,b,stage,profile)
    deps=list(b.rglob('Mapping.d'));fixed=stage not in ('ship','group')
    assert bool(deps)==fixed
    if fixed:assert ('MappingAliasDetails.inc' in only(deps).read_text())==(stage in ('arm','combined'))
    results[profile][stage]=dict(passed=True,tracked_include=stage in ('arm','combined'),depfile=fixed,library=dig(lib))
    continue
   product=profile=='product';diet=profile=='arm-diet';debug=profile=='arm-debug'
   static=profile!='arm-shared';shared=not product and profile!='arm-static';variants=['capstone_'+v for v,yes in [('static',static),('shared',shared)] if yes]
   flags=['-DCMAKE_BUILD_TYPE='+('Debug' if debug else 'Release'),'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON']
   if product:flags+=['-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers']
   else:flags+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS='+('ON'if static else'OFF'),'-DCAPSTONE_BUILD_SHARED_LIBS='+('ON'if shared else'OFF'),'-DCAPSTONE_BUILD_DIET='+('ON'if diet else'OFF')]
   run('cmake','-G','Ninja','-S',proj if product else src,'-B',b,*flags)
   run('cmake','--build',b,'--target',*variants,'--parallel','4')
   commands=json.loads((b/'compile_commands.json').read_bytes())
   active_units={Path(v['file']).name for v in commands if '-DCAPSTONE_ARM_INLINE_ALIAS_DETAILS' in v['command']}
   assert active_units==({'ARMInstPrinter.c','ARMMapping.c'} if active else set()),(stage,profile,active_units)
   libs={}
   if static:libs['static']=only(b.rglob('libcapstone.a'))
   if shared:libs['shared']=only(p for p in b.rglob('libcapstone.*.dylib'if darwin else'libcapstone.so.*')if not p.is_symlink())
   for lib in libs.values():verify_unit(lib,b,stage,profile)
   picked=next(iter(libs.values()));exe=b/'observe'
   run('c++','-O3','-std=c++17','-I',src/'include',r/'time.cpp',picked,'-o',exe)
   objects={str(f.relative_to(b)):dig(f) for f in b.rglob('*.c.o')}
   result={'libraries':{k:dig(v)for k,v in libs.items()},'linked':dig(exe),'objects':objects,'active':sorted(active_units),'passed':True}
   if product:assert {'ARMMapping.c.o','AArch64Mapping.c.o','MipsMapping.c.o','PPCMapping.c.o','X86Mapping.c.o','RISCVMapping.c.o'} <= {Path(k).name for k in objects}
   results[profile][stage]=result
  if profile in ('product','make'):
   a=results[profile]
   for core,improved,arm in (('ship','makeShip','arm'),('group','makeGroup','combined')):
    if profile=='product':assert a[core]==a[improved]==a[arm]
    else:assert a[core]['library']==a[improved]['library']
  if profile=='make':
   from make_increment import verify
   receipts=[]
   for cc,uni in ([('clang',False),('clang',True)]if darwin else [('clang',False),('gcc',False)]):
    tmp=w/('make-probe-'+cc+str(uni));tmp.mkdir()
    receipts.append(verify(src,tmp,cc,uni));shutil.rmtree(tmp)
   put('incremental-make',receipts)
  put('stages',results)
  a=results[profile]
  if profile=='product' or profile=='arm-diet' or darwin and profile.startswith('arm') and profile!='arm-debug':
   assert a['ship']==a['arm'] and a['group']==a['combined'],profile
  elif profile in ('arm-both','arm-static','arm-shared'):
   assert a['ship']==a['group'] and a['arm']==a['combined']==a['reference'],profile
   assert a['arm']['libraries']!=a['ship']['libraries']
   assert (a['arm']['linked']==a['ship']['linked'])==(profile=='arm-shared')
  shutil.rmtree(b)
 put('complete',dict(complete=True,source=q,system=platform.system(),isa=isa,compiler=out('clang','--version').splitlines()[0],profiles=profiles))
finally:
 size=sum(p.stat().st_size for p in w.rglob('*') if p.is_file() and not p.is_symlink());shutil.rmtree(w);put('cleanup',dict(removed=not w.exists(),bytes=size))
