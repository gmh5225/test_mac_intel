from pathlib import Path
import json,subprocess as sp,re,shutil,tempfile
w=Path('neverd').resolve()
out=Path('cursor-evidence/compiler-cxx').resolve()
out.mkdir(parents=True,exist_ok=True)
source=(w/'unittests/lift/aarch64/AArch64AsyncUnwindFixtures.def').read_text()
bodies=dict(re.findall(r'ASYNC_FRAME_TEXT\((kCatch\w+), R"cpp\((.*?)\)cpp"\)',source,re.S))
cfg=json.loads(Path('neverd-arm64e-variadic/CxxControl.def').read_text())
for name,body in [('catcher.cpp',bodies['kCatchBody']),('provider.cpp',bodies['kCatchProvider']),('driver.cpp',bodies['kCatchDriver']),('probe.cpp',cfg['args_source']),('probe-driver.cpp',cfg['args_driver']),('single.cpp',cfg['single'])]:
 (out/name).write_text(body)
def invoke(args,name):
 run=sp.run(list(map(str,args)),cwd=out,capture_output=True,text=True,timeout=35)
 (out/(name+'.txt')).write_text(run.stdout+run.stderr)
 return {'exit':run.returncode,'text':(run.stdout+run.stderr)[-700:]}
report={}
for arch in ('arm64e','arm64'):
 cc=['/usr/bin/clang++','-target',arch+'-apple-macos15','-std=c++20','-fno-omit-frame-pointer']
 provider=out/(arch+'-provider.dylib')
 drv=out/(arch+'-driver')
 one=out/(arch+'-single')
 for args in ([*cc,'-O2','-dynamiclib','provider.cpp','-o',provider],[*cc,'-O2','driver.cpp','-o',drv],[*cc,'-O2','single.cpp','-o',one]):
  sp.run(args,cwd=out,check=True)
 for n,flags in [('O0',['-O0']),('O2',['-O2']),('dwarf',['-O2','-DNEVERD_TEST_DWARF_CATCH']),('args',['-O2','-DNEVERD_TEST_STACK_ARGS'])]:
  tag=arch+'-'+n
  f=out/(tag+'.dylib')
  sp.run([*cc,*flags,'-dynamiclib','catcher.cpp',str(provider),'-o',str(f)],cwd=out,check=True)
  sp.run([*cc,*flags,'-S','catcher.cpp','-o',tag+'.s'],cwd=out,check=True)
  sp.run([*cc,*flags,'-DRETURN_ADJUSTMENT=1','-c','catcher.cpp','-o',tag+'.o'],cwd=out,check=True)
  report[tag]={'driver':invoke([drv,f],tag+'-driver')}
  for v in (0,1,2,3):report[tag]['path-'+str(v)]=invoke([one,f,v],tag+'-path-'+str(v))
  for name,args in [('unwind',['xcrun','llvm-objdump','--macho','--unwind-info',f]),('text',['otool','-tvV',f]),('loads',['otool','-l',f]),('dwarf',['xcrun','dwarfdump','--eh-frame',f]),('fixups',['xcrun','dyld_info','-fixups',f]),('syms',['nm','-nm',f])]:
   invoke(args,tag+'-'+name)
 for size in (0,16):
  p=out/(arch+'-sp-'+str(size))
  sp.run([*cc,'-O2',f'-DRECORD_SIZE="{size}"','probe.cpp','probe-driver.cpp','-o',str(p)],cwd=out,check=True)
  report[p.name]=invoke([p],p.name)
with (out/'observed.json').open('w') as f:json.dump(report,f,indent=2)
print(json.dumps({k:{a:x['exit'] for a,x in v.items()} if 'driver' in v else v for k,v in report.items()},indent=2))
