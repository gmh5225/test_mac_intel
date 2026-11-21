from pathlib import Path
import hashlib,json,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
import corpus
import avx_corpus
r=Path(__file__).resolve().parent;root=r.parent;nd=root/'neverd';out=root/'product-evidence';out.mkdir(exist_ok=True)
def write(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
 print(label,flush=True)
 with (out/(label+'.log')).open('w') as log:rv=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT).returncode
 if rv:print((out/(label+'.log')).read_text(errors='replace')[-4000:],flush=True);raise RuntimeError(label)
def rev(d):return sp.check_output(['git','-C',d,'rev-parse','HEAD'],text=True).strip()
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project'
cc=os.environ['CC']
assert cc == 'clang' and platform.machine()=='x86_64'
feature_active = True
write('scope',dict(active=feature_active,policy='Test the ordinary NeverD C++ Decoder entry on PE32, PE64, ELF scalar and vector data with the shipping static iterators. Measure scan, text, detail and batch using the production backend.'))
expected=json.loads((r/'inputs.json').read_text())
variants=expected['variants']
write('inputs',expected)
assert rev(nd)==expected['neverd'] and rev(cs)==expected['capstone']
write('sources',dict(neverd=rev(nd),capstone=rev(cs),llvm_fork=rev(ll),llvm_source=str(ll)))
with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
 t=Path(temp);build=t/'build'
 try:
  write('llvm_source_build',dict(revision=rev(ll),compiler='clang++',prebuilt=False,unmodified_latest_fork=True))
  cases=corpus.prepare(r,t,out,command)
  selected={'arm64-ls','arm64-cp','libjpeg-arm64','arm-cp','putty-32-0.85'}
  cases=[v for v in cases if v['name'] in selected]
  assert len(cases)==len(selected)
  shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp');cm=nd/'CMakeLists.txt'
  cm.write_text(cm.read_text()+'\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'original-probe.cpp',nd/'capstone-product-legacy.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-product-legacy capstone-product-legacy.cpp)\ntarget_link_libraries(capstone-product-legacy PRIVATE NeverDDecode)\n')
  shutil.copyfile(r/'route.cpp',nd/'capstone-route.cpp')
  with cm.open('a') as f:f.write('\nadd_executable(capstone-route capstone-route.cpp)\ntarget_link_libraries(capstone-route PRIVATE NeverDDecode)\n')
  with cm.open('a') as f:f.write('target_link_options(capstone-product PRIVATE "LINKER:-Map,${CMAKE_BINARY_DIR}/capstone-product.map")'+chr(10))
  command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCMAKE_CXX_COMPILER=clang++','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
  assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in (build/'CMakeCache.txt').read_text()
  write('compiler',dict(c=sp.check_output([cc,'--version'],text=True).splitlines()[0],cxx=sp.check_output(['clang++','--version'],text=True).splitlines()[0],cpu=Path('/proc/cpuinfo').read_text(),host=platform.machine()))
  command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','--parallel','4'],'swift-demangle-from-source',nd)
  def llvm_identity():
   modified=sp.check_output(['git','-C',ll,'diff','--binary','HEAD'])
   untracked=sp.check_output(['git','-C',ll,'ls-files','--others','--exclude-standard','-z']).split(b'\0')
   extras={os.fsdecode(name):hashlib.sha256((ll/os.fsdecode(name)).read_bytes()).hexdigest() for name in untracked if name}
   return dict(revision=rev(ll),tracked_diff_sha256=hashlib.sha256(modified).hexdigest(),untracked=extras)
  llvm_reference=llvm_identity()
  write('llvm-baseline-identity',llvm_reference)
  import re,shlex
  def properties(path):
      sections=sp.check_output(['readelf','-SW',path],text=True)
      headers=sp.check_output(['readelf','-lW',path],text=True)
      table={}
      for m in re.finditer(r'^\s*\[\s*\d+\]\s+(\.\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S+)',sections,re.M):
          if 'A' in m[4] and m[1]!='.placement_control':table[m[1]]=[int(m[2],16),int(m[3],16),m[4]]
      loads=[line.split()[6:-1] for line in headers.splitlines()if line.lstrip().startswith('LOAD ')]
      assert loads and not any('W' in ''.join(v) and 'E' in ''.join(v) for v in loads),loads
      syms={}
      for line in sp.check_output(['nm','-S','--defined-only',path],text=True).splitlines():
          parts=line.split()
          if len(parts)==4 and parts[3] in ('cs_disasm_iter','ARM_getInstruction','AArch64_getInstruction','Mips_getInstruction','X86_disasmIter32','X86_disasmIterText'):syms[parts[3]]=parts[:2]
      assert len(syms)==6,syms
      return dict(sections=table,load_permissions=loads,symbols=syms)
  def layout_matches(a,b,offset):
      if a['symbols']!=b['symbols'] or a['sections'].keys()!=b['sections'].keys():return False
      for name,(address,size,flags)in a['sections'].items():
          shift=offset if address>=a['sections']['.rodata'][0] else 0
          if b['sections'][name]!=[address+shift,size,flags]:return False
      return True
  products={};layouts={};reference=json.loads((r/'layout-reference.json').read_text())
  for label in ('base','qualified'):
      if label=='qualified':
          patch=r/variants[label]['capstone_patch'];assert hashlib.sha256(patch.read_bytes()).hexdigest()==variants[label]['capstone_sha256']
          command(['git','apply',patch],'apply-qualified',cs)
      command([sys.executable,nd/'scripts/build.py',build,'--target','capstone-product','--parallel','4'],'build-'+label,nd)
      product,=[p for p in build.rglob('capstone-product') if p.is_file()]
      baseline=t/(label+'-original');shutil.copy2(product,baseline);products[label]=baseline;base=properties(baseline);layouts[label]=base
      cmd=shlex.split(sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'],text=True).splitlines()[-1])
      begin=next(i for i,x in enumerate(cmd) if Path(x).name in ('clang++','clang++-18','c++'));cmd=cmd[begin:]
      if '&&' in cmd:cmd=cmd[:cmd.index('&&')]
      xo=cmd.index('-o')+1
      for pages in ((1,2) if label=='base' else (1,)):
          name=label+'-p'+str(pages);dest=t/name;loc=base['sections']['.rodata'][0];delta=4096*pages
          fragment=t/(name+'.ld');fragment.write_text('SECTIONS { .placement_control (READONLY) : { BYTE(0); . += '+str(delta-1)+'; } } INSERT BEFORE .rodata;\n')
          attempts=[['-Wl,--section-start=.rodata='+hex(loc+delta)],['-Wl,-T,'+str(fragment)]]
          for i,extra in enumerate(attempts):
              link=cmd[:];link[xo]=str(dest);log=out/(name+'-link-'+str(i)+'.log')
              with log.open('wb')as f:proc=sp.run([*link,*extra],cwd=build,stdout=f,stderr=sp.STDOUT)
              if proc.returncode:continue
              obs=properties(dest)
              if layout_matches(base,obs,delta):break
          else:raise RuntimeError('Could not shift just the read-only and following data addresses for '+name)
          products[name]=dest;layouts[name]=dict(obs,intervention=extra)
  write('layouts',layouts)
  assert layouts['qualified']['sections']['.rodata'][0]-layouts['base']['sections']['.rodata'][0]==4096
  write('source-control',dict(llvm=llvm_identity(),sources=[rev(nd),rev(cs)],reference=reference,actual={k:hashlib.sha256(products[k].read_bytes()).hexdigest()for k in ('base','qualified')}))
  products['copy']=products['base'];images={k:v.read_bytes()for k,v in products.items()};size=max(map(len,images.values()));images={k:v+bytes(size-len(v))for k,v in images.items()}
  slot=t/'fixed-image';slot.write_bytes(images['base']);slot.chmod(0o755);inode=slot.stat().st_ino
  os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});bind=['setarch',platform.machine(),'-R'];sp.run(bind+['/bin/true'],check=True)
  def execute(key,case,mode,reps):
      with slot.open('r+b')as f:f.write(images[key])
      assert slot.stat().st_ino==inode and slot.stat().st_size==size
      selector=case['selector'];selector={0:'arm64',1:'arm',4:'mips64el'}.get(selector,selector)
      v=list(map(int,sp.check_output([*bind,slot,case['path'],str(selector),str(mode),str(reps)],text=True).split()));assert v[0]>0 and v[1]>0;return v
  scale_src=t/'clock.c';scale_src.write_text('#include <stdio.h>\n#include <time.h>\nint main(void){printf("%ld\\n",(long)CLOCKS_PER_SEC);return 0;}\n');command(['cc',scale_src,'-o',t/'scale'],'scale');scale=int(sp.check_output([t/'scale'],text=True))
  rows=[]
  for case in cases:
      for mode in (1,2):
          first=execute('base',case,mode,1);reps=max(1,round(0.08*scale/first[0]));sig=execute('base',case,mode,reps)[1:]
          cycles=[];rng=random.Random(case['name']+str(mode))
          for i in range(13):
              keys=list(products);rng.shuffle(keys);c={k:[]for k in keys}
              for k in keys+keys[::-1]:
                  ticks,*record=execute(k,case,mode,reps);assert record==sig;c[k].append(ticks)
              cycles.append(c)
          rows.append(dict(case=case['name'],mode=mode,sha=case['text_sha256'],reps=reps,signature=sig,cycles=cycles))
          write('timings',rows)
  write('complete',dict(success=True,cases=len(rows),scale=scale,inode=inode,affinity=list(os.sched_getaffinity(0))))

 finally:
  size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
