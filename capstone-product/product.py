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
  selected={'arm64-ls','arm64-cp','libjpeg-arm64','arm-cp','mips64el-ls','putty-32-0.85'}
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
  products={};layouts={};symbols={};reference=json.loads((r/'layout-reference.json').read_text())
  def entrypoints(path):
      aliases={};rest=[]
      for line in sp.check_output(['objdump','-t',path],text=True).splitlines():
          m=re.match(r'^\s*([0-9a-f]{8,16})\s+(.*?)\s+(\.\S+)\s+([0-9a-f]+)\s+(.+?)$',line)
          if not m:continue
          addr=int(m[1],16);size=int(m[4],16);sec=m[3];name=m[5].split()[-1]
          if sec.startswith('.cs_alias_lookup') or name in ('map_set_aarch64_alias_id','map_set_mips_alias_id','map_set_alias_id_trie_impl','aarch64_alias_trie','mips_alias_trie'):
              if size and not name.startswith('.'):aliases[name]=[addr,size,sec]
          elif sec.startswith('.') and (size or 'F' in m[2].split()):rest.append([name,addr,size,sec])
      assert {'map_set_aarch64_alias_id','map_set_mips_alias_id','aarch64_alias_trie','mips_alias_trie'}<=aliases.keys(),aliases
      return dict(aliases=aliases,other_sha256=hashlib.sha256(json.dumps(sorted(rest)).encode()).hexdigest(),other_count=len(rest))
  def input_section(obj,sec,tag):
      dst=t/(tag+'.bin')
      sp.run(['objcopy','--dump-section',sec+'='+str(dst),obj,t/(tag+'-dump.o')],check=True)
      v=dst.read_bytes();return [len(v),hashlib.sha256(v).hexdigest()]
  def link_at(template,archive,label):
      link=template[:]
      slots=[i for i,x in enumerate(link)if x.endswith('/libcapstone.a') or x=='libcapstone.a']
      assert slots,link
      for i in slots:link[i]=str(archive)
      dest=t/label;link[link.index('-o')+1]=str(dest)
      command(link,'link-'+label,build)
      products[label]=dest;layouts[label]=properties(dest);symbols[label]=entrypoints(dest)
  def image_archive(archive,name,original,composite):
      v=t/name/'libcapstone.a'
      shutil.copyfile(archive,v)
      new=t/name/'AliasMapping.c.o'
      if new!=composite:shutil.copy2(composite,new)
      before=sp.check_output(['ar','t',v])
      command(['ar','rDs',v,new],'replace-'+name)
      assert before==sp.check_output(['ar','t',v])
      assert sp.check_output(['ar','p',v,'AliasMapping.c.o'])==new.read_bytes()
      return v
  controls=['pad00','pad10','pad01','pad11']
  dcode=reference['code_delta'];ddata=reference['data_delta'];assert dcode>0 and ddata>0
  asm_receipts={}
  for label in ('base','qualified'):
      if label=='qualified':
          patch=r/variants[label]['capstone_patch'];assert hashlib.sha256(patch.read_bytes()).hexdigest()==variants[label]['capstone_sha256']
          command(['git','apply',patch],'apply-qualified',cs)
      command([sys.executable,nd/'scripts/build.py',build,'--target','capstone-product','--parallel','4'],'build-'+label,nd)
      product,=[p for p in build.rglob('capstone-product') if p.is_file()]
      archive,=[p for p in build.rglob('libcapstone.a') if p.is_file()]
      baseline=t/(label+'-original');shutil.copy2(product,baseline);products[label]=baseline;layouts[label]=properties(baseline);symbols[label]=entrypoints(baseline)
      cmd=shlex.split(sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'],text=True).splitlines()[-1])
      pos=next(i for i,x in enumerate(cmd)if Path(x).name in ('clang++','clang++-18','c++'))
      cmd=cmd[pos:]
      if '&&' in cmd:cmd=cmd[:cmd.index('&&')]
      obj=t/(label+'-alias.o');obj.write_bytes(sp.check_output(['ar','p',archive,'AliasMapping.c.o']))
      original_sections=[input_section(obj,s,label+str(i))for i,s in enumerate(('.cs_alias_lookup','.cs_alias_lookup_rodata'))]
      assert all(n>0 for n,_ in original_sections)
      name=label+'-grouped';wd=t/name;wd.mkdir()
      merged=wd/'AliasMapping.c.o'
      command(['objcopy','--rename-section','.cs_alias_lookup=.text.cs_alias_lookup','--rename-section','.cs_alias_lookup_rodata=.rodata.cs_alias_lookup',obj,merged],'rename-'+label)
      assert [input_section(merged,s,name+str(i))for i,s in enumerate(('.text.cs_alias_lookup','.rodata.cs_alias_lookup'))]==original_sections
      grouped_image=name+'-image'
      link_at(cmd,image_archive(archive,name,obj,merged),grouped_image)
      if label=='qualified':continue
      for name in controls:
          code_front=dcode*int(name[-2]);data_front=ddata*int(name[-1])
          wd=t/name;wd.mkdir()
          for side,ncode,ndata in [('before',code_front,data_front),('after',dcode-code_front,ddata-data_front)]:
              assembly=wd/(side+'.s')
              assembly.write_text('.section .cs_alias_lookup,"ax",@progbits\n'+('.zero '+str(ncode)+'\n'if ncode else '')+'.section .cs_alias_lookup_rodata,"a",@progbits\n'+('.zero '+str(ndata)+'\n'if ndata else '')+'.section .note.GNU-stack,"",@progbits\n')
              command(['cc','-c',assembly,'-o',wd/(side+'.o')],'assemble-'+name+'-'+side)
          compound=wd/'AliasMapping.c.o'
          command(['ld','-r','--build-id=none',wd/'before.o',obj,wd/'after.o','-o',compound],'combine-'+name)
          asm_receipts[name]=dict(code_front=code_front,table_front=data_front,original_sections=original_sections,combined_sha256=hashlib.sha256(compound.read_bytes()).hexdigest())
          link_at(cmd,image_archive(archive,name,obj,compound),name+'-image')
  write('layouts',layouts);write('alias-symbols',symbols);write('member-controls',asm_receipts)
  base_symbols=symbols['pad00-image'];anchor=layouts['pad00-image']
  for name in controls:
      key=name+'-image';code_front=asm_receipts[name]['code_front'];table_front=asm_receipts[name]['table_front']
      assert layouts[key]==anchor,(key,[(k,v,anchor['sections'].get(k))for k,v in layouts[key]['sections'].items()if v!=anchor['sections'].get(k)])
      assert symbols[key]['other_sha256']==base_symbols['other_sha256'] and symbols[key]['other_count']==base_symbols['other_count']
      assert symbols[key]['aliases'].keys()==base_symbols['aliases'].keys()
      for fn,(addr,size,sec) in base_symbols['aliases'].items():
          delta=table_front if sec.endswith('_rodata') else code_front
          assert symbols[key]['aliases'][fn]==[addr+delta,size,sec],(name,fn,symbols[key]['aliases'][fn],delta)
  # Actual code and table addresses in the controlled pair must reproduce both original layouts.
  addresses={}
  for key,label in [('pad00-image','base'),('pad11-image','qualified')]:
      address_report={}
      for name,(addr,size,sec) in symbols[key]['aliases'].items():
          target=symbols[label]['aliases'][name][0]
          # The baseline's .rodata moves one full page when the padding consumes the vacant code tail.
          address_report[name]=dict(actual=addr,target=target,exact=addr==target,same_page_offset=(addr-target)%4096==0)
      addresses[key]=address_report
  write('source-control',dict(llvm=llvm_identity(),sources=[rev(nd),rev(cs)],reference=reference,actual={k:hashlib.sha256(products[k].read_bytes()).hexdigest()for k in ('base','qualified')},controlled_aliases=addresses))

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
          first=execute('base',case,mode,1);reps=max(1,round(0.065*scale/first[0]));sig=execute('base',case,mode,reps)[1:]
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
