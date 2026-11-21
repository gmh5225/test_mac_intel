def measure_layout(r,t,build,nd,cs,out,cases,expected,command,write,rev,llvm_identity,llvm_reference):
 import hashlib,json,os,platform,random,re,shlex,shutil,statistics,subprocess as sp
 from pathlib import Path
 import corpus
 command([os.sys.executable,nd/'scripts/build.py',build,'--target','capstone-product','--parallel','4'],'build-unaltered-decoder',nd)
 assert rev(cs)==expected['capstone']and llvm_identity()==llvm_reference
 args=shlex.split(sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'],text=True).splitlines()[-1])
 start=next(i for i,v in enumerate(args)if Path(v).name.startswith('clang++'));args=args[start:];args=args[:args.index('&&')]if '&&'in args else args;assert '-o'in args and any('libcapstone.a'in a for a in args)
 original=build/args[args.index('-o')+1];assert original.is_file();sizes=json.loads((r/'padding-extents.json').read_text());products={};layouts={}
 archive=next(build.rglob('libcapstone.a'));members=sp.check_output(['ar','t',archive],text=True).splitlines();digest=lambda data:hashlib.sha256(data).hexdigest()
 write('linked-inputs',dict(archive_sha256=digest(archive.read_bytes()),members={s:digest(sp.check_output(['ar','p',archive,s]))for s in members},llvm=llvm_reference))
 for name,(tx,ro)in sizes.items():
  cmd=args[:];target=t/('trial-'+name);cmd[cmd.index('-o')+1]=str(target)
  if tx or ro:
   f=t/(name+'.s');o=t/(name+'.o');lines=[]
   for section,flags,size in [('.cs_x86_i386_text','ax',tx),('.cs_x86_i386_rodata','a',ro)]:
    if size:lines.extend(['.section '+section+',"'+flags+'",@progbits','.zero '+str(size)])
   lines.append('.section .note.GNU-stack,"",@progbits');f.write_text('\n'.join(lines)+'\n')
   command(['clang','-c',f,'-o',o],name+'-assemble')
   # Clang emits an empty, four-byte aligned .text for an assembly input.
   # It changed the end of the ordinary text by a byte in the first control.
   command(['objcopy','--remove-section=.text','--remove-section=.data','--remove-section=.bss',o],name+'-remove-empty-inputs')
   inventory=sp.check_output(['readelf','-SW',o],text=True)
   assert not any(re.search(r'\]\s+\.(text|data|bss)\s',line)for line in inventory.splitlines());cmd.append(str(o))
  command(cmd,name+'-relink',build);products[name]=target
  if name=='base':assert digest(target.read_bytes())==digest(original.read_bytes())
  sections=sp.check_output(['readelf','-SW',target],text=True);symbols=sp.check_output(['nm','-S',target],text=True)
  (out/(name+'-sections.log')).write_text(sections);(out/(name+'-segments.log')).write_bytes(sp.check_output(['readelf','-lW',target]))
  sec={m[1]:[int(m[2],16),int(m[3],16)]for line in sections.splitlines()if(m:=re.search(r'\[\s*\d+\]\s+(\S+)\s+PROGBITS\s+(\w+)\s+\w+\s+(\w+)',line))}
  keys={'Mips_getInstruction','Mips_printer','map_set_mips_alias_id','mips_alias_trie','mips_insns','cs_disasm_iter'};sy={v[3]:[int(v[0],16),int(v[1],16)]for line in symbols.splitlines()if len(v:=line.split())==4 and v[3] in keys};assert len(sy)==len(keys)
  layouts[name]=dict(sections={k:sec[k]for k in ('.text','.cs_x86_i386_text','.cs_alias_lookup','.rodata','.cs_x86_i386_rodata','.cs_alias_lookup_rodata')},symbols=sy)
  base=layouts['base']['sections'];assert sec['.text']==base['.text']and sec['.rodata'][1]==base['.rodata'][1] and sec['.cs_x86_i386_text'][1]-base['.cs_x86_i386_text'][1]==tx and sec['.cs_x86_i386_rodata'][1]-base['.cs_x86_i386_rodata'][1]==ro
  assert sy['Mips_getInstruction']==layouts['base']['symbols']['Mips_getInstruction']and sy['cs_disasm_iter']==layouts['base']['symbols']['cs_disasm_iter']
 write('layouts',layouts);q=next(v for v in cases if v['name']=='mips64el-ls');inputs={'ls':Path(q['path'])};pkg=t/'corpus'/q['package_sha256'];assert digest(pkg.read_bytes())==q['package_sha256']
 for name in ('cp','sort'):
  f=t/(name+'.text');f.write_bytes(corpus.elf_text(corpus.deb_binary(pkg,name)));inputs[name]=f
 write('guest', {k:dict(bytes=v.stat().st_size,sha256=digest(v.read_bytes()))for k,v in inputs.items()})
 products['copy']=t/'copy';shutil.copy2(products['base'],products['copy']);payloads={k:f.read_bytes()for k,f in products.items()};maximum=max(map(len,payloads.values()));payloads={k:v+bytes(maximum-len(v))for k,v in payloads.items()};fixed=t/'same-image';fixed.write_bytes(payloads['base']);fixed.chmod(0o755);ino=fixed.stat().st_ino
 os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});bind=['setarch',platform.machine(),'-R'];command([*bind,'/bin/true'],'fixed-aslr')
 def invoke(k,f,mode,n,launch):
  if launch=='fixed':
   with fixed.open('r+b')as fp:assert fp.write(payloads[k])==maximum
   assert fixed.stat().st_ino==ino
  args=([*bind,str(fixed)]if launch=='fixed'else[str(products[k])])+list(map(str,[f,'mips64el',mode,n]))
  return list(map(int,sp.check_output(args,text=True).split()))
 clock_probe=t/'clock-scale'
 sp.run(['cc','-x','c','-','-o',clock_probe],input=b'#include <time.h>\n#include <stdio.h>\nint main(void) { printf("%ld", (long)CLOCKS_PER_SEC); }\n',check=True)
 ticks_per_sec=int(sp.check_output([clock_probe],text=True));assert ticks_per_sec>0
 target=ticks_per_sec*55/1000
 write('timer-scale',dict(ticks_per_second=ticks_per_sec,target_milliseconds=55,target_ticks=target))
 rows=[]
 for sample,f in inputs.items():
  for mode in (0,1,2):
   for launch in (['fixed','images']if sample=='ls' else ['fixed']):
    one=invoke('base',f,mode,1,launch);reps=max(1,min(20000,round(target/one[0])));ref=invoke('base',f,mode,reps,launch);assert ref[0]>0 and ref[1]>0
    keys=list(products);cycles=[]
    for i in range(15):
     order=keys[i%len(keys):]+keys[:i%len(keys)];vals={k:[] for k in keys}
     for k in order+order[::-1]:
      z=invoke(k,f,mode,reps,launch);assert z[1:]==ref[1:]and z[0]>0;vals[k].append(z[0])
     cycles.append(vals)
    rows.append(dict(sample=sample,mode=mode,launch=launch,reps=reps,signature=ref[1:],cycles=cycles));write('timings',rows)
 assert len(rows)==12;write('complete',dict(cases=len(rows),controls=list(products),same_source=rev(cs),fixed_inode=ino,original_executable=digest(original.read_bytes())))
