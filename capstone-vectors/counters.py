import hashlib,json,os,platform,re,shutil,subprocess as sp
from pathlib import Path
def placements(paths,w):
 out={}
 for label,f in paths.items():
  symbols=sp.check_output(['nm','-S','-n','--defined-only',f],text=True)
  hot={s[3]:[int(s[0],16),int(s[1],16)]for line in symbols.splitlines()if len(s:=line.split())==4 and s[3]in ('X86_disasmIter32','X86_disasmIterText','tryOutput64','tryOutput32','X86_reg_access','X86_writeMemoryOutput','decodeInstructionFull','cs_disasm_iter','i386_register_rows','i386_register_plans','x86_simple_registers')}
  elf=sp.check_output(['readelf','-SW',f],text=True);sections={}
  for line in elf.splitlines():
   m=re.search(r'\[\s*\d+\]\s+(\S+)\s+PROGBITS\s+(\w+)\s+\w+\s+(\w+)',line)
   if not m or m[1]not in ('.text','.rodata','.cs_x86_i386_text','.cs_x86_i386_rodata','.cs_x86_amd64_text','.cs_x86_amd64_rodata'):continue
   section=m[1];data=sp.check_output(['objcopy','--dump-section',section+'=/dev/stdout',f,w/'scratch.elf'])
   sections[section]=dict(start=int(m[2],16),size=len(data),sha256=hashlib.sha256(data).hexdigest());assert len(data)==int(m[3],16)
  assert {'X86_disasmIter32','X86_disasmIterText','X86_reg_access','cs_disasm_iter'}<=hot.keys()
  out[label]=dict(symbols=hot,sections=sections)
 return out

def collect(w,name,mode,bits,code,spans,image,padded,evidence):
 counters={};results={};opt=['setarch',platform.machine(),'-R'];names=('baseline','aa','escaped_pairs')
 for label in names:
  with image.open('r+b')as fp:fp.write(padded[label])
  observations={};ids={}
  for reps in (1,2):
   tag='%s-%s-%s'%(name,label,reps);log=w/'cache.out';args=[*opt,'valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--dump-instr=no','--compress-pos=yes','--callgrind-out-file='+str(log),str(image),'x86_iter',str(mode),str(reps),str(code),str(spans),str(bits)]
   q=sp.run(args,capture_output=True,text=True);(evidence/(tag+'-cache.log')).write_text(q.stderr);q.check_returncode();vals=list(map(int,q.stdout.split()));assert vals[2]>0
   ids[reps]=vals[2:];lines=log.read_text().splitlines();events=next(l.split()[1:]for l in lines if l.startswith('events:'));totals=list(map(int,next(l.split()[1:]for l in lines if l.startswith('totals:'))))
   totals.extend([0]*(len(events)-len(totals)));assert len(totals)==len(events);observations[reps]=dict(zip(events,totals));log.unlink()
  extra=ids[2][0]-ids[1][0];assert extra>0 and extra==ids[1][0]
  counters[label]={k:(observations[2][k]-v)/extra for k,v in observations[1].items()}
  results[label]=dict(records=ids,extra=extra,events=observations)
 assert results['baseline']['records']==results['escaped_pairs']['records']==results['aa']['records']
 hardware={}
 if shutil.which('perf'):
  for label in names:
   with image.open('r+b')as fp:fp.write(padded[label])
   f=evidence/(name+'-'+label+'-perf.csv');args=[*opt,'perf','stat','-x',',','-r','3','-e','cycles,instructions,branches,branch-misses,cache-misses','-o',str(f),'--',str(image),'x86_iter',str(mode),'8',str(code),str(spans),str(bits)]
   q=sp.run(args,capture_output=True,text=True);hardware[label]=dict(result=q.returncode,diagnostic=q.stderr[-600:],available=f.exists()and 'cycles'in f.read_text()and bool(re.search(r'^\s*\d+,',f.read_text(),re.M)))
   if not hardware[label]['available']:break
 return dict(case=name,mode=mode,bits=bits,events_per_instruction=counters,records=results,hardware=hardware)
