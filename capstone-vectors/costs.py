"""Attribute a measured traversal to call edges, including work in their callees."""
import collections,json,platform,re,subprocess as sp
def parse(path):
 names={};current=None;callee=None;pending=None;own=collections.Counter();calls=collections.Counter();through=collections.Counter()
 pos=None;footer=None
 with path.open()as f:
  for raw in f:
   line=raw.strip()
   if line.startswith('events:'):assert line.split()[1]=='Ir' and 'Bcm' in line.split()
   elif line.startswith('positions:'):pos=len(line.split())-1
   elif line.startswith('totals:'):footer=int(line.split()[1])
   elif line.startswith(('fn=','cfn=')):
    key,val=line.split('=',1);m=re.fullmatch(r'\((\d+)\)(?: (.*))?',val)
    if m:
     ident,literal=m.groups()
     if literal is not None:names[ident]=literal
     val=names[ident]
    if key=='fn':current=val
    else:callee=val
   elif line.startswith('calls='):
    n=int(line[6:].split()[0]);pending=(current,callee);calls[pending]+=n
   elif line and line[0] in '+-0123456789*' and pos is not None:
    fields=line.split();v=int(fields[pos])if len(fields)>pos else 0
    if pending is not None:through[pending]+=v;pending=None
    else:own[current]+=v
 assert footer is not None and sum(own.values())==footer,(sum(own.values()),footer)
 return footer,own,calls,through

def collect(w,case,mode,bits,source,intervals,image,padded,evidence):
 configurations=[('release','baseline','x86_iter'),('alu_immediates','alu_immediates','x86_iter'),('fast','baseline','fast____')]
 output={};accepted=None
 for label,variant,engine in configurations:
  with image.open('r+b')as f:f.write(padded[variant])
  runs=[];sig=[];events=[]
  for reps in (1,2):
   args=['setarch',platform.machine(),'-R','valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--dump-instr=no','--callgrind-out-file='+str(w/'call.out'),str(image),engine,str(mode),str(reps),str(source),str(intervals),str(bits)]
   q=sp.run(args,capture_output=True,text=True);(evidence/(case+'-'+str(mode)+'-'+label+'-'+str(reps)+'.log')).write_text(q.stderr);q.check_returncode()
   sig.append(list(map(int,q.stdout.split()))[2:]);runs.append(parse(w/'call.out'))
   lines=(w/'call.out').read_text().splitlines();names=next(l.split()[1:]for l in lines if l.startswith('events:'));values=list(map(int,next(l.split()[1:]for l in lines if l.startswith('totals:'))));values.extend([0]*(len(names)-len(values)));events.append(dict(zip(names,values)));(w/'call.out').unlink()
  n=sig[1][0]-sig[0][0];assert n==sig[0][0]and n>0
  if accepted is None:accepted=sig
  assert [s[:3]for s in accepted]==[s[:3]for s in sig]
  if label!='fast':assert accepted==sig
  old,new=runs;total=new[0]-old[0]
  selfcost={k:new[1][k]-old[1][k]for k in new[1].keys()|old[1].keys()}
  assert total>0 and sum(selfcost.values())==total
  counts=collections.Counter();inclusive=collections.Counter();incoming=collections.defaultdict(list)
  for edge in new[2].keys()|old[2].keys():
   up,fn=edge;times=new[2][edge]-old[2][edge];ir=new[3][edge]-old[3][edge];counts[fn]+=times;inclusive[fn]+=ir
   if times or ir:incoming[fn].append(dict(caller=up,calls=times,inclusive_ir=ir))
  focus=('writeAluMemory32','writeAluMemory64','writeMemoryImmediate32','writeMemoryImmediate64','writeMemory32','X86_writeMemoryOutput','writeUnsignedImmediate','X86_writeAluImmediate','writeRegisterImmediate','X86_writeImmediateOutput','cs_decode_full_insn','X86_reg_access','cs_regs_access','decodeInstructionFull','writeVexRegisterOutput','writeVectorRegisters','tryOutput32','tryOutput64','X86_disasmIterText','X86_disasmIter32')
  metrics={fn:dict(calls=counts[fn],self_ir=selfcost.get(fn,0),inclusive_ir=inclusive[fn],ir_per_call=inclusive[fn]/counts[fn] if counts[fn]>0 else None,share_of_total=inclusive[fn]/total,parents=incoming[fn])for fn in focus}
  if label!='fast':
   assert 0<metrics['cs_decode_full_insn']['calls']<=n and metrics['cs_decode_full_insn']['inclusive_ir']>0
   assert metrics['X86_reg_access']['calls'] == (n if mode==2 else 0),(case,mode,n,metrics['X86_reg_access'])
  output[label]=dict(events_per_instruction={k:(events[1][k]-v)/n for k,v in events[0].items()},records=sig,decoded=n,total_ir=total,ir_per_instruction=total/n,functions=metrics,top_exclusive=sorted([(fn,v/n) for fn,v in selfcost.items() if v>0],key=lambda q:-q[1])[:25])
 return dict(case=case,mode=mode,bits=bits,engines=output)
