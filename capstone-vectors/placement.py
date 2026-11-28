from pathlib import Path
from collections import Counter
from bisect import bisect_right
import hashlib,json,os,random,re,subprocess as sp,sys
from elftools.elf.elffile import ELFFile

def symbols(path):
 rows={};addrs={}
 with path.open('rb')as fp:
  elf=ELFFile(fp)
  for s in elf.get_section_by_name('.symtab').iter_symbols():
   if s['st_info']['type']!='STT_FUNC' or not s['st_size'] or not s['st_value']:continue
   name=s.name;rows.setdefault(name,[]).append((s['st_value'],s['st_size']));addrs.setdefault(s['st_value'],[]).append((name,s['st_size']))
 return rows,addrs

def train(r,w,archive,ice,flags,project,regular,save):
 inputs=json.loads((r/'training.json').read_bytes());tracer=w/'traced';clfiles=w/'sections'
 def build(builddir,extra):
  sp.run(['cmake','-G','Ninja','-S',project,'-B',builddir,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_C_FLAGS=-ffunction-sections -funique-internal-linkage-names '+extra],check=True)
  sp.run(['cmake','--build',builddir,'--target','capstone_static','--parallel','4'],check=True)
  lib,=builddir.rglob('libcapstone.a');return lib
 def link(exe,lib,*more):sp.run(['clang++',w/'driver.o',lib,ice,*flags,*more,'-o',exe],check=True)
 trace=build(tracer,'-finstrument-functions-after-inlining');sp.run(['cc','-O2','-c',r/'calls.c','-o',w/'calls.o'],check=True)
 tx=w/'tracer';link(tx,trace,w/'calls.o');lib=build(clfiles,'');natural=w/'plain-sections';link(natural,lib)
 refs,locations=symbols(tx);regular_names,_=symbols(natural);starts=sorted(locations)
 def where(pc):
  i=bisect_right(starts,pc)-1
  if i<0:return None
  addr=starts[i];names=[name for name,size in locations[addr]if pc<addr+size and len(refs[name])==1 and len(regular_names.get(name,[]))==1]
  return names[0]if len(names)==1 else None
 weights=Counter();edges=Counter();runs=[];texts=set()
 for arch,meta in inputs.items():
  deb=w/(arch+'.deb');sp.run(['curl','-fsSL','--retry','3','--max-time','90','-o',deb,meta['url']],check=True)
  digest=lambda b:hashlib.sha256(b).hexdigest();assert digest(deb.read_bytes())==meta['package']
  member=next(z for z in sp.check_output(['ar','t',deb],text=True).splitlines()if z.startswith('data.tar'));tar=w/'payload.tar';tar.write_bytes(sp.check_output(['ar','p',deb,member]));out=w/'training-program';out.write_bytes(sp.check_output(['tar','-xOf',tar,meta['member']]));assert digest(out.read_bytes())==meta['binary']
  with out.open('rb')as fp:
   section=ELFFile(fp).get_section_by_name('.text');data=section.data();assert digest(data)==meta['text'] and section['sh_addr']==meta['address'] and len(data)==meta['size']
  texts.add(meta['text']);out.write_bytes(data);ranges=w/'training.tsv';ranges.write_text(f"0 {len(data)} {meta['address']}\n")
  for route in ('capstone','private'):
   for mode in (0,1,2):
    log=w/'calls.tsv';obs=list(map(int,sp.check_output([tx,route,str(mode),'1',out,ranges,'32'if arch=='i386'else'64'],env=dict(os.environ,COUNT_OUTPUT=str(log)),text=True).split()));assert len(obs)==6 and obs[2]>50000
    count=0
    for line in log.read_text().splitlines():
     fr,to,n=line.split();n=int(n);callee=where(int(to,16));caller=where(int(fr,16)-1)
     if callee:weights[callee]+=n;count+=n
     if callee and caller and caller!=callee:edges[caller,callee]+=n
    runs.append(dict(arch=arch,route=route,mode=mode,instructions=obs[2],mapped=count));assert count>0;log.unlink()
  for p in (tar,deb,out,ranges):p.unlink()
 assert not texts & {s['text_sha256']for s in json.loads((r/'experiment.json').read_bytes())['provenance'].values()}
 # Only time placements of input functions that have their own unambiguous input section.
 sec=set()
 for line in sp.check_output(['objdump','-h',lib],text=True).splitlines():
  match=re.match(r'\s*\d+\s+\.text\.(\S+)\s+',line)
  if match:sec.add(match[1])
 names=sorted(n for n in weights if n in sec and re.fullmatch(r'[\w.$]+',n))
 assert len(names)>70,len(names)
 chain={n:[n]for n in names};owner={n:n for n in names}
 for (a,b),v in edges.most_common():
  if a not in owner or b not in owner:continue
  x,y=owner[a],owner[b]
  if x==y or chain[x][-1]!=a or chain[y][0]!=b:continue
  for n in chain[y]:owner[n]=x
  chain[x].extend(chain.pop(y))
 order=[n for seq in sorted(chain.values(),key=lambda g:-sum(weights[n]for n in g)/sum(regular_names[n][0][1]for n in g))for n in seq]
 control=sorted(names,key=lambda n:regular_names[n][0][0]);shuffled=control[:];random.Random(40049).shuffle(shuffled)
 products={'stock':regular};placements={};sh=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
 for k,seq in [('control',control),('placed',order),('shuffled',shuffled)]:
  assert set(seq)==set(names);script=w/(k+'.ld');script.write_text('SECTIONS { .capstone_hot : ALIGN(64) {\n'+''.join('  *(.text.'+n+')\n' for n in seq)+'} } INSERT BEFORE .text;\n')
  exe=w/k;link(exe,lib,'-Wl,-T,'+str(script));syms,_=symbols(exe)
  with exe.open('rb')as fp:
   section=ELFFile(fp).get_section_by_name('.capstone_hot');start=section['sh_addr'];size=section['sh_size']
  actual=[(n,syms[n][0][0]-start) for n in sorted(names,key=lambda n:syms[n][0][0])]
  assert [n for n,_ in actual]==seq and all(0<=offset<size for n,offset in actual)
  placements[k]=dict(sha=sh(exe),section=[start,size],symbols=actual);products[k]=exe
 assert len({z['section'][0] for z in placements.values()})==1
 save('training',dict(runs=runs,inputs=inputs,weights=weights,edges=[[a,b,v]for (a,b),v in edges.most_common()],sampled_functions=len(names),instrumented=sh(trace),shipping_archive=sh(archive),common_uninstrumented_archive=sh(lib),driver=sh(w/'driver.o'),iced=sh(ice),products=placements,stock=sh(regular),control_linker=sp.check_output(['ld','--version'],text=True).splitlines()[0]))
 return products

