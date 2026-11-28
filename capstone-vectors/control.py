"""Keep both pairs of x86 objects mapped, then resolve their external symbols to one pair."""
from pathlib import Path
import collections,hashlib,json,os,re,shutil,subprocess as sp
from elftools.elf.elffile import ELFFile
def sh(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def funcs(p,aliases):
 rows={}
 with p.open('rb')as src:
  elf=ELFFile(src);sections={};sym=elf.get_section_by_name('.symtab')
  for s in sym.iter_symbols():
   idx=s['st_shndx'];name=s.name
   if s['st_info']['type']!='STT_FUNC' or not s['st_size'] or not isinstance(idx,int) or name in aliases:continue
   if idx not in sections:
    sec=elf.get_section(idx);sections[idx]=(sec['sh_addr'],sec.data())
   origin,data=sections[idx];addr=s['st_value'];off=addr-origin;n=s['st_size']
   assert 0<=off<=len(data)-n
   rows.setdefault(name,[]).append([addr,n,hashlib.sha256(data[off:off+n]).hexdigest()])
 return {k:sorted(v)for k,v in rows.items()}
def build_pairs(w,lib,ice,flags,before,after,save):
 def run(*args):sp.run(args,check=True)
 def read(*args):return sp.check_output(args,text=True)
 names=sorted(n for n in before if before[n]!=after[n]);assert set(names)<={'X86Mapping.c.o','X86Disassembler.c.o','X86DisassemblerDecoder.c.o'} and 'X86Mapping.c.o'in names
 rest=w/'capstone-common.a';shutil.copyfile(lib,rest)
 members=read('ar','t',rest).splitlines();assert all(members.count(n)==1 for n in names);run('ar','d',rest,*names);run('ar','s',rest)
 symbols={};res={}
 for tag in ('base','fixed'):
  source=w/(tag+'-objects');defs=set()
  for f in names:
   ls=read('nm','-g','--defined-only','--format=posix',source/f).splitlines()
   defs.update(line.split()[0]for line in ls if line.strip())
  assert all(re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9.]*',n)for n in defs) and len(defs)>20
  symbols[tag]=sorted(defs)
 assert symbols['base']==symbols['fixed'];defs=symbols['base'];objects=[]
 for tag in ('base','fixed'):
  source=w/(tag+'-objects');symmap=w/(tag+'.map');symmap.write_text(''.join(s+' '+tag+'__'+s+'\n' for s in defs))
  for f in names:
   obj=w/(tag+'-'+f);run('objcopy','--redefine-syms',symmap,source/f,obj);objects.append(obj)
 for kind,driver in [('x86',[w/'driver.o']),('foreign',[w/'foreign.o',w/'ref.o'])]:
  rows={};selected={}
  for tag in ('base','fixed'):
   args=['-Wl,--defsym='+s+'='+tag+'__'+s for s in defs]
   exe=w/(kind+'-frozen-'+tag)
   run('clang++',*driver,*objects,rest,*([ice]if kind=='x86'else []),*flags,*args,'-o',exe)
   rows[tag]=funcs(exe,set(defs));selected[tag]=sh(exe)
  same=set(rows['base'])==set(rows['fixed']);keys=set(rows['base'])|set(rows['fixed'])
  moved=[];changed=[];foreign=[]
  for n in sorted(keys):
   a=rows['base'].get(n,[]);b=rows['fixed'].get(n,[])
   if [x[:2]for x in a]!=[x[:2]for x in b]:moved.append(n)
   if a!=b:changed.append(n)
   if n.startswith(('RISCV_','ARM_','AArch64_','PPC_','Mips_','MIPS_')) and a==b:foreign.append(n)
  res[kind]=dict(binaries=selected,common_function_names=same,symbols=len(keys),different_vmas=moved,different_bytes_or_addresses=changed,identical_foreign_functions=foreign)
  assert len(foreign)>40 and selected['base']!=selected['fixed']
 save('placement-control',dict(changed_members=names,alias_count=len(defs),aliases=defs,shared_archive=sh(rest),objects={x.name:sh(x)for x in objects},links=res))

