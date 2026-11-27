from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
from elftools.elf.elffile import ELFFile
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';nd=p/'neverd-config';e=p/'evidence';e.mkdir(exist_ok=True)
read=lambda f:json.loads(f.read_bytes());q=read(r/'source.json')
def run(*a,**kw):sp.run(a,check=True,**kw)
def get(*a):return sp.check_output(a,text=True).strip()
def save(key,data):(e/(key+'.json')).write_text(json.dumps(data,indent=1)+'\n')
def h(data):return hashlib.sha256(data).hexdigest()
def once(s,a,b):assert s.count(a)==1,(a,s.count(a));return s.replace(a,b)
def symbols(exe):
 data={}
 with exe.open('rb')as f:
  elf=ELFFile(f);tab=elf.get_section_by_name('.symtab')
  for sym in tab.iter_symbols():
   if sym['st_info']['type']!='STT_FUNC' or not sym['st_size'] or not isinstance(sym['st_shndx'],int):continue
   sec=elf.get_section(sym['st_shndx']);off=sym['st_value']-sec['sh_addr'];f.seek(sec['sh_offset']+off)
   data.setdefault(sym.name,[]).append([sym['st_value'],sym['st_size'],h(f.read(sym['st_size']))])
 return {k:sorted(v)for k,v in data.items()}
assert get('git','-C',src,'rev-parse','HEAD')==q['base'] and get('git','-C',nd,'rev-parse','HEAD')==q['neverd']
w=Path(tempfile.mkdtemp())
try:
 pr=w/'proj';build=w/'build';(pr/'third_party').mkdir(parents=True);(pr/'third_party/capstone').symlink_to(src);(pr/'cmake').mkdir()
 conf='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/conf,pr/conf);top=(nd/'CMakeLists.txt').read_text()
 (pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(DetailOption LANGUAGES C CXX)\n'+top[top.index('# --- Capstone (our fork'):top.index('# --- NeverD CMake helpers')])
 run('cmake','-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-S',pr,'-B',build)
 # Ask for the actual native and ordinary entry points in a single non-PIE ELF.
 (w/'probe.c').write_text('#include <capstone/capstone.h>\n#include "arch/X86/X86ScanAdapter.h"\nint main(void){csh h; if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);cs_insn *a=cs_malloc(h);const uint8_t input[]={0x90,0x90};const uint8_t *p=input;size_t n=2;uint64_t ip=0;int ok=cs_disasm_iter(h,&p,&n,&ip,a)&&X86_disasmIterText(h,&p,&n,&ip,a);cs_free(a,1);cs_close(&h);return !ok;}\n')
 run('clang','-std=c11','-O2','-I',src,'-I',src/'include','-c',w/'probe.c','-o',w/'probe.o')
 path=src/'cs.c';base=path.read_text();a=base.index('\t\tif (value == CS_OPT_OFF)',base.index('\n\tcase CS_OPT_DETAIL:'));b=base.index('\n#ifdef',a);old=base[a:b];assert 'handle->detail_opt |= (cs_opt_value)value;' in old
 norm=old.replace('(cs_opt_value)value','(cs_opt_value)(value | CS_OPT_ON)')
 alt={'shipping':base,'option_case':once(base,old,norm)}
 variants={
 'conditional':'\t\thandle->detail_opt = value == CS_OPT_OFF ? CS_OPT_OFF :\n\t\t\t(cs_opt_value)(value | handle->detail_opt | CS_OPT_ON);',
 'inherit':'\t\thandle->detail_opt = (cs_opt_value)value |\n\t\t\t(value ? (handle->detail_opt | CS_OPT_ON) : CS_OPT_OFF);',
 'accumulate':'\t\tif (value != CS_OPT_OFF)\n\t\t\tvalue |= handle->detail_opt | CS_OPT_ON;\n\t\thandle->detail_opt = (cs_opt_value)value;',
 'enable_then_merge':'\t\tif (value == CS_OPT_OFF)\n\t\t\thandle->detail_opt = CS_OPT_OFF;\n\t\telse {\n\t\t\thandle->detail_opt |= CS_OPT_ON;\n\t\t\thandle->detail_opt |= (cs_opt_value)value;\n\t\t}',
 'raw_predicate':'\t\thandle->detail_opt = (cs_opt_value)((value | handle->detail_opt) * (value != 0));\n\t\thandle->detail_opt |= (cs_opt_value)(value != 0);',
 }
 for key,body in variants.items():alt[key]=once(base,old,body)
 pin='\tswitch (type) {'
 idx=base.index(pin,base.index('cs_err CAPSTONE_API cs_option('))
 alt['normalize_at_entry']=base[:idx]+'\tif (type == CS_OPT_DETAIL && value != CS_OPT_OFF)\n\t\tvalue |= CS_OPT_ON;\n'+base[idx:]
 # A cold detail setter is a distinct ownership boundary and consumes no per-instruction work.
 setter='static cs_opt_value add_detail_view(cs_opt_value current, uintptr_t requested)\n{\n\treturn requested ? (cs_opt_value)(current | requested | CS_OPT_ON) : CS_OPT_OFF;\n}\n\n'
 i=base.index('CAPSTONE_EXPORT\ncs_err CAPSTONE_API cs_option(')
 alt['cold_setter']=once(base[:i]+'#if defined(__GNUC__)\n__attribute__((cold, noinline))\n#endif\n'+setter+base[i:],old,'\t\thandle->detail_opt = add_detail_view(handle->detail_opt, value);')
 summary={};reference=None
 for key,source in alt.items():
  path.write_text(source);run('cmake','--build',build,'--target','capstone_static','--parallel','4')
  archive,=build.rglob('libcapstone.a');exe=w/'probe';run('clang','-no-pie',w/'probe.o',archive,'-o',exe);run(exe)
  if key!='shipping':
   test=r/'detail_views.c';run('clang','-std=c11','-O2','-I',src/'include',test,archive,'-o',w/'views');run(w/'views')
  sym=symbols(exe)
  for func in ('cs_option','cs_decode_full_insn','cs_disasm_iter','X86_disasmIterText'):assert func in sym
  if reference is None:reference=sym
  changed={n for n in reference if n not in sym or reference[n]!=sym[n]};hot=sorted(changed-{'cs_option','add_detail_view'})
  common=sorted(n for n in changed if n in sym)
  cs=sym['cs_option'][0];base_cs=reference['cs_option'][0]
  changed_code=[n for n in common if [x[2] for x in sym[n]]!=[x[2] for x in reference[n]]]
  summary[key]=dict(source=h(source.encode()),cs_option=cs,option_size_delta=cs[1]-base_cs[1],changed_count=len(changed),unmodified_other_functions=not hot,changed_names=sorted(changed),changed_code=changed_code,extra_symbols=sorted(sym.keys()-reference.keys()),archive=h(archive.read_bytes()),hot={n:sym[n]for n in ['cs_decode_full_insn','cs_disasm_iter','X86_disasmIterText']})
  for f in ('cs_option','cs_decode_full_insn'):
   asm=get('objdump','-d','--no-show-raw-insn','--disassemble='+f,exe)
   start=asm.index('<'+f+'>:');(e/(key+'-'+f+'.asm')).write_text(asm[start:]+'\n')
  save('variants',summary)
 save('complete',dict(complete=True,host=platform.machine(),compiler=get('clang','--version').splitlines()[0],source=q,variants=summary))
finally:
 size=sum(x.stat().st_size for x in w.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
