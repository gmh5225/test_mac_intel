from pathlib import Path
import json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import re
import run,corpus
src=run.SOURCE
def main(root):
 run.WORK=root;man=json.loads((src/'manifest.json').read_text());w=run.fetch('capstone','https://github.com/NeverSight/capstone.git',man['capstone_revision'])
 inputs={row['name'] for row in man['inputs']}
 cases=[row for row in corpus.prepare(src,root,run.EVIDENCE,run.command) if row['name'] in inputs]
 assert len(cases)==len(inputs)==10 and {row['name'] for row in cases}==inputs
 f=src/'alias-trie.patch';assert run.sha(f)==(src/'alias-trie.sha256').read_text().strip()
 cpp=(src/'single.cpp').read_text();a=cpp.index('  API() {');z=cpp.index('\n  }',a)
 names=['cs_open','cs_option','cs_malloc','cs_disasm_iter','cs_regs_access','cs_free','cs_close']
 cpp=cpp[:a]+'''  explicit API(const char *path) {
    library=dlopen(path, RTLD_NOW|RTLD_LOCAL);
    if (!library) throw std::runtime_error(dlerror());
'''+''.join('    '+n+'=reinterpret_cast<decltype('+n+')>(dlsym(library,"'+n+'")); if (!'+n+') throw std::runtime_error("'+n+'");\n' for n in names)+cpp[z:]
 cpp=cpp[:cpp.index('int main(int argc')]+(src/'register_pair.cpp').read_text()
 (root/'pair.cpp').write_text(cpp)
 consumer=root/'pair';run.command(['clang++','-DNDEBUG','-O3','-std=c++17','-I',w/'include',root/'pair.cpp','-o',consumer,*(['-ldl'] if platform.system()=='Linux' else [])],'consumer')
 b=root/'build';bins={}
 layout=w/'CMakeLists.txt';original=layout.read_text()
 block=original[original.index('set(ALL_SOURCES'):original.index('set(ALL_HEADERS')]
 assert block.count('${SOURCES_AARCH64}')==1 and block.count('${SOURCES_X86_NUMBERS}')==1
 # Move the AArch64 object inputs together to the back of the existing CMake list.
 tail=block.replace('    ${SOURCES_AARCH64}\n','').replace('    ${SOURCES_X86_NUMBERS}','    ${SOURCES_X86_NUMBERS}\n    ${SOURCES_AARCH64}')
 reordered=original.replace(block,tail)
 symbols={};objects={}
 for label,apply,move in [('base',False,False),('new',True,False),('tail_base',False,True),('tail_new',True,True)]:
  if label=='tail_base':run.command(['git','apply','-R',f],'remove',w)
  if apply:run.command(['git','apply',f],'apply-'+label,w)
  if move:layout.write_text(reordered)
  run.command(['cmake','-S',w,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON'],'config-'+label)
  run.command(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+label)
  lib='libcapstone.'+('dylib' if platform.system()=='Darwin' else 'so');out=root/(label+'-'+lib);shutil.copyfile(b/lib,out);bins[label]=out
  objects[label]={str(o.relative_to(b)):run.sha(o)for o in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
  lines=sp.check_output(['nm','-an',out],text=True).splitlines()
  watch={'cs_disasm_iter','cs_decode_full_insn','X86_getInstruction','X86_Intel_printInst','decodeInstructionFull','printPCRelImm','X86_reg_access','ARM_printInst','Thumb_getInstruction','printRegName','printRegNameAlt','SStream_concat0','readModRM','cs_open','X86_get_insn_id','ARM_getInstruction','AArch64_printInst','asmwriter_recipe','reg_map','x86LegacyDecisions','x86LegacyPublicDecisions'}
  syms={}
  for line in lines:
   parts=line.split()
   if len(parts)!=3 or not all(c in '0123456789abcdefABCDEF' for c in parts[0]):continue
   key=parts[2].lstrip('_')
   if key in watch:syms.setdefault(key,[]).append(int(parts[0],16))
  assert 'cs_disasm_iter' in syms and 'X86_getInstruction' in syms
  symbols[label]=syms
 run.write('symbol-offsets.json',symbols);run.write('objects.json',objects)
 for x,y in [('base','new'),('tail_base','tail_new')]:
  changes=[k for k,v in objects[x].items() if objects[y][k]!=v]
  assert changes==['CMakeFiles/capstone.dir/arch/AArch64/AArch64InstPrinter.c.o'],changes

 run.write('inputs.json',dict(capstone=man['capstone_revision'],patch=run.sha(f),consumer=run.sha(consumer),libraries={k:run.sha(v)for k,v in bins.items()}))
 if platform.system()=='Linux':os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 results=[]
 for row in cases:
  if row['name'] not in ('arm-ls','thumb-ls','arm64-ls','arm64-cp','putty-32-0.85'):continue
  for m in (1,2):
   for baseline,candidate in [('base','new'),('tail_base','tail_new'),('base','tail_new')]:
    orders=[]
    for rev in (0,1):
     libs=[bins[baseline],bins[candidate]];libs=libs[::-1] if rev else libs
     data=json.loads(sp.check_output([consumer,*libs,str(row['selector']),str(m),row['path']],text=True))
     raw=data['ticks'];assert len(raw)==9
     values=[(sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2])) for i,t in enumerate(raw)]
     if rev:values=[1/x for x in values]
     orders.append(dict(raw=data,gain=st.median(values),pairs=values))
    results.append(dict(case=row['name'],baseline=baseline,candidate=candidate,mode=('scan','format','detail')[m],orders=orders,gain=st.median(p for v in orders for p in v['pairs'])))
    run.write('measurements.json',results)

if __name__=='__main__':
 run.EVIDENCE.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
  try:main(Path(temp))
  finally:
   n=sum(f.stat().st_size for f in Path(temp).rglob('*')if f.is_file());shutil.rmtree(temp);run.write('cleanup.json',dict(bytes=n,removed=True))
