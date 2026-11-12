from pathlib import Path
import gzip,json,os,re,shutil,statistics,subprocess as sp,tempfile
import run,corpus
s=run.SOURCE
def main(w):
 run.WORK=w;man=json.loads((s/'manifest.json').read_text());src=run.fetch('base','https://github.com/NeverSight/capstone.git',man['capstone_revision'])
 rows=[x for x in corpus.prepare(s,w,run.EVIDENCE,run.command) if x['name']in('putty-32-0.85','scalar32','simd64','amd64-cp')];assert len(rows)==4
 unit=src/'arch/X86/X86DisassemblerTranslator.h';old=unit.read_text()
 run.command(['git','apply','--check',s/'candidate.patch'],'patch-check',src);run.command(['git','apply',s/'candidate.patch'],'patch',src);new=unit.read_text()
 a='X86_TRANSLATE_INLINE bool translateRMMemoryImpl(';b='static bool translateRMMemoryFull(';z='static bool validateRMMemory(';begin=old.index(a);end=old.index(z,begin)
 entry=(s/'single.cpp').read_text();entry=entry[:entry.index('int main(int argc')]+(s/'entry.cpp').read_text();(w/'consumer.cpp').write_text(entry)
 bdir=w/'cmake'
 run.command(['cmake','-S',src,'-B',bdir,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ('ARM','AARCH64','X86','MIPS')],'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
 trees=[]
 for reverse in (False,True):
  impls=[]
  for name,text in [('original',old),('grouped',new)]:
   part=text[text.index(a):text.index(z,text.index(a))].replace('translateRMMemoryImpl','memory_impl_'+name).replace(b,'static __attribute__((noinline)) bool memory_full_'+name+'(')
   slot='a' if (name=='original') != reverse else 'z'
   part=part.replace('__attribute__((noinline))','__attribute__((noinline, section(".text.cs_memory_'+slot+'")))')
   impls.append(part)
  if reverse:impls.reverse()
  selector='''extern unsigned cs_probe_memory_variant;
static bool translateRMMemoryFull(MCInst *m, InternalInstruction *i, OperandType t) {
    if (cs_probe_memory_variant) return memory_full_grouped(m,i,t);
    return memory_full_original(m,i,t);
}
'''
  remainder=old[end:].replace('return translateRMMemoryImpl(mcInst, insn, type, false);','return memory_impl_original(mcInst, insn, type, false);')
  unit.write_text(old[:begin]+''.join(impls)+selector+remainder)
  tag='reversed' if reverse else 'forward'
  run.command(['cmake','--build',bdir,'--target','capstone_static','--parallel','4'],'build-'+tag)
  binary=w/tag
  run.command(['clang++','-DNDEBUG','-O3','-std=c++17','-fno-pie','-no-pie','-Wl,--sort-section=name','-I',src/'include',w/'consumer.cpp',bdir/'libcapstone.a','-ldl','-o',binary],'link-'+tag)
  nm=sp.check_output(['nm','-an',binary],text=True)
  funcs=[v for v in nm.splitlines()if v.endswith((' memory_full_original',' memory_full_grouped'))];assert len(funcs)>=2 and len({v.split()[0] for v in funcs})==len(funcs),funcs
  trees.append(dict(binary=binary,tag=tag,symbols=funcs,sha256=run.sha(binary)))
  original_addresses=sorted(int(v.split()[0],16)for v in funcs if v.endswith('memory_full_original'))
  grouped_addresses=sorted(int(v.split()[0],16)for v in funcs if v.endswith('memory_full_grouped'))
  assert len(original_addresses)==len(grouped_addresses)==2
  assert all((a<b)!=reverse for a,b in zip(original_addresses,grouped_addresses)),funcs
 os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 out=[];profiles=[]
 for tree in trees:
  for row in rows:
   for mode in (1,2):
    args=[str(row['selector']),str(mode),row['path']]
    for plan,start in ((0,0),(0,1),(1,0),(2,1)):
     data=json.loads(sp.check_output([tree['binary'],str(plan),str(start),*args],text=True));assert len(data['ratios'])==11
     out.append(dict(image=tree['tag'],binary_sha256=tree['sha256'],symbols=tree['symbols'],case=row['name'],mode=mode,plan=plan,start=start,median=statistics.median(data['ratios']),**data))
     run.write('rows.json',out)
 assert len(out)==64,len(out)
if __name__=='__main__':
 run.EVIDENCE.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP'])as temp:
  try:main(Path(temp))
  finally:
   n=sum(p.stat().st_size for p in Path(temp).rglob('*')if p.is_file());shutil.rmtree(temp);run.write('cleanup.json',dict(bytes=n,removed=True))
