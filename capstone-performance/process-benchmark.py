from pathlib import Path
import json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
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
 for label,patch in [('base',False),('new',True)]:
  if patch:run.command(['git','apply',f],'apply',w)
  run.command(['cmake','-S',w,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON'],'config-'+label)
  run.command(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+label)
  lib='libcapstone.'+('dylib' if platform.system()=='Darwin' else 'so');out=root/(label+'-'+lib);shutil.copyfile(b/lib,out);bins[label]=out
 run.write('inputs.json',dict(capstone=man['capstone_revision'],patch=run.sha(f),consumer=run.sha(consumer),libraries={k:run.sha(v)for k,v in bins.items()}))
 if platform.system()=='Linux':os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 results=[]
 for row in cases:
  for m in (1,2):
   orders=[]
   for rev in (0,1):
    libs=[bins['base'],bins['new']];libs=libs[::-1] if rev else libs
    data=json.loads(sp.check_output([consumer,*libs,str(row['selector']),str(m),row['path']],text=True))
    raw=data['ticks'];assert len(raw)==9
    values=[(sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2])) for i,t in enumerate(raw)]
    if rev:values=[1/x for x in values]
    orders.append(dict(raw=data,gain=st.median(values),pairs=values))
   results.append(dict(case=row['name'],mode=('scan','format','detail')[m],orders=orders,gain=st.median(p for v in orders for p in v['pairs'])))
   run.write('measurements.json',results)
if __name__=='__main__':
 run.EVIDENCE.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
  try:main(Path(temp))
  finally:
   n=sum(f.stat().st_size for f in Path(temp).rglob('*')if f.is_file());shutil.rmtree(temp);run.write('cleanup.json',dict(bytes=n,removed=True))
