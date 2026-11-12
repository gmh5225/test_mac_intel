from pathlib import Path
import json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import run,corpus,native
src=run.SOURCE
cc=os.environ['CC']
def main(root):
 run.WORK=root;man=json.loads((src/'manifest.json').read_text());w=run.fetch('capstone','https://github.com/NeverSight/capstone.git',man['capstone_revision'])
 inputs={row['name'] for row in man['inputs']} | {'scalar32','scalar64','simd64'}
 cases=[row for row in corpus.prepare(src,root,run.EVIDENCE,run.command) if row['name'] in inputs]
 assert len(cases)==len(inputs)==8 and {row['name'] for row in cases}==inputs
 f=src/'alias-trie.patch';assert run.sha(f)==(src/'alias-trie.sha256').read_text().strip()
 run.command(['lscpu'],'cpu')
 run.command([cc,'--version'],'compiler')
 cfg=os.environ['CONFIGURATION']
 native.verify(w, root, cases, cc, cfg)
 if os.environ['TIMING']!='yes':return
 cases=[row for row in cases if row['name']in('putty-32-0.85','amd64-sort','amd64-cp','simd64')]
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
  # Verify the exact objects produced for the unaffected mixed build.
  mixed=root/'mixed'
  run.command(['cmake','-S',w,'-B',mixed,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+k+'_SUPPORT=ON' for k in ('ARM','AARCH64','X86','MIPS','SPARC','LOONGARCH','RISCV')],'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'mixed-config-'+label)
  run.command(['cmake','--build',mixed,'--target','capstone_static','--parallel','4'],'mixed-build-'+label)
  digest={str(f.relative_to(mixed)):run.sha(f) for f in (mixed/'CMakeFiles/capstone.dir').rglob('*.o')}
  assert len(digest)>20
  if label=='base': control=digest
  else:
   assert digest==control,[k for k,v in digest.items() if control.get(k)!=v]
   run.write('mixed-objects.json',digest)
  run.command(['cmake','-S',w,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON'],'config-'+label)
  run.command(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+label)
  if label=='new':
   assert 'CAPSTONE_X86_ONLY' in (b/'build.ninja').read_text()
   assert 'CAPSTONE_X86_ONLY' not in (mixed/'build.ninja').read_text()
  lib='libcapstone.' +('dylib' if platform.system()=='Darwin' else 'so');out=root/(label+'-'+lib);shutil.copyfile(b/lib,out);bins[label]=out
  dedicated={str(f.relative_to(b)):run.sha(f) for f in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
  if label=='base': original=dedicated
  else:
   changed=[k for k in original if original[k]!=dedicated[k]]
   expected=['CMakeFiles/capstone.dir/arch/X86/X86Mapping.c.o'] if platform.system()=='Linux' else []
   assert changed==expected,changed
   run.write('dedicated-objects.json',dict(changed=changed,base=original,new=dedicated))
 if platform.system()!='Linux':return
 # Make is a separate supported entry point. Compile the official encoding
 # regression with the same allocator/architecture configuration as the lib.
 make=root/'make'
 run.command(['make','-j4','CAPSTONE_ARCHS=x86','CC='+cc,'BUILDDIR='+str(make),str(make/'libcapstone.a')],'gnu-make',w)
 run.command([cc,'-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',w/'include','-I',w/'tests/unit/include',w/'tests/unit/x86_encoding_accuracy.c',make/'libcapstone.a','-o',root/'make-unit'],'make-unit-build')
 run.command([root/'make-unit'],'make-unit')
 for label, lib in list(bins.items()):
  twin=root/('aa-'+lib.name); shutil.copyfile(lib,twin); assert run.sha(twin)==run.sha(lib)
  bins[label+'_aa']=twin
 run.write('inputs.json',dict(capstone=man['capstone_revision'],patch=run.sha(f),consumer=run.sha(consumer),libraries={k:run.sha(v)for k,v in bins.items()}))
 if platform.system()=='Linux':os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 results=[]
 for row in cases:
  for m in (0,1,2):
   orders=[]
   for rev in (0,1):
    libs=[bins['base'],bins['new']];libs=libs[::-1] if rev else libs
    data=json.loads(sp.check_output([consumer,*libs,str(row['selector']),str(m),row['path']],text=True))
    raw=data['ticks'];assert len(raw)==9
    values=[(sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2])) for i,t in enumerate(raw)]
    if rev:values=[1/x for x in values]
    orders.append(dict(raw=data,gain=st.median(values),pairs=values))
   aa=[]
   for label in ['base','new']:
    data=json.loads(sp.check_output([consumer,bins[label],bins[label+'_aa'],str(row['selector']),str(m),row['path']],text=True))
    assert len(data['ticks'])==9
    values=[(sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2])) for i,t in enumerate(data['ticks'])]
    aa.append(dict(label=label,raw=data,gain=st.median(values),pairs=values))
   results.append(dict(aa=aa,case=row['name'],mode=('scan','format','detail')[m],orders=orders,gain=st.median(p for v in orders for p in v['pairs'])))
   run.write('measurements.json',results)
if __name__=='__main__':
 run.EVIDENCE.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
  try:main(Path(temp))
  finally:
   n=sum(f.stat().st_size for f in Path(temp).rglob('*')if f.is_file());shutil.rmtree(temp);run.write('cleanup.json',dict(bytes=n,removed=True))
