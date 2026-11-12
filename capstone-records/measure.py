from pathlib import Path
import hashlib,json,os,platform,shutil,statistics as st,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir();s=r.parent/'source'
def write(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,cwd=None):
 print(label,flush=True)
 with (e/(label+'.log')).open('w') as f:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
 if rc:raise RuntimeError((label,(e/(label+'.log')).read_text()[-1000:]))
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==json.loads((r/'manifest.json').read_text())['capstone_revision']
mac=platform.system()=='Darwin'
with tempfile.TemporaryDirectory(prefix='capstone-pe32-order-') as tmp:
 t=Path(tmp)
 try:
  cases=corpus.prepare(r,t,e,run)
  cases=[x for x in cases if x['name'].startswith('arm64-')]
  assert len(cases)==3
  arches=['AARCH64'];cc=os.environ['MEASURE_CC'];mixed=['X86','AARCH64','ARM','MIPS','LOONGARCH','RISCV','SPARC']
  def configure(name,architectures,extra):
   opts=['-DCAPSTONE_'+x+'_SUPPORT=ON' for x in architectures]
   build=t/name
   run(['cmake','-S',s,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*opts,*extra],'config-'+name+'-'+label)
   return build
  suffix='.dylib' if mac else '.so';products={};controls={}
  for label in ['base','new']:
   if label=='new':run(['git','apply',r/'product.patch'],'apply',s)
   for key,subset in [('four',mixed[:4]),('seven',mixed)]:
    mb=configure(key,subset,[]);run(['cmake','--build',mb,'--target','capstone_static','--parallel','4'],'mixed-'+key+'-'+label)
    assert 'CAPSTONE_AARCH64_INIT_CONSTRUCTED_OPERANDS' not in (mb/'build.ninja').read_text()
    hashes={str(x.relative_to(mb)):hashlib.sha256(x.read_bytes()).hexdigest()for x in (mb/'CMakeFiles/capstone.dir').rglob('*.o')}
    assert len(hashes)>25
    if label=='new':assert controls[key]==hashes
    controls[key]=hashes;write('mixed-objects',controls)
   b=configure('build',arches,['-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON'])
   assert ('CAPSTONE_AARCH64_INIT_CONSTRUCTED_OPERANDS' in (b/'build.ninja').read_text())==(label=='new')
   run(['cmake','--build',b,'--target','capstone_shared','cstest','mcinst','aarch64_postprocess','--parallel','4'],'build-'+label)
   run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_(mcinst|aarch64_postprocess)$'],'units-'+label)
   exe=next(x for x in b.rglob('cstest') if x.is_file());run([exe,s/'tests/MC/AArch64'],'mc-'+label)
   log=e/('mc-'+label+'.log');data=log.read_bytes();log.unlink();write('mc-'+label,dict(digest=hashlib.sha256(data).hexdigest(),summary=data[-600:].decode()))
   if label=='base':reference=data
   else:assert data==reference
   lib=t/'build'/('libcapstone.6.0.0.dylib' if mac else 'libcapstone.so.6.0.0')
   for key in (label,label+'-aa'):
    f=t/(key+suffix);shutil.copyfile(lib,f);products[key]=f
  identities={k:hashlib.sha256(v.read_bytes()).hexdigest()for k,v in products.items()}
  assert identities['base']==identities['base-aa'] and identities['new']==identities['new-aa'] and identities['base']!=identities['new'];write('images',identities)
  if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
  run(['clang++','-std=c++17','-O3','-DNDEBUG','-I',s/'include',r/'pair.cpp','-ldl','-o',t/'pair'],'pair')
  data=[]
  for x in cases:
   for mode in (0,1,2):
    row=dict(case=x['name'],mode=mode,plans={})
    for left,right,key in [('base','new','forward'),('new','base','reverse'),('base','base-aa','base-aa'),('new','new-aa','new-aa')]:
     raw=json.loads(sp.check_output(list(map(str,[t/'pair',products[left],products[right],x['selector'],mode,x['path']])),text=True));assert len(raw['ticks'])==11
     ratios=[sum(t[::2])/sum(t[1::2]) if i%2==0 else sum(t[1::2])/sum(t[::2]) for i,t in enumerate(raw['ticks'])]
     if key=='reverse':ratios=[1/q for q in ratios]
     row['plans'][key]=dict(raw=raw,ratios=ratios,median=st.median(ratios))
    q=row['plans']['forward']['ratios']+row['plans']['reverse']['ratios'];row['median']=st.median(q);row['wins']=sum(n>1 for n in q)
    data.append(row);write('timings',data)
  write('complete',dict(host=platform.platform(),arches=arches,cases=len(data)))
 finally:
  size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
