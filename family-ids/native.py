from pathlib import Path
from io import BytesIO
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from elftools.elf.elffile import ELFFile
from corpus import deb_binary,elf_text
from fixed_image import FixedImage
r=Path(__file__).resolve().parent;src=r.parent/'source';ev=r.parent/'evidence';ev.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_bytes());digest=lambda b:hashlib.sha256(b).hexdigest()
def save(k,v):
 f=ev/(k+'.json');tmp=f.with_suffix('.temp');tmp.write_text(json.dumps(v,indent=1)+'\n');tmp.replace(f)
def run(*a):sp.run(a,check=True)
def get(*a):return sp.check_output(a,text=True).strip()
q=rd(r/'source.json');meta=rd(r/'samples.json');isa=platform.machine();mac=platform.system()=='Darwin'
os.environ['ZERO_AR_DATE']='1';w=Path(tempfile.mkdtemp());tests={};coverage={};experiment={};compiled={};timed={}
try:
 assert get('git','-C',src,'rev-parse','HEAD')==q['parent'] and digest((r/'candidate.patch').read_bytes())==q['sha256']
 pkg=w/'coreutils.deb'
 for url in (meta['snapshot_url'],meta['url']):
  v=sp.run(['curl','--retry','2','--http1.1','--fail','--silent','--show-error','--location','--max-time','70',url,'-o',pkg])
  if not v.returncode and digest(pkg.read_bytes())==meta['package_sha256']:break
 else:raise RuntimeError('Both locations failed to supply the pinned Debian package.')
 for n,z in meta['programs'].items():
  el=deb_binary(pkg,n);assert digest(el)==z['elf_sha256'];sec=ELFFile(BytesIO(el)).get_section_by_name('.text');text=sec.data()
  assert text==elf_text(el) and digest(text)==z['section_sha256'] and len(text)==z['bytes'] and sec['sh_addr']==z['text_address']
  (w/(n+'.text')).write_bytes(text);(w/(n+'.ranges')).write_text('0 %d %d\n'%(len(text),z['text_address']))
 pkg.unlink()
 for name in ('records','views'):
  run('c++','-std=c++17','-O2','-I',src/'include',r/(name+'.cpp'),*([] if mac else ['-ldl']),'-o',w/name)
 project=w/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
 shutil.copyfile(r/'consumer.cmake',project/'CMakeLists.txt');shutil.copyfile(r/'options.cmake',project/'cmake/NeverDCapstoneCompilerOptions.inc')
 if not mac:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 for prof in ('loongarch','debug','diet','mixed-loongarch','consumer'):
  b=w/'build';diet=prof=='diet';compiled[prof]={};tests[prof]={};libs={}
  for stage in ('base','fixed'):
   run('git','-C',src,'restore','--source','HEAD','--staged','--worktree','--','.')
   if stage=='fixed':
    run('git','-C',src,'apply','--index',r/'candidate.patch');assert get('git','-C',src,'write-tree')==q['tree']
   cfg=['cmake','-G','Ninja','-S',project if prof=='consumer' else src,'-B',b,'-DCMAKE_BUILD_TYPE='+('Debug' if prof=='debug' else 'Release'),'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
   if mac:cfg+=['-DCAPSTONE_BUILD_MACOS_THIN=ON']
   if prof!='consumer':
    cfg+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_LOONGARCH_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_DIET='+('ON' if diet else 'OFF')]
    if prof=='mixed-loongarch':cfg+=['-DCAPSTONE_MIPS_SUPPORT=ON']
   run(*cfg);targets=['capstone_static']
   if prof!='consumer':targets+=['capstone_shared','register_descriptors']+(['loongarch_register_detail'] if stage=='fixed' and not diet else [])
   run('cmake','--build',b,'--target',*targets,'--parallel','4')
   lib,=b.rglob('libcapstone.a')
   if prof!='consumer':
    so,=[f for f in b.glob('libcapstone*.dylib' if mac else 'libcapstone.so.*') if not f.is_symlink()]
    dll=w/(stage+'-library');shutil.copyfile(so,dll);libs[stage]=dll
    result=get('ctest','--test-dir',b,'-R','^unit_(register_descriptors|loongarch_register_detail)$','--no-tests=error','--output-on-failure')
    assert '100% tests passed' in result;tests[prof][stage]=dict(ctest=result)
    if stage=='base' and not diet:
     exe=w/'red';run('cc','-I',src/'include',r/'regression.c',lib,'-o',exe);red=sp.run([exe],text=True,capture_output=True)
     assert red.returncode==1 and 'read 1 of 2 registers' in red.stderr and '$f27, $r13, $r31' in red.stderr
     tests[prof][stage]['red']=red.stderr
   if prof in ('loongarch','consumer'):
    exe=w/'timed';run('c++','-O3','-std=c++17','-I',src/'include',r/'time.cpp',lib,*([] if mac else ['-no-pie']),'-o',exe)
    compiled[prof][stage]=dict(objects={str(f.relative_to(b)):digest(f.read_bytes())for f in b.rglob('*.c.o')},lib=digest(lib.read_bytes()),exe=digest(exe.read_bytes()))
    if prof=='loongarch':timed[stage]=exe.read_bytes()
    if prof=='consumer':
     assert not any('/arch/LoongArch/' in c['file'] for c in rd(b/'compile_commands.json'));shutil.rmtree(b)
  if prof=='consumer':
   assert compiled[prof]['base']==compiled[prof]['fixed'];continue
  coverage[prof]={}
  for name,spec in meta['programs'].items():
   res={}
   for tool,num in [('records',16),('views',2)]:
    lines=[list(map(int,z.split()))for z in get(w/tool,libs['base'],libs['fixed'],w/(name+'.text'),str(spec['text_address']),str(int(diet))).splitlines()]
    assert len(lines)==num and all(s[1]*4==spec['bytes'] for s in lines)
    res[tool]=lines
   coverage[prof][name]=res
  save('coverage',coverage);shutil.rmtree(b)
 assert coverage['loongarch']==coverage['mixed-loongarch']==coverage['debug']
 # Mode 3 consumes corrected register read counts. Only compare unchanged default work for this check.
 image=FixedImage(w/'same-file',{'base':timed['base'],'candidate':timed['fixed']},True)
 for name in meta['programs']:
  for mode in range(3):
   key=name+'/'+str(mode)
   def take(tag,n):
    image.select(tag);return list(map(int,get(*([] if mac else ['setarch',isa,'-R']),image.path,'108',str(mode),w/(name+'.text'),'0',str(n),w/(name+'.ranges')).split()))
   warm=take('base',1);reps=max(1,math.ceil(18e6/warm[0]));rng=random.Random(key);cycles=[];tags=['base','candidate','copy','repeat']
   for _ in range(17):
    rng.shuffle(tags);pair={k:[]for k in tags}
    for t in tags+tags[::-1]:
     z=take(t,reps);assert z[2]==warm[2] and min(z[:2])>0;pair[t].append(z[:2])
    cycles.append({k:[sum(d[i] for d in v)for i in (0,1)]for k,v in pair.items()})
   experiment[key]=dict(reps=reps,records=warm[2],cycles=cycles);save('times',experiment)
 save('builds',compiled);save('tests',tests);save('complete',dict(complete=True,tree=q,system=platform.system(),isa=isa,compiler=get('cc','--version').splitlines()[0],image=image.receipt(),samples=meta,consumer=rd(r/'consumer.json')))
finally:
 n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
