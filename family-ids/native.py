"""Measure dedicated alias printers and verify the six-architecture consumer is byte identical."""
from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from corpus import deb_binary,elf_text
from arm_corpus import prepare as arm_extents
from elftools.elf.elffile import ELFFile
from fixed_image import FixedImage
from io import BytesIO
r=Path(__file__).resolve().parent;src=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True)
read=lambda f:json.loads(f.read_bytes())
def put(k,v):
 f=e/(k+'.json');p=f.with_suffix('.tmp');p.write_text(json.dumps(v,indent=1)+'\n');p.replace(f)
def run(*args):sp.run(args,check=True)
def out(*args):return sp.check_output(args,text=True).strip()
def sha(data):return hashlib.sha256(data).hexdigest()
def dig(path):return sha(path.read_bytes())
q=read(r/'source.json');w=Path(tempfile.mkdtemp());samples=read(r/'samples.json');isa=platform.machine();darwin=platform.system()=='Darwin';os.environ['ZERO_AR_DATE']='1'
try:
 assert out('git','-C',src,'rev-parse','HEAD')==q['checkout']
 inputs={}
 for arch,meta in samples.items():
  pkg=w/(arch+'.deb');run('curl','--http1.1','--retry-all-errors','--retry','3','--max-time','120','-fsSL',meta['url'],'-o',pkg)
  assert dig(pkg)==meta['package_sha256'];inputs[arch]={}
  for name,spec in meta['programs'].items():
   elf=deb_binary(pkg,name);section=ELFFile(BytesIO(elf)).get_section_by_name('.text')
   text=elf_text(elf);assert sha(text)==spec['section_sha256'] and text==section.data()
   if 'elf_sha256'in spec:assert sha(elf)==spec['elf_sha256']
   path=w/(arch+name+'.text');path.write_bytes(text);spans=path.with_suffix('.ranges');spans.write_text('0 %d %d\n'%(len(text),section['sh_addr']))
   inputs[arch][name]=(path,spans)
  pkg.unlink()
 builds={};observations={};measure={};archs={'HPPA':111,'mixed':0}
 if not darwin:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 archs['hppa-diet']=111;archs['hppa-debug']=111
 for arch,sel in archs.items():
  b=w/'build';images={};builds[arch]={};records={}
  for tag in ('shipping','base','candidate'):
   run('git','-C',src,'restore','--source','HEAD','--staged','--worktree','--','.')
   patch=r/(tag+'.patch');assert dig(patch)==q[tag]['patch']
   if patch.stat().st_size:run('git','-C',src,'apply','--index',patch)
   assert out('git','-C',src,'write-tree')==q[tag]['tree']
   aset=['ARM','AARCH64','MIPS','PPC','X86','RISCV'] if arch=='mixed' else ['HPPA'] if arch.startswith('hppa-') else [arch]
   run('cmake','-G','Ninja','-S',src,'-B',b,'-DCMAKE_BUILD_TYPE='+('Debug' if arch=='hppa-debug' else 'Release'),'-DCAPSTONE_BUILD_DIET='+('ON' if arch=='hppa-diet' else 'OFF'),*(['-DCAPSTONE_BUILD_MACOS_THIN=ON'] if darwin else []),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST='+('OFF' if arch=='mixed' else 'ON'),'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in aset])
   run('cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared')
   if arch!='mixed' and tag!='shipping':
    run('cmake','--build',b,'--parallel','4','--target','hppa_register_detail')
    check=out('ctest','--test-dir',b,'-R','^unit_hppa_register_detail$','--no-tests=error','--output-on-failure')
    assert '100% tests passed' in check;put('detail-'+arch+'-'+tag,dict(cases=12,ctest=check))
   lib=b/'libcapstone.a';so=next(f for f in b.glob('libcapstone.*.dylib' if darwin else 'libcapstone.so.*')if not f.is_symlink())
   builds[arch][tag]={'static':dig(lib),'shared':dig(so),'objects':{str(p.relative_to(b)):dig(p)for p in (b/'CMakeFiles/capstone.dir').rglob('*.c.o')}}
   if arch not in ('HPPA','hppa-diet','hppa-debug'):continue
   if arch!='mixed':
    exe=w/'name-check';run('cc','-I',src/'include',r/'names.c',lib,'-o',exe);run(exe)
    check=w/'register-records';run('c++','-std=c++17','-O2','-I',src/'include',r/'register-records.cpp',lib,'-o',check)
    verified={}
    for name,(path,ranges) in inputs['HPPA'].items():
     addr=samples['HPPA']['programs'][name]['text_address']
     for option in range(5):
      row=list(map(int,out(check,'0' if tag=='shipping' else '1',str(option),path,str(addr),name).split()))
      assert len(row)==8 and 4*sum(row[:2])==path.stat().st_size
      if tag!='shipping':assert row[-2:]==[0,0]
      verified[f'{name}/{option}']=row
    put('register-records-'+arch+'-'+tag,verified)
   if tag=='shipping':continue
   shutil.copyfile(so,w/(tag+'-hppa-library'))
   texe=w/'timed-link';run('c++','-std=c++17','-O3',*([] if darwin else ['-no-pie']),'-I',src/'include',r/'time.cpp',lib,'-o',texe)
   images[tag]=texe.read_bytes()
   exe=w/'observe';run('c++','-std=c++17','-O2','-I',src/'include',r/'raw.cpp',lib,'-o',exe)
   records[tag]={f'{name}/{opt}':list(map(int,out(exe,str(sel),path,str(opt),ranges).split()))for name,(path,ranges)in inputs['HPPA'].items()for opt in range(5)}
   assert all(row[0]>0 for row in records[tag].values())
  put('compilation',builds)
  if arch not in ('HPPA','hppa-diet','hppa-debug'):
   assert builds[arch]['shipping']==builds[arch]['base']==builds[arch]['candidate'],(arch,isa);shutil.rmtree(b);continue
  maps=builds[arch]
  changed=[key for key,h in maps['base']['objects'].items() if maps['candidate']['objects'][key]!=h]
  assert set(Path(key).name for key in changed)<={'HPPAMapping.c.o','HPPAInstPrinter.c.o','HPPAModule.c.o'}
  assert records['base']==records['candidate'];observations[arch]=records['base'];put('public-records',observations)
  guard={}
  for name in (('guard',) if arch=='hppa-diet' else ('guard','callback')):
   compare=w/name;run('c++','-std=c++17','-O2','-I',src/'include',r/('hppa-'+name+'.cpp'),*([] if darwin else ['-ldl']),'-o',compare)
   guard[name]=out(compare,w/'base-hppa-library',w/'candidate-hppa-library');assert guard[name]
  put('domain-'+arch,guard)
  if arch!='HPPA':shutil.rmtree(b);continue
  exe=w/'timed';image=FixedImage(exe,images,True)
  for name,(path,ranges) in inputs[arch].items():
   for mode in range(4):
    key=f'{arch}/{name}/{mode}'
    def take(tag,n):
     image.select(tag);return list(map(int,out(*([]if darwin else ['setarch',isa,'-R']),exe,str(sel),str(mode),path,'0',str(n),ranges).split()))
    warm=take('base',1);reps=max(1,math.ceil(30e6/warm[0]));rng=random.Random(key);cycles=[];labels=['base','candidate','copy','repeat']
    for _ in range(17):
     rng.shuffle(labels);values={k:[]for k in labels}
     for tag in labels+labels[::-1]:
      z=take(tag,reps);assert z[2]==warm[2]and min(z[:2])>0;values[tag].append(z[:2])
     cycles.append({k:[sum(t[i] for t in vs)for i in range(2)]for k,vs in values.items()})
    measure[key]=dict(cycles=cycles,reps=reps,observed=warm[2],text=dig(path),extents=dig(ranges));put('timings',measure)
  put('image-'+arch,image.receipt());exe.unlink();shutil.rmtree(b)
 put('complete',dict(complete=True,source=q,isa=isa,system=platform.system(),panels=len(measure),compiler=out('clang','--version').splitlines()[0]))
finally:
 size=sum(p.stat().st_size for p in w.rglob('*')if p.is_file() and not p.is_symlink());shutil.rmtree(w);put('cleanup',dict(removed=not w.exists(),bytes=size))
