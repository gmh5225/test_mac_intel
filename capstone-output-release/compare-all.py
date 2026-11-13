from pathlib import Path
import hashlib,json,os,platform,re,shutil,tempfile,subprocess as sp
d=Path(__file__).resolve().parent;s=d.parent/'source';o=d.parent/'evidence';o.mkdir();cc=os.environ['TOOLCHAIN']
def run(args,label):
 print(label,flush=True)
 with (o/(label+'.log')).open('wb')as out:sp.run(list(map(str,args)),cwd=s,stdout=out,stderr=sp.STDOUT,check=True)
def save(name,value):(o/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def sha(f):
 h=hashlib.sha256()
 with f.open('rb')as stream:
  for buf in iter(lambda:stream.read(1024*1024),b''):h.update(buf)
 return h.hexdigest()
with tempfile.TemporaryDirectory(prefix='all-capstone-isas-') as tmp:
 w=Path(tmp);b=w/'build'
 try:
  arches=re.search(r'set\(SUPPORTED_ARCHITECTURES ([ A-Z0-9]+)\)',(s/'CMakeLists.txt').read_text()).group(1).split();assert len(arches)>=23
  run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
  cache=(b/'CMakeCache.txt').read_text();assert all(('CAPSTONE_'+n+'_SUPPORT:BOOL=ON')in cache for n in arches)
  for who in ('base','candidate'):
   if who=='candidate':run(['git','apply',d/'combined.patch'],'apply')
   run(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+who)
   obj=b/'CMakeFiles/capstone.dir';items={k.relative_to(obj).as_posix():sha(k) for k in obj.rglob('*.o')};assert len(items)>95
   fs=[v for v in b.iterdir()if v.is_file() and not v.is_symlink() and ('.so' in v.name or v.name.endswith('.dylib'))];assert len(fs)==1,fs
   if who=='base':original=items;lib=sha(fs[0])
   else:
    diffs=[k for k in set(original)|set(items) if original.get(k)!=items.get(k)];save('objects',dict(differences=diffs,total=len(items)));assert not diffs,diffs;assert sha(fs[0])==lib
  save('complete',dict(architectures=arches,objects=len(original),library_sha256=lib,identical=True,cc=cc,host=platform.platform()))
 finally:
  size=sum(x.lstat().st_size for x in w.rglob('*')if x.is_file());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
