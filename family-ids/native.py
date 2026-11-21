from pathlib import Path
import hashlib,json,os,re,shutil,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';o=root/'evidence';o.mkdir(exist_ok=True)
def write(k,v):(o/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sh(a,cwd=None):return sp.check_output(list(map(str,a)),cwd=cwd)
def run(a,k):
 with (o/(k+'.log')).open('wb')as log:z=sp.run(list(map(str,a)),stdout=log,stderr=sp.STDOUT)
 if z.returncode:print((o/(k+'.log')).read_text()[-2000:],flush=True);z.check_returncode()
def sha(z):return hashlib.sha256(z).hexdigest()
def inspect(f,symbols=False):
 v=f.read_bytes();h=struct.unpack_from('<16sHHIQQQIHHHHHH',v);assert v[:6]==b'\x7fELF\x02\x01'
 sections=[struct.unpack_from('<IIQQQQIIQQ',v,h[6]+i*h[11])for i in range(h[12])];c=sections[h[13]];names=v[c[4]:c[4]+c[5]]
 def name(t,n):return t[n:t.index(0,n)].decode()
 sections_out={name(names,c[0]):[c[3],c[5],sha(v[c[4]:c[4]+c[5]])] for c in sections[1:] if c[1]!=8}
 if not symbols:return sections_out
 emitted={}
 for tab in sections:
  if tab[1]!=2:continue
  st=sections[tab[6]];ss=v[st[4]:st[4]+st[5]]
  for off in range(tab[4],tab[4]+tab[5],tab[9]):
   nm,info,vis,idx,addr,sz=struct.unpack_from('<IBBHQQ',v,off)
   if idx>=len(sections)or not idx or not sz or (info&15)not in (1,2):continue
   c=sections[idx];start=c[4]+addr-c[3];label=name(ss,nm);emitted[label]=[addr,sz,sha(v[start:start+sz])]
 return emitted
def diff_cache(a,b):
 return {k:[a.get(k),b.get(k)]for k in sorted(a.keys()|b.keys())if a.get(k)!=b.get(k)}
m=json.loads((r/'tree.json').read_text());patch=r/'candidate.patch';assert sha(patch.read_bytes())==m['sha256']
t=Path(tempfile.mkdtemp());b=t/'build';base={};results={};so={}
try:
 run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC')]],'configure')
 assert sh(['git','rev-parse','HEAD'],s).decode().strip()==m['parent']
 files={k:'arch/X86/'+k for k in ('X86UnsignedImmediate.h','X86SimpleOutputImpl.h','X86MemoryOutputImpl.h')}
 source={}
 for label,key in [('base',None),('candidate',None),('old_number','X86UnsignedImmediate.h'),('old_admission','X86SimpleOutputImpl.h'),('old_address','X86MemoryOutputImpl.h')]:
  if label=='candidate':
   run(['git','-C',s,'apply','--index',patch],'candidate');assert sh(['git','write-tree'],s).decode().strip()==m['tree']
   source={n:(s/f).read_bytes() for n,f in files.items()}
  if key:
   for n,f in files.items():(s/f).write_bytes(sh(['git','show','HEAD:'+f],s)if n==key else source[n])
  run(['cmake','--build',b,'--parallel','4','--target','capstone_shared'],'build-'+label)
  lib=next(q for q in b.glob('libcapstone.so.*')if not q.is_symlink());vals=inspect(lib)
  objs={str(f.relative_to(b)):f for f in b.rglob('*.c.o')if '/CMakeFiles/capstone.dir/'in str(f)}
  got={k:sha(f.read_bytes())for k,f in objs.items()};assert len(got)>30
  if label=='base':
   original=got;initial=vals;base['lib']=sha(lib.read_bytes());base['objects']={}
   for k,f in objs.items():
    if '/X86' in k or '/cs.' in k:base['objects'][k]=inspect(f,True)
  changed=sorted(k for k in original if got[k]!=original[k])
  deltas={k:diff_cache(base['objects'][k],inspect(objs[k],True))for k in changed if k in base['objects']}
  so[label]=sha(lib.read_bytes());results[label]=dict(library=so[label],changed_objects=changed,sections=diff_cache(initial,vals),symbols=deltas)
  write('comparisons',results)
 assert so['base']!=so['candidate']
 write('complete',dict(tree=m['tree'],hashes=so,compiler=sh(['gcc','--version']).decode().splitlines()[0],restorations=[k for k in so if k not in ('base','candidate')and so[k]==so['base']]))
finally:
 size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
