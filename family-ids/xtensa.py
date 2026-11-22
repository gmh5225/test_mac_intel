from pathlib import Path
import hashlib,io,json,struct,shutil,subprocess as sp,tarfile,tempfile,urllib.request
def digest(b):return hashlib.sha256(b).hexdigest()
url='https://deb.debian.org/debian/pool/main/p/picolibc/picolibc-xtensa-lx106-elf_1.8.12-1_all.deb'
def get(scratch,expected=None):
 with tempfile.TemporaryDirectory(dir=scratch)as tmp:
  t=Path(tmp);p=t/'p.deb';p.write_bytes(urllib.request.urlopen(url,timeout=75).read())
  package=digest(p.read_bytes());assert expected is None or package==expected['package_sha256']
  mem,=[n for n in sp.check_output(['ar','t',p],text=True).splitlines()if n.startswith('data.tar')]
  with tarfile.open(fileobj=io.BytesIO(sp.check_output(['ar','p',p,mem])),mode='r:*')as a:
   libc,=[n for n in a.getnames() if n.lstrip('./')=='usr/lib/xtensa-lx106-elf/lib/libc.a']
   lib=t/'libc.a';lib.write_bytes(a.extractfile(libc).read())
  ar=shutil.which('llvm-ar') or next((str(x)for x in Path('/opt/homebrew/opt').glob('llvm*/bin/llvm-ar')), 'ar')
  names=sp.check_output([ar,'t',lib],text=True).splitlines()
  if expected:names=[expected['object']]
  elif not any('vfprintf' in n or 'dtoa' in n for n in names):print(names[:50],len(names))
  options=[]
  for name in names:
   if expected is None and not any(n in name for n in ('vfprintf','dtoa','strtod','pow_')):continue
   obj=sp.check_output([ar,'p',lib,name])
   assert obj[:6]==b'\x7fELF\x01\x01' and struct.unpack_from('<H',obj,18)[0]==94
   off=struct.unpack_from('<I',obj,32)[0];sz,num,si=struct.unpack_from('<HHH',obj,46);sh=[struct.unpack_from('<IIIIIIIIII',obj,off+n*sz) for n in range(num)];ss=obj[sh[si][4]:sh[si][4]+sh[si][5]]
   for head in sh:
    sid,kind,flags,addr,start,size=head[:6]
    if not size or kind!=1 or not flags&4:continue
    sec=ss[sid:ss.index(b'\0',sid)].decode();code=obj[start:start+size]
    if expected is None or sec==expected['section']:options.append((size,name,sec,addr,code))
  if not options:print('possible members', [n for n in names if any(k in n for k in ('printf','dtoa','strtod','pow_'))][:35])
  size,obj,sec,addr,code=max(options)
  info=dict(name='xtensa-picolibc',package_sha256=package,archive_sha256=digest(lib.read_bytes()),object=obj,section=sec,text_sha256=digest(code),bytes=size,address=addr,url=url,member=libc)
  assert size>=500 and (expected is None or expected==info),(info,expected)
  output=scratch/'xtensa.text';output.write_bytes(code);return output,info
if __name__=='__main__':
 root=Path(__file__).resolve().parent
 with tempfile.TemporaryDirectory(dir=root) as t:
  data,meta=get(Path(t));(root/'xtensa-source.json').write_text(json.dumps(meta,indent=2)+'\n');print(meta)
