"""Expose real i386 AVX2 JPEG assembly with local symbol boundaries from Debian's static archive."""
import hashlib,io,re,subprocess as sp,tarfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def jpeg_avx2(w,host,packages):
 fields=dict(v.split(': ',1) for v in packages['libjpeg62-turbo-dev'].splitlines() if not v.startswith(' ') and ': ' in v)
 file=w/'jpeg-dev.deb';url=host+fields['Filename']
 sp.run(['curl','-fsSL','--retry','3','--max-time','80','-o',file,url],check=True)
 sha=lambda d:hashlib.sha256(d).hexdigest()
 assert sha(file.read_bytes())==fields['SHA256']
 payload=next(n for n in sp.check_output(['ar','t',file],text=True).splitlines() if n.startswith('data.tar'))
 data=io.BytesIO(sp.check_output(['ar','p',file,payload]));file.unlink()
 if payload.endswith('.zst'):
  import zstandard
  data=zstandard.ZstdDecompressor().stream_reader(data)
 with tarfile.open(fileobj=data,mode='r|*') as ar:
  found=[ar.extractfile(m).read() for m in ar if m.isfile() and Path(m.name).name=='libjpeg.a']
 assert len(found)==1;archive=w/'libjpeg-i386.a';archive.write_bytes(found[0])
 names=[v for v in sp.check_output(['ar','t',archive],text=True).splitlines() if 'avx2' in v.lower()];assert names
 out=bytearray();spans=[];members={}
 for name in names:
  obj=sp.check_output(['ar','p',archive,name]);elf=ELFFile(io.BytesIO(obj));assert elf['e_machine']=='EM_386'
  sec=elf.get_section_by_name('.text');idx=elf.get_section_index('.text')
  if sec is None or not sec['sh_size']:continue
  code=sec.data();entries=sorted({int(s['st_value']) for sym in elf.iter_sections() if isinstance(sym,SymbolTableSection) for s in sym.iter_symbols() if s['st_shndx']==idx and s['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK') and s['st_info']['type'] in ('STT_FUNC','STT_NOTYPE') and int(s['st_value'])<len(code)})
  if not entries:continue
  members[name]=dict(sha256=sha(obj),functions=len(entries),section_bytes=len(code))
  base=len(out);out.extend(code)
  spans.extend((base+a,b-a,0x100000+base+a) for a,b in zip(entries,entries[1:]+[len(code)]))
 assert len(spans)>=3 and len(out)>4096,(names,members)
 f=w/'jpeg-avx2-i386.text';f.write_bytes(out);archive.unlink()
 return ('jpeg-avx2-i386',32,f,spans,dict(package=fields['Package'],version=fields['Version'],url=url,package_sha256=fields['SHA256'],text_sha256=sha(out),members=members,selection='ELF .text in AVX2 i386 libjpeg.a objects, extents bounded by external assembly entry symbols within each object'))
