"""Select all non-overlapping .text function extents from FDEs and ELF symbols."""
import hashlib,io,lzma,re,subprocess as sp,tarfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from elftools.elf.sections import SymbolTableSection
def download(url,path):
 sp.run(['curl','--location','--silent','--show-error','--fail','--max-time','80','--retry','3','--output',path,url],check=True)
def digest(b):return hashlib.sha256(b).hexdigest()
def prepare(w):
 host='https://deb.debian.org/debian/';download(host+'dists/trixie/Release',w/'Release');doc=(w/'Release').read_text();checks=doc.split('\nSHA256:\n')[1].split('\nSHA512:')[0];items=[]
 for arch,bits in [('amd64',64),('i386',32)]:
  name='main/binary-'+arch+'/Packages.xz';want=re.search(r'^ ([0-9a-f]{64})\s+\d+ '+re.escape(name)+'$',checks,re.M).group(1);idx=w/'Packages.xz';download(host+'dists/trixie/'+name,idx);data=idx.read_bytes();assert digest(data)==want;text=lzma.decompress(data).decode();idx.unlink()
  packages={b.split('\n',1)[0][9:]:b for b in text.split('\n\n') if b.startswith('Package: ')}
  if arch=='i386':
   from jpeg_archive import jpeg_avx2
   items.append(jpeg_avx2(w,host,packages))
  for pkg,prefix in [('libjpeg62-turbo','libjpeg.so.'),('libzstd1','libzstd.so.'),('libssl3t64','libcrypto.so.')]:
   fields=dict(v.split(': ',1) for v in packages[pkg].splitlines() if not v.startswith(' ') and ': ' in v);url=host+fields['Filename'];f=w/(pkg+'.deb');download(url,f);assert digest(f.read_bytes())==fields['SHA256'];member=next(x for x in sp.check_output(['ar','t',f],text=True).splitlines() if x.startswith('data.tar'))
   payload=sp.check_output(['ar','p',f,member]);f.unlink()
   if member.endswith('.zst'):
    import zstandard as z
    stream=z.ZstdDecompressor().stream_reader(io.BytesIO(payload))
   else:stream=io.BytesIO(payload)
   with tarfile.open(fileobj=stream,mode='r|*') as archive:
    binary=None
    for m in archive:
     if m.isfile() and Path(m.name).name.startswith(prefix):
      assert binary is None;binary=archive.extractfile(m).read()
   assert binary;elf=ELFFile(io.BytesIO(binary));sec=elf.get_section_by_name('.text');addr,size=sec['sh_addr'],sec['sh_size'];code=sec.data();spans=set()
   for st in elf.iter_sections():
    if isinstance(st,SymbolTableSection):
     spans.update((sy['st_value'],sy['st_size'])for sy in st.iter_symbols() if sy['st_info']['type']=='STT_FUNC' and sy['st_size'])
   if elf.get_section_by_name('.eh_frame'):
    spans.update((e['initial_location'],e['address_range'])for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e,FDE))
   intervals=[];end=addr
   for start,n in sorted(spans,key=lambda v:(v[0],-v[1])):
    if start>=end and n>0 and start+n<=addr+size:
     intervals.append((start-addr,n,start));end=start+n
   label=pkg+'-'+arch;path=w/(label+'.text');path.write_bytes(code);items.append((label,bits,path,intervals,dict(package=pkg,version=fields['Version'],url=url,package_sha256=fields['SHA256'],binary_sha256=digest(binary),text_sha256=digest(code),text_bytes=len(code),function_bytes=sum(v[1]for v in intervals),functions=len(intervals),index_sha256=want)))
 return items
