"""Rebuild official SQLite DLL and Debian liblzma .text ranges from package metadata."""
import hashlib, io, lzma, struct, subprocess, tarfile, zipfile
from pathlib import Path
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def sha(v):return hashlib.sha256(v).hexdigest()
def get(url,path):
    subprocess.run(['curl','-fsSL','--retry','3','--max-time','120','-o',path,url],check=True)
def table_bytes(extents):
    return ''.join(f'{pos}\t{n}\t{ip}\n' for pos,n,ip in extents).encode()
def pe32_exports(dll):
    pe,=struct.unpack_from('<I',dll,60)
    assert dll[:2]==b'MZ' and dll[pe:pe+4]==b'PE\0\0'
    machine,count=struct.unpack_from('<HH',dll,pe+4);opt=pe+24
    assert machine==0x14c and struct.unpack_from('<H',dll,opt)[0]==0x10b
    image_base,=struct.unpack_from('<I',dll,opt+28)
    opt_size,=struct.unpack_from('<H',dll,pe+20);sections=[]
    for i in range(count):
        at=opt+opt_size+40*i
        n,rva,raw,offset=struct.unpack_from('<IIII',dll,at+8)
        sections.append((dll[at:at+8].split(b'\0')[0],rva,n,raw,offset))
    def locate(rva,length):
        choices=[(pos+rva-start) for _,start,vs,raw,pos in sections if start<=rva and rva+length<=start+raw and pos+rva-start+length<=len(dll)]
        assert len(choices)==1,(hex(rva),length);return choices[0]
    _,start,vs,raw,pos=next(x for x in sections if x[0]==b'.text')
    size=min(vs,raw);data=dll[pos:pos+size]
    er,el=struct.unpack_from('<II',dll,opt+96);ed=locate(er,40)
    n=struct.unpack_from('<I',dll,ed+20)[0];funcs=struct.unpack_from('<I',dll,ed+28)[0]
    values=struct.unpack_from('<'+'I'*n,dll,locate(funcs,n*4))
    starts=sorted({x for x in values if start<=x<start+size and not er<=x<er+el})
    assert len(starts)>200
    # PE32 has no .pdata requirement. Treat these as intervals between exported entries.
    ranges=[(a-start,b-a,image_base+a) for a,b in zip(starts,starts[1:]+[start+size])]
    return data,ranges
def materialize(name,spec,work):
    f=work/(name+'.package');get(spec['url'],f);payload=f.read_bytes()
    if spec['kind']=='zip':
        assert hashlib.sha3_256(payload).hexdigest()==spec['published_sha3'] and len(payload)==spec['package_bytes']
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entry,=[n for n in archive.namelist() if n.split('/')[-1].lower()=='sqlite3.dll'];binary=archive.read(entry)
        if spec['bits']==64:
            from pdata import functions
            code,spans,outside=functions(binary)
        else:
            code,spans=pe32_exports(binary);outside=[]
    else:
        assert sha(payload)==spec['published_sha256'];member,=[s for s in subprocess.check_output(['ar','t',f],text=True).splitlines() if s.startswith('data.tar')]
        data=subprocess.check_output(['ar','p',f,member])
        if member.endswith('.zst'):
            import zstandard
            data=zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
        with tarfile.open(fileobj=io.BytesIO(data)) as a:
            one,=[m for m in a.getmembers() if m.isfile() and m.name.rsplit('/',1)[-1].startswith('liblzma.so.')];binary=a.extractfile(one).read()
        elf=ELFFile(io.BytesIO(binary));assert elf.elfclass==spec['bits']
        text=elf.get_section_by_name('.text');start=text['sh_addr'];code=text.data();candidates=set()
        for t in elf.iter_sections():
            if isinstance(t,SymbolTableSection):
                candidates.update((s['st_value'],s['st_size']) for s in t.iter_symbols() if s['st_info']['type']=='STT_FUNC' and s['st_size'])
        candidates.update((f['initial_location'],f['address_range']) for f in elf.get_dwarf_info().EH_CFI_entries() if isinstance(f,FDE))
        spans=[];end=start;outside=[]
        for at,n in sorted(candidates,key=lambda v:(v[0],-v[1])):
            if at>=end and n>0 and at+n<=start+len(code):spans.append((at-start,n,at));end=at+n
    assert spans and all(n>0 and 0<=pos<=len(code)-n for pos,n,ip in spans)
    assert all(a[0]+a[1]<=b[0] for a,b in zip(spans,spans[1:]))
    f.unlink()
    text_path=work/(name+'.text');text_path.write_bytes(code);ranges=table_bytes(spans);(work/(name+'.ranges')).write_bytes(ranges)
    metadata=dict(package=sha(payload),binary=sha(binary),text=sha(code),text_bytes=len(code),ranges=sha(ranges),candidates=len(spans),candidate_bytes=sum(x[1] for x in spans),outside=len(outside))
    return metadata,spans
