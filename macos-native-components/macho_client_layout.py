"""Typed layout and complete SHA-256 CodeDirectory page verification."""
from pathlib import Path
import hashlib
import struct


def inspect(path):
    return inspect_bytes(Path(path).read_bytes())


def inspect_bytes(body):
    assert len(body)>=32
    header=struct.unpack_from('<8I',body);assert header[0]==0xfeedfacf and header[1] in [0x100000c,0x1000007]
    assert 0<header[4]<=4096 and 32+header[5]<=len(body)
    at=32;commands=[];segments=[];signature=None
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    for _ in range(header[4]):
        command,size=struct.unpack_from('<II',body,at);assert size>=8 and at+size<=32+header[5]
        commands.append(dict(type=command,bytes=size,sha256=digest(body[at:at+size])))
        if command==0x19:
            name=body[at+8:at+24].split(b'\0')[0].decode();vm,vmsize,offset,length=struct.unpack_from('<QQQQ',body,at+24)
            count=struct.unpack_from('<I',body,at+64)[0];assert size==72+count*80 and offset+length<=len(body)
            sections=[]
            for index in range(count):
                p=at+72+index*80;section=body[p:p+16].split(b'\0')[0].decode();segment=body[p+16:p+32].split(b'\0')[0].decode()
                addr,n,fileoff,align,reloff,nreloc,flags=struct.unpack_from('<QQIIIII',body,p+32)
                assert segment==name and align<=31
                item=dict(name=section,address=addr,bytes=n,file_offset=fileoff,alignment=align,flags=flags)
                if flags&255 not in [1,12,18]:
                    assert fileoff+n<=len(body);item['sha256']=digest(body[fileoff:fileoff+n])
                sections.append(item)
            segments.append(dict(name=name,vm_address=vm,vm_bytes=vmsize,file_offset=offset,file_bytes=length,sections=sections))
        elif command==0x1d:
            assert size==16 and signature is None;signature=struct.unpack_from('<II',body,at+8)
        at+=size
    assert at==32+header[5] and signature is not None
    sigoff,sigsize=signature;assert sigoff>at and sigsize>=12 and sigoff+sigsize==len(body)
    blob=body[sigoff:sigoff+sigsize];magic,length,count=struct.unpack_from('>III',blob)
    assert magic==0xfade0cc0 and 12+count*8<=length<=sigsize and 0<count<=32
    directories=[];blobs=[];slots=set()
    for index in range(count):
        slot,offset=struct.unpack_from('>II',blob,12+index*8);assert slot not in slots;slots.add(slot)
        assert 12+count*8<=offset and offset+8<=length
        kind,n=struct.unpack_from('>II',blob,offset);assert n>=8 and offset+n<=length
        data=blob[offset:offset+n];blobs.append(dict(slot=slot,magic=kind,bytes=n,sha256=digest(data)))
        if kind!=0xfade0c02:continue
        assert n>=88
        version,flags,hashoff,identoff,special,pages,limit=struct.unpack_from('>7I',data,8)
        hashsize,hashtype,platform,shift=struct.unpack_from('>4B',data,36)
        assert version>=0x20400 and hashsize==32 and hashtype==2 and 0<shift<=20
        assert limit==sigoff and pages==(limit+(1<<shift)-1)//(1<<shift) and special<=32
        assert special*32<=hashoff and hashoff+pages*32<=n and 88<=identoff<hashoff
        end=data.find(b'\0',identoff,hashoff);assert end!=-1 and end-identoff<=1024
        identifier=data[identoff:end].decode()
        for page in range(pages):
            raw=body[page*(1<<shift):min((page+1)*(1<<shift),limit)]
            assert hashlib.sha256(raw).digest()==data[hashoff+page*32:hashoff+(page+1)*32], 'CodeDirectory page hash mismatch'
        directories.append(dict(slot=slot,version=version,flags=flags,identifier=identifier,page_size=1<<shift,
            code_pages=pages,special_slots=special,code_limit=limit,sha256=digest(data),all_code_page_hashes_verified=True))
    assert len(directories)==1
    return dict(binary_sha256=digest(body),bytes=len(body),header=list(header),commands=commands,segments=segments,
        signature=dict(file_offset=sigoff,bytes=sigsize,superblob_bytes=length,sha256=digest(blob),blobs=blobs,code_directories=directories))
