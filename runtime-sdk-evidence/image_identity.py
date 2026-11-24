"""Read the RSDS identity and section-relative export locations from installed Microsoft images."""
import ctypes
import hashlib
import json
import os
import platform
import struct
from pathlib import Path

SYSTEM = Path(os.environ["SystemRoot"]).resolve()
MODULES = {"rtm.dll": ["CreateTable"], "ole32.dll": ["StgConvertPropertyToVariant"],
           "gdiplus.dll": ["GdipEnumerateMetafileDestPoint", "GdipEnumerateMetafileDestRectI"],
           "bcryptprimitives.dll": ["ProcessPrng"]}
def scan(name, wanted):
    dll = ctypes.WinDLL(name)
    get = ctypes.windll.kernel32.GetModuleFileNameW
    get.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32)
    get.restype = ctypes.c_uint32
    buf = ctypes.create_unicode_buffer(32768)
    length = get(dll._handle, buf, len(buf))
    assert 0 < length < len(buf)
    path = Path(buf.value).resolve()
    assert path.is_relative_to(SYSTEM) and path.name.lower() == name
    image = path.read_bytes()
    def num(fmt, off): return struct.unpack_from("<"+fmt,image,off)
    pe, = num("I",60)
    assert image[pe:pe+4] == b"PE\0\0"
    machine, count = num("HH",pe+4)
    assert machine == 0xaa64
    size, = num("H",pe+20)
    opt = pe+24
    assert num("H",opt)[0] == 0x20b
    sections = []
    for k in range(count):
        vsize,rva,rsize,raw = num("4I",opt+size+k*40+8)
        sections.append((rva,vsize,rsize,raw))
    def offset(rva,n):
        for va,vs,sz,raw in sections:
            if va<=rva and rva+n<=va+sz and raw+rva-va+n<=len(image):return raw+rva-va
        raise ValueError(f"unmapped RVA {rva:x}")
    def string(rva):
        start=offset(rva,1);return image[start:image.index(0,start)].decode("ascii")
    export,exsize=num("II",opt+112)
    _,_,_,_,_,ordinal,nfunc,nname,functions,names,ordinals=num("IIHH7I",offset(export,40))
    entries={}
    for i in range(nname):
        val=string(num("I",offset(names+i*4,4))[0])
        if val not in wanted:continue
        index=num("H",offset(ordinals+i*2,2))[0];assert index<nfunc
        address=num("I",offset(functions+index*4,4))[0]
        seg=next((k+1, address-row[0]) for k,row in enumerate(sections) if row[0]<=address<row[0]+max(row[1:3]))
        entries[val]=dict(ordinal=ordinal+index,rva=address,section=seg[0],offset=seg[1],
                          forwarder=string(address) if export<=address<export+exsize else None)
    debug,dsize=num("II",opt+112+6*8)
    records=[]
    import uuid
    for i in range(0,dsize,28):
        typ,recordsize,addr,raw=num("IIII",offset(debug+i,28)+12)
        if typ!=2 or image[raw:raw+4]!=b"RSDS":continue
        guid=uuid.UUID(bytes_le=image[raw+4:raw+20]);age=num("I",raw+20)[0]
        n=image[raw+24:image.index(0,raw+24,raw+recordsize)].decode("utf-8")
        pdb=Path(n).name
        assert pdb.lower().endswith(".pdb") and all(c.isalnum() or c in "._-" for c in pdb)
        records.append(dict(file=pdb,guid=str(guid),age=age,key=guid.hex.upper()+format(age,"x")))
    assert set(entries)==set(wanted) and len(records)==1,(name,entries,records)
    return dict(module=name,path=str(path.relative_to(SYSTEM)),machine=machine,
                image_sha256=hashlib.sha256(image).hexdigest(),debug=records[0],exports=entries)

result=dict(host=platform.machine(),version=platform.version(),images=[scan(n,x) for n,x in MODULES.items()])
Path("installed-image-identities.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
