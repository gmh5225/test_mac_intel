"""Read the authoritative table size and bytes directly from the ELF64 object."""
from pathlib import Path
import hashlib,struct

def mapping_bytes(file):
    data=Path(file).read_bytes()
    assert data[:6]==b'\x7fELF\x02\x01'
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,header[6]+i*header[11]) for i in range(header[12])]
    matches=[]
    for table in sections:
        if table[1]!=2:continue
        strings=sections[table[6]]
        names=data[strings[4]:strings[4]+strings[5]]
        for offset in range(table[4],table[4]+table[5],table[9]):
            name,info,visibility,index,address,size=struct.unpack_from('<IBBHQQ',data,offset)
            if info!=1 or names[name:names.index(0,name)]!=b'insns':continue
            section=sections[index]
            relative=address-section[3]
            assert 0<=relative and relative+size<=section[5]
            start=section[4]+relative
            matches.append(dict(bytes=size,sha256=hashlib.sha256(data[start:start+size]).hexdigest()))
    assert len(matches)==1,matches
    return matches[0]
