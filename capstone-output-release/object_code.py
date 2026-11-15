import hashlib,struct

def code_sections(blob):
    rows=[]
    if blob[:4]==b'\x7fELF':
        assert blob[4:6]==b'\x02\x01'
        shoff=struct.unpack_from('<Q',blob,40)[0]
        step,count,names=struct.unpack_from('<HHH',blob,58)
        headers=[struct.unpack_from('<IIQQQQIIQQ',blob,shoff+i*step)for i in range(count)]
        string_header=headers[names];strings=blob[string_header[4]:string_header[4]+string_header[5]]
        for i,h in enumerate(headers):
            if h[1]==1 and h[2]&4:
                name=strings[h[0]:].split(b'\0',1)[0].decode()
                rows.append((name,i,blob[h[4]:h[4]+h[5]]))
    elif blob[:4]==b'\xcf\xfa\xed\xfe':
        count=struct.unpack_from('<I',blob,16)[0];pos=32
        for _ in range(count):
            cmd,size=struct.unpack_from('<II',blob,pos)
            if cmd==0x19:
                n=struct.unpack_from('<I',blob,pos+64)[0]
                for i in range(n):
                    start=pos+72+i*80
                    name=blob[start:start+16].split(b'\0',1)[0].decode()
                    length=struct.unpack_from('<Q',blob,start+40)[0]
                    off=struct.unpack_from('<I',blob,start+48)[0]
                    flags=struct.unpack_from('<I',blob,start+64)[0]
                    if flags&0x80000400:rows.append((name,i,blob[off:off+length]))
            pos+=size
    else:
        machine,count=struct.unpack_from('<HH',blob)
        assert machine==0x8664,hex(machine)
        optional=struct.unpack_from('<H',blob,16)[0]
        for i in range(count):
            pos=20+optional+i*40
            name=blob[pos:pos+8].split(b'\0',1)[0].decode()
            length,off=struct.unpack_from('<II',blob,pos+16)
            flags=struct.unpack_from('<I',blob,pos+36)[0]
            if flags&0x20:rows.append((name,i,blob[off:off+length]))
    assert rows
    return [dict(name=name,index=i,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())for name,i,data in rows]
