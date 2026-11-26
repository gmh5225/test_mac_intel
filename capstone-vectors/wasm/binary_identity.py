from pathlib import Path
import hashlib,struct,subprocess
def identity(path):
    raw=path.read_bytes();data=bytearray(raw);meta={}
    digest=lambda b:hashlib.sha256(b).hexdigest()
    if raw.startswith(b'!<arch>\n'):
        i=8;dates=[];n=0
        while i<len(raw):
            assert raw[i+58:i+60]==b'\x60\n'
            size=int(raw[i+48:i+58]);dates.append(raw[i+16:i+28].decode().strip());data[i+16:i+28]=b' '*12
            n+=1;i+=60+size+(size%2)
        assert i==len(raw);meta.update(members=n,dates=sorted(set(dates)))
    elif raw[:4]==b'\xcf\xfa\xed\xfe':
        n,span=struct.unpack_from('<II',raw,16);i=32
        for _ in range(n):
            command,size=struct.unpack_from('<II',raw,i);assert size>=8 and size%8==0
            if command==0xd:
                meta['id_timestamp']=struct.unpack_from('<I',raw,i+12)[0];data[i+12:i+16]=bytes(4)
            elif command==0x1b:
                meta['uuid']=raw[i+8:i+24].hex();data[i+8:i+24]=bytes(16)
            elif command==0x1d:
                offset,length=struct.unpack_from('<II',raw,i+8);assert offset>=32+span and offset+length<=len(raw)
                subprocess.run(['/usr/bin/codesign','--verify',path],check=True)
                meta['verified_signature_sha256']=digest(raw[offset:offset+length]);data[offset:offset+length]=bytes(length)
            i+=size
        assert i==32+span and 'id_timestamp' in meta
    return dict(raw=digest(raw),content=digest(data),metadata=meta)
