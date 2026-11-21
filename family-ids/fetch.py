from pathlib import Path
import hashlib
import json
import struct
import urllib.request

root=Path(__file__).resolve().parent
source_page='https://www.chiark.greenend.org.uk/~sgtatham/putty/releases/0.85.html'
base='https://the.earth.li/~sgtatham/putty/0.85/'
expected={32:'4c70267ca03a00ea761ec358498b990a7221decb36eace9b7dbe6a751be0fb3b',
          64:'d01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87'}
records=[]
for bits in [32,64]:
    url=base+f'w{bits}/putty.exe'
    output=root/f'putty-0.85-{bits}.exe'
    if not output.exists():
        with urllib.request.urlopen(url,timeout=25) as response:
            data=response.read(8*1024*1024)
        assert hashlib.sha256(data).hexdigest()==expected[bits]
        output.write_bytes(data)
    data=output.read_bytes()
    assert hashlib.sha256(data).hexdigest()==expected[bits]
    assert data[:2]==b'MZ'
    pe=struct.unpack_from('<I',data,0x3c)[0]
    assert data[pe:pe+4]==b'PE\0\0'
    machine,count=struct.unpack_from('<HH',data,pe+4)
    assert machine==(0x14c if bits==32 else 0x8664)
    optional=struct.unpack_from('<H',data,pe+20)[0]
    first=pe+24+optional
    texts=[]
    for i in range(count):
        off=first+40*i
        name=data[off:off+8].rstrip(b'\0')
        virtual_size,rva,raw_size,raw_offset=struct.unpack_from('<IIII',data,off+8)
        flags=struct.unpack_from('<I',data,off+36)[0]
        if name!=b'.text':
            continue
        assert flags & 0x20000000
        size=min(virtual_size,raw_size)
        assert raw_offset+size<=len(data)
        texts.append((data[raw_offset:raw_offset+size],rva,raw_offset))
    assert len(texts)==1
    text,rva,raw_offset=texts[0]
    target=root/f'putty-0.85-{bits}.text'
    target.write_bytes(text)
    record=dict(name=f'putty-{bits}-0.85',bits=bits,path=target.name,bytes=len(text),
                executable=output.name,executable_sha256=expected[bits],sha256=hashlib.sha256(text).hexdigest(),
                source=url,source_page=source_page,checksums=base+'sha256sums',
                section='.text',section_rva=rva,section_file_offset=raw_offset,
                extraction='Entire initialized executable .text section; no instruction filtering.',
                executable_was_run=False)
    records.append(record)
    (root/'corpus.json').write_text(json.dumps(records,indent=2)+'\n')
    print(record,flush=True)
