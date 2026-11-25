import hashlib,re,shutil,struct
from elftools.elf.elffile import ELFFile
from pathlib import Path

def recipe_values(text):
    start=text.index('static const uint32_t X86RecipeRecords[] = {')
    table=text[start:text.index('};',start)]
    return [int(x) for x in re.findall(r'^\s*([0-9]+)U,',table,re.M)]

def variants(w, base_values, merged_values):
    count=len(merged_values);mask=(1<<26)-1
    assert count==len(base_values)==15289 and [x & mask for x in merged_values]==base_values
    assert sum(x>>26!=0 for x in merged_values)==6870
    old=struct.pack('<'+'I'*count,*base_values);new=struct.pack('<'+'I'*count,*merged_values)
    on=(w/'on').read_bytes();off=bytearray(on);locations=[]
    with (w/'on').open('rb') as src:
        elf=ELFFile(src);assert elf.little_endian
        at=on.find(new)
        while at!=-1:
            sec,=(s for s in elf.iter_sections()if s['sh_type']=='SHT_PROGBITS' and s['sh_offset']<=at and s['sh_offset']+s['sh_size']>=at+len(new))
            assert sec['sh_flags']&2 and not sec['sh_flags']&5
            locations.append(dict(offset=at,section=sec.name));off[at:at+len(new)]=old;at=on.find(new,at+len(new))
        text_section=elf.get_section_by_name('.text');a=text_section['sh_offset'];length=text_section['sh_size']
        assert on[a:a+length]==off[a:a+length]
    assert locations and off.find(new)==-1
    assert sum(x!=y for x,y in zip(on,off))==len(locations)*sum(x!=y for x,y in zip(new,old))
    (w/'off').write_bytes(off);(w/'off').chmod(0o755)
    images={k:(w/k).read_bytes()for k in ('base','on','off')};images['duplicate']=images['off']
    length=max(map(len,images.values()))
    padded={k:v+bytes(length-len(v)) for k,v in images.items()};path=w/'selected';shutil.copy2(w/'base',path)
    path.write_bytes(padded['base']);inode=path.stat().st_ino
    offsets=[j for j in range(0,length,4096)if len({v[j:j+4096] for v in padded.values()})>1];verified={}
    def select(tag):
        with path.open('r+b',buffering=0) as out:
            for j in offsets:
                out.seek(j);data=padded[tag][j:j+4096];assert out.write(data)==len(data)
        assert path.stat().st_ino==inode and path.stat().st_size==length
        if tag not in verified:
            data=path.read_bytes();assert data==padded[tag] and data[:len(images[tag])]==images[tag]
            verified[tag]=hashlib.sha256(data).hexdigest()
    for tag in padded:select(tag)
    return select,path,dict(tables=locations,entries=count,hints=6870,bytes_changed=sum(x!=y for x,y in zip(on,off)),inode=inode,sha256=verified,text_sha256=hashlib.sha256(on[a:a+text_section['sh_size']]).hexdigest())
