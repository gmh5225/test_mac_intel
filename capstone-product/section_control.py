from io import BytesIO
from pathlib import Path
import hashlib,struct
from elftools.elf.elffile import ELFFile
def describe(raw):
    elf=ELFFile(BytesIO(raw))
    image={}
    for sec in elf.iter_sections():
        key=sec.name
        assert key not in image
        image[key]={'header':{k:v for k,v in sec.header.items() if k!='sh_offset'},
                    'sha256':hashlib.sha256(sec.data()).hexdigest() if sec['sh_type']!='SHT_NOBITS' else None}
    return image
def extend(source,target,name,extra):
    raw=Path(source).read_bytes()
    elf=ELFFile(BytesIO(raw))
    eh=elf.header
    assert extra>0 and elf.elfclass==64 and elf.little_endian and eh['e_type']=='ET_REL' and eh['e_phnum']==0
    assert eh['e_shentsize']==64 and 0<eh['e_shnum']==elf.num_sections()<0xff00
    section=elf.get_section_by_name(name)
    assert section['sh_type']=='SHT_PROGBITS' and section['sh_flags']&4
    end=section['sh_offset']+section['sh_size'];assert eh['e_ehsize']<=end<=eh['e_shoff']
    sections=list(elf.iter_sections())
    alignment=max(8,*(s['sh_addralign'] for s in sections if s['sh_offset']>=end))
    assert alignment&(alignment-1)==0
    grow=(extra+alignment-1)&-alignment
    new=bytearray(raw[:end]+bytes(grow)+raw[end:])
    table=eh['e_shoff']+grow
    struct.pack_into('<Q',new,40,table)
    for i,s in enumerate(sections):
        sh=table+64*i;offset=s['sh_offset']
        if s.name==name:
            struct.pack_into('<Q',new,sh+32,s['sh_size']+extra)
        elif offset>=end:
            struct.pack_into('<Q',new,sh+24,offset+grow)
        elif s['sh_type']!='SHT_NOBITS':
            assert offset+s['sh_size']<=end
    before=describe(raw);after=describe(new)
    assert before.keys()==after.keys()
    assert all(before[x]==after[x] for x in before if x!=name)
    meta=dict(before[name]['header']);meta['sh_size']+=extra;assert meta==after[name]['header']
    assert ELFFile(BytesIO(new)).get_section_by_name(name).data()==section.data()+bytes(extra)
    related=[s for s in sections if s['sh_type'] in ('SHT_REL','SHT_RELA') and s['sh_info']==elf.get_section_index(name)]
    relocations={s.name:{'count':s.num_relocations(),'sha256':before[s.name]['sha256']} for s in related}
    assert sum(x['count'] for x in relocations.values())>0
    Path(target).write_bytes(new)
    return dict(relocations=relocations,unchanged_sections=len(before)-1,file_growth=grow,code_growth=extra)
