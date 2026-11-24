"""Increase one ELF64 relocatable section, retaining its relocations and section indices."""
import io,struct
from elftools.elf.elffile import ELFFile

def extend(obj, name, tail):
    data=obj.read_bytes()
    elf=ELFFile(io.BytesIO(data))
    assert elf.elfclass==64 and elf.little_endian and elf['e_type']=='ET_REL' and elf['e_phnum']==0
    sections=list(elf.iter_sections())
    target=elf.get_section_index(name)
    ts=sections[target]
    assert ts['sh_type']=='SHT_PROGBITS' and ts['sh_size']>0 and tail>0
    end=ts['sh_offset']+ts['sh_size']
    # Moving by a multiple of all subsequent input alignments leaves their placement valid.
    align=max(8,*(s['sh_addralign'] for s in sections))
    assert align & (align-1)==0 and elf['e_shoff']>=end and elf['e_shentsize']==64
    shift=(tail+align-1)//align*align
    result=bytearray(data[:end]+bytes(shift)+data[end:])
    shoff=elf['e_shoff']+shift
    struct.pack_into('<Q',result,40,shoff)
    for i,s in enumerate(sections):
        h=shoff+i*64
        if i==target:
            struct.pack_into('<Q',result,h+32,s['sh_size']+tail)
        elif s['sh_offset']>=end:
            struct.pack_into('<Q',result,h+24,s['sh_offset']+shift)
    after=ELFFile(io.BytesIO(result))
    counts={}
    for i,old in enumerate(sections):
        new=after.get_section(i)
        assert new.name==old.name
        for key,val in old.header.items():
            if key not in ('sh_offset','sh_size'):assert new[key]==val
        assert new['sh_size']==old['sh_size']+(tail if i==target else 0)
        if old['sh_type']!='SHT_NOBITS':
            assert new.data()==old.data()+(bytes(tail)if i==target else b'')
        if old['sh_type'] in ('SHT_RELA','SHT_REL') and old['sh_info']==target:
            counts[old.name]=old.num_relocations()
    assert sum(counts.values())>0
    obj.write_bytes(result)
    return counts
