import hashlib
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
def read(path):
    with path.open('rb') as f:
        e=ELFFile(f)
        sym,=e.get_section_by_name('.symtab').get_symbol_by_name('cs_disasm_iter')
        idx=sym['st_shndx'];pos=sym['st_value'];size=sym['st_size']
        section=e.get_section(idx);body=section.data()[pos:pos+size];assert len(body)==size
        rels=[]
        for rel in e.iter_sections():
            if not isinstance(rel,RelocationSection) or rel['sh_info']!=idx:continue
            table=e.get_section(rel['sh_link'])
            for entry in rel.iter_relocations():
                off=entry['r_offset']
                if not pos<=off<pos+size:continue
                dest=table.get_symbol(entry['r_info_sym'])
                name=dest.name
                if not name and isinstance(dest['st_shndx'],int):name=e.get_section(dest['st_shndx']).name
                rels.append([off-pos,entry['r_info_type'],name,entry['r_addend']])
        return dict(offset=pos,size=size,sha256=hashlib.sha256(body).hexdigest(),relocations=rels)
