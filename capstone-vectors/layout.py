from elftools.elf.elffile import ELFFile
import hashlib
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def layout(binary):
    with binary.open('rb')as f:
        elf=ELFFile(f);sec={x.name:[x['sh_addr'],x['sh_size']]for x in elf.iter_sections()if x['sh_flags']&2}
        syms={}
        for s in elf.get_section_by_name('.symtab').iter_symbols():
            index=s['st_shndx'];name=s.name
            if not isinstance(index,int) or s['st_info']['type']!='STT_FUNC' or not s['st_size']:continue
            if not any(v in name for v in ('cs_disasm_iter','cs_decode_full','X86_ATT_printInst','X86_Intel_printInst','X86_getInstruction','decodeInstruction','writeVexBaseMemory','writeVexSibTransfer','X86_decodeOutputMiss64','X86_decodeVector','VexReader','X86_writeDisplacement')):continue
            segment=elf.get_section(index);off=s['st_value']-segment['sh_addr'];f.seek(segment['sh_offset']+off)
            syms[name]=[s['st_value'],s['st_size'],hashlib.sha256(f.read(s['st_size'])).hexdigest()]
        assert {'cs_disasm_iter','cs_decode_full_insn','X86_ATT_printInst'}<=syms.keys()
        return dict(sections=sec,symbols=syms,sha=sha(binary))
