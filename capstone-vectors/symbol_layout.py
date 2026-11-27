import hashlib
from elftools.elf.elffile import ELFFile

def symbols(path):
    selected = (
        'cs_disasm_iter', 'cs_decode_full_insn', 'X86_disasmIter32',
        'X86_disasmIterText', 'tryOutput32', 'writeExtraOutput32',
        'X86_decodeRegisterFallback32', 'X86_decodeOutputMiss32',
        'X86_scanNativeBatch', 'X86_reg_access', 'X86_writeSimpleDetail',
        'X86_decodeVexMemoryFallback64', 'X86_decodeOutputMiss64', 'X86_writeVexRegisterImmediate', 'X86_writeVectorOutput', 'scanBatch32', 'scanBatch64', 'readVex3Plan',
    )
    result = {}
    with path.open('rb') as source:
        elf = ELFFile(source)
        segments = {}
        table = elf.get_section_by_name('.symtab')
        for symbol in table.iter_symbols():
            index, size = symbol['st_shndx'], symbol['st_size']
            name = symbol.name
            if symbol['st_info']['type']!='STT_FUNC' or not size or not isinstance(index,int):
                continue
            if not any(name == item or name.startswith(item+'.') for item in selected):
                continue
            section = elf.get_section(index)
            if index not in segments:
                segments[index] = section.data()
            address = symbol['st_value']
            offset = address-section['sh_addr']
            data = segments[index][offset:offset+size]
            assert offset>=0 and len(data)==size
            result.setdefault(name, []).append(dict(address=address, size=size, section=section.name, sha256=hashlib.sha256(data).hexdigest()))
    assert all(k in result for k in ('cs_disasm_iter','X86_decodeRegisterFallback32','X86_disasmIter32','X86_reg_access'))
    return result
