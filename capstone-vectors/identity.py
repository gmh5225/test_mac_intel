import gzip
import hashlib
import json
from elftools.elf.elffile import ELFFile

def payloads(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        sections = list(elf.iter_sections())
        data = {}
        code, arrays = {}, {}
        for symbol in elf.get_section_by_name('.symtab').iter_symbols():
            section = symbol['st_shndx']
            kind = symbol['st_info']['type']
            if not isinstance(section, int) or not symbol['st_size'] or kind not in ('STT_FUNC', 'STT_OBJECT'):
                continue
            owner = sections[section]
            assert owner['sh_type'] != 'SHT_NOBITS'
            if section not in data:
                data[section] = owner.data()
            start = symbol['st_value'] - owner['sh_addr']
            value = data[section][start:start + symbol['st_size']]
            assert len(value) == symbol['st_size']
            (code if kind == 'STT_FUNC' else arrays)[symbol.name] = value
    assert 'X86_writeEvexMemoryOutput' in code
    assert 'evex_memory_rows' in arrays
    return code, arrays

def compare(old, new):
    assert old == new, dict(code_equal=old[0] == new[0], arrays_equal=old[1] == new[1],
                           old_functions={k: len(v) for k, v in old[0].items()},
                           new_functions={k: len(v) for k, v in new[0].items()})
    fields = lambda values: {key: dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest()) for key, value in values.items()}
    return dict(functions=fields(old[0]), arrays=fields(old[1]),
                scope='Every named function instruction payload and immutable object payload in the new writer is byte-identical; relocations and linked addresses are separate.')

def signatures(binary, target):
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        sections = list(elf.iter_sections())
        data, rows = {}, []
        for symbol in elf.get_section_by_name('.symtab').iter_symbols():
            section = symbol['st_shndx']
            if not isinstance(section, int) or not symbol['st_size'] or symbol['st_info']['type'] not in ('STT_FUNC', 'STT_OBJECT'):
                continue
            owner = sections[section]
            if owner['sh_type'] == 'SHT_NOBITS':
                continue
            if section not in data:
                data[section] = owner.data()
            offset = symbol['st_value'] - owner['sh_addr']
            value = data[section][offset:offset + symbol['st_size']]
            assert len(value) == symbol['st_size']
            rows.append(dict(name=symbol.name, address=symbol['st_value'], size=symbol['st_size'],
                             section=owner.name, sha256=hashlib.sha256(value).hexdigest()))
    with gzip.open(target, 'wt') as out:
        json.dump(rows, out)
