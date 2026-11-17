import gzip
import hashlib
import json
from elftools.elf.elffile import ELFFile

def payloads(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        sections = list(elf.iter_sections())
        data = {}
        code, arrays, functions = {}, {}, {}
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
            if kind == 'STT_FUNC':
                functions[symbol.name] = (section, symbol['st_value'])
        calls = {name: {} for name in code}
        locations = {value: name for name, value in functions.items()}
        for section in sections:
            if section['sh_type'] != 'SHT_RELA':
                continue
            target = section['sh_info']
            symbols = sections[section['sh_link']]
            for relocation in section.iter_relocations():
                if relocation['r_info_type'] not in (2, 4):
                    continue
                offset = relocation['r_offset']
                for name, (owner, start) in functions.items():
                    local = offset - start
                    if owner != target or not 0 < local < len(code[name]) - 3 or code[name][local-1] != 0xe8:
                        continue
                    symbol = symbols.get_symbol(relocation['r_info_sym'])
                    destination = symbol['st_value'] + relocation['r_addend'] + 4
                    if symbol['st_shndx'] == 'SHN_UNDEF':
                        assert destination == 0
                        callee = 'external:' + symbol.name
                    else:
                        callee = locations[(symbol['st_shndx'], destination)]
                    calls[name][local] = callee
    assert 'X86_writeEvexMemoryOutput' in code
    assert 'evex_memory_rows' in arrays
    return code, arrays, functions, calls

def compare(old, new):
    assert old[1] == new[1] and old[0].keys() == new[0].keys()
    normalized, resolved = {}, {}
    for name in old[0]:
        before, after = bytearray(old[0][name]), bytearray(new[0][name])
        assert len(before) == len(after)
        resolved[name] = {}
        for offset in old[3][name].keys() | new[3][name].keys():
            destinations = []
            for record in (old, new):
                target = record[3][name].get(offset)
                if target is None:
                    data = record[0][name]
                    assert data[offset-1] == 0xe8
                    section, start = record[2][name]
                    address = start + offset + 4 + int.from_bytes(data[offset:offset+4], 'little', signed=True)
                    target, = [callee for callee, location in record[2].items() if location == (section, address)]
                destinations.append(target)
            assert destinations[0] == destinations[1]
            resolved[name][offset] = destinations[0]
            before[offset:offset+4] = after[offset:offset+4] = bytes(4)
        assert before == after, dict(function=name, differing_bytes=[i for i in range(len(before)) if before[i] != after[i]])
        normalized[name] = bytes(before)
    fields = lambda values: {key: dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest()) for key, value in values.items()}
    return dict(functions=fields(normalized), arrays=fields(old[1]), resolved_calls=resolved,
                scope='Function instructions match after normalizing only verified direct-call displacement operands. Every normalized call resolves to the same named internal/external callee. Immutable array payloads match exactly; linked placement remains separate.')

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
