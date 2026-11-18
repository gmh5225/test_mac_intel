from pathlib import Path
import hashlib
from elftools.elf.elffile import ELFFile


def ordinary_text_proof(before, after, active):
    def load(path):
        with Path(path).open('rb') as stream:
            elf = ELFFile(stream)
            table = elf.get_section_by_name('.symtab')
            index = elf.get_section_index('.text')
            functions = {s.name: (s['st_value'], s['st_size']) for s in table.iter_symbols()
                         if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] == index}
            data = {s.name: s.data() for s in elf.iter_sections() if s['sh_type'] == 'SHT_PROGBITS' and
                    (s.name.startswith('.rodata') or s.name == '.data.rel.ro')}
            plans, = table.get_symbol_by_name('x86_simple_plans')
            plan = dict(section=elf.get_section(plans['st_shndx']).name,
                        offset=plans['st_value'], size=plans['st_size'])
            relocations = []
            section = elf.get_section_by_name('.rela.text')
            if section:
                for rel in section.iter_relocations():
                    symbol = table.get_symbol(rel['r_info_sym'])
                    target = symbol.name
                    if isinstance(symbol['st_shndx'], int) and symbol['st_info']['type'] != 'STT_FUNC':
                        target = (elf.get_section(symbol['st_shndx']).name, symbol['st_value'], symbol['st_size'])
                    relocations.append((rel['r_offset'], rel['r_info_type'], target, rel['r_addend']))
            return elf.get_section_by_name('.text').data(), functions, data, plan, relocations

    if not active:
        return dict(active=False, passed=Path(before).read_bytes() == Path(after).read_bytes())
    left, fa, da, pa, ra = load(before)
    right, fb, db, pb, rb = load(after)
    data_proof = {}
    for name, raw in da.items():
        updated = bytearray(db.get(name, b''))
        original = bytearray(raw)
        changes = []
        if name == pa['section']:
            assert pa == pb and pa['size'] == 2*4*256*2
            for opcode in (0xc4, 0xc5):
                offset = pa['offset']+opcode*2
                old_value = int.from_bytes(original[offset:offset+2], 'little')
                new_value = int.from_bytes(updated[offset:offset+2], 'little')
                assert old_value == 0 and new_value == 65535, (opcode, old_value, new_value)
                changes.append(dict(opcode=opcode, offset=offset, before=old_value, after=new_value))
                updated[offset:offset+2] = original[offset:offset+2]
        data_proof[name] = dict(allowed_plan_cells=changes, original_bytes_preserved=original == updated)
    redirects = [x for x in rb if x[2] == 'X86_writeVectorOutputDispatch']
    normalized = [(a, b, 'X86_writeVectorOutput' if c == 'X86_writeVectorOutputDispatch' else c, d) for a,b,c,d in rb]
    result = dict(active=True, ordinary_text_identical=left == right,
        function_positions_and_sizes_identical=fa == fb, original_functions=fa, candidate_functions=fb,
        normalized_relocations_identical=ra == normalized, redirects=redirects, original_data=data_proof,
        text_sha256=hashlib.sha256(left).hexdigest(),
        scope='Only two existing 32-bit C4/C5 plan cells and the existing vector call relocation may change. No arbitrary text or data movement is allowed by this object proof.')
    result['passed'] = left == right and fa == fb and ra == normalized and bool(redirects) and all(v['original_bytes_preserved'] for v in data_proof.values())
    return result


def linked_layout(before, after, label):
    from collections import defaultdict
    import re
    assert label == 'output'
    def symbols(path, kinds):
        result = defaultdict(list)
        for line in Path(path).read_text().splitlines():
            match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
            if match and match[3] in kinds:
                result[match[4]].append((match[3], int(match[1],16), int(match[2],16)))
        return dict(result)
    result = dict(captured=True, criterion='Report linked symbol positions independently of object identity; the exceptional-arm iterator intentionally changes.')
    for category, kinds in (('text','tTwW'),('readonly','rR'),('writable','bBdDgGsSvV')):
        left, right = symbols(before,kinds), symbols(after,kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k]==right[k] for k in common),
            changed=[dict(symbol=k,before=left[k],after=right[k]) for k in sorted(common) if left[k]!=right[k]],
            added=[dict(symbol=k,positions=right[k]) for k in sorted(right.keys()-left.keys())],
            removed=[dict(symbol=k,positions=left[k]) for k in sorted(left.keys()-right.keys())])
    return result
