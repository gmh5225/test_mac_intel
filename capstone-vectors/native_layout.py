from pathlib import Path
import hashlib
from elftools.elf.elffile import ELFFile


def iterator_proof(before, after):
    def load(path):
        with Path(path).open('rb') as stream:
            elf = ELFFile(stream)
            table = elf.get_section_by_name('.symtab')
            text = elf.get_section_by_name('.text').data()
            index = elf.get_section_index('.text')
            functions = {s.name: (s['st_value'], s['st_size']) for s in table.iter_symbols()
                         if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] == index}
            records = {}
            for name in ('x86_simple_plans', 'x86_simple_outputs', 'x86_simple_registers',
                         'x86_push_rows', 'x86_shift_rows'):
                symbol, = table.get_symbol_by_name(name)
                start, size = symbol['st_value'], symbol['st_size']
                records[name] = elf.get_section(symbol['st_shndx']).data()[start:start+size]
            rel = elf.get_section_by_name('.rela.text')
            calls = sorted({table.get_symbol(x['r_info_sym']).name for x in rel.iter_relocations()})
            return text, functions, records, calls

    left, fa, da, ra = load(before)
    right, fb, db, rb = load(after)
    proof = {}
    for name, original in da.items():
        updated = bytearray(db[name])
        changes = []
        if name == 'x86_simple_plans':
            assert len(original) == len(updated) == 2*4*256*2
            for opcode in (0xc4, 0xc5):
                offset = opcode*2
                old = int.from_bytes(original[offset:offset+2], 'little')
                new = int.from_bytes(updated[offset:offset+2], 'little')
                assert old == 0 and new == 65528, (opcode, old, new)
                changes.append(dict(opcode=opcode, before=old, after=new))
                updated[offset:offset+2] = original[offset:offset+2]
        proof[name] = dict(allowed_plan_cells=changes, original_bytes_preserved=original == updated,
                           original_sha256=hashlib.sha256(original).hexdigest())
    return dict(passed=all(x['original_bytes_preserved'] for x in proof.values()) and
                       set(fa) == set(fb) and 'X86_writeVectorOutput' in rb and
                       'X86_writeVex32Output' in rb and 'X86_writeVectorOutputDispatch' not in rb,
                ordinary_text_identical=left == right, function_positions_and_sizes_identical=fa == fb,
                original_functions=fa, candidate_functions=fb, original_data=proof,
                original_calls=ra, candidate_calls=rb,
                before_text_sha256=hashlib.sha256(left).hexdigest(),
                after_text_sha256=hashlib.sha256(right).hexdigest(),
                scope='Only two 32-bit C4/C5 plan entries change in the existing generated records. '
                      'The owning iterator intentionally changes; no ordinary-text identity claim. '
                      'Separate archive-member checks preserve every other original runtime object.')


def linked_layout(before, after, label):
    from collections import defaultdict
    import re
    assert label == 'output'

    def symbols(path, kinds):
        result = defaultdict(list)
        for line in Path(path).read_text().splitlines():
            match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
            if match and match[3] in kinds:
                result[match[4]].append((match[3], int(match[1], 16), int(match[2], 16)))
        return dict(result)

    result = dict(captured=True, criterion='Report every linked symbol position independently of object identity; iterator code intentionally changes.')
    for category, kinds in (('text', 'tTwW'), ('readonly', 'rR'), ('writable', 'bBdDgGsSvV')):
        left, right = symbols(before, kinds), symbols(after, kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k] == right[k] for k in common),
            changed=[dict(symbol=k, before=left[k], after=right[k]) for k in sorted(common) if left[k] != right[k]],
            added=[dict(symbol=k, positions=right[k]) for k in sorted(right.keys() - left.keys())],
            removed=[dict(symbol=k, positions=left[k]) for k in sorted(left.keys() - right.keys())])
    return result


def object_proof(label, before, after):
    assert label == 'output'
    result = iterator_proof(before, after)
    assert result['passed'], result
    return result
