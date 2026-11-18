from pathlib import Path
from collections import defaultdict
import hashlib
import re
import subprocess as sp

from elftools.elf.elffile import ELFFile


def ordinary_text_proof(before, after, active):
    def load(path):
        with Path(path).open('rb') as stream:
            elf = ELFFile(stream)
            text = elf.get_section_by_name('.text')
            index = elf.get_section_index('.text')
            table = elf.get_section_by_name('.symtab')
            functions = {s.name: (s['st_value'], s['st_size']) for s in table.iter_symbols()
                         if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] == index}
            data = {section.name: section.data() for section in elf.iter_sections()
                    if section['sh_type'] == 'SHT_PROGBITS' and section.name != '.text'}
            relocations = []
            section = elf.get_section_by_name('.rela.text')
            if section:
                for rel in section.iter_relocations():
                    symbol = table.get_symbol(rel['r_info_sym'])
                    name = symbol.name
                    target = name
                    if isinstance(symbol['st_shndx'], int) and symbol['st_info']['type'] != 'STT_FUNC':
                        sec = elf.get_section(symbol['st_shndx'])
                        target = (sec.name, symbol['st_value'], symbol['st_size'])
                    relocations.append(dict(offset=rel['r_offset'], kind=rel['r_info_type'], target=target,
                        name=name, addend=rel['r_addend']))
            target = table.get_symbol_by_name('decodeVex32OrGeneric')
            target = None if not target else (elf.get_section(target[0]['st_shndx']).name, target[0]['st_value'])
            return text.data(), functions, relocations, data, target

    left, fa, ra, da, _ = load(before)
    right, fb, rb, db, target = load(after)
    result = dict(active=active, before_size=len(left), after_size=len(right),
                  original_functions=fa, candidate_functions=fb,
                  function_positions_and_sizes_identical=fa == fb)
    if not active:
        result['passed'] = Path(before).read_bytes() == Path(after).read_bytes()
        return result
    assembly = sp.check_output(['objdump', '-dr', before], text=True)
    calls = [int(m[1], 16) for m in re.finditer(
        r'^\s*([0-9a-f]+):.*\b(?:callq?|jmpq?)\s+[^\n]*<decodeScanResultGeneric>', assembly, re.M)]
    result['generic_calls'] = calls
    if not calls or len(left) != len(right) or not target:
        result['passed'] = False
        return result
    a, b = bytearray(left), bytearray(right)
    records, redirected = [], set()
    for pc in calls:
        old = pc + 5 + int.from_bytes(left[pc + 1:pc + 5], 'little', signed=True)
        refs = [v for v in rb if v['offset'] == pc + 1]
        valid = len(refs) == 1 and (
            (refs[0]['target'] == (target[0], 0, 0) and refs[0]['addend'] + 4 == target[1]) or
            (refs[0]['target'] == 'decodeVex32OrGeneric' and refs[0]['addend'] == -4))
        records.append(dict(pc=pc, before_target=old, after=refs,
            passed=left[pc] == right[pc] and left[pc] in (0xe8, 0xe9) and old == fa['decodeScanResultGeneric'][0] and valid))
        a[pc + 1:pc + 5] = b[pc + 1:pc + 5] = bytes(4)
        redirected.add(pc + 1)
    normalize = lambda rows: [(x['offset'], x['kind'], x['target'], x['addend']) for x in rows]
    rb_other = [x for x in rb if x['offset'] not in redirected]
    referenced = {x['target'][0] for x in ra if isinstance(x['target'], tuple)}
    data_proof = {name: dict(before_sha256=hashlib.sha256(da[name]).hexdigest(),
                            original_bytes_preserved=db.get(name, b'')[:len(da[name])] == da[name])
                  for name in referenced if name in da}
    result.update(redirects=records, dispatcher=target, original_data=data_proof,
        normalized_relocations_identical=normalize(ra) == normalize(rb_other),
        original_relocations=ra, candidate_relocations=rb,
        masked_text_identical=a == b, before_masked_sha256=hashlib.sha256(a).hexdigest(),
        after_masked_sha256=hashlib.sha256(b).hexdigest())
    result['passed'] = (fa == fb and a == b and all(x['passed'] for x in records) and
        result['normalized_relocations_identical'] and all(x['original_bytes_preserved'] for x in data_proof.values()))
    return result


def symbols(path, kinds):
    result = defaultdict(list)
    for line in Path(path).read_text().splitlines():
        match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
        if match and match[3] in kinds:
            result[match[4]].append((match[3], int(match[1], 16), int(match[2], 16)))
    return dict(result)


def linked_layout(before, after, label):
    assert label == 'output'
    result = dict(captured=True, criterion='Require ordinary decoder object text and relocation identity except the verified fallback target, then retain every linked symbol movement for actual throughput qualification.')
    for category, kinds in (('text', 'tTwW'), ('readonly', 'rR'), ('writable', 'bBdDgGsSvV')):
        left, right = symbols(before, kinds), symbols(after, kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k] == right[k] for k in common),
            changed=[dict(symbol=k, before=left[k], after=right[k]) for k in sorted(common) if left[k] != right[k]],
            removed=[dict(symbol=k, positions=left[k]) for k in sorted(left.keys() - right.keys())],
            added=[dict(symbol=k, positions=right[k]) for k in sorted(right.keys() - left.keys())])
    return result
