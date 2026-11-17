from pathlib import Path
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
            functions = {s.name: (s['st_value'], s['st_size'])
                         for s in table.iter_symbols()
                         if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] == index}
            relocations = []
            section = elf.get_section_by_name('.rela.text')
            if section:
                for relocation in section.iter_relocations():
                    symbol = table.get_symbol(relocation['r_info_sym'])
                    name = symbol.name or elf.get_section(symbol['st_shndx']).name
                    relocations.append((relocation['r_offset'], relocation['r_info_type'], name, relocation['r_addend']))
            dispatcher = table.get_symbol_by_name('X86_tryModeSimpleOutput')
            target = None if not dispatcher else (
                elf.get_section(dispatcher[0]['st_shndx']).name, dispatcher[0]['st_value'])
            return text.data(), functions, relocations, target

    a, fa, ra, _ = load(before)
    b, fb, rb, target = load(after)
    result = dict(active=active, before_size=len(a), after_size=len(b),
                  functions_before=fa, functions_after=fb,
                  function_positions_and_sizes_identical=fa == fb)
    if not active:
        result.update(exact_object_identity=Path(before).read_bytes() == Path(after).read_bytes(),
                      passed=Path(before).read_bytes() == Path(after).read_bytes())
        return result
    assembly = sp.check_output(['objdump', '-dr', before], text=True)
    calls = [int(m[1], 16) for m in re.finditer(
        r'^\s*([0-9a-f]+):.*\bcallq?\s+[^\n]*<X86_trySimpleOutput>', assembly, re.M)]
    result['generic_calls'] = calls
    if len(calls) != 1 or len(a) != len(b):
        result['passed'] = False
        return result
    pc, = calls
    old_target = pc + 5 + int.from_bytes(a[pc + 1:pc + 5], 'little', signed=True)
    redirected = [v for v in rb if v[0] == pc + 1]
    valid_target = len(redirected) == 1 and target is not None and (
        (redirected[0][2] == target[0] and redirected[0][3] + 4 == target[1]) or
        (redirected[0][2] == 'X86_tryModeSimpleOutput' and redirected[0][3] == -4))
    left, right = bytearray(a), bytearray(b)
    left[pc + 1:pc + 5] = right[pc + 1:pc + 5] = bytes(4)
    result.update(call_address=pc, original_target=old_target, new_relocation=redirected,
                  dispatcher=target, redirected_to_dispatcher=valid_target,
                  masked_text_identical=left == right,
                  other_relocations_identical=ra == [v for v in rb if v[0] != pc + 1],
                  before_masked_sha256=hashlib.sha256(left).hexdigest(),
                  after_masked_sha256=hashlib.sha256(right).hexdigest())
    result['passed'] = (fa == fb and a[pc] == b[pc] == 0xe8 and
                        old_target == fa['X86_trySimpleOutput'][0] and valid_target and
                        result['masked_text_identical'] and result['other_relocations_identical'])
    return result

from collections import defaultdict

def symbols(path, kinds):
    result = defaultdict(list)
    for line in Path(path).read_text().splitlines():
        match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
        if match and match[3] in kinds:
            result[match[4]].append((match[3], int(match[1], 16), int(match[2], 16)))
    return dict(result)

def linked_layout(before, after, label):
    assert label == 'output'
    result = dict(captured=True, criterion='Record every symbol relocation and size change. Object isolation is mandatory; actual native timing and A/A controls determine performance acceptance.')
    for category, kinds in (('text', 'tTwW'), ('readonly', 'rR'), ('writable', 'bBdDgGsSvV')):
        left, right = symbols(before, kinds), symbols(after, kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k] == right[k] for k in common),
            changed=[dict(symbol=k, before=left[k], after=right[k]) for k in sorted(common) if left[k] != right[k]],
            removed=[dict(symbol=k, positions=left[k]) for k in sorted(left.keys() - right.keys())],
            added=[dict(symbol=k, positions=right[k]) for k in sorted(right.keys() - left.keys())])
    permitted = {'X86_writeDisplacement', 'X86_writeEvexMemoryDispatch',
                 'X86_decodeScanFeatureExtension', 'decodeEvexRegisterScan',
                 'X86_writeEvexMemoryOutput'}
    moved = result['text']['changed']
    assert {row['symbol'] for row in moved} == permitted
    assert all(len(row['before']) == len(row['after']) == 1 and
               row['before'][0][2] == row['after'][0][2] for row in moved)
    assert len({row['after'][0][1] - row['before'][0][1] for row in moved}) == 1
    result['scope'] = 'Ordinary text identity is separately required; exactly five unmodified functions in existing isolated EVEX sections move by one common delta. Every real-input native timing observation is retained for qualification.'
    return result


def object_proof(label, before, after):
    assert label == 'output'
    result = ordinary_text_proof(before, after, True)
    assert result['passed'], 'Existing ordinary text changed beyond the intended call target'
    return result
