from pathlib import Path
import hashlib
from elftools.elf.elffile import ELFFile

def allocated(path):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        return {s.name: (s['sh_type'], s['sh_flags'], s['sh_size'], s['sh_addralign'],
                         hashlib.sha256(s.data()).hexdigest())
                for s in elf.iter_sections() if s['sh_flags'] & 2}

def table(path, name):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        symbol, = elf.get_section_by_name('.symtab').get_symbol_by_name(name)
        section = elf.get_section(symbol['st_shndx'])
        start = symbol['st_value'] - section['sh_addr']
        return section.data()[start:start + symbol['st_size']]

def decoder_proof(before, after):
    left, right = allocated(before), allocated(after)
    allowed = {'.cs_x86_evex_scan_text', '.cs_x86_evex_scan_rodata', '.cs_x86_evex_transfer_rodata', '.eh_frame'}
    changed = sorted(name for name in left.keys() | right.keys() if left.get(name) != right.get(name))
    assert set(changed) <= allowed, changed
    assert not any(row[2] for name, row in right.items() if name in ('.text', '.data', '.rodata', '.bss'))
    assert table(before, 'evex_scan_plans') == table(after, 'evex_scan_plans')
    old, new = table(before, 'evex_scan_index'), table(after, 'evex_scan_index')
    assert len(old) == len(new) == 256
    diffs = [(i, a, b) for i, (a, b) in enumerate(zip(old, new)) if a != b]
    assert diffs == [(0x1a, 0, 129), (0x6f, 0, 128), (0x7f, 0, 128)]
    return dict(only_declared_plan_sections_changed=True, changed=changed,
                original_register_id_plans_identical=True, opcode_index_changes=diffs,
                old_text_size=left['.cs_x86_evex_scan_text'][2], new_text_size=right['.cs_x86_evex_scan_text'][2])

def symbols(path, kinds):
    rows = []
    for line in Path(path).read_text().splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[2] in kinds:
            rows.append((fields[3], fields[2], int(fields[0], 16), int(fields[1], 16)))
    return sorted(rows)

def linked_proof(before, after):
    old_text, new_text = symbols(before, 'tTwW'), symbols(after, 'tTwW')
    modified = lambda x: x[0] == 'X86_decodeScanFeatureExtension' or x[0].startswith('decodeEvexRegisterScan')
    old_entries, new_entries = [x for x in old_text if modified(x)], [x for x in new_text if modified(x)]
    assert len(old_entries) == len(new_entries) == 2
    left, right = [x for x in old_text if not modified(x)], [x for x in new_text if not modified(x)]
    assert left == right, dict(missing=sorted(set(left)-set(right))[:12], changed=sorted(set(right)-set(left))[:12])
    old_data = symbols(before, 'rR')
    new_data = [x for x in symbols(after, 'rR') if x[0] not in ('evex_transfer_scan_ids', 'evex_transfer_lengths')]
    assert old_data == new_data, dict(missing=sorted(set(old_data)-set(new_data))[:12], changed=sorted(set(new_data)-set(old_data))[:12])
    return dict(unmodified_text_positions_identical=True, original_readonly_positions_identical=True,
                text_symbols=len(left), readonly_symbols=len(old_data), modified_entries=dict(before=old_entries, after=new_entries))
