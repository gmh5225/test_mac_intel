from pathlib import Path
import hashlib
from elftools.elf.elffile import ELFFile


def object_sections(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        rows = []
        for sec in elf.iter_sections():
            if sec['sh_flags'] & 2:
                rows.append((sec.name, sec['sh_type'], sec['sh_flags'], sec['sh_size'],
                             sec['sh_addralign'], hashlib.sha256(sec.data()).hexdigest()))
        relocations = []
        for sec in elf.iter_sections():
            if sec['sh_type'] not in ('SHT_RELA', 'SHT_REL'):
                continue
            target = elf.get_section(sec['sh_info']).name
            symbols = elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym = symbols.get_symbol(rel['r_info_sym'])
                name = sym.name
                if sym['st_info']['type'] == 'STT_SECTION':
                    name = 'section:' + elf.get_section(sym['st_shndx']).name
                relocations.append((target, rel['r_offset'], rel['r_info_type'],
                                    rel.entry.get('r_addend', 0), name))
        return rows, sorted(relocations)


def decoder_proof(before, after):
    left, left_rel = object_sections(before)
    right, right_rel = object_sections(after)
    assert left == right, (left, right)
    changed = [x for x in right_rel if x[-1] == 'X86_decodeEvexTransferScan']
    assert changed
    normalized = sorted((*x[:-1], 'X86_decodeFeatureExtension'
                         if x[-1] == 'X86_decodeEvexTransferScan' else x[-1])
                        for x in right_rel)
    assert left_rel == normalized
    return dict(all_allocated_section_bytes_sizes_alignments_identical=True,
                only_relocation_change='X86_decodeFeatureExtension -> X86_decodeEvexTransferScan',
                changed_call_sites=changed)


def leaf_proof(path):
    sections, _ = object_sections(path)
    extra_text = [x for x in sections if x[0] == '.cs_x86_evex_transfer_text']
    extra_data = [x for x in sections if x[0] == '.cs_x86_evex_transfer_rodata']
    assert len(extra_text) == len(extra_data) == 1
    assert 0 < extra_text[0][3] <= 512, extra_text
    assert extra_data[0][3] == 48, extra_data
    other = [x for x in sections if x[0] not in (
        '.cs_x86_evex_transfer_text', '.cs_x86_evex_transfer_rodata', '.eh_frame', '.note.gnu.property') and x[3]]
    assert not other, other
    return dict(sections=sections, no_ordinary_code_or_data=True)


def symbols(path, kinds):
    rows = []
    for line in Path(path).read_text().splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[2] in kinds:
            rows.append((fields[3], fields[2], int(fields[0], 16), int(fields[1], 16)))
    return sorted(rows)


def linked_proof(before, after):
    old_text, new_text = symbols(before, 'tTwW'), symbols(after, 'tTwW')
    entries = [x for x in new_text if x[0] == 'X86_decodeEvexTransferScan']
    retained = [x for x in new_text if x not in entries]
    assert len(entries) == 1
    assert old_text == retained, dict(missing=sorted(set(old_text)-set(retained))[:12],
                                      changed=sorted(set(retained)-set(old_text))[:12])
    old_data = symbols(before, 'rR')
    new_data = [x for x in symbols(after, 'rR') if x[0] not in ('evex_transfer_scan_ids',)]
    assert old_data == new_data, dict(missing=sorted(set(old_data)-set(new_data))[:12],
                                      changed=sorted(set(new_data)-set(old_data))[:12])
    return dict(original_text_positions_identical=True, original_readonly_positions_identical=True,
                text_symbols=len(old_text), readonly_symbols=len(old_data), new_entries=entries)
