from pathlib import Path
import hashlib
from elftools.elf.elffile import ELFFile


def sections(path, executable):
    rows = []
    with Path(path).open('rb') as stream:
        for section in ELFFile(stream).iter_sections():
            flags = section['sh_flags']
            selected = bool(flags & 4) if executable else (
                bool(flags & 2) and not flags & 5 and section['sh_type'] == 'SHT_PROGBITS'
                and section.name != '.eh_frame')
            if selected:
                rows.append((section.name, section['sh_size'],
                             hashlib.sha256(section.data()).hexdigest()))
    return rows


def object_proof(baseline, candidate):
    original_text = sections(baseline, True)
    candidate_text = sections(candidate, True)
    entry = [x for x in candidate_text if x[0] == '.cs_x86_feature_text']
    assert len(entry) == 1 and 0 < entry[0][1] <= 256, entry
    ordinary_text = [x for x in candidate_text if x[0] != '.cs_x86_feature_text']
    assert ordinary_text == original_text, (ordinary_text, original_text)
    original_data = sections(baseline, False)
    candidate_data = sections(candidate, False)
    table = [x for x in candidate_data if x[0] == '.cs_x86_feature_rodata']
    assert len(table) == 1 and table[0][1] == 256, table
    ordinary_data = [x for x in candidate_data if x[0] != '.cs_x86_feature_rodata']
    assert ordinary_data == original_data, (ordinary_data, original_data)
    return dict(original_executable_section_bytes_identical=True,
                original_readonly_section_bytes_identical=True,
                metadata_excluded=['.eh_frame: the new entry requires an additional unwind record'],
                original_text=original_text, original_data=original_data,
                added_entry=entry, added_table=table)


def symbols(path, kinds):
    rows = []
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in kinds:
            rows.append((fields[3], fields[2], int(fields[0], 16), int(fields[1], 16)))
    return rows


def linked_proof(baseline, candidate):
    # The original function body is renamed to a hidden internal symbol.
    # Its address and extent must stay exactly as in the baseline, along with
    # every other sized text symbol. The new public entry is the only addition.
    text = symbols(baseline, 'tTwW')
    expected = sorted((('X86_decodeFeatureExtensionSlow' if n == 'X86_decodeFeatureExtension' else n),
                       k, a, z) for n, k, a, z in text)
    actual = symbols(candidate, 'tTwW')
    new_entry = [x for x in actual if x[0] == 'X86_decodeFeatureExtension']
    assert len(new_entry) == 1
    actual = sorted(x for x in actual if x[0] != 'X86_decodeFeatureExtension')
    assert actual == expected, dict(missing=sorted(set(expected)-set(actual))[:20],
                                   changed=sorted(set(actual)-set(expected))[:20])
    original_data = sorted(symbols(baseline, 'rR'))
    actual_data = sorted(x for x in symbols(candidate, 'rR') if x[0] != 'evex_feature_maps')
    assert actual_data == original_data, dict(
        missing=sorted(set(original_data)-set(actual_data))[:20],
        changed=sorted(set(actual_data)-set(original_data))[:20])
    return dict(original_text_symbol_positions_identical=True,
                original_readonly_symbol_positions_identical=True,
                text_symbols=len(expected), readonly_symbols=len(original_data),
                added_entry=new_entry,
                scope='Original object section bytes plus linked symbol positions; final linked relocation bytes may differ because calls now target the new entry.')
