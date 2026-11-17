from pathlib import Path
import hashlib
import json
import shutil
import subprocess as sp
from elftools.elf.elffile import ELFFile
from layout import linked_layout, symbols


def section(path, name):
    with Path(path).open('rb') as stream:
        return ELFFile(stream).get_section_by_name(name).data()


def relocations(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        records = elf.get_section_by_name('.rela.text')
        table = elf.get_section(records['sh_link'])
        result = []
        for relocation in records.iter_relocations():
            target = table.get_symbol(relocation['r_info_sym'])
            index = target['st_shndx']
            target_section = elf.get_section(index).name if isinstance(index, int) else index
            result.append((relocation['r_offset'], relocation['r_info_type'],
                           target.name, target['st_info']['type'], target_section,
                           target['st_value'], relocation['r_addend']))
        return result


def function_bytes(path, entries):
    result = {}
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        loads = [segment for segment in elf.iter_segments() if segment['p_type'] == 'PT_LOAD']
        for name, positions in entries.items():
            rows = []
            for kind, address, size in positions:
                segment, = [s for s in loads if s['p_vaddr'] <= address and address + size <= s['p_vaddr'] + s['p_filesz']]
                stream.seek(segment['p_offset'] + address - segment['p_vaddr'])
                data = stream.read(size)
                assert len(data) == size
                rows.append((kind, address, size, hashlib.sha256(data).hexdigest()))
            result[name] = rows
    return result


def build_geometry(t, b, evidence, run, bins):
    obj = b / 'CMakeFiles/capstone.dir/arch/X86'
    before = t / 'baseline-plan.o'
    after = obj / 'X86VectorOutput.c.o'
    original, changed = section(before, '.text'), section(after, '.text')
    growth = len(changed) - len(original)
    assert growth in (16, 32), growth
    control = t / 'geometry-objects'
    control.mkdir()
    text = control / 'text.bin'
    text.write_bytes(original + b'\x90' * growth)
    patched = control / 'X86VectorOutput.c.o'
    run(['objcopy', '--update-section', '.text=' + str(text), before, patched], 'geometry-object')
    assert section(patched, '.text') == text.read_bytes()
    original_relocations, patched_relocations = relocations(before), relocations(patched)
    (evidence / 'relocation-equivalence.json').write_text(json.dumps(dict(
        before=original_relocations, after=patched_relocations,
        raw_bytes_identical=section(patched, '.rela.text') == section(before, '.rela.text'),
        resolved_records_identical=original_relocations == patched_relocations), indent=2) + '\n')
    assert original_relocations == patched_relocations
    library = control / 'libcapstone.a'
    shutil.copyfile(t / 'baseline-libcapstone.a', library)
    leaf = obj / 'X86EvexMemoryOutput.c.o'
    run(['ar', 'r', library, patched, leaf], 'geometry-members')
    wanted = sp.check_output(['ar', 't', b / 'libcapstone.a'], text=True).splitlines()
    assert len(set(wanted)) == len(wanted)
    predecessor = wanted[wanted.index(leaf.name) - 1]
    run(['ar', 'ma', predecessor, library, leaf.name], 'geometry-order')
    run(['ar', 's', library], 'geometry-index')
    assert sp.check_output(['ar', 't', library], text=True).splitlines() == wanted
    binary = t / 'geometry'
    run(['clang++', t / 'single.o', '-Wl,-u,X86_writeEvexMemoryOutput', library, '-lm', '-o', binary], 'link-geometry')
    bins['geometry'] = binary
    for name, path in [('geometry', binary), ('base-vector', before), ('output-vector', after)]:
        (evidence / (name + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', path]))
    excluded = set(symbols(evidence / 'base-vector-symbols.txt', 'tTwW')) | set(symbols(evidence / 'output-vector-symbols.txt', 'tTwW'))
    layout = linked_layout(evidence / 'geometry-symbols.txt', evidence / 'output-symbols.txt', 'output')
    executable = {key: function_bytes(bins[key], symbols(evidence / (key + '-symbols.txt'), 'tTwW')) for key in ('geometry', 'output')}
    names = executable['geometry'].keys() | executable['output'].keys()
    mismatches = [name for name in sorted(names - excluded) if executable['geometry'].get(name) != executable['output'].get(name)]
    data_matches = all(not layout[k]['changed'] and not layout[k]['added'] and not layout[k]['removed'] for k in ('readonly', 'writable'))
    proof = dict(padding_bytes=growth, original_text_prefix_preserved=True,
        original_relocation_semantics_preserved=True,
        synthetic_control_only=True, production_source_modified=False,
        method='Keep every baseline text byte and relocation; append exactly the observed text growth, then link the same otherwise-unreachable memory-writer object in the candidate archive order. This is a diagnostic binary, never a production patch.',
        layout=layout, excluded_vector_functions=sorted(excluded),
        compared_other_functions=len(names - excluded), other_function_byte_mismatches=mismatches,
        data_symbols_match=data_matches, matched=not mismatches and data_matches)
    (evidence / 'geometry-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    return proof
