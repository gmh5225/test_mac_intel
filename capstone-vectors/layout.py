"""Diagnostic ELF slots: equal placement for every allocated input section.

This is deliberately outside the production patch. Both compared objects get
the same reserved space; added tables have an unused zero-filled control slot.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess as sp

from elftools.elf.elffile import ELFFile


def sections(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        return {s.name: dict(size=s['sh_size'], align=s['sh_addralign'],
                            flags=s['sh_flags'], type=s['sh_type'], data=s.data())
                for s in elf.iter_sections() if s['sh_flags'] & 2 and s['sh_size']}


def freeze(objects, directory, command):
    directory = Path(directory)
    directory.mkdir()
    original = {name: sections(path) for name, path in objects.items()}
    names = sorted(set().union(*(set(v) for v in original.values())))
    schema = []
    notes = set()
    for idx, name in enumerate(names):
        values = [v[name] for v in original.values() if name in v]
        if values[0]['type'] == 'SHT_NOTE':
            assert len(values) == len(original) and all(v == values[0] for v in values)
            notes.add(name)
            continue
        assert all(v['type'] == 'SHT_PROGBITS' for v in values), (name, values)
        assert len({v['flags'] for v in values}) == 1
        # The focused C object has no TLS or writable state.
        assert not values[0]['flags'] & (1 | 1024), name
        assert not name.startswith('.eh_frame'), name
        align = max(v['align'] for v in values)
        size = (max(v['size'] for v in values) + align - 1) // align * align
        schema.append(dict(original=name, slot=f'.cs_diag_{idx:04d}',
                           size=size, align=align, flags=values[0]['flags']))
    result = {}
    for variant, obj in objects.items():
        args = [os.environ.get('OBJCOPY', 'objcopy')]
        for item in schema:
            name, slot = item['original'], item['slot']
            current = original[variant].get(name)
            data = current['data'] if current else b''
            content = directory / f'{variant}-{slot}.bin'
            content.write_bytes(data + bytes(item['size'] - len(data)))
            if current:
                args += ['--update-section', name + '=' + str(content),
                         '--rename-section', name + '=' + slot]
            else:
                args += ['--add-section', slot + '=' + str(content)]
            flags = 'alloc,load,readonly,' + ('code' if item['flags'] & 4 else 'data')
            args += ['--set-section-flags', slot + '=' + flags,
                     '--set-section-alignment', slot + '=' + str(item['align'])]
        target = directory / variant / 'X86OutputIterator.c.o'
        target.parent.mkdir()
        command([*args, obj, target], 'slot-object-' + variant)
        actual = sections(target)
        assert {v['slot'] for v in schema} | notes == set(actual)
        for item in schema:
            assert actual[item['slot']]['size'] == item['size']
            assert actual[item['slot']]['align'] == item['align']
        result[variant] = target
    script = directory / 'layout.ld'
    pieces = []
    for executable, section, anchor in [(True, '.text.cs_diag', '.text'),
                                        (False, '.rodata.cs_diag', '.rodata')]:
        body = []
        for item in schema:
            if bool(item['flags'] & 4) == executable:
                body.append(f"  . = ALIGN({item['align']}); KEEP(*({item['slot']}))")
        pieces.append('SECTIONS { ' + section + ' : {\n' + '\n'.join(body)
                      + '\n} } INSERT BEFORE ' + anchor + ';\n')
    script.write_text(''.join(pieces))
    return result, script, schema


def validate_binaries(paths):
    snapshots = {}
    for variant, path in paths.items():
        with Path(path).open('rb') as stream:
            elf = ELFFile(stream)
            allocated = [(s.name, s['sh_addr'], s['sh_size'], s['sh_addralign'])
                         for s in elf.iter_sections() if s['sh_flags'] & 2]
            symbols = sorted((s.name, s['st_value'], s['st_info']['type'])
                             for s in elf.get_section_by_name('.symtab').iter_symbols()
                             if s['st_shndx'] != 'SHN_UNDEF'
                             and s['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'))
            segments = [dict(p.header) for p in elf.iter_segments()]
        snapshots[variant] = dict(allocated=allocated, symbols=symbols, segments=segments)
    base, candidate = list(snapshots.values())
    assert base['allocated'] == candidate['allocated'], 'Allocated section placement differs'
    assert base['segments'] == candidate['segments'], 'Program mappings differ'
    shared = set(base['symbols']) & set(candidate['symbols'])
    left = {name: (address, kind) for name, address, kind in base['symbols']}
    right = {name: (address, kind) for name, address, kind in candidate['symbols']}
    changed = {name: [left[name], right[name]] for name in left.keys() & right.keys()
               if left[name] != right[name]}
    assert not changed, changed
    return dict(allocated=base['allocated'], segments=base['segments'],
                shared_symbols=len(shared), changed_shared_symbols=changed,
                added_symbols=sorted(right.keys()-left.keys()),
                binary_sha256={k: hashlib.sha256(Path(v).read_bytes()).hexdigest()
                               for k, v in paths.items()})
