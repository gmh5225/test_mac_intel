"""Diagnostic ELF slots: equal placement for every allocated input section.

This is deliberately outside the production patch. Both compared objects get
the same reserved space; added tables have an unused zero-filled control slot.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess as sp
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def sections(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        return {s.name: dict(size=s['sh_size'], align=s['sh_addralign'],
                            flags=s['sh_flags'], type=s['sh_type'], data=s.data())
                for s in elf.iter_sections() if s['sh_flags'] & 2 and s['sh_size']}


def relocations(path, renamed):
    result=[]
    with Path(path).open('rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section,RelocationSection):
                continue
            target=elf.get_section(section['sh_info']).name
            symbols=elf.get_section(section['sh_link'])
            for reloc in section.iter_relocations():
                symbol=symbols.get_symbol(reloc['r_info_sym'])
                name=symbol.name
                if symbol['st_info']['type']=='STT_SECTION':
                    name=elf.get_section(symbol['st_shndx']).name
                result.append((renamed.get(target,target),reloc['r_offset'],reloc['r_info_type'],
                               renamed.get(name,name),reloc.entry.get('r_addend')))
    return sorted(result)


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
    renamed = {item['original']: item['slot'] for item in schema}
    for variant, obj in objects.items():
        args = [os.environ.get('OBJCOPY', 'objcopy')]
        for item in schema:
            if item['original'] in original[variant]:
                args += ['--rename-section', item['original']+'='+item['slot']]
        target = directory / variant / 'X86OutputIterator.c.o'
        target.parent.mkdir()
        command([*args,obj,target], 'slot-object-'+variant)
        actual = sections(target)
        for name,value in original[variant].items():
            assert actual[renamed.get(name,name)] == value, (variant,name,'section changed')
        assert relocations(obj,renamed) == relocations(target,{}), (variant,'relocations changed')
        result[variant] = target
    script = directory / 'layout.ld'
    pieces = []
    for executable, section, anchor in [(True, '.text.cs_diag', '.text'),
                                        (False, '.rodata.cs_diag', '.rodata')]:
        body = []
        alignment=max(item['align'] for item in schema if bool(item['flags'] & 4)==executable)
        for idx,item in enumerate(schema):
            if bool(item['flags'] & 4) == executable:
                start = f'__cs_diag_slot_{idx}'
                body.append(f"  . = ALIGN({item['align']}); {start} = .; KEEP(*({item['slot']})) . = {start}+{item['size']};")
        pieces.append('SECTIONS { ' + section + f' ALIGN({alignment}) : ALIGN({alignment}) {{\n' + '\n'.join(body)
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
    assert base['allocated'] == candidate['allocated'], ('Allocated section placement differs',base['allocated'],candidate['allocated'])
    assert base['segments'] == candidate['segments'], 'Program mappings differ'
    shared = set(base['symbols']) & set(candidate['symbols'])
    left, right = defaultdict(list), defaultdict(list)
    for name,address,kind in base['symbols']:
        left[name].append((address,kind))
    for name,address,kind in candidate['symbols']:
        right[name].append((address,kind))
    changed = {name: [left[name], right[name]] for name in left.keys() & right.keys()
               if left[name] != right[name]}
    assert not changed, changed
    hashes = {k: hashlib.sha256(Path(v).read_bytes()).hexdigest() for k,v in paths.items()}
    assert len(set(hashes.values())) == len(paths), 'The intended decoder variant was not linked'
    return dict(allocated=base['allocated'], segments=base['segments'],
                shared_symbols=len(shared), changed_shared_symbols=changed,
                added_symbols=sorted(right.keys()-left.keys()),
                binary_sha256=hashes)
