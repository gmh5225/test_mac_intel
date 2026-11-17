"""Relink unchanged baseline instructions with independently controlled growth."""
from pathlib import Path
from collections import defaultdict
import hashlib
import json
import re
import shutil
import struct
import subprocess as sp


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf(path, relocatable=True):
    data = path.read_bytes()
    header = list(struct.unpack_from('<16sHHIQQQIHHHHHH', data))
    assert header[0][:6] == b'\x7fELF\x02\x01' and header[2] == 62
    if relocatable:
        assert header[1] == 1 and header[5] == header[10] == 0
    assert header[8] == header[11] == 64
    assert 0 < header[12] < 0xff00 and header[13] < header[12]
    sections = [list(struct.unpack_from('<IIQQQQIIQQ', data, header[6] + 64 * i))
                for i in range(header[12])]
    strings = sections[header[13]]
    names = data[strings[4]:strings[4] + strings[5]]
    labels = [names[s[0]:names.index(b'\0', s[0])].decode() for s in sections]
    return data, header, sections, labels


def grow_object(source, target, growth, added):
    data, header, sections, names = elf(source)
    original = {name: data[s[4]:s[4] + s[5]] for name, s in zip(names, sections)
                if s[1] not in (0, 8)}
    bodies = dict(original)
    for name, size in growth.items():
        assert name in ('.text', '.rodata') and size >= 0
        section = sections[names.index(name)]
        assert section[1] == 1 and not section[2] & (16 | 32 | 2048)
        bodies[name] += (b'\x90' if name == '.text' else b'\0') * size
    string_name = names[header[13]]
    for name, shape in added.items():
        assert name not in names
        offset = len(bodies[string_name])
        bodies[string_name] += name.encode() + b'\0'
        sections.append([offset, 1, shape['flags'], 0, 0, shape['size'], 0, 0, shape['alignment'], 0])
        names.append(name)
        bodies[name] = (b'\x90' if shape['flags'] & 4 else b'\0') * shape['size']
    header[12] = len(sections)
    chunks = bytearray(data[:64])
    for name, section in zip(names, sections):
        if section[1] == 0:
            continue
        alignment = max(1, section[8])
        assert alignment & (alignment - 1) == 0
        chunks.extend(bytes((-len(chunks)) % alignment))
        section[4] = len(chunks)
        if section[1] != 8:
            body = bodies[name]
            section[5] = len(body)
            chunks.extend(body)
    chunks.extend(bytes((-len(chunks)) % 8))
    header[6] = len(chunks)
    for section in sections:
        chunks.extend(struct.pack('<IIQQQQIIQQ', *section))
    chunks[:64] = struct.pack('<16sHHIQQQIHHHHHH', *header)
    target.write_bytes(chunks)
    after, _, new_sections, new_names = elf(target)
    for name, section in zip(new_names, new_sections):
        if name not in original or section[1] in (0, 8):
            continue
        body = after[section[4]:section[4] + section[5]]
        if name in growth or name == string_name:
            assert body[:len(original[name])] == original[name], name
        else:
            assert body == original[name], name
    return dict(original_sha256=sha(source), padded_sha256=sha(target), growth=growth,
                added_inert_sections=added, all_original_section_prefixes_preserved=True,
                symbol_and_relocation_tables_identical=True)


def symbols(path):
    result = defaultdict(list)
    for line in sp.check_output(['nm', '-n', '-S', '--defined-only', path], text=True).splitlines():
        m = re.match(r'^([0-9a-f]+) ([0-9a-f]+) (\w) (.*)$', line)
        if m:
            result[m[4]].append([int(m[1], 16), int(m[2], 16), m[3]])
    return result
