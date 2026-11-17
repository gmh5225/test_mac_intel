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


class Controls:
    def __init__(self, work, evidence, run, write):
        self.work, self.evidence, self.run, self.write = work, evidence, run, write
        self.archives, self.vector_objects, self.object_symbols = {}, {}, {}

    def capture(self, label, build):
        archive = self.work / (label + '.a')
        shutil.copyfile(build / 'libcapstone.a', archive)
        self.archives[label] = archive
        obj = self.work / (label + '-vector.o')
        shutil.copyfile(build / 'CMakeFiles/capstone.dir/arch/X86/X86VectorOutput.c.o', obj)
        self.vector_objects[label] = obj
        if label == 'base':
            for arch in ('ARM', 'AArch64', 'Mips'):
                for path in (build / 'CMakeFiles/capstone.dir/arch' / arch).glob('*.o'):
                    for name, values in symbols(path).items():
                        self.object_symbols.setdefault(name, []).extend(values)

    def prepare(self, consumer, bins):
        baseline, candidate = symbols(bins['base']), symbols(bins['scan'])
        common = {name for name in self.object_symbols if name in baseline and name in candidate
                  and len(baseline[name]) == len(candidate[name]) == 1}
        assert len(common) > 100
        anchor = 'AArch64_getInstruction'
        text_growth = candidate[anchor][0][0] - baseline[anchor][0][0]
        assert 0 < text_growth < 1024 and text_growth % 16 == 0
        rodata_sizes = {}
        for label, path in self.vector_objects.items():
            _, _, sections, names = elf(path)
            rodata_sizes[label] = sections[names.index('.rodata')][5]
        rodata_growth = rodata_sizes['scan'] - rodata_sizes['base']
        assert 0 < rodata_growth < 16384
        _, _, sections, names = elf(bins['scan'], relocatable=False)
        added = {name: dict(size=section[5], flags=section[2], alignment=section[8])
                 for name, section in zip(names, sections)
                 if name in ('.cs_x86_vex32_text', '.cs_x86_vex32_rodata')}
        assert set(added) == {'.cs_x86_vex32_text', '.cs_x86_vex32_rodata'}
        assert added['.cs_x86_vex32_text']['flags'] == 6
        assert added['.cs_x86_vex32_rodata']['flags'] == 2
        reports = {}
        original_members = sp.check_output(['ar', 't', self.archives['base']], text=True).splitlines()
        assert len(set(original_members)) == len(original_members)
        for label, text, rodata in [('text', True, False), ('data', False, True), ('both', True, True)]:
            folder = self.work / ('objects-' + label)
            folder.mkdir()
            replacement = folder / 'X86VectorOutput.c.o'
            growth = {}
            if text:
                growth['.text'] = text_growth
            if rodata:
                growth['.rodata'] = rodata_growth
            proof = grow_object(self.vector_objects['base'], replacement, growth, added if rodata else {})
            archive = self.work / (label + '.a')
            shutil.copyfile(self.archives['base'], archive)
            self.run(['ar', 'r', archive, replacement], 'archive-' + label)
            assert sp.check_output(['ar', 't', archive], text=True).splitlines() == original_members
            target = self.work / label
            self.run(['clang++', consumer, archive, '-lm', '-Wl,-Map=' + str(self.evidence / (label + '-link.map')), '-o', target], 'link-' + label)
            bins[label] = target
            current = symbols(target)
            assert set(current) == set(baseline)
            assert all([(n, k) for _, n, k in current[name]] == [(n, k) for _, n, k in values]
                       for name, values in baseline.items())
            code_names = {name for name in common if baseline[name][0][2].lower() == 't'}
            data_names = {name for name in common if baseline[name][0][2].lower() == 'r'}
            code_target = candidate if text else baseline
            code_differences = {name: dict(control=current[name], target=code_target[name])
                                for name in sorted(code_names) if current[name] != code_target[name]}
            # All three non-x86 backends must have the intended text addresses.
            assert not code_differences, (label, code_differences)
            data_target = candidate if rodata else baseline
            data_differences = {name: dict(control=current[name], target=data_target[name])
                                for name in sorted(data_names) if current[name] != data_target[name]}
            reports[label] = dict(transformation=proof, code_symbols_checked=len(code_names),
                                  code_addresses_match=True, data_symbols_checked=len(data_names),
                                  data_addresses_match=not data_differences, data_address_differences=data_differences,
                                  incomplete_data_control=bool(data_differences), consumer_sha256=sha(consumer))
            (self.evidence / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', target]))
            (self.evidence / (label + '-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', target]))
        self.write('layout-controls', dict(text_growth=text_growth, rodata_growth=rodata_growth,
                                          reports=reports, source_unchanged=True,
                                          claim='No timing conclusion until measured. Data isolation is qualified only where recorded addresses match.'))
