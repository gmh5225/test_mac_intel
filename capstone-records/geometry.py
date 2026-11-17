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


def symbols(path):
    result = defaultdict(list)
    for line in sp.check_output(['nm', '-n', '-S', '--defined-only', path], text=True).splitlines():
        m = re.match(r'^([0-9a-f]+) ([0-9a-f]+) (\w) (.*)$', line)
        if m:
            result[m[4]].append([int(m[1], 16), int(m[2], 16), m[3]])
    return result


class Geometry:
    def __init__(self, evidence):
        self.evidence = evidence
        self.shapes, self.constants, self.symbols = {}, {}, {}
        self.backend_symbols = set()

    def capture(self, label, build, binary):
        root = build / 'CMakeFiles/capstone.dir'
        path = root / 'arch/X86/X86VectorOutput.c.o'
        data, _, sections, names = elf(path)
        self.shapes[label] = {name: dict(size=section[5], alignment=section[8])
                              for name, section in zip(names, sections)
                              if name == '.text' or name.startswith('.rodata')}
        self.constants[label] = {name: hashlib.sha256(data[section[4]:section[4] + section[5]]).hexdigest()
                                 for name, section in zip(names, sections)
                                 if name.startswith('.rodata')}
        self.symbols[label] = symbols(binary)
        (self.evidence / (label + '-vector-assembly.txt')).write_bytes(
            sp.check_output(['objdump', '-dr', path]))
        if label == 'base':
            for arch in ('ARM', 'AArch64', 'Mips'):
                for obj in (root / 'arch' / arch).glob('*.o'):
                    self.backend_symbols.update(symbols(obj))

    def finish(self):
        assert self.constants['base'] == self.constants['scan']
        baseline = self.symbols['base']
        shifts = {}
        for label in ('packed','scan'):
            current = self.symbols[label]
            common = {name for name in self.backend_symbols if name in baseline and name in current
                      and len(baseline[name]) == len(current[name]) == 1}
            assert len(common) > 100
            categories = {}
            for kind in ('t', 'r'):
                entries = {name: current[name][0][0] - baseline[name][0][0]
                           for name in common if baseline[name][0][2].lower() == kind}
                assert entries
                assert all(current[name][0][1:] == baseline[name][0][1:] for name in entries)
                categories[kind] = dict(symbols=len(entries), shifts=sorted(set(entries.values())),
                                         by_delta={str(delta): sorted(name for name, value in entries.items() if value == delta)
                                                   for delta in sorted(set(entries.values()))})
            shifts[label] = categories
        result = dict(original_vector_constants_identical=True, constant_sha256=self.constants,
                      vector_object_shapes=self.shapes, backend_address_shifts=shifts,
                      source_variants=['base', 'packed', 'scan'])
        (self.evidence / 'geometry.json').write_text(json.dumps(result, indent=2) + '\n')
