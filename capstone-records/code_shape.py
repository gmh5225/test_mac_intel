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
