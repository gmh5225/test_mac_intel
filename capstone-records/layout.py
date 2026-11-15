"""Diagnostic code placement control; never a Capstone release transformation."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import math
import platform
import random
import re
import statistics
import struct
import subprocess as sp

SECTION = '.text.cs_tied_op_access'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def symbols(path):
    records = []
    for line in sp.check_output(['nm', '-S', '--defined-only', path], text=True).splitlines():
        parts = line.split()
        if len(parts) == 4:
            address, size, kind, name = parts
        elif len(parts) == 3:
            address, kind, name = parts
            size = '0'
        else:
            raise ValueError(line)
        records.append((int(address, 16), int(size, 16), kind, name))
    return records


def section_bytes(path, selected):
    data = path.read_bytes()
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    assert header[0][:6] == b'\x7fELF\x02\x01' and header[2] == 62
    assert header[11] == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + 64 * i)
                for i in range(header[12])]
    strings = sections[header[13]]
    names = data[strings[4]:strings[4] + strings[5]]
    for section in sections:
        end = names.index(b'\0', section[0])
        name = names[section[0]:end].decode()
        if name == selected:
            assert section[1] == 1
            return data[section[4]:section[4] + section[5]]
    raise ValueError((path, selected))


def freeze_objects(root, archive, linkmap, directory):
    directory.mkdir()
    objects = {obj.name: obj for obj in root.rglob('*.o')}
    assert len(objects) == len(list(root.rglob('*.o')))
    names = list(dict.fromkeys(re.findall(re.escape(str(archive)) + r'\(([^)]+)\)', linkmap.read_text())))
    assert names and set(names) <= set(objects)
    for name in names:
        target = directory / name
        target.write_bytes(objects[name].read_bytes())
    return [directory / name for name in names]


def pad(source, target, capacity, work):
    raw = section_bytes(source, SECTION)
    assert capacity >= len(raw)
    payload = work / 'section.bin'
    payload.write_bytes(raw + b'\x90' * (capacity - len(raw)))
    sp.run(['objcopy', '--update-section', SECTION + '=' + str(payload),
            '--set-section-alignment', SECTION + '=64', source, target], check=True)
    assert section_bytes(target, SECTION) == payload.read_bytes()
    assert symbols(source) == symbols(target)
    return dict(source=sha(source), target=sha(target), before=len(raw), after=capacity,
                original_instructions_preserved=True, original_symbols_preserved=True)


def compare_addresses(a, b):
    left, right = symbols(a), symbols(b)
    counts = Counter(x[3] for x in left)
    other_counts = Counter(x[3] for x in right)
    assert counts == other_counts
    unique = {name for name, n in counts.items() if n == 1 and name != 'mapping_get_op_access'}
    aa = {name: [address, size, kind] for address, size, kind, name in left if name in unique}
    bb = {name: [address, size, kind] for address, size, kind, name in right if name in unique}
    differences = {name: dict(integer=aa[name], scan=bb[name]) for name in aa if aa[name] != bb[name]}
    return dict(unique_symbols_checked=len(unique), differences=differences,
                all_common_addresses_equal=not differences)


def measure(work, bins, cases, save):
    payload = {layout: {variant: path.read_bytes() for variant, path in pair.items()}
               for layout, pair in bins.items()}
    size = max(len(data) for pair in payload.values() for data in pair.values())
    for pair in payload.values():
        for key in pair:
            pair[key] += bytes(size - len(pair[key]))
        pair['aa'] = pair['integer']
    image = work / 'same-image'
    image.write_bytes(payload['original']['integer'])
    image.chmod(0o755)
    inode = image.stat().st_ino
    sp.run(['setarch', platform.machine(), '-R', '/bin/true'], check=True)
    save('launch-controls.json', dict(size=size, inode=inode, aslr_disabled=True,
        hashes={layout: {key: hashlib.sha256(data).hexdigest() for key, data in pair.items()}
                for layout, pair in payload.items()}, cycles=21, retained_original_layout=True))
    rows = []
    for case in cases:
        for mode in range(3):
            def sample(layout, variant, repeats):
                with image.open('r+b') as out:
                    assert out.write(payload[layout][variant]) == size
                assert image.stat().st_ino == inode and image.stat().st_size == size
                command = ['setarch', platform.machine(), '-R', image,
                           str(case['selector']), str(mode), case['path'], str(repeats)]
                return json.loads(sp.check_output(command, text=True))
            probe = sample('original', 'integer', 2)
            repeats = max(2, min(4000, math.ceil(2 * 120e6 / probe['cpu_ns'])))
            cycles = {layout: [] for layout in payload}
            rng = random.Random(case['name'] + str(mode))
            signature = None
            for cycle in range(21):
                order = [(layout, variant) for layout in payload for variant in ('integer', 'aa', 'scan')]
                rng.shuffle(order)
                observed = [(layout, variant, sample(layout, variant, repeats))
                            for layout, variant in order + order[::-1]]
                for layout, variant, result in observed:
                    current = (result['first'], result['result'])
                    if signature is None:
                        signature = current
                    assert current == signature, (case, mode, layout, variant)
                for layout in payload:
                    times = {variant: statistics.mean(result['cpu_ns'] for lay, var, result in observed
                                                      if lay == layout and var == variant)
                             for variant in ('integer', 'aa', 'scan')}
                    cycles[layout].append(dict(ns=times,
                        gain=times['integer'] / times['scan'], aa=times['integer'] / times['aa'],
                        raw=[(variant, result) for lay, variant, result in observed if lay == layout]))
            for layout in payload:
                observations = cycles[layout]
                rows.append(dict(case=case['name'], mode=mode, layout=layout, cycles=observations,
                                 gain=statistics.median(c['gain'] for c in observations),
                                 aa=statistics.median(c['aa'] for c in observations), repetitions=repeats))
            save('measurements.json', rows)
            print(case['name'], mode, flush=True)
    return rows
