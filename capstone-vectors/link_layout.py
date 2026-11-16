"""Diagnostic assertions for restoring old code and data positions."""
from collections import Counter, defaultdict
import gzip
import hashlib
import re
import struct


def symbols(path):
    result = defaultdict(list)
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 4:
            address, size, kind, name = fields
            if kind in 'tTwWrRdDbBvV':
                result[kind, name].append((int(address, 16), int(size, 16)))
    return {key: values[0] for key, values in result.items() if len(values) == 1}


def section_body(path, name):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    assert size == 64
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size)
               for i in range(count)]
    strings = headers[names]
    table = data[strings[4]:strings[4] + strings[5]]
    selected = [header for header in headers
                if table[header[0]:table.index(b'\0', header[0])].decode() == name]
    assert len(selected) == 1
    header = selected[0]
    assert header[1] == 1 and header[2] == 2  # PROGBITS, ALLOC, no WRITE/EXEC
    return data[header[4]:header[4] + header[5]]


def verify_positions(executables, evidence):
    maps = {label: symbols(evidence / (label + '-symbols.txt'))
            for label in ('integer', 'scan', 'pad0', 'both')}
    definitions = set(re.findall(r'^[0-9a-f]+ <([^>]+)>:',
        gzip.decompress((evidence / 'scan-X86OutputIterator.asm.gz').read_bytes()).decode(), re.M))
    counts, exceptions, failures = Counter(), [], []
    shifts = {label: defaultdict(Counter) for label in ('scan', 'pad0', 'both')}
    for key, before in maps['integer'].items():
        if not all(key in maps[label] for label in ('scan', 'pad0', 'both')):
            continue
        kind, name = key
        after = maps['both'][key]
        for label in shifts:
            shifts[label][kind][str(maps[label][key][0] - before[0])] += 1
        if after != before:
            row = dict(kind=kind, name=name, before=before,
                       candidate=maps['scan'][key], text_only=maps['pad0'][key], combined=after)
            if kind in 'tT' and name in definitions:
                exceptions.append(row)
            else:
                failures.append(row)
        else:
            counts[kind] += 1
    old = section_body(executables['pad0'], '.cs_x86_vex32_rodata')
    new = section_body(executables['both'], '.cs_x86_vex32_rodata')
    assert old == new
    result = dict(complete=not failures, restored_by_kind=dict(counts),
                  within_iterator_exceptions=exceptions, failures=failures,
                  shifts={label: {kind: dict(values) for kind, values in groups.items()}
                          for label, groups in shifts.items()},
                  readonly_section_bytes=len(new), readonly_section_sha256=hashlib.sha256(new).hexdigest(),
                  readonly_section_payload_unchanged=True,
                  scope='Diagnostic only; all original runtime object hashes are checked separately. No claim about CPU cache or branch prediction.')
    # Preserve a failed placement hypothesis before refusing the timing phase.
    import json
    (evidence / 'combined-placement-review.json').write_text(json.dumps(result, indent=2) + '\n')
    assert not failures, failures[:10]
    assert counts['t'] + counts['T'] > 4000
    assert sum(counts[kind] for kind in 'dDbBvV') > 240
    assert counts['r'] + counts['R'] > 1500
    return result
