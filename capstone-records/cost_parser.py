from collections import defaultdict
from pathlib import Path
import gzip
import hashlib
import json
import random
import re
import statistics

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())

def trace(path, variant):
    names, objects = {}, {}
    costs = defaultdict(lambda: [0, 0, 0])
    executed = defaultdict(int)
    positions = []
    function = owner = None
    call = False
    totals = None
    for raw in gzip.open(path, 'rt'):
        line = raw.strip()
        if line.startswith('positions: '):
            positions = [0] * (len(line.split()) - 1)
        elif line.startswith('totals: '):
            totals = list(map(int, line.split()[1:]))[:3]
        elif line.startswith(('fn=', 'cfn=')):
            m = re.fullmatch(r'c?fn=\((\d+)\)(?: (.*))?', line)
            assert m, line
            if m[2] is not None:
                names[m[1]] = m[2]
            if line.startswith('fn='):
                function = names[m[1]]
        elif line.startswith(('ob=', 'cob=')):
            m = re.fullmatch(r'c?ob=\((\d+)\)(?: (.*))?', line)
            assert m, line
            if m[2] is not None:
                objects[m[1]] = m[2]
            if line.startswith('ob='):
                owner = objects[m[1]]
        elif line.startswith('calls='):
            call = True
        elif line and line[0] in '+-*0123456789':
            fields = line.split()
            for i, token in enumerate(fields[:len(positions)]):
                if token == '*':
                    continue
                if token[0] in '+-':
                    positions[i] += int(token, 0)
                else:
                    positions[i] = int(token, 0)
            if not call and len(fields) > len(positions):
                counts = list(map(int, fields[len(positions):]))
                counts += [0] * (3 - len(counts))
                for i in range(3):
                    costs[function][i] += counts[i]
                if counts[0] and owner and owner.endswith('/' + variant):
                    executed[positions[0]] += counts[0]
            call = False
    costs = {name: value for name, value in costs.items() if any(value)}
    assert [sum(v[i] for v in costs.values()) for i in range(3)] == totals
    return costs, executed

def instructions(path):
    values = {}
    last = None
    owner = start = None
    occurrences = defaultdict(int)
    for line in gzip.open(path, 'rt'):
        header = re.match(r'^([0-9a-f]+) <(.+)>:', line)
        if header:
            start, owner = int(header[1], 16), header[2]
            occurrences[owner] += 1
            if occurrences[owner] > 1:
                owner += '#' + str(occurrences[owner])
        m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)(.*)$', line)
        if not m:
            continue
        address = int(m[1], 16)
        data = bytes.fromhex(m[2])
        asm = m[3].strip()
        if asm:
            values[address] = [data, asm, owner, start]
            last = address
        else:
            assert last is not None and last + len(values[last][0]) == address
            values[last][0] += data
    return values

def interval(values, seed):
    rng = random.Random(seed)
    points = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return [points[49], points[1949]]
