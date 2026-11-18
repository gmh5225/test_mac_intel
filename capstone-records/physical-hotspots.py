from collections import Counter, defaultdict
from pathlib import Path
import gzip
import hashlib
import json
import re

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
d, = (r / 'native').iterdir()
assert read(r / 'native-review.json')['complete']
pattern = re.compile(r'^\s*(\d+)\s+(\S+):\s+([0-9a-fA-F]+)\s+(.+)\s+\((.+)\)\s*$')
header = re.compile(r'^([0-9a-fA-F]+) <(.+)>:$')
instruction = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(.+)$')
offset = re.compile(r'^(.+)\+0x([0-9a-fA-F]+)$')
images = {}
for variant in ('base', 'dispatch', 'scan'):
    raw = gzip.open(d / (variant + '-linked-assembly.gz'), 'rt').read()
    symbols, addresses, code, owner = {}, [], {}, None
    for line in raw.splitlines():
        match = header.fullmatch(line)
        if match:
            start, name = int(match[1], 16), match[2]
            symbols.setdefault(name, []).append(start)
            addresses.append((start, name))
            owner = name
        match = instruction.fullmatch(line)
        if match:
            pc = int(match[1], 16)
            assert owner is not None and pc not in code
            code[pc] = dict(bytes=match[2], instruction=match[3], owner=owner)
    assert len(code) > 10000
    images[variant] = dict(symbols=symbols, code=code,
                           assembly_sha256=hashlib.sha256(raw.encode()).hexdigest())
images['aa'] = images['base']
histograms = defaultdict(Counter)
family = defaultdict(Counter)
unresolved = Counter()
relocations = {}
ownership_differences = Counter()
for row in read(d / 'sample-index.json'):
    image = images[row['variant']]
    raw = gzip.open(d / (row['key'] + '.samples.gz'), 'rt').read()
    assert hashlib.sha256(raw.encode()).hexdigest() == row['text_sha256']
    samples, biases = [], Counter()
    for line in raw.splitlines():
        if not line.strip() or line.startswith('#') or 'PERF_RECORD_LOST' in line:
            continue
        match = pattern.fullmatch(line)
        assert match, (row['key'], line)
        weight, event, ip, symbol, dso = match.groups()
        if not dso.endswith('/same-image'):
            continue
        samples.append((int(ip, 16), symbol.strip(), int(weight)))
        match = offset.fullmatch(symbol.strip())
        name, displacement = (match[1], int(match[2], 16)) if match else (symbol.strip(), 0)
        if name in image['symbols'] and len(image['symbols'][name]) == 1:
            biases[int(ip, 16) - image['symbols'][name][0] - displacement] += 1
    assert len(biases) == 1, (row['key'], biases)
    bias, = biases
    relocations[row['key']] = dict(load_bias=hex(bias), witnesses=sum(biases.values()))
    key = row['case'], row['mode'], row['event'], row['variant']
    for ip, reported, weight in samples:
        pc = ip - bias
        if pc not in image['code']:
            unresolved[row['key']] += 1
            continue
        site = image['code'][pc]
        match = offset.fullmatch(reported)
        reported_owner = match[1] if match else reported
        if site['owner'] != reported_owner:
            ownership_differences[(row['variant'], reported_owner, site['owner'])] += 1
        histograms[key][pc] += weight
        family[key][site['owner']] += weight

panels = []
for name, mode, event in sorted({key[:3] for key in histograms}):
    variants = {}
    for variant in ('base', 'aa', 'dispatch', 'scan'):
        code = images[variant]['code']
        rows = []
        for pc, weight in histograms[name, mode, event, variant].most_common(30):
            site = code[pc]
            rows.append(dict(pc=hex(pc), weight=weight, **site,
                             window=[dict(pc=hex(address), **code[address])
                                     for address in range(max(0, pc-16), pc+20, 4) if address in code]))
        variants[variant] = dict(family_weights=dict(family[name, mode, event, variant]), top_sites=rows)
    panels.append(dict(case=name, mode=mode, event=event, variants=variants))
report = dict(complete=True, source=read(r/'candidates.json'), panels=panels,
              relocations=relocations, unresolved_samples=dict(unresolved),
              ownership_differences=[dict(variant=v, reported=a, physical=b, samples=n)
                                     for (v, a, b), n in ownership_differences.items()],
              assembly_sha256={v: x['assembly_sha256'] for v, x in images.items()},
              exact_branch_attribution=False, production_modified=False,
              scope='Runtime PCs rebased using every unambiguous symbol-offset witness, then joined to exact linked AArch64 instructions. A sampled PC is where the event interrupt was observed; it is not necessarily the branch causing the miss. No sampled execution time is a qualification result.')
(r/'physical-hotspots.json').write_text(json.dumps(report, indent=2)+'\n')
print('panels', len(panels), 'unresolved', sum(unresolved.values()), 'ownership differences', sum(ownership_differences.values()))
for panel in panels:
    if panel['case'] == 'simd64' and panel['event'] == 'branch-misses:u':
        for variant, data in panel['variants'].items():
            print(variant)
            for row in data['top_sites'][:10]:
                print(row['pc'], row['owner'], row['instruction'], row['weight'])
