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
                if counts[0] and owner and owner.endswith('/run-' + variant):
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

run = read(r / 'diagnostic-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
rows, native, receipts = [], [], []
for d in sorted((r / 'diagnostic').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed']
    assert read(d / 'cost-protocol.json')['consumer_unchanged']
    meta = read(r / 'tree.json')
    assert read(d / 'tested-source.json') == dict(tree=meta['tree'], patch_sha256=meta['sha256'])
    assert read(d / 'complete.json')['cases'] == 12
    assembly = {v: instructions(d / (v + '-linked-disassembly.gz')) for v in ('integer', 'scan')}
    costs = read(d / 'instruction-costs.json')
    cpu = read(d / 'cpu.json')
    model = next(line.split(':', 1)[1].strip() for line in cpu['cpu'].splitlines() if line.startswith('model name'))
    receipts.append(dict(host=d.name, cpu=model, cleanup=read(d / 'cleanup.json')))
    for mode in (0, 1, 2):
        variants = {v['variant']: v for v in costs if v['mode'] == mode}
        assert set(variants) == {'integer', 'scan'}
        assert variants['integer']['result'] == variants['scan']['result']
        parsed = {v: trace(d / f'{v}-{mode}.callgrind.gz', v) for v in variants}
        functions = {}
        for name in parsed['integer'][0].keys() | parsed['scan'][0].keys():
            delta = [parsed['scan'][0].get(name, [0]*3)[i] - parsed['integer'][0].get(name, [0]*3)[i] for i in range(3)]
            if any(delta):
                functions[name] = delta
        total = {key: [row['events'][v] for v in ('Ir', 'Dr', 'Dw')] for key, row in variants.items()}
        for key in variants:
            assert [sum(x[i] for x in parsed[key][0].values()) for i in range(3)] == total[key]
        code = None
        if mode == 0:
            assert not functions and total['integer'] == total['scan']
            before, after = parsed['integer'][1], parsed['scan'][1]
            missing = {v: [ip for ip in parsed[v][1] if ip not in assembly[v]] for v in variants}
            assert not any(missing.values()), missing
            def relative(variant):
                result = {}
                for ip, count in parsed[variant][1].items():
                    data, asm, name, start = assembly[variant][ip]
                    key = (name, ip-start)
                    assert key not in result, (variant, key, result[key], hex(ip))
                    result[key] = dict(ip=ip, count=count, data=data, asm=asm, start=start)
                return result
            mapped = {v: relative(v) for v in variants}
            assert {k:v['count'] for k,v in mapped['integer'].items()} == {k:v['count'] for k,v in mapped['scan'].items()}
            changed, moved = [], {}
            for key, old in mapped['integer'].items():
                new = mapped['scan'][key]
                name, offset = key
                if old['ip'] != new['ip']:
                    entry = moved.setdefault(name, dict(old_address=hex(old['start']), new_address=hex(new['start']),
                                 address_delta=new['start']-old['start'], executed_positions=0, dynamic_instructions=0))
                    entry['executed_positions'] += 1
                    entry['dynamic_instructions'] += old['count']
                if old['data'] != new['data']:
                    changed.append(dict(function=name, offset=hex(offset), old_address=hex(old['ip']), new_address=hex(new['ip']),
                                        count=old['count'], old=old['asm'], new=new['asm']))
            code = dict(executed_instruction_addresses=len(before), relative_instruction_counts_identical=True,
                        moved_functions=moved, changed_executed_instructions=changed,
                        scope='Function-relative execution counts are identical. Absolute addresses and resolved instruction bytes may change with linking; differences are reported, not masked. Shared-library self Ir/Dr/Dw counts match but library bytes are not captured.')
        rows.append(dict(host=d.name, cpu=model, mode=mode, collected_traversals=2,
                         decoded_per_traversal=variants['integer']['result'][0], totals=total,
                         instruction_reduction=1-total['scan'][0]/total['integer'][0],
                         changed_function_costs=functions, raw_code=code))
        print(d.name, mode, 'Ir reduction', round(1-total['scan'][0]/total['integer'][0], 6),
              'changed executed raw instructions', len(code['changed_executed_instructions']) if code else '-')
    for x in read(d / 'measurements.json'):
        assert len(x['cycles']) == 31
        gain = [v['ns']['integer']/v['ns']['scan'] for v in x['cycles']]
        aa = [v['ns']['integer']/v['ns']['aa'] for v in x['cycles']]
        assert statistics.median(gain) == x['gain']['scan']
        key = '/'.join((d.name, x['case'], x['mode'], x['launch']))
        native.append(dict(host=d.name, cpu=model, case=x['case'], mode=x['mode'], launch=x['launch'],
                           gain=x['gain']['scan'], aa=x['gain']['aa'], ci95=interval(gain,key), aa_ci95=interval(aa,key+'/aa')))
assert len(rows) == 9 and len(native) == 36 and len(receipts) == 3
report = dict(complete=True, run=run, source=read(r/'tree.json'), rows=rows, native=native, receipts=receipts,
              losses=[v for v in native if v['gain'] < .99], aa_outside_one_percent=[v for v in native if abs(v['aa']-1) > .01],
              native_qualified=False,
              limits='Callgrind confirms executed instruction/read/write work. Native hardware-cache, predictor or timing causality is not established by simulated counters. Native timing and counts are kept distinct.')
(r / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
