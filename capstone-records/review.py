from collections import defaultdict
from pathlib import Path
import gzip
import hashlib
import json
import random
import re
import statistics as st

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run = read(r / 'native-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
d, = (r / 'native').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'complete.json')['source'] == read(r / 'candidates.json')
assert read(d / 'cleanup.json')['removed'] and read(d / 'pmu.json')['setting_restored']
control = read(d / 'launch-controls.json')
assert control['original_sha256']['base'] == control['original_sha256']['aa']
protocol = read(d / 'protocol.json')
variants = protocol['variants']
expected = {tuple(x) for x in protocol['cases']}
assert len(expected) == 3 and variants == ['base', 'aa', 'dispatch', 'scan']
references = {}


def check(row, cycles):
    key = row['case'], row['mode']
    assert key in expected and 0 <= row['cycle'] < cycles
    seq = variants[row['cycle'] % 4:] + variants[:row['cycle'] % 4]
    assert row['variant'] == (seq + seq[::-1])[row['position']]
    value = row['consumer']['first'], row['consumer']['result']
    references.setdefault(key, value)
    assert references[key] == value and row['consumer']['repeats'] >= 20


def estimate(values, seed):
    rng = random.Random(seed)
    points = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return dict(median=st.median(values), ci95=[points[49], points[1949]])


records = read(d / 'counter-samples.json')
assert len(records) == 960
assert {(x['group'], x['case'], x['mode'], x['cycle'], x['position']) for x in records} == {
    (group, name, mode, cycle, position) for group in protocol['counter_groups']
    for name, mode in expected for cycle in range(20) for position in range(8)}
totals = defaultdict(lambda: defaultdict(int))
running = defaultdict(list)
for row in records:
    check(row, 20)
    for event, value in row['counters']['counts'].items():
        totals[row['case'], row['mode'], event, row['cycle']][row['variant']] += value
        running[event].append(row['counters']['running_percent'][event])
hardware = []
for name, mode, event in sorted({(n, m, e) for n, m, e, _ in totals}):
    for variant in variants[1:]:
        pairs = [totals[name, mode, event, c] for c in range(20)]
        assert all(x['base'] for x in pairs)
        seed = str((name, mode, event, variant))
        hardware.append(dict(case=name, mode=mode, event=event, variant=variant,
                             cost_ratio=estimate([x[variant] / x['base'] for x in pairs], seed),
                             delta=estimate([x[variant] - x['base'] for x in pairs], seed + '/delta'),
                             running_percent_range=[min(running[event]), max(running[event])]))

index = read(d / 'sample-index.json')
assert len(index) == 192
assert {(x['case'], x['mode'], x['event'], x['cycle'], x['position']) for x in index} == {
    (name, mode, event, cycle, position) for name, mode in expected for event, _ in protocol['events']
    for cycle in range(4) for position in range(8)}
histograms = defaultdict(lambda: defaultdict(int))
sample_counts = defaultdict(int)
losses = []
pattern = re.compile(r'^\s*(\d+)\s+(\S+):\s+([0-9a-fA-F]+)\s+(.+)\s+\((.+)\)\s*$')
for row in index:
    check(row, 4)
    raw = gzip.open(d / (row['key'] + '.samples.gz'), 'rt').read()
    assert hashlib.sha256(raw.encode()).hexdigest() == row['text_sha256']
    lost = [line for line in raw.splitlines() if 'PERF_RECORD_LOST' in line]
    assert lost == row['lost_records']
    if lost:
        losses.append(dict(key=row['key'], records=lost))
    key = row['case'], row['mode'], row['event'], row['variant']
    for line in raw.splitlines():
        if not line.strip() or line.startswith('#') or 'PERF_RECORD_LOST' in line:
            continue
        match = pattern.fullmatch(line)
        assert match, (row['key'], line)
        weight, event, ip, symbol, dso = match.groups()
        assert event == row['event'] and int(weight) > 0
        family = re.sub(r'\+0x[0-9a-fA-F]+$', '', symbol.strip())
        owner = 'image' if dso.endswith('/same-image') else Path(dso).name
        histograms[key][owner + ':' + family] += int(weight)
        sample_counts[key] += 1
sampled = []
for name, mode in sorted(expected):
    for event, _ in protocol['events']:
        values = {v: dict(histograms[name, mode, event, v]) for v in variants}
        counts = {v: sample_counts[name, mode, event, v] for v in variants}
        assert all(counts.values())
        changes = {}
        for v in variants[1:]:
            changes[v] = sorted([
                dict(symbol=k, baseline=values['base'].get(k, 0), candidate=values[v].get(k, 0),
                     delta=values[v].get(k, 0)-values['base'].get(k, 0))
                for k in values['base'].keys() | values[v].keys()], key=lambda x: abs(x['delta']), reverse=True)
        sampled.append(dict(case=name, mode=mode, event=event, sample_counts=counts, values=values, changes=changes))

report = dict(complete=True, run=run, source=read(r / 'candidates.json'), environment=read(d / 'environment.json'),
              hardware=hardware, sampled=sampled, lost_records=losses, protocol=protocol,
              cleanup=read(d / 'cleanup.json'), publication_qualified=False, production_modified=False,
              scope='Sampled symbol families with raw PCs and full sample text preserved. Sampling skid prevents exact faulting-branch attribution; raw counter groups are separate whole-process launches. Sampled execution times are not native performance qualification. Counter bootstrap intervals are descriptive and unadjusted; sample-weight changes are descriptive without confidence intervals.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('complete', len(hardware), 'counter comparisons', len(sampled), 'sample panels', len(losses), 'loss records')
for row in hardware:
    if row['variant'] == 'scan':
        print('counter', row['case'], row['mode'], row['event'], row['cost_ratio'])
for row in sampled:
    print('samples', row['case'], row['mode'], row['event'], row['sample_counts'])
    print('largest tagged changes', row['changes']['scan'][:5])
