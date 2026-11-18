from collections import defaultdict
from pathlib import Path
import json
import random
import statistics

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
run = read(r / 'native-run.json')
assert run['status'] == 'completed' and run['conclusion'] == 'success'
assert run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
d, = (r / 'native').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'complete.json')['source'] == read(r / 'candidates.json')
assert read(d / 'cleanup.json')['removed'] and read(d / 'consumer.json')['shared_by_all_variants']
control = read(d / 'launch-controls.json')
assert control['aslr_disable_returncode'] == 0
assert control['original_sha256']['base'] == control['original_sha256']['aa']
protocol = read(d / 'protocol.json')
expected = {(name, mode) for name, mode in protocol['cases']}
assert len(expected) == 7


def estimate(values, seed):
    randomizer = random.Random(seed)
    points = sorted(statistics.median(randomizer.choices(values, k=len(values))) for _ in range(2000))
    return dict(median=statistics.median(values), ci95=[points[49], points[1949]])


timings = read(d / 'timings.json')
assert len(timings) == 14
assert {(x['case'], x['mode'], x['launch']) for x in timings} == {
    (name, mode, launch) for name, mode in expected for launch in ('images', 'same-file-fixed')}
native = []
for row in timings:
    assert len(row['pairs']) == 21 and row['repeats'] >= 20
    for variant in ('aa', 'dispatch', 'scan'):
        stats = estimate([x[variant] for x in row['pairs']], str((row['case'], row['mode'], row['launch'], variant)))
        assert stats['median'] == row['median'][variant]
        native.append(dict(case=row['case'], mode=row['mode'], launch=row['launch'], variant=variant, **stats))

pmu = read(d / 'pmu.json')
assert pmu['setting_restored']
supported = {group for group, state in pmu['groups'].items() if state['supported']}
records = read(d / 'pmu-samples.json') if supported else []
assert len(records) == len(supported) * 1120 == pmu['samples']
assert {(x['group'], x['case'], x['mode'], x['cycle'], x['position']) for x in records} == {
    (group, name, mode, cycle, position) for group in supported for name, mode in expected
    for cycle in range(20) for position in range(8)}
reference = {}
totals = defaultdict(lambda: defaultdict(int))
running = defaultdict(list)
variants = ['base', 'aa', 'dispatch', 'scan']
for row in records:
    case = (row['case'], row['mode'])
    value = (row['consumer']['first'], row['consumer']['result'])
    reference.setdefault(case, value)
    assert reference[case] == value
    sequence = variants[row['cycle'] % 4:] + variants[:row['cycle'] % 4]
    assert row['variant'] == (sequence + sequence[::-1])[row['position']]
    for event, count in row['counters']['counts'].items():
        key = (row['group'], *case, row['cycle'], event)
        totals[key][row['variant']] += count
        running[row['group'], event].append(row['counters']['running_percent'][event])

hardware = []
for group, name, mode, event in sorted({(g, n, m, event) for g, n, m, _, event in totals}):
    for variant in ('aa', 'dispatch', 'scan'):
        values = [totals[group, name, mode, cycle, event] for cycle in range(20)]
        ratios = ([x[variant] / x['base'] for x in values] if all(x['base'] for x in values) else None)
        deltas = [x[variant] - x['base'] for x in values]
        seed = str((group, name, mode, event, variant))
        hardware.append(dict(group=group, case=name, mode=mode, event=event, variant=variant,
                             cost_ratio=estimate(ratios, seed + '/ratio') if ratios is not None else None,
                             absolute_delta=estimate(deltas, seed + '/delta'),
                             zero_baseline_pairs=sum(x['base'] == 0 for x in values),
                             running_percent_range=[min(running[group, event]), max(running[group, event])]))

report = dict(complete=True, run=run, source=read(r / 'candidates.json'),
              host=read(d / 'environment.json'), protocol=protocol, native=native, hardware=hardware,
              pmu=pmu, cleanup=read(d / 'cleanup.json'), publication_qualified=False,
              scope='Native ratios are baseline/candidate throughput. Hardware ratios are candidate/baseline '
                    'whole-process counts; they include unchanged setup and printing. Paired bootstrap '
                    'intervals are descriptive and unadjusted. Unsupported events and zero denominators '
                    'remain explicit; simulated instruction counts are separate evidence.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Native comparisons', len(native), 'hardware comparisons', len(hardware), 'supported groups', sorted(supported))
for row in native:
    if row['variant'] == 'scan' and row['launch'] == 'same-file-fixed':
        print('native', row['case'], row['mode'], row['median'], row['ci95'])
for row in hardware:
    if row['variant'] == 'scan' and row['case'] in ('simd64', 'arm64-ls'):
        print('hardware', row['case'], row['mode'], row['event'], row['cost_ratio'])
