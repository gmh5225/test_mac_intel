from pathlib import Path
import json

r = Path(__file__).resolve().parent
prior = r.parent / 'round1494-coalesced-operand-tags'
read = lambda p: json.loads(p.read_text())
normalize = lambda host: host.split('-four-')[1].rsplit('-', 1)[0]
old = {normalize(d.name): d for d in (prior / 'native').iterdir()}
rows = []
for d in sorted((r / 'native').iterdir()):
    host = normalize(d.name)
    a, b = read(old[host] / 'binaries.json'), read(d / 'binaries.json')
    rows.append(dict(host=host, previous_directory=old[host].name, current_directory=d.name,
                     binary_identical={v: a[v] == b[v] for v in ('base', 'scan')},
                     previous_sha256=a, current_sha256=b))
assert len(rows) == 4
costs = {}
for label, directory in (('previous', prior), ('current', r)):
    report = read(directory / 'cost-attribution.json')
    assert report['complete']
    costs[label] = {(normalize(x['host']), x['case'], x['mode']): x for x in report['rows']}
assert costs['previous'].keys() == costs['current'].keys()
deltas = []
for key, current in sorted(costs['current'].items()):
    previous = costs['previous'][key]
    deltas.append(dict(host=key[0], case=key[1], mode=key[2],
                       previous_ir_delta=previous['ir_delta'], current_ir_delta=current['ir_delta'],
                       difference=current['ir_delta']-previous['ir_delta']))
(r / 'predecessor-review.json').write_text(json.dumps(dict(
    complete=True, rows=rows, work_deltas=deltas,
    previous_source=read(prior / 'tree.json'), current_source=read(r / 'tree.json'),
    scope='Linked binary hashes and changes in per-run baseline-relative simulated work. Native timing samples from independent jobs are not pooled; binary identity does not imply identical hosts or timing.'), indent=2) + '\n')
for row in rows:
    print(row['host'], row['binary_identical'])
for row in deltas:
    if 'gcc' in row['host'] and row['case'] in ('arm-ls', 'putty-32-0.85', 'putty-64-0.85', 'scalar32'):
        print(row)
