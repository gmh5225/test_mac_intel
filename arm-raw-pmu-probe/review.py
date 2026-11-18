from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run = read(r / 'native-run.json')
assert run['status'] == 'completed' and run['conclusion'] == 'success'
assert run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
d, = (r / 'native').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'complete.json')['complete']
assert read(d / 'permissions.json')['restored'] and read(d / 'cleanup.json')['removed']
cap = read(d / 'capability.json')
assert len(cap['sampling']) == 2
if cap['raw_cpu_gate']:
    assert len(cap['raw']) == 8
usable = []
for group in sorted({row['group'] for row in cap['raw']}):
    rows = [row for row in cap['raw'] if row['group'] == group]
    assert len(rows) == 2
    if all(row['all_events_positive'] and all(v == 100.0 for v in row['running_percent'].values()) for row in rows):
        usable.append(group)
report = dict(complete=True, run=run, environment=read(d / 'environment.json'), capability=cap,
              observable_raw_groups=usable, sampling_events=[x['event'] for x in cap['sampling'] if x['available']],
              cleanup=read(d / 'cleanup.json'), production_modified=False, publication_qualified=False,
              scope='Capability checks only, not candidate-performance evidence. All unsupported and accepted-but-zero event records are retained.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('observable raw groups', usable, 'sampling events', report['sampling_events'])
for row in cap['raw']:
    print(row['group'], row['workload'], row['accepted'], row['counts'])
