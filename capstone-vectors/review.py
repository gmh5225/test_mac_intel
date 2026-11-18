from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())
run = read(r / 'profile-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'profile-revision.txt').read_text().strip()
d, = (r / 'profile').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
done = read(d / 'complete.json')
assert done['success'] and done['source'] == read(r / 'protocol.json')['source']
assert read(d / 'cleanup.json')['removed']
rows = read(d / 'census.json')
assert len(rows) == done['cases'] == 5
for row in rows:
    totals = {key: sum(x['count'] for x in row['counts'] if x['admission'] == key)
              for key in ('original', 'added', 'fallback')}
    row['admission_totals'] = totals
    row['residual_memory'] = sum(x['count'] for x in row['counts'] if x['admission'] == 'fallback' and x['operand'] == 'memory')
    print(row['case'], totals, 'residual memory', row['residual_memory'])
    print([(x['prefix'], x['operand'], x['mnemonic'], x['count']) for x in row['counts'] if x['admission'] == 'fallback'][:8])
(r / 'census-review.json').write_text(json.dumps(dict(complete=True, run=run, source=done['source'],
    rows=rows, comparisons=done['comparisons'], cleanup=read(d / 'cleanup.json'), scope=done['scope'],
    throughput_measured=False, publication_qualified=False), indent=2) + '\n')
