from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run, protocol = read(r / 'run.json'), read(r / 'protocol.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
profiles, rows, aa = [], [], []
def interval(values, key):
    rng = random.Random(key)
    samples = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return [samples[49], samples[1949]]
for d in sorted((r / 'results').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed']
    proof, done = read(d / 'geometry-proof.json'), read(d / 'complete.json')
    assert proof['matched'] == done['geometry_matched']
    source = read(d / 'output-tested-source.json')
    assert source['tree'] == protocol['source']['variants']['output']['tree']
    profiles.append(dict(profile=d.name, cpu=read(d / 'cpu.json'), proof=proof, complete=done,
                         cleanup=read(d / 'cleanup.json')))
    if not proof['matched']:
        assert not done['native_timing'] and done['cases'] == 0
        continue
    assert not proof['other_function_byte_mismatches'] and proof['data_symbols_match']
    controls = read(d / 'launch-controls.json')
    assert controls['launches'] == protocol['launches']
    values = read(d / 'timings.json')
    assert len(values) == done['cases'] == 10
    for value in values:
        assert len(value['pairs']) == 40
        key = '/'.join(map(str, (d.name, value['case'], value['mode'], value['launch'])))
        ratios = {label: [v[label] for v in value['pairs']] for label in ('aa', 'geometry', 'output')}
        ratios['output_vs_geometry'] = [v['output'] / v['geometry'] for v in value['pairs']]
        result = dict(profile=d.name, case=value['case'], mode=value['mode'], launch=value['launch'],
                      comparisons={label: dict(median=st.median(v), ci95=interval(v, key + '/' + label)) for label, v in ratios.items()})
        rows.append(result)
        if abs(result['comparisons']['aa']['median'] - 1) > .01:
            aa.append(result)
assert len(profiles) == 2
report = dict(complete=True, run=run, protocol=protocol, profiles=profiles, rows=rows,
    matched_profiles=sum(x['proof']['matched'] for x in profiles), aa_outside_one_percent=aa,
    publication_qualified=False, production_modified=False,
    scope='Synthetic placement controls retain baseline text. Matching is checked before timing; unmatched controls yield no speed inference. This does not repair or qualify the original formatter candidate.')
(r / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Matched placement controls:', report['matched_profiles'], 'rows:', len(rows), 'A/A flags:', len(aa))
for row in rows:
    if row['launch'] == 'same-file-fixed':
        print(row['profile'], row['case'], row['mode'], {k: round(v['median'], 5) for k, v in row['comparisons'].items()})
