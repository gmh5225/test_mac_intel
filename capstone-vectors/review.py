from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
run = read(r / 'profile-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
def ci(values, key):
    rng = random.Random(key)
    samples = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return [samples[49], samples[1949]]
profiles, rows, costs = [], [], []
for d in sorted((r / 'profile').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed'] and read(d / 'complete.json')['cases'] == 12
    assert read(d / 'bypass-proof.json')['passed']
    assert read(d / 'consumer-object.json')['all_variants_identical']
    assert read(d / 'output-object-isolation.json')['proof']['passed']
    assert read(d / 'launch-controls.json')['launches'] == ['images','same-file-fixed']
    values = read(d / 'measurements.json')
    assert len(values) == 12
    for row in values:
        assert len(row['cycles']) == 60
        key = '/'.join(map(str, [d.name, row['case'], row['mode'], row['launch']]))
        comparisons = {}
        for label, numerator, denominator in [('aa','integer','aa'), ('candidate','integer','output'),
                ('bypass','integer','bypass'), ('selector','bypass','output')]:
            ratios = [v['ns'][numerator] / v['ns'][denominator] for v in row['cycles']]
            comparisons[label] = dict(gain=st.median(ratios), ci95=ci(ratios,key+'/'+label))
        rows.append(dict(profile=d.name, case=row['case'], mode=row['mode'], launch=row['launch'], comparisons=comparisons))
    counts = read(d / 'instruction-costs.json')
    assert len(counts) == 9
    for mode in (0,1,2):
        pair = {v['variant']:v for v in counts if v['mode'] == mode}
        assert set(pair) == {'integer','output','bypass'}
        assert len({tuple(v['result']) for v in pair.values()}) == 1
        costs.append(dict(profile=d.name,mode=mode,counts=pair))
    profiles.append(dict(profile=d.name,bypass=read(d/'bypass-proof.json'),cleanup=read(d/'cleanup.json')))
assert len(profiles) == 2 and len(rows) == 24
report = dict(complete=True,run=run,protocol=read(r/'protocol.json'),profiles=profiles,rows=rows,costs=costs,
    aa_flags=[v for v in rows if abs(v['comparisons']['aa']['gain']-1)>.01],
    native_qualification=False,publication_qualified=False,
    scope='Diagnostic within-image intervention; retain all original failures and both launch contexts. Native ratios do not identify a specific hardware cache mechanism.')
(r/'profile-review.json').write_text(json.dumps(report,indent=2)+'\n')
for row in rows:
    if row['case']=='libssl3t64-amd64':
        print(row['profile'],row['mode'],row['launch'],{k:round(v['gain'],5) for k,v in row['comparisons'].items()})
