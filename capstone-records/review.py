from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())
run = read(r / 'profile-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'profile-revision.txt').read_text().strip()
def interval(values, key):
    rng = random.Random(key)
    samples = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return [samples[49], samples[1949]]
rows, profiles = [], []
for d in sorted((r / 'profile').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed'] and read(d / 'complete.json')['cases'] == 2
    cross = read(d / 'crossover.json')
    assert cross['cycles'] == 96 and len(set(cross['inodes'])) == 3 and cross['aslr_disable_returncode'] == 0
    assert cross['source_payload_sha256']['base'] == cross['source_payload_sha256']['aa']
    layout = read(d / 'output-linked-layout.json')
    assert not layout['text']['changed'] and not layout['readonly']['changed']
    caller = read(d / 'output-caller-proof.json')
    assert caller['ordinary_text_bytes'] == 0 and all(x['unchanged_except_lookup_target'] for x in caller['callers'].values())
    expected = read(r / 'inputs.json')['variants']['output']
    assert read(d / 'output-tested-source.json') == dict(tree=expected['tree'], patch_sha256=expected['sha256'])
    values = read(d / 'timings.json')
    assert len(values) == 2
    for row in values:
        assert row['case'] == 'arm-cp' and row['mode'] == 0 and len(row['pairs']) == 96
        key = d.name + '/' + row['launch']
        stats = {}
        for label in ('aa', 'output'):
            ratios = [x[label] for x in row['pairs']]
            assert st.median(ratios) == row['median'][label]
            stats[label] = dict(gain=st.median(ratios), ci95=interval(ratios, key + '/' + label))
        rows.append(dict(profile=d.name, case=row['case'], mode=row['mode'], launch=row['launch'], comparisons=stats))
    profiles.append(dict(profile=d.name, crossover=cross, cleanup=read(d / 'cleanup.json')))
assert len(rows) == 4 and len(profiles) == 2
losses = [x for x in rows if x['comparisons']['output']['gain'] < .99]
uncertain = [x for x in rows if x['comparisons']['output']['ci95'][0] < .99]
aa = [x for x in rows if abs(x['comparisons']['aa']['gain'] - 1) > .01]
(r / 'profile-review.json').write_text(json.dumps(dict(complete=True, run=run, protocol=read(r / 'protocol.json'),
    rows=rows, profiles=profiles, losses=losses, uncertainty_below_threshold=uncertain,
    aa_outside_one_percent=aa, publication_qualified=False), indent=2) + '\n')
print('Four file-crossover observations:', len(losses), 'losses,', len(uncertain), 'uncertain,', len(aa), 'A/A flags')
for x in rows:
    print(x['profile'], x['launch'], x['comparisons'])
