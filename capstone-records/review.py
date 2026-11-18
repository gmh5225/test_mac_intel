from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run = read(r / 'native-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
inputs = read(r / 'inputs.json')
def estimate(values, key):
    rng = random.Random(key)
    sampled = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return dict(gain=st.median(values), ci95=[sampled[49], sampled[1949]])

rows, factors, profiles, costs, flags = [], [], [], [], []
for d in sorted((r / 'native').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed']
    controls = read(d / 'launch-controls.json')
    assert controls['launches'] == ['images', 'same-file-fixed'] and controls['aslr_disable_returncode'] == 0
    assert controls['original_sha256']['base'] == controls['original_sha256']['aa']
    source = inputs['variants']['candidate']
    assert read(d / 'candidate-tested-source.json') == dict(tree=source['tree'], patch_sha256=source['sha256'])
    proof = read(d / 'factorial-object-proof.json')
    for variant, member in [('iterator', 'X86Vex32Output.c.o'), ('leaf', 'X86OutputIterator.c.o')]:
        assert proof[variant]['changed_members'] == [member]
        assert proof[variant]['archive_member_order_identical']
        assert len(proof[variant]['before']) - 1 == proof[variant]['untouched_members']
    assert read(d / 'candidate-object-proof.json')['passed']
    observed = read(d / 'timings.json')
    assert len(observed) == read(d / 'complete.json')['cases'] == 18
    profiles.append(dict(host=d.name, cpu=read(d / 'cpu.json'), compiler=read(d / 'compiler.json'),
                         cleanup=read(d / 'cleanup.json'), pmu=read(d / 'pmu.json')))
    for case in observed:
        samples = case['pairs']
        assert len(samples) == 21
        key = '/'.join(map(str, [d.name, case['case'], case['mode'], case['launch']]))
        common = dict(host=d.name, case=case['case'], mode=case['mode'], launch=case['launch'])
        aa = estimate([x['aa'] for x in samples], key + '/aa')
        if abs(aa['gain'] - 1) > .01:
            flags.append(dict(**common, **aa))
        for variant in ('iterator', 'leaf', 'candidate'):
            values = [x[variant] for x in samples]
            assert st.median(values) == case['median'][variant]
            rows.append(dict(**common, variant=variant, aa=aa, **estimate(values, key + '/' + variant)))
        for effect, values in [
            ('leaf_given_iterator', [x['candidate']/x['iterator'] for x in samples]),
            ('iterator_given_leaf', [x['candidate']/x['leaf'] for x in samples]),
            ('interaction', [x['candidate']/(x['iterator']*x['leaf']) for x in samples])]:
            factors.append(dict(**common, effect=effect, **estimate(values, key + '/' + effect)))
    counted = read(d / 'instruction-costs.json')
    expected = {(case, mode, variant) for case, mode in [('arm-ls', 2), ('arm64-ls', 0), ('mips64el-ls', 2)]
                for variant in ('base', 'iterator', 'leaf', 'candidate')}
    assert len(counted) == len(expected) and {(x['case'], x['mode'], x['variant']) for x in counted} == expected
    assert all(x['traversals'] == 3 for x in counted)
    for case, mode in [('arm-ls', 2), ('arm64-ls', 0), ('mips64el-ls', 2)]:
        data = {x['variant']: x for x in counted if x['case'] == case and x['mode'] == mode}
        assert all(x['result'] == data['base']['result'] for x in data.values())
        costs.append(dict(host=d.name, case=case, mode=mode,
            events={k: x['events'] for k, x in data.items()},
            ir_delta={k: x['events']['Ir']-data['base']['events']['Ir'] for k, x in data.items()}))
assert len(profiles) == 2 and len(rows) == 108
report = dict(complete=True, run=run, inputs=inputs, profiles=profiles, rows=rows, factors=factors, costs=costs,
    losses=[x for x in rows if x['gain'] < .99], stable_losses=[x for x in rows if x['ci95'][1] < 1],
    aa_outside_one_percent=flags, publication_qualified=False,
    policy='Frozen-object diagnostic, not source qualification. Every predeclared sample retained. Bootstrap intervals are descriptive, without multiplicity correction. Model differences and unavailable PMU counters remain explicit.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('factorial comparisons', len(rows), 'A/A flags', len(flags), 'losses', len(report['losses']))
for item in profiles:
    print(item['host'], item['cpu'], 'PMU supported', item['pmu']['supported'])
for row in costs:
    print(row['host'], row['case'], 'Ir deltas', row['ir_delta'])
