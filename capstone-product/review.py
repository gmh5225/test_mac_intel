from pathlib import Path
import json
import random
import statistics
import sys

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
inputs = read(r / 'product-check/inputs.json')
paths = list((r/'product').glob('*/complete.json'))
assert len(paths) == 1
path = paths[0]
d = path.parent
complete = read(path)
run=read(r/'product-run.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'product-check/revision.txt').read_text().strip()
assert complete['cases'] == 96
assert set(complete['variants']) == set(inputs['variants'])
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'cleanup.json')['removed']
assert not any(read(d / 'residual.json').values())
assert read(d / 'inputs.json') == inputs
assert read(d / 'avx32-corpus.json')['selected_instructions'] == 7764
probe=read(d / 'original-probe-equivalence.json')
assert probe['unchanged'] and len(probe['checks']) == 45
batch_probe=read(d/'batch-probe-equivalence.json')
assert batch_probe['unchanged'] and len(batch_probe['checks'])==11 and batch_probe['capacity']==64
controls = read(d / 'launch-controls.json')
assert controls['aslr_disable_returncode'] == 0
assert set(controls['launches']) == {'images', 'same-file-fixed'}
assert controls['original_sha256']['base'] == controls['original_sha256']['base-copy']
reference = read(d / 'llvm-baseline-identity.json')
managed = read(d / 'base-managed-source-identity.json')
states, test_summaries = {}, {}
for label in ['base', *inputs['variants']]:
    assert read(d / (label + '-llvm-identity.json')) == reference
    assert read(d / (label + '-managed-source-identity.json')) == managed
    log = (d / ('tests-' + label + '.log')).read_text()
    assert '100% tests passed' in log
    test_summaries[label] = [line for line in log.splitlines() if 'tests passed' in line]
    states[label] = read(d / (label + '-public-state.json'))
    if label != 'base':
        diff = read(d / ('record-difference-' + label + '.json'))
        assert diff['changed'] == 0 and diff['states'] > 0
        assert read(d / (label + '-source-tree.json'))['tree'] == inputs['variants'][label]['tree']

rows = read(d / 'timings.json')
assert len(rows) == 96
results = []
for x in rows:
    row = {k: x[k] for k in ['case', 'mode', 'launch', 'reps', 'signature']}
    if row['case']=='jpeg-avx2-i386':
        assert row['signature'][:2] == [7764*row['reps'],0]
    row['comparisons'] = {}
    for label, result in x['pairs'].items():
        values = [sum(v['ticks']['base']) / sum(v['ticks'][label]) for v in result['plans']]
        assert len(values) == inputs['timing_protocol']['cycles'] == 32
        assert statistics.median(values) == result['median']
        rng = random.Random('/'.join(map(str, [x['case'], x['mode'], x['launch'], label])))
        samples = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(2000))
        row['comparisons'][label] = dict(median=result['median'], ci95=[samples[49], samples[1949]])
    results.append(row)
losses = {label: [x for x in results if x['comparisons'][label]['median'] < .99]
          for label in inputs['variants']}
aa = [x for x in results if abs(x['comparisons']['base-copy']['median'] - 1) > .01]
report = dict(inputs=inputs, complete=True, run=run, source=read(d / 'sources.json'),
              llvm_identity=reference, managed_source_identity=managed,
              tests=test_summaries, states=states, rows=results, losses=losses,
              aa_outside_one_percent=aa, cleanup=read(d / 'cleanup.json'),
              raw=str(d.relative_to(r)), avx32_corpus=read(d / 'avx32-corpus.json'),
              original_probe_equivalence=probe, batch_probe_equivalence=batch_probe, publication_authorized_by_report=False,
              statistical_scope='2000 deterministic resamples of 32 interleaved balanced cycles; no outlier removal')
(r / 'product-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('records', len(results), 'aa outside 1%', len(aa))
for label, observations in losses.items():
    print(label, 'losses', len(observations))
    for x in observations:
        print(x['case'], x['mode'], x['launch'], x['comparisons'][label],
              'aa', x['comparisons']['base-copy']['median'])
