from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())
inputs, run = read(r / 'inputs.json'), read(r / 'native-run.json')
assert run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
assert run['status'] == 'completed' and run['conclusion'] == 'success'
def estimate(values, seed):
    rng = random.Random(seed)
    values = list(values)
    samples = sorted(st.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return dict(median=st.median(values), ci95=[samples[49], samples[1949]])
rows, profiles, flags = [], [], []
for d in sorted((r / 'native').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed']
    assert read(d / 'iced-source.json')['revision'] == inputs['iced_revision']
    assert read(d / 'memory-tested-source.json') == dict(
        tree=inputs['variants']['memory']['tree'], patch_sha256=inputs['variants']['memory']['sha256'])
    proof = read(d / 'memory-object-isolation.json')
    assert not proof['added'] and set(proof['changed']) <= {
        'arch/X86/X86OutputIterator.c.o','arch/X86/X86MemoryOutput.c.o','arch/X86/X86ImmediateOutput.c.o'}
    assert read(d / 'consumer-object.json')['all_variants_identical']
    controls = read(d / 'launch-controls.json')
    assert controls['launches'] == ['images','same-file-fixed']
    assert controls['original_sha256']['integer'] == controls['original_sha256']['aa']
    values = read(d / 'measurements.json')
    assert len(values) == read(d / 'complete.json')['cases'] == 42
    for row in values:
        cycles = row['cycles']
        assert len(cycles) == 20
        key = '/'.join(map(str,[d.name,row['case'],row['panel'],row['mode'],row['launch']]))
        relative = {label: estimate((c['ns']['integer']/c['ns'][label] for c in cycles), key+'/'+label)
                    for label in ('aa','memory')}
        assert all(relative[label]['median'] == row['gain'][label] for label in relative)
        comparisons = {engine: {label: estimate((c['ns'][engine]/c['ns'][label] for c in cycles), key+'/'+engine+'/'+label)
                      for label in ('integer','memory')} for engine in ('iced','fast') if engine in cycles[0]['ns']}
        item = dict(host=d.name,case=row['case'],panel=row['panel'],mode=row['mode'],launch=row['launch'],
                    gain=relative['memory']['median'],ci95=relative['memory']['ci95'],aa=relative['aa'],comparisons=comparisons)
        rows.append(item)
        if abs(item['aa']['median']-1) > .01:
            flags.append(item)
    profiles.append(dict(host=d.name,cpu=read(d/'cpu.json'),cleanup=read(d/'cleanup.json'),
                         iced=read(d/'iced-source.json'),objects=proof))
assert len(profiles) == 4 and len(rows) == 168
report = dict(complete=True,run=run,inputs=inputs,profiles=profiles,rows=rows,
              aa_outside_one_percent=flags,losses=[x for x in rows if x['gain']<.99],
              stable_losses=[x for x in rows if x['ci95'][1]<1],publication_qualified=False,
              scope='Frozen seven real-library panels and consumers; current forked iced built from source. All 20 paired cycles retained. Bootstrap intervals are descriptive without multiplicity correction. R1481 retains independent PE32, scalar/SIMD and other-ISA evidence; current NeverD product qualification remains separate.')
(r / 'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('comparisons',len(rows),'AA flags',len(flags),'losses',len(report['losses']),'stable losses',len(report['stable_losses']))
