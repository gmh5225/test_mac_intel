from pathlib import Path
import hashlib
import json
import random
import statistics

r = Path(__file__).resolve().parent
read = lambda path: json.loads(path.read_text())
meta = read(r / 'semantic-review.json')
assert hashlib.sha256((r / 'candidate.patch').read_bytes()).hexdigest() == meta['sha256']
runs = {label:read(r/(label+'-run.json')) for label in ['native','clang']}
assert runs['native']['head_sha'] == (r/'native-revision.txt').read_text().strip()
assert runs['native']['conclusion'] == 'failure'
assert runs['clang']['head_sha'] == (r/'clang-revision.txt').read_text().strip()
assert runs['clang']['conclusion'] == 'success'
parent = read(r/'input.json')


def interval(values, key):
    rng = random.Random(key)
    samples = sorted(statistics.median(rng.choices(values, k=len(values)))
                     for _ in range(2000))
    return [samples[49], samples[1949]]


rows, receipts = [], []
paths = sorted((r/'native').glob('*gcc*')) + sorted((r/'clang').glob('*clang*'))
assert len(paths) == 4
for d in paths:
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    cleanup = read(d / 'cleanup.json')
    assert cleanup['removed']
    assert read(d/'tested-source-scan.json') == dict(tree=meta['tree'],patch_sha256=meta['sha256'])
    assert read(d/'tested-source-plain.json') == dict(tree=parent['tree'],patch_sha256=parent['sha256'])
    controls = read(d / 'launch-controls.json')
    assert controls['aslr_disable_returncode'] == 0
    assert set(controls['launches']) == {'images', 'same-file-fixed'}
    hashes = controls['original_sha256']
    assert hashes['integer'] == hashes['aa'] != hashes['scan']
    isolation = read(d / 'object-isolation-scan.json')
    assert read(d/'writer-identity.json')['unchanged_existing_objects'] == 37
    assert read(d/'generator-proof-scan.json')['both_outputs_reproduced']
    assert read(d/'generator-proof-plain.json')['both_outputs_reproduced']
    assert set(isolation['changed']) == {'arch/X86/X86VectorOutput.c.o'}
    assert set(isolation['added']) == {'arch/X86/X86EvexMemoryOutput.c.o'}
    for label in ('integer','plain','scan'):
        assert '100% tests passed' in (d/('units-'+label+'.log')).read_text()
    assert read(d / 'consumer-object.json')['all_variants_identical']
    inputs = read(d / 'measurements.json')
    assert read(d / 'complete.json')['cases'] == len(inputs) == 42
    panels = {(case,panel): ['scan','format','detail']
              for case in ('libjpeg62-turbo-amd64','libzstd1-amd64','libssl3t64-amd64','jpeg-avx2-i386','libssl3t64-i386')
              for panel in (['all-functions','simd-functions'] if case in ('libjpeg62-turbo-amd64','libzstd1-amd64') else (['all-functions'] if case=='libssl3t64-i386' else ['simd-functions']))}
    expected = {(case,panel,mode,launch) for (case,panel),modes in panels.items()
                for mode in modes for launch in ('images','same-file-fixed')}
    assert {(x['case'],x['panel'],x['mode'],x['launch']) for x in inputs} == expected

    cpu = read(d/'cpu.json')
    model = next(l.split(':',1)[1].strip() for l in cpu['cpu'].splitlines() if l.startswith('model name'))
    receipts.append(dict(host=d.name, cpu=model, cleanup=cleanup, identity=read(d/'writer-identity.json')))
    for x in inputs:
        pairs = [{name: c['ns']['integer'] / c['ns'][name]
                  for name in ('scan', 'plain', 'aa')} for c in x['cycles']]
        assert len(pairs) == 21
        gains = {k: statistics.median(v[k] for v in pairs) for k in ('scan', 'plain', 'aa')}
        assert all(abs(gains[k] - x['gain'][k]) < 1e-12 for k in gains)
        key = '/'.join((d.name, x['case'], x['panel'], x['mode'], x['launch']))
        rows.append(dict(host=d.name, case=x['case'], panel=x['panel'],
                         mode=x['mode'], launch=x['launch'], cpu=model, gain=gains['scan'], plain=gains['plain'], aa=gains['aa'],
                         vs_plain=statistics.median(c['ns']['plain']/c['ns']['scan'] for c in x['cycles']),
                         ci95=interval([v['scan'] for v in pairs], key),
                         aa_ci95=interval([v['aa'] for v in pairs], key + '/aa'),
                         vs_iced=x['vs_iced'], vs_fast=x['vs_fast']))
assert len(receipts) == 4 and len(rows) == 168
losses = [x for x in rows if x['gain'] < .99]
aa = [x for x in rows if abs(x['aa'] - 1) > .01]
review = dict(candidate=meta, runs=runs, rows=rows, receipts=receipts,
              losses=losses, aa_outside_one_percent=aa, complete=True,
              native_qualified=False,
              scope='Matched plain and isolated output placement against baseline on GCC11/13 and Clang14/18, 7 frozen library panels, 3 modes and 2 launch controls; 21 balanced cycles. The corrected Clang identity checker resolves direct-call relocations. Original failed Clang attempts contain no native measurements.')
review['checksum_scope'] = 'Native timing compares instruction boundaries and selected output checksums. Complete Capstone records, error and cursor equality are verified separately against the baseline.'
(r / 'review.json').write_text(json.dumps(review, indent=2) + '\n')
print('rows', len(rows), 'losses', len(losses), 'aa outliers', len(aa))
for x in rows:
    if x['launch']=='same-file-fixed' and x['case']=='libssl3t64-amd64':
        print(x['host'], x['case'], x['panel'], round(x['gain'], 6), 'iced',round(x['vs_iced'],6),'aa',round(x['aa'],6))
