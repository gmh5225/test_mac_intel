from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run, source = read(r / 'profile-run.json'), read(r / 'tree.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'profile-revision.txt').read_text().strip()
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text()
scope = {'__file__': str(parser)}
exec(code[:code.index('rows=[]')], scope)
profiles, rows = [], []
for d in sorted((r / 'profile').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    assert read(d / 'cleanup.json')['removed']
    assert read(d / 'complete.json')['traces'] == 24
    assert read(d / 'deferred-tested-source.json') == dict(tree=source['tree'], patch_sha256=source['sha256'])
    assert set(read(d / 'object-isolation.json')['changed']) == {'arch/X86/X86EvexScan.c.o','arch/X86/X86DisassemblerDecoder.c.o'}
    assert read(d / 'consumer-object.json')['all_variants_identical']
    records = {name: (d / (name + '.log')).read_text().strip() for name in ('records', 'owned', 'guard')}
    for name, count in [('records', 6946816), ('owned', 6946816), ('guard', 3145728)]:
        assert str(count) in records[name], (name, records[name])
    for label in ('integer', 'deferred'):
        assert '100% tests passed' in (d / ('units-' + label + '.log')).read_text()
    symbols = {}
    for label in ('integer', 'deferred'):
        symbols[label] = [line for line in (d / (label + '-symbols.txt')).read_text().splitlines()
                          if any(n in line for n in ('decodeEvexRegisterScan', 'X86_decodeScanFeatureExtension', 'decodeScanResultFallback', 'decodeScanResultGeneric'))]
    profiles.append(dict(host=d.name, records=records, scan_symbols=symbols, cleanup=read(d / 'cleanup.json')))
    values = read(d / 'instruction-costs.json')
    assert len(values) == 24
    keys = sorted({(v['case'], v['mode']) for v in values})
    assert len(keys) == 12
    for case, mode in keys:
        pair = {v['variant']: v for v in values if v['case'] == case and v['mode'] == mode}
        assert set(pair) == {'integer', 'deferred'}
        assert pair['integer']['result'] == pair['deferred']['result']
        assert all(v['collected_traversals'] == 2 for v in pair.values())
        parsed = {label: scope['trace'](d / (case + '-' + str(mode) + '-' + label + '.callgrind.gz'), label)[0]
                  for label in pair}
        for label in pair:
            assert [sum(v[i] for v in parsed[label].values()) for i in range(3)] == [pair[label]['events'][k] for k in ('Ir','Dr','Dw')]
        changes = []
        for name in parsed['integer'].keys() | parsed['deferred'].keys():
            a, b = parsed['integer'].get(name, [0]*3), parsed['deferred'].get(name, [0]*3)
            delta = [b[i] - a[i] for i in range(3)]
            if any(delta): changes.append(dict(function=name, before=a, after=b, delta=delta))
        changes.sort(key=lambda x: -abs(x['delta'][0]))
        before, after = pair['integer']['events'], pair['deferred']['events']
        rows.append(dict(host=d.name, case=case, mode=mode, totals={k:v['events'] for k,v in pair.items()},
                         ir_change=after['Ir']-before['Ir'], instruction_reduction=1-after['Ir']/before['Ir'], changed_function_costs=changes))
assert len(profiles) == 4 and len(rows) == 48
report = dict(complete=True, run=run, source=source, profiles=profiles, rows=rows,
    instruction_increases=[x for x in rows if x['ir_change'] > 0], publication_qualified=False,
    parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
    scope='Original frozen consumer, two traversals of four real-library panels per compiler. Instruction counts and scan construction are diagnostic evidence, not native throughput.')
(r / 'profile-review.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case']=='libssl3t64-amd64' or row['instruction_reduction'] < -.001:
        print(row['host'],row['case'],row['mode'],'Ir reduction %.4f%%' % (row['instruction_reduction']*100))
