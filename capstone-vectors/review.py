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
    assert read(d / 'plan32-tested-source.json') == dict(tree=source['tree'], patch_sha256=source['sha256'])
    active='-clang-' in d.name
    assert set(read(d / 'object-isolation.json')['changed']) == ({'arch/X86/X86OutputIterator.c.o'} if active else set())
    assert read(d/'ordinary-text-proof.json')['passed']
    if not active:assert read(d/'binary-identity.json')['identical']
    assert read(d / 'object-isolation.json')['added'] == ['arch/X86/X86Vex32Output.c.o']
    assert read(d / 'vector-core-identity.json')['entire_disassembly_identical']
    assert read(d / 'consumer-object.json')['all_variants_identical']
    records = {name: (d / (name + '.log')).read_text().strip() for name in ('verify', 'private-guard', 'public-verify')}
    for name, count in [('verify', 56885248), ('private-guard', 3145734), ('public-verify', 69140480)]:
        assert str(count) in records[name], (name, records[name])
    for label in ('integer', 'plan32'):
        assert '100% tests passed' in (d / ('units-' + label + '.log')).read_text()
    symbols = {}
    for label in ('integer', 'plan32'):
        symbols[label] = [line for line in (d / (label + '-symbols.txt')).read_text().splitlines()
                          if any(n in line for n in ('writeVectorRegisters', 'writeEvexOutput', 'writeVexRegisterOutput'))]
    profiles.append(dict(host=d.name, records=records, writer_symbols=symbols, cleanup=read(d / 'cleanup.json'),lowering=read(d/'ordinary-text-proof.json'),linked_layout=read(d/'linked-layout.json'),binary=read(d/'binary-identity.json')))
    values = read(d / 'instruction-costs.json')
    assert len(values) == 24
    keys = sorted({(v['case'], v['mode']) for v in values})
    assert len(keys) == 12
    for case, mode in keys:
        pair = {v['variant']: v for v in values if v['case'] == case and v['mode'] == mode}
        assert set(pair) == {'integer', 'plan32'}
        assert pair['integer']['result'] == pair['plan32']['result']
        assert all(v['collected_traversals'] == 2 for v in pair.values())
        parsed = {label: scope['trace'](d / (case + '-' + str(mode) + '-' + label + '.callgrind.gz'), label)[0]
                  for label in pair}
        for label in pair:
            assert [sum(v[i] for v in parsed[label].values()) for i in range(3)] == [pair[label]['events'][k] for k in ('Ir','Dr','Dw')]
        changes = []
        for name in parsed['integer'].keys() | parsed['plan32'].keys():
            a, b = parsed['integer'].get(name, [0]*3), parsed['plan32'].get(name, [0]*3)
            delta = [b[i] - a[i] for i in range(3)]
            if any(delta): changes.append(dict(function=name, before=a, after=b, delta=delta))
        changes.sort(key=lambda x: -abs(x['delta'][0]))
        before, after = pair['integer']['events'], pair['plan32']['events']
        rows.append(dict(host=d.name, case=case, mode=mode, totals={k:v['events'] for k,v in pair.items()},
                         ir_change=after['Ir']-before['Ir'], instruction_reduction=1-after['Ir']/before['Ir'], changed_function_costs=changes))
assert len(profiles) == 4 and len(rows) == 48
report = dict(complete=True, run=run, source=source, profiles=profiles, rows=rows,
    instruction_increases=[x for x in rows if x['ir_change'] > 0], publication_qualified=False,
    parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
    scope='Original frozen consumer, two traversals of four real-library panels per compiler. Instruction counts and compiler inlining are diagnostic evidence, not native throughput.')
(r / 'profile-review.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case'] in ('libssl3t64-amd64','jpeg-avx2-i386') or row['instruction_reduction'] < -.001:
        print(row['host'],row['case'],row['mode'],'Ir reduction %.4f%%' % (row['instruction_reduction']*100))
