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
    assert read(d / 'complete.json')['traces'] == 30
    assert read(d / 'tested-source.json') == dict(tree=source['tree'], patch_sha256=source['sha256'])
    proof = read(d / 'object-isolation.json')
    assert set(proof['changed']) == {'arch/AArch64/AArch64Mapping.c.o', 'arch/Mips/MipsMapping.c.o'}
    assert proof['added'] == ['AliasMapping.c.o'] and proof['mapping_object_identical']
    assert read(d / 'consumer-object.json')['all_variants_identical']
    assert '56623104' in (d / 'verify.log').read_text()
    assert '769142' in (d / 'direct-alias-check.log').read_text()
    for label in ('base', 'trie'):
        assert '100% tests passed' in (d / ('units-' + label + '.log')).read_text()
    layout = read(d / 'linked-layout.json')
    assert not layout['text']['changed']
    assert read(d/'lookup-section-isolation.json')['ordinary_text_bytes']==0
    assert all(x['unchanged_except_lookup_target'] for x in read(d/'caller-identity.json').values())
    profiles.append(dict(host=d.name, cleanup=read(d / 'cleanup.json'), object_isolation=proof,
        layout={k:{a:len(layout[k][a]) for a in ('changed','added','removed')} for k in ('text','readonly','writable')}))
    values = read(d / 'instruction-costs.json')
    assert len(values) == 30
    keys = sorted({(v['case'], v['mode']) for v in values})
    assert len(keys) == 15
    for case, mode in keys:
        pair = {v['variant']:v for v in values if v['case']==case and v['mode']==mode}
        assert set(pair) == {'base','trie'} and pair['base']['result']==pair['trie']['result']
        assert all(v['collected_traversals']==3 for v in pair.values())
        parsed = {label:scope['trace'](d/(case+'-'+str(mode)+'-'+label+'.callgrind.gz'),label)[0] for label in pair}
        for label in pair:
            assert [sum(v[i] for v in parsed[label].values()) for i in range(3)] == [pair[label]['events'][k] for k in ('Ir','Dr','Dw')]
        changes = []
        for name in parsed['base'].keys() | parsed['trie'].keys():
            a,b=parsed['base'].get(name,[0]*3),parsed['trie'].get(name,[0]*3)
            delta=[b[i]-a[i]for i in range(3)]
            if any(delta):changes.append(dict(function=name,before=a,after=b,delta=delta))
        changes.sort(key=lambda x:-abs(x['delta'][0]))
        before,after=pair['base']['events'],pair['trie']['events']
        rows.append(dict(host=d.name,case=case,mode=mode,totals={k:v['events']for k,v in pair.items()},
            ir_change=after['Ir']-before['Ir'],instruction_reduction=1-after['Ir']/before['Ir'],changed_function_costs=changes))
assert len(profiles)==4 and len(rows)==60
report=dict(complete=True,run=run,source=source,profiles=profiles,rows=rows,
    instruction_increases=[x for x in rows if x['ir_change']>0],publication_qualified=False,
    scope='Five frozen mixed consumer panels, three traversals per ROI, including scalar PE32/64 and ARM controls. Simulated costs do not establish native throughput.')
(r/'profile-review.json').write_text(json.dumps(report,indent=2)+'\n')
for row in rows:
    if row['mode'] or row['ir_change']:
        print(row['host'],row['case'],row['mode'],'Ir reduction %.4f%%'%(row['instruction_reduction']*100))
