from pathlib import Path
import hashlib
import json

r=Path(__file__).resolve().parent
read=lambda f:json.loads(f.read_text())
run=read(r/'native-run.json')
assert run['status']=='completed' and run['conclusion']=='success'
assert run['head_sha']==(r/'native-revision.txt').read_text().strip()
meta=read(r/'candidates.json')
parser=r.parent/'round1362-evex-extension-isolated-entry/review-cost.py'
code=parser.read_text()
scope={'__file__':str(parser)}
exec(code[:code.index('rows=[]')],scope)
directories=list((r/'native').iterdir())
assert len(directories)==1
d=directories[0]
assert read(d/'download.json')['digest'].startswith('sha256:')
assert read(d/'complete.json')['source']==meta and read(d/'cleanup.json')['removed']
assert read(d/'consumer.json')['shared_by_all_variants']
assert read(d/'cost-protocol.json')['available'] and read(d/'cost-protocol.json')['fixed_guest_argv']
values=read(d/'instruction-costs.json')
expected={(c,m,v)for c,m in [('scalar32',1),('scalar64',1),('simd64',1),('simd64',2),
                            ('putty-32-0.85',1),('putty-64-0.85',1),('mips64el-ls',2)]
          for v in ('base','dispatch','scan')}
assert len(values)==21 and {(x['case'],x['mode'],x['variant'])for x in values}==expected
rows=[]
for case,mode in sorted({(x['case'],x['mode'])for x in values}):
    records={x['variant']:x for x in values if (x['case'],x['mode'])==(case,mode)}
    assert all(x['result']==records['base']['result'] for x in records.values())
    functions={v:scope['trace'](d/f'cost-{case}-{mode}-{v}.callgrind.gz',v)[0]for v in records}
    for v in records:
        assert [sum(x[i]for x in functions[v].values())for i in range(3)]==[records[v]['events'][k]for k in ('Ir','Dr','Dw')]
    changes={}
    for v in ('dispatch','scan'):
        delta={f:[functions[v].get(f,[0]*3)[i]-functions['base'].get(f,[0]*3)[i]for i in range(3)]
               for f in functions[v].keys()|functions['base'].keys()}
        changes[v]={f:x for f,x in delta.items()if any(x)}
    rows.append(dict(case=case,mode=mode,events={k:v['events']for k,v in records.items()},changes=changes))
report=dict(complete=True,run=run,source=meta,host=read(d/'environment.json'),rows=rows,
            cleanup=read(d/'cleanup.json'),parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
            publication_qualified=False,scope='ARM64 fixed-guest exclusive simulated instructions and memory references. This diagnoses generated work; hardware timing and complete semantic qualification are separate evidence.')
(r/'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
for row in rows:
    for v,changes in row['changes'].items():
        print(row['case'],row['mode'],v,'Ir',row['events'][v]['Ir']-row['events']['base']['Ir'],
              dict(sorted(changes.items(),key=lambda x:-abs(x[1][0]))[:4]))
