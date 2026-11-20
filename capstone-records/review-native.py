from pathlib import Path
import json,statistics
r=Path(__file__).resolve().parent
load=lambda f:json.loads(f.read_text());run=load(r/'native-run.json');assert run['head_sha']==(r/'native-revision.txt').read_text().strip() and run['conclusion']=='success'
reports=[]
for d in sorted((r/'native').iterdir()):
    matched=load(d/'matched-text.json');done=load(d/'complete.json');control=load(d/'controls.json');assert control['images']['base']==control['images']['copy'] and control['aslr_disabled'] and load(d/'cleanup.json')['removed']
    assert done['rows']==15
    layouts={k:load(d/('layout-'+k+'.json')) for k in ['base','layout','candidate']}
    hotspots=[]
    for row in sorted([x for x in layouts['base']['symbols'] if x.get('simulated_self_ir')],key=lambda x:-x['simulated_self_ir']):
        n=row['name'];matches={key:[x for x in val['symbols'] if x['name']==n] for key,val in layouts.items()}
        if all(len(v)==1 for v in matches.values()):
            hotspots.append(dict(symbol=n,ir=row['simulated_self_ir'],addresses={k:v[0]['address'] for k,v in matches.items()},sizes={k:v[0]['size'] for k,v in matches.items()},code_digests={k:v[0]['sha256'] for k,v in matches.items()}))
    rows=[]
    for x in load(d/'timings.json'):
        values={}
        for a,b in [('base','copy'),('base','candidate'),('base','layout'),('layout','candidate')]:
            v=[sum(y[0] for y in cycle[a])/sum(y[0] for y in cycle[b]) for cycle in x['cycles']];assert len(v)==12
            quartiles=statistics.quantiles(v,n=4,method='inclusive');values[a+'/'+b]=dict(median=statistics.median(v),iqr=[quartiles[0],quartiles[2]])
        rows.append(dict(case=x['case'],mode=x['mode'],gains=values))
    reports.append(dict(host=d.name,match=matched,rows=rows,hotspots=hotspots,cleanup=load(d/'cleanup.json')))
assert len(reports)==2
(r/'native-review.json').write_text(json.dumps(dict(complete=True,run=run,profiles=reports,scope='Two x86 hosts, unchanged ELF relocations and original object placement. Padding without a change to the baseline algorithm is diagnostic only.'),indent=2)+'\n')
for h in reports:
    print(h['host'],h['match'],[(x['case'],x['mode'],{k:round(v['median'],4) for k,v in x['gains'].items()}) for x in h['rows'] if x['case']=='mips64el-ls'])
