from pathlib import Path
import json, statistics, random
r=Path(__file__).resolve().parent
load=lambda p:json.loads(p.read_text());meta=load(r/'tree.json');receipt=load(r/'native-run.json')
assert receipt['head_sha']==(r/'native-revision.txt').read_text().strip() and receipt['conclusion']=='success'
rows=[];profiles=[]
for d in sorted((r/'native').iterdir()):
    done=load(d/'complete.json');assert done['tested_candidate_tree']==meta['tree']
    raw=load(d/'timings.json');assert len(raw)==done['rows']==49
    rec={p.stem:load(p)['complete_record_comparisons'] for p in d.glob('records-*.log')}
    assert len(rec)==8 and min(rec.values())>0 and load(d/'cleanup.json')['removed']
    batch={p.stem:{k:load(p)[k] for k in ("batch_records","batch_calls")} for p in d.glob("records-*.log")}
    assert all(x["batch_records"] and x["batch_calls"] for x in batch.values())
    ctl=load(d/'controls.json');assert ctl['cycle_count']==12 and ctl['aslr_disabled'] and ctl['images']['base']==ctl['images']['copy']
    assert '100% tests passed' in (d/'tests.log').read_text()
    profiles.append(dict(host=d.name,env=load(d/'environment.json'),controls=ctl,records=rec,batches=batch,cleanup=load(d/'cleanup.json'),objects=load(d/'objects.json')))
    for x in raw:
        assert len(x['cycles'])==12
        row=dict(host=d.name,case=x['case'],mode=x['mode'],route=x['route'])
        for col,metric in [(0,'cpu'),(1,'wall')]:
            by={}
            for k in ('copy','leaf','candidate'):
                v=[sum(y[col] for y in s['base'])/sum(y[col] for y in s[k]) for s in x['cycles']]
                rng=random.Random('/'.join(map(str,[d.name,x['case'],x['mode'],x['route'],k,metric])))
                boots=sorted(statistics.median(rng.choices(v,k=len(v))) for _ in range(1200))
                q=statistics.quantiles(v,n=4,method='inclusive')
                by[k]=dict(median=statistics.median(v),iqr=[q[0],q[2]],ci95=[boots[29],boots[1169]])
            row[metric]=by
        rows.append(row)
assert len(profiles)==4
report=dict(complete=True,run=receipt,source=meta,rows=rows,profiles=profiles,
            aa_outside_one_percent=[x for x in rows if abs(x['cpu']['copy']['median']-1)>.01],
            median_losses_over_one_percent=[x for x in rows if x['cpu']['candidate']['median']<.99],
            scope='Four-backend native Release fixed-image paired baseline/candidate and copied baseline. Twelve cycles; bootstrap intervals are descriptive and unadjusted. No iced timings in this factorial test.')
(r/'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
print(len(rows),'rows;',len(report['median_losses_over_one_percent']),'medians below 0.99')
