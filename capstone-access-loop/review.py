from pathlib import Path
import json
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
run=read(r/'profile-run.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'profile-revision.txt').read_text().strip()
rows=[]
for d in sorted((r/'profile').iterdir()):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    x=read(d/'complete.json');assert x['candidate']==read(r/'tree.json') and x['success']
    assert read(d/'cleanup.json')['removed']
    rows.append(dict(host=d.name,complete=x,cleanup=read(d/'cleanup.json')))
assert len(rows)==4
summary=dict(complete=True,run=run,candidate=read(r/'tree.json'),profiles=rows,
    identity_profiles=sum(len(x['complete']['identity_profiles']) for x in rows),
    repaired_profiles=sum(len(x['complete']['repaired_profiles']) for x in rows),
    checks=sum(len(v['tests']) for x in rows for group in ('identity_profiles','repaired_profiles') for v in x['complete'][group]),
    publication_qualified=False)
(r/'identity-review.json').write_text(json.dumps(summary,indent=2)+'\n')
assert summary['identity_profiles']==4 and summary['repaired_profiles']==0
print('Shared predicate:',summary['identity_profiles'],'archive identities,',summary['checks'],'checks')
