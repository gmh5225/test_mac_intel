from pathlib import Path
import json

r=Path(__file__).resolve().parent
read=lambda f:json.loads(f.read_text())
run=read(r/'profile-run.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'profile-revision.txt').read_text().strip()
profiles=[]
for d in sorted((r/'profile').iterdir()):
    complete=read(d/'complete.json');proof=read(d/'order-proof.json')
    assert complete['success'] and complete['candidate']==read(r/'tree.json') and proof['compiled_members_identical'] and proof['vector_positions_restored']
    assert read(d/'cleanup.json')['removed'] and read(d/'download.json')['digest'].startswith('sha256:')
    layouts={name:read(d/(name+'-linked-layout.json')) for name in ('original','candidate')}
    profiles.append(dict(host=d.name,complete=complete,proof=proof,layouts=layouts,cleanup=read(d/'cleanup.json')))
assert len(profiles)==4
report=dict(complete=True,run=run,source=read(r/'tree.json'),profiles=profiles,checks=sum(x['complete']['tests'] for x in profiles),
    original_costs='../round1445-existing-plan-cost-repair/profile-review.json',native_qualification=False,publication_qualified=False,
    scope='Only one static archive member moved; every compiled member is identical. Recovered addresses establish the cause of the vector object relocation. They do not establish native throughput or remove the measured dispatch instruction overhead.')
(r/'identity-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('Four compiler member identities and restored vector positions; checks',report['checks'])
