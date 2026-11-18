from pathlib import Path
import json
import random
import statistics as st

r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
run=read(r/'profile-run.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'profile-revision.txt').read_text().strip()
def interval(values,key):
    rng=random.Random(key)
    samples=sorted(st.median(rng.choices(values,k=len(values)))for _ in range(2000))
    return [samples[49],samples[1949]]
rows=[];profiles=[]
for d in sorted((r/'profile').iterdir()):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    assert read(d/'cleanup.json')['removed']
    assert read(d/'complete.json')['cases']==34
    controls=read(d/'launch-controls.json')
    assert controls['launches']==['images','same-file-fixed'] and controls['aslr_disable_returncode']==0
    assert controls['original_sha256']['base']==controls['original_sha256']['aa']
    layout=read(d/'output-linked-layout.json')
    assert not layout['text']['changed'] and not layout['readonly']['changed']
    caller=read(d/'output-caller-proof.json')
    assert caller['ordinary_text_bytes']==0 and all(v['unchanged_except_lookup_target'] for v in caller['callers'].values())
    objects=read(d/'objects-output.json')
    assert set(objects['changed'])=={'arch/AArch64/AArch64Mapping.c.o','arch/Mips/MipsMapping.c.o'}
    assert objects['added']==['AliasMapping.c.o']
    expected=read(r/'inputs.json')['variants']['output']
    assert read(d/'output-tested-source.json')==dict(tree=expected['tree'],patch_sha256=expected['sha256'])
    values=read(d/'timings.json');assert len(values)==34
    for row in values:
        assert len(row['pairs'])==64
        key='/'.join(map(str,[d.name,row['case'],row['mode'],row['launch']]))
        stats={}
        for label in ('aa','output'):
            ratios=[v[label] for v in row['pairs']]
            assert st.median(ratios)==row['median'][label]
            stats[label]=dict(gain=st.median(ratios),ci95=interval(ratios,key+'/'+label))
        rows.append(dict(profile=d.name,case=row['case'],mode=row['mode'],launch=row['launch'],comparisons=stats))
    profiles.append(dict(profile=d.name,cleanup=read(d/'cleanup.json')))
assert len(rows)==68 and len(profiles)==2
losses=[row for row in rows if row['comparisons']['output']['gain']<.99]
aa=[row for row in rows if abs(row['comparisons']['aa']['gain']-1)>.01]
(r/'profile-review.json').write_text(json.dumps(dict(complete=True,run=run,protocol=read(r/'protocol.json'),
    profiles=profiles,rows=rows,losses=losses,aa_outside_one_percent=aa,
    publication_qualified=False,scope='Every predeclared row and original loss is retained; no outlier removal.'),indent=2)+'\n')
print('Rows',len(rows),'losses',len(losses),'A/A flags',len(aa))
for row in rows:
    if row['case']=='arm-cp':print(row)
