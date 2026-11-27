from pathlib import Path
import json,os,subprocess as sp,sys
r=Path(__file__).resolve().parent;root=r.parent/'evidence';root.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
for stage in ('base','candidate'):
    sp.run([sys.executable,'-B',r/'stage.py'],env=dict(os.environ,RECORD_STAGE=stage),check=True)
first=rd(root/'base'/'counts.json');second=rd(root/'candidate'/'counts.json')
assert set(first)==set(second)
for k in first:
    for n in ('1','2'):assert first[k]['private'][n]['records']==second[k]['private'][n]['records']
clean=[rd(root/stage/'cleanup.json')for stage in ('base','candidate')]
(root/'cleanup.json').write_text(json.dumps(dict(removed=all(s['removed']for s in clean),bytes=sum(s['bytes']for s in clean))))
(root/'complete.json').write_text(json.dumps(dict(complete=True,source=rd(r/'source.json'),workloads=len(first))))
