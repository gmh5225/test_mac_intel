from pathlib import Path
import json,subprocess as sp,sys
r=Path(__file__).resolve().parent;out=r.parent/'evidence'
for stage in ('base','candidate'):sp.run([sys.executable,'-B',r/'stage.py',stage],check=True)
results={}
for f in (out/'base').glob('*-shapes.tsv'):
    def read(file):
        v=[line.split(maxsplit=5)for line in file.read_text().splitlines()]
        z={int(i):(int(off),int(n),int(mr),int(sib),name)for i,off,n,mr,sib,name in v};assert len(z)==len(v);return z
    name=f.name.removesuffix('-shapes.tsv');a=read(f);b=read(out/'candidate'/f.name)
    assert all(a.get(k)==v for k,v in b.items());hits=[a[k]for k in a.keys()-b.keys()]
    from collections import Counter
    assert all(0x20<=sib<=0x27 and sib!=0x24 and not (mr<0x40 and sib==0x25) for off,n,mr,sib,mn in hits)
    results[name]=dict(base=len(a),candidate=len(b),new=len(hits),mnemonics=dict(Counter(v[-1]for v in hits)))
(out/'delta.json').write_text(json.dumps(results,indent=2)+'\\n')
assert len(results)==6 and all(json.loads((out/k/'cleanup.json').read_text())['removed']for k in ('base','candidate'))
(out/'cleanup.json').write_text(json.dumps(dict(removed=True,bytes=sum(json.loads((out/k/'cleanup.json').read_text())['bytes']for k in ('base','candidate'))))+'\\n')
