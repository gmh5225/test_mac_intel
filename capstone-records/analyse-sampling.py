from pathlib import Path
from collections import Counter
import json,re,statistics as st
r=Path(__file__).resolve().parent
profiles=[]
for d in sorted((r/'native').iterdir()):
 if not (d/'cycle-sampling.json').exists():continue
 sampling=json.loads((d/'cycle-sampling.json').read_text());items=[];counts={}
 for record in sampling['records']:
  raw=(d/record['report']).read_text();lost=re.search(r'^# Total Lost Samples: (\d+)$',raw,re.M);assert lost and int(lost[1])==0
  histogram=Counter()
  for line in raw.splitlines():
   m=re.match(r'\s*[\d.]+%\s+(\d+)\s+\[.\]\s+(\S+)',line)
   if m:histogram[m[2]]+=int(m[1])
  assert sum(histogram.values())>1000
  v=record['variant'];counts.setdefault(v,[]).append(dict(histogram));items.append(dict(variant=v,cycle=record['cycle'],position=record['position'],total_samples=sum(histogram.values()),report=record['report'],histogram=dict(histogram)))
 assert set(counts)=={'base','aa','iterator','leaf','candidate'} and all(len(x)==4 for x in counts.values())
 combined={v:Counter()for v in counts}
 for v in counts:
  for x in counts[v]:combined[v].update(x)
 all_functions=set().union(*(x.keys()for x in combined.values()))
 rows=[dict(symbol=s,counts={v:combined[v][s]for v in combined},sample_delta={v:combined[v][s]-combined['base'][s] for v in combined if v!='base'})for s in all_functions]
 rows.sort(key=lambda x:-abs(x['sample_delta']['candidate']))
 profiles.append(dict(host=d.name,runs=items,symbols=rows,total_samples={v:sum(x.values())for v,x in combined.items()}))
report=dict(complete=True,profiles=profiles,scope='Four fixed-period cycles samples per binary on one capable host; same input and 400 traversals. Raw sample counts and A/A variation retained. Samples can skid and are too coarse to prove per-function causal attribution; no throughput or unique instruction blame is inferred.')
(r/'sampling-review.json').write_text(json.dumps(report,indent=2)+'\n')
for p in profiles:
 print(p['host'],p['total_samples'])
 for x in p['symbols'][:12]:print(x['symbol'],x['counts'],x['sample_delta'])
