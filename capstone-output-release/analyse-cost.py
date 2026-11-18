from pathlib import Path
import gzip,hashlib,json,re
r=Path(__file__).resolve().parent
parser=r.parent/'round1362-evex-extension-isolated-entry/review-cost.py';code=parser.read_text();scope={'__file__':str(parser)};exec(code[:code.index('rows=[]')],scope)
rows=[]
for d in sorted((r/'native').iterdir()):
 if not (d/'instruction-costs.json').exists():continue
 measured=json.loads((d/'instruction-costs.json').read_text())
 for case,mode in sorted({(x['case'],x['mode']) for x in measured}):
  counts={v:scope['trace'](d/f'cost-{case}-{mode}-{v}.callgrind.gz',v)[0] for v in ('base','scan')}
  totals={x['variant']:x['events'] for x in measured if (x['case'],x['mode'])==(case,mode)}
  for v in counts:assert [sum(x[i] for x in counts[v].values()) for i in range(3)]==[totals[v][k] for k in ('Ir','Dr','Dw')]
  changes={name:[counts['scan'].get(name,[0]*3)[i]-counts['base'].get(name,[0]*3)[i] for i in range(3)] for name in counts['base'].keys()|counts['scan'].keys()}
  changes={name:x for name,x in changes.items() if any(x)}
  rows.append(dict(host=d.name,case=case,mode=mode,changes=changes,ir_delta=totals['scan']['Ir']-totals['base']['Ir']))
report=dict(complete=len(rows)==33,rows=rows,parser_sha256=hashlib.sha256(code.encode()).hexdigest(),scope='Exclusive fixed-guest Callgrind events; instructions and memory references are simulated, not hardware timings.')
(r/'cost-attribution.json').write_text(json.dumps(report,indent=2)+'\n')
for row in rows:
 if row['case'] in ('scalar32','scalar64','simd64'): print(row['host'],row['case'],row['mode'],row['changes'])
