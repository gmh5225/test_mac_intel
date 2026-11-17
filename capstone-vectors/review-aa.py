from pathlib import Path
import json,random,statistics
r=Path(__file__).resolve().parent
prior=r.parent/'round1392-evex-prechecked-dispatch-native'
read=lambda p:json.loads(p.read_text())
def estimate(values,key):
 rng=random.Random(key)
 boot=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(2000))
 return dict(median=statistics.median(values),ci95=[boot[49],boot[1949]])
def identity(row):return tuple(row.get(k) for k in ('case','panel','mode'))
results=[];flags=[];missing=[]
for mode in ('native','mixed'):
 f=r/(mode+'-review.json')
 if not f.exists():missing.append(mode);continue
 current,old=read(f),read(prior/(mode+'-review.json'))
 assert current['complete'] and old['complete']
 for label,report in [('original',old),('repeat',current)]:
  flags.extend(dict(round=label,family=mode,**x) for x in report['aa_outside_one_percent'] if '-clang-' in x['host'])
 for d in sorted((r/mode).iterdir()):
  values=read(d/('measurements.json' if mode=='native' else 'timings.json'))
  for x in values:
   if mode=='native':ratios=[v['ns']['aa']/v['ns']['output'] for v in x['cycles']]
   else:ratios=[v['output']/v['aa'] for v in x['pairs']]
   key='/'.join(map(str,[d.name,mode,*identity(x),x['launch']]))
   original=next(z for z in current['rows'] if z['host']==d.name and identity(z)==identity(x) and z['launch']==x['launch'])
   results.append(dict(family=mode,**original,candidate_vs_identical_copy=estimate(ratios,key)))
followups=[]
for flag in flags:
 compiler='22.04' if '22.04' in flag['host'] else '24.04'
 matches=[x for x in results if x['family']==flag['family'] and compiler in x['host'] and identity(x)==identity(flag)]
 assert len(matches)==2
 followups.append(dict(original_flag=flag,repeat=matches))
report=dict(complete=not missing,pending=missing,rows=results,flag_followups=followups,
 fixed_image_aa_flags=[x for x in results if x['launch']=='same-file-fixed' and abs(x['aa']-1)>.01],
 fixed_image_copy_comparison_losses=[x for x in results if x['launch']=='same-file-fixed' and x['candidate_vs_identical_copy']['median']<.99],
 original_negative_evidence_preserved=True,
 scope='Diagnostic paired candidate/A/A ratios from all existing frozen cycles, plus matched fixed-inode and disabled-ASLR observations for every Clang A/A flag in both rounds. These do not replace the original baseline ratios or delete any observation.')
(r/'aa-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('complete',report['complete'],'flags followed',len(followups),'fixed A/A flags',len(report['fixed_image_aa_flags']),'fixed copy losses',len(report['fixed_image_copy_comparison_losses']))
for row in followups:
 f=row['original_flag'];print(f['round'],f['family'],f['case'],f['mode'],f['launch'],[(x['launch'],round(x['gain'],5),round(x['aa'],5),round(x['candidate_vs_identical_copy']['median'],5)) for x in row['repeat']])
