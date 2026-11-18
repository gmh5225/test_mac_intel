from pathlib import Path
import json
import random
import statistics as st
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
run=read(r/'native-run.json')
assert run['conclusion']=='success' and run['head_sha']==(r/'native-revision.txt').read_text().strip()
def estimate(values,key):
 rng=random.Random(key);v=sorted(st.median(rng.choices(values,k=len(values))) for _ in range(2000))
 return dict(median=st.median(values),ci95=[v[49],v[1949]])
profiles=[];rows=[];hardware=[]
for d in sorted((r/'native').iterdir()):
 assert read(d/'download.json')['digest'].startswith('sha256:') and read(d/'cleanup.json')['removed']
 assert read(d/'candidate-tested-source.json')['tree']=='42bfcf28c2d8bcff40d0871185fb9ba5f5ac3aaa'
 assert read(d/'launch-controls.json')['aslr_disable_returncode']==0
 observed=read(d/'timings.json');assert len(observed)==read(d/'complete.json')['cases']==8
 for x in observed:
  assert len(x['pairs'])==21
  key='/'.join(map(str,[d.name,x['case'],x['mode'],x['launch']]))
  for variant in ('aa','iterator','leaf','candidate'):
   rows.append(dict(host=d.name,case=x['case'],mode=x['mode'],launch=x['launch'],variant=variant,**estimate([v[variant] for v in x['pairs']],key+'/'+variant)))
 pmu=read(d/'pmu.json');assert pmu.get('setting_restored',True)
 if (d/'pmu-samples.json').exists():
  samples=read(d/'pmu-samples.json');assert len(samples)==pmu['samples']
  for group,case,mode in sorted({(x['group'],x['case'],x['mode']) for x in samples}):
   chunk=[x for x in samples if (x['group'],x['case'],x['mode'])==(group,case,mode)]
   cycles=11 if group=='core' else 5
   variants=['base','aa','iterator','leaf','candidate'] if group=='core' else ['base','aa','candidate']
   assert len(chunk)==cycles*2*len(variants)
   events=chunk[0]['counters']['counts'].keys()
   values={v:{event:[] for event in events} for v in variants}
   for cycle in range(cycles):
    pair={v:[x for x in chunk if x['cycle']==cycle and x['variant']==v] for v in variants}
    assert all(len(a)==2 for a in pair.values())
    for event in events:
     baseline=sum(x['counters']['counts'][event] for x in pair['base'])
     assert baseline>0
     for v in variants:values[v][event].append(sum(x['counters']['counts'][event] for x in pair[v])/baseline)
   for v in variants[1:]:
    hardware.append(dict(host=d.name,group=group,case=case,mode=mode,variant=v,
        event_cost_ratios={event:estimate(vals,d.name+'/'+group+'/'+case+'/'+str(mode)+'/'+v+'/'+event) for event,vals in values[v].items()},
        minimum_running_percent=min(x['counters']['running_percent'][event] for x in chunk for event in events)))
 profiles.append(dict(host=d.name,cpu=read(d/'cpu.json'),cleanup=read(d/'cleanup.json'),pmu=pmu,
    native_memset={v:read(d/('gdb-fixed-'+v+'.json')) for v in ('base','iterator','leaf','candidate')}))
assert len(profiles)==2 and len(rows)==64
report=dict(complete=True,run=run,profiles=profiles,rows=rows,hardware=hardware,publication_qualified=False,
 scope='Native timings are baseline/candidate gains. PMU ratios are candidate/baseline event costs, covering the unchanged whole process. Bootstrap intervals are descriptive, not corrected for multiple comparisons. Unsupported events remain unavailable.')
(r/'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('native comparisons',len(rows),'hardware comparisons',len(hardware))
for p in profiles:print(p['host'],p['cpu'],'PMU',p['pmu']['supported'],'GDB observations',[len(x['observations']) for x in p['native_memset'].values()])
