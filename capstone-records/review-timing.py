from pathlib import Path
import json
import random
import statistics as st
import sys

r=Path(__file__).resolve().parent
mode,=sys.argv[1:]
assert mode in ('native','mixed')
read=lambda p:json.loads(p.read_text())
inputs,run=read(r/'inputs.json'),read(r/(mode+'-run.json'))
assert run['conclusion']=='success' and run['head_sha']==(r/(mode+'-revision.txt')).read_text().strip()
def interval(values,key):
    rng=random.Random(key)
    samples=sorted(st.median(rng.choices(values,k=len(values))) for _ in range(2000))
    return [samples[49],samples[1949]]
rows,aa_flags,profiles,costs=[],[],[],[]
for d in sorted((r/mode).iterdir()):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    complete=read(d/'complete.json')
    assert read(d/'cleanup.json')['removed']
    controls=read(d/'launch-controls.json')
    assert controls['launches']==['images','same-file-fixed'] and controls['aslr_disable_returncode']==0
    base='integer' if mode=='native' else 'base'
    assert controls['original_sha256'][base]==controls['original_sha256']['aa']
    layouts={}
    for label in ('output',):
        assert read(d/(label+'-tested-source.json'))==dict(tree=inputs['variants'][label]['tree'],patch_sha256=inputs['variants'][label]['sha256'])
        layout=read(d/(label+'-linked-layout.json'))
        assert layout['captured']
        layouts[label]={key:{k:len(layout[key][k]) for k in ('changed','added','removed')} for key in ('text','readonly','writable')}
        if mode=='native':
            proof=read(d/(label+'-object-isolation.json'))
            assert proof['changed']==['arch/X86/X86VectorOutput.c.o']
            assert proof['added']==['arch/X86/X86EvexMemoryOutput.c.o']
            assert '100% tests passed' in (d/('units-'+label+'.log')).read_text()
        else:
            proof=read(d/('objects-'+label+'.json'))
            assert proof['changed']==['arch/X86/X86VectorOutput.c.o']
            assert proof['added']==['arch/X86/X86EvexMemoryOutput.c.o']
    profiles.append(dict(profile=d.name,layouts=layouts,cleanup=read(d/'cleanup.json')))
    values=read(d/('measurements.json' if mode=='native' else 'timings.json'))
    assert len(values)==complete['cases']==(42 if mode=='native' else 48)
    for row in values:
        key='/'.join(map(str,[d.name,row['case'],row.get('panel','all'),row['mode'],row['launch']]))
        if mode=='native':
            cycles=row['cycles'];assert len(cycles)==32
            ratios={label:[c['ns']['integer']/c['ns'][label] for c in cycles] for label in ('aa','output')}
            assert all(st.median(v)==row['gain'][label] for label,v in ratios.items())
        else:
            cycles=row['pairs'];assert len(cycles)==32
            ratios={label:[c[label] for c in cycles] for label in ('aa','output')}
            assert all(st.median(v)==row['median'][label] for label,v in ratios.items())
        common=dict(host=d.name,case=row['case'],panel=row.get('panel'),mode=row['mode'],launch=row['launch'],
                    aa=st.median(ratios['aa']),aa_ci95=interval(ratios['aa'],key+'/aa'))
        if abs(common['aa']-1)>.01:aa_flags.append(common)
        for label in ('output',):
            rows.append(dict(**common,variant=label,gain=st.median(ratios[label]),ci95=interval(ratios[label],key+'/'+label),
                             vs_iced=row['vs_iced'][label] if mode=='native' else None,
                             vs_fast=row['vs_fast'][label] if mode=='native' and row['vs_fast'] else None))
    if mode=='native':
        observed=read(d/'instruction-costs.json');assert len(observed)==6
        for which in range(3):
            records={x['variant']:x for x in observed if x['mode']==which}
            assert set(records)=={'integer','output'}
            assert len({tuple(x['result']) for x in records.values()})==1
            assert all(x['collected_traversals']==2 for x in records.values())
            baseline=records['integer']['events']['Ir']
            costs.append(dict(host=d.name,mode=which,events={k:v['events'] for k,v in records.items()},
                              instruction_reduction={k:1-records[k]['events']['Ir']/baseline for k in ('output',)}))
assert len(profiles)==4 and len(rows)==(168 if mode=='native' else 192)
losses={label:[x for x in rows if x['variant']==label and x['gain']<.99] for label in ('output',)}
report=dict(complete=True,run=run,inputs=inputs,profiles=profiles,rows=rows,losses=losses,
            aa_outside_one_percent=aa_flags,costs=costs,publication_qualified=False,
            policy='All predeclared observations and all data relocations are retained. Layout movement is not itself a timing verdict. No outlier removal; 2000 deterministic resamples of 32 balanced cycles. Simulated instruction counts are not native cycles.')
(r/(mode+'-review.json')).write_text(json.dumps(report,indent=2)+'\n')
print(mode,'comparisons',len(rows),'A/A flags',len(aa_flags),'losses',{k:len(v) for k,v in losses.items()})
for label,values in losses.items():
    for x in values[:10]:print(label,x['host'],x['case'],x['mode'],x['launch'],round(x['gain'],5),'AA',round(x['aa'],5))
