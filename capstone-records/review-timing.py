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
protocol=read(r/'protocol.json')
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
    assert controls['launches']==['images','images-fixed','same-file','same-file-fixed'] and controls['aslr_disable_returncode']==0
    base='integer' if mode=='native' else 'base'
    assert controls['original_sha256'][base]==controls['original_sha256']['aa']
    layouts={}
    for label in ('scan','merge'):
        assert read(d/(label+'-tested-source.json'))==dict(tree=inputs['variants'][label]['tree'],patch_sha256=inputs['variants'][label]['sha256'])
        layout=read(d/(label+'-linked-layout.json'))
        assert layout['unmodified_text_positions_identical']
        layouts[label]={key:dict(original_symbols=layout[key]['original_symbols'],moved=len(layout[key]['moves']),deltas=layout[key]['address_deltas']) for key in ('readonly','writable')}
        if mode=='native':
            proof=read(d/(label+'-object-isolation.json'))
            assert proof['changed']==['arch/X86/X86EvexScan.c.o']
            assert proof['added']==(['arch/X86/X86EvexTransferScan.c.o'] if label=='scan' else [])
            assert '100% tests passed' in (d/('units-'+label+'.log')).read_text()
        else:
            proof=read(d/('objects-'+label+'.json'))
            assert proof['changed']==['arch/X86/X86EvexScan.c.o']
            assert proof['added']==(['arch/X86/X86EvexTransferScan.c.o'] if label=='scan' else [])
    profiles.append(dict(profile=d.name,layouts=layouts,cleanup=read(d/'cleanup.json')))
    values=read(d/('measurements.json' if mode=='native' else 'timings.json'))
    profile=next(p for p in protocol['focus'][mode] if p in d.name)
    selected=protocol['focus'][mode][profile]
    assert len(values)==complete['cases']==len(selected)*4
    for row in values:
        key='/'.join(map(str,[d.name,row['case'],row.get('panel','all'),row['mode'],row['launch']]))
        if mode=='native':
            cycles=row['cycles'];assert len(cycles)==21
            ratios={label:[c['ns']['integer']/c['ns'][label] for c in cycles] for label in ('aa','scan','merge')}
            assert all(st.median(v)==row['gain'][label] for label,v in ratios.items())
        else:
            cycles=row['pairs'];assert len(cycles)==21
            ratios={label:[c[label] for c in cycles] for label in ('aa','scan','merge')}
            assert all(st.median(v)==row['median'][label] for label,v in ratios.items())
        common=dict(host=d.name,case=row['case'],panel=row.get('panel'),mode=row['mode'],launch=row['launch'],
                    aa=st.median(ratios['aa']),aa_ci95=interval(ratios['aa'],key+'/aa'))
        if abs(common['aa']-1)>.01:aa_flags.append(common)
        for label in ('scan','merge'):
            rows.append(dict(**common,variant=label,gain=st.median(ratios[label]),ci95=interval(ratios[label],key+'/'+label),
                             vs_iced=None,vs_fast=None))
    if mode=='mixed':
        from cost_parser import trace
        observed=read(d/'instruction-costs.json')
        assert len(observed)==len(selected)*3
        for case,which in selected:
            records={x['variant']:x for x in observed if x['case']==case and x['mode']==which}
            assert set(records)=={'base','scan','merge'}
            assert all(x['collected_traversals']==3 for x in records.values())
            assert all(x['result']==records['base']['result'] for x in records.values())
            parsed={label:trace(d/(case+'-'+str(which)+'-'+label+'.callgrind.gz'),label)for label in records}
            for label,(functions,pcs)in parsed.items():
                assert [sum(v[i]for v in functions.values())for i in range(3)]==[records[label]['events'][k]for k in ('Ir','Dr','Dw')]
                assert pcs
            for label in ('scan','merge'):
                old_fn,old_pc=parsed['base'];new_fn,new_pc=parsed[label]
                changes={name:[new_fn.get(name,[0]*3)[i]-old_fn.get(name,[0]*3)[i]for i in range(3)]for name in old_fn.keys()|new_fn.keys()}
                changes={name:delta for name,delta in changes.items()if any(delta)}
                changed_pcs=sum(old_pc.get(pc,0)!=new_pc.get(pc,0)for pc in old_pc.keys()|new_pc.keys())
                costs.append(dict(host=d.name,case=case,mode=which,variant=label,
                    events={k:records[k]['events']for k in ('base',label)},
                    totals_equal=all(records['base']['events'][k]==records[label]['events'][k]for k in ('Ir','Dr','Dw')),
                    function_counts_equal=old_fn==new_fn,executable_pc_counts_equal=old_pc==new_pc,
                    changed_pc_count=changed_pcs,changed_function_costs=changes))
assert len(profiles)==4 and len(rows)==sum(len(v) for v in protocol['focus'][mode].values())*8
losses={label:[x for x in rows if x['variant']==label and x['gain']<.99] for label in ('scan','merge')}
report=dict(complete=True,run=run,inputs=inputs,profiles=profiles,rows=rows,losses=losses,
            aa_outside_one_percent=aa_flags,costs=costs,publication_qualified=False,
            protocol=protocol,policy='All predeclared observations and all data relocations are retained. Layout movement is not itself a timing verdict. No outlier removal; 2000 deterministic resamples of 21 balanced cycles. Simulated instruction counts are not native cycles.')
(r/(mode+'-review.json')).write_text(json.dumps(report,indent=2)+'\n')
print(mode,'comparisons',len(rows),'A/A flags',len(aa_flags),'losses',{k:len(v) for k,v in losses.items()})
for label,values in losses.items():
    for x in values[:10]:print(label,x['host'],x['case'],x['mode'],x['launch'],round(x['gain'],5),'AA',round(x['aa'],5))
