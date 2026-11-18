from pathlib import Path
import json
import random
import statistics as st
from placement import symbols

r=Path(__file__).resolve().parent
read=lambda f:json.loads(f.read_text())
run=read(r/'native-run.json')
candidate=read(r/'hypothesis.json')['candidate']
assert run['conclusion']=='success' and run['head_sha']==(r/'native-revision.txt').read_text().strip()
def interval(values,seed):
    rng=random.Random(seed)
    points=sorted(st.median(rng.choices(values,k=len(values))) for _ in range(2000))
    return [points[49],points[1949]]
rows,profiles=[],[]
for d in sorted((r/'native').iterdir()):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    assert read(d/'cleanup.json')['removed']
    assert read(d/'output-tested-source.json') == dict(tree=candidate['tree'], patch_sha256=candidate['sha256'])
    control=read(d/'placement-control.json')
    assert control['complete'] and control['all_allocated_section_bytes_flags_alignment_preserved']
    assert control['no_writable_executable_segment']
    original, placed = symbols(d/'base-symbols.txt'), symbols(d/'placed-symbols.txt')
    groups = {}
    for kind in ('t', 'r', 'd', 'b'):
        selected = {name: [x for x in entries if x[2].lower() == kind]
                    for name, entries in original.items()}
        selected = {name: entries for name, entries in selected.items() if entries}
        differences = [dict(symbol=name, before=entries, after=placed.get(name, []))
                       for name, entries in selected.items()
                       if not all(x in placed.get(name, []) for x in entries)]
        groups[kind] = dict(original_symbols=len(selected), restored_symbols=len(selected)-len(differences), differences=differences)
    decoder_tables = {name: entries for name, entries in original.items()
                      if name.startswith('DecoderTable') and all(x[2].lower() == 'r' for x in entries)}
    unrestored_tables = [name for name, entries in decoder_tables.items()
                         if not all(x in placed.get(name, []) for x in entries)]
    layout = dict(original_symbol_types=groups, decoder_tables=len(decoder_tables),
                  unrestored_decoder_tables=unrestored_tables,
                  all_original_readonly_restored=not groups['r']['differences'],
                  all_original_writable_restored=not groups['d']['differences'] and not groups['b']['differences'])
    profiles.append(dict(host=d.name,cpu=read(d/'cpu.json'),control=control,layout_review=layout,cleanup=read(d/'cleanup.json')))
    values=read(d/'timings.json')
    assert len(values)==24 and read(d/'complete.json')['cases']==24
    for value in values:
        assert len(value['pairs'])==32
        item={k:value[k] for k in ('case','mode','launch')}
        item['host']=d.name
        item['comparisons']={}
        for variant in ('aa','output','placed','placed_vs_output'):
            samples=[x['placed']/x['output'] if variant=='placed_vs_output' else x[variant] for x in value['pairs']]
            item['comparisons'][variant]=dict(median=st.median(samples),ci95=interval(samples,100+len(rows)))
        rows.append(item)
assert len(profiles)==2 and len(rows)==48
report=dict(complete=True,run=run,profiles=profiles,rows=rows,publication_qualified=False,
    interpretation='Paired diagnostic placement comparison of frozen objects; original negative observations remain valid. No PMU/cache mechanism claim.',
    losses={v:[x for x in rows if x['comparisons'][v]['median']<.99] for v in ('output','placed')},
    aa_flags=[x for x in rows if not .99<=x['comparisons']['aa']['median']<=1.01])
(r/'native-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('Rows',len(rows),'losses',{k:len(v) for k,v in report['losses'].items()},'A/A flags',len(report['aa_flags']))
for item in rows:
    if item['launch']=='same-file-fixed':
        print(item['host'],item['case'],item['mode'],{k:round(v['median'],5) for k,v in item['comparisons'].items()})
