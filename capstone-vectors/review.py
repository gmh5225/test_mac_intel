from pathlib import Path
import gzip
import hashlib
import json
import random
import statistics

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())
meta, parent = read(r/'semantic-review.json'), read(r/'input.json')
assert hashlib.sha256((r/'candidate.patch').read_bytes()).hexdigest() == meta['sha256']
run = read(r/'native-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r/'native-revision.txt').read_text().strip()

def interval(points, key):
    rng = random.Random(key)
    samples = sorted(statistics.median(rng.choices(points,k=len(points))) for _ in range(2000))
    return [samples[49], samples[1949]]

profiles, rows = [], []
for d in sorted((r/'native').iterdir()):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    cleanup = read(d/'cleanup.json'); assert cleanup['removed']
    complete = read(d/'complete.json'); assert complete['success']
    assert read(d/'tested-source-scan.json') == dict(tree=meta['tree'],patch_sha256=meta['sha256'])
    assert read(d/'tested-source-plain.json') == dict(tree=parent['tree'],patch_sha256=parent['sha256'])
    identity = read(d/'writer-identity.json'); assert identity['unchanged_existing_objects'] == 37
    assert read(d/'helper-section.json')['ordinary_text_empty']
    assert read(d/'generator-proof-scan.json')['both_outputs_reproduced']
    assert read(d/'generator-proof-plain.json')['both_outputs_reproduced']
    for name in ('integer','plain','scan'):
        assert '100% tests passed' in (d/('units-'+name+'.log')).read_text()
    symbols = {v:json.load(gzip.open(d/(v+'-linked-symbols.json.gz'),'rt')) for v in ('integer','plain','scan')}
    functions = {}
    for name in ('X86_getInstructionAfterExtensions','X86_completeScan','decodeEVEXInstruction','decodeEVEXInstruction.constprop.0','X86_writeEvexMemoryOutput','X86_writeDisplacement'):
        functions[name] = {v:[s for s in values if s['name']==name] for v,values in symbols.items()}
    model = next(l.split(':',1)[1].strip() for l in read(d/'cpu.json')['cpu'].splitlines() if l.startswith('model name'))
    profiles.append(dict(host=d.name,cpu=model,complete=complete,identity=identity,functions=functions,cleanup=cleanup))
    if 'gcc' in d.name:
        assert complete['cases']==0 and complete['plain_scan_objects_identical'] and complete['plain_scan_binary_identical']
        continue
    assert read(d/'consumer-object.json')['all_variants_identical']
    control=read(d/'launch-controls.json'); assert control['aslr_disable_returncode']==0
    assert control['original_sha256']['integer']==control['original_sha256']['aa']
    cases=read(d/'measurements.json'); assert len(cases)==complete['cases']==18
    expected={(case,mode,launch)for case in ('libzstd1-amd64','libssl3t64-amd64','jpeg-avx2-i386') for mode in ('scan','format','detail')for launch in ('images','same-file-fixed')}
    assert {(c['case'],c['mode'],c['launch'])for c in cases}==expected
    for c in cases:
        assert c['panel']=='simd-functions' and len(c['cycles'])==21
        pairs=[{name:x['ns']['integer']/x['ns'][name]for name in ('scan','plain','aa')}for x in c['cycles']]
        gains={name:statistics.median(x[name]for x in pairs)for name in ('scan','plain','aa')}
        assert all(abs(gains[name]-c['gain'][name])<1e-12 for name in gains)
        key='/'.join((d.name,c['case'],c['mode'],c['launch']))
        rows.append(dict(host=d.name,cpu=model,case=c['case'],mode=c['mode'],launch=c['launch'],gain=gains['scan'],plain=gains['plain'],aa=gains['aa'],vs_plain=statistics.median(x['ns']['plain']/x['ns']['scan']for x in c['cycles']),ci95=interval([x['scan']for x in pairs],key),aa_ci95=interval([x['aa']for x in pairs],key+'/aa')))
assert len(profiles)==4 and len(rows)==36
report=dict(complete=True,source=meta,run=run,profiles=profiles,rows=rows,losses=[x for x in rows if x['gain']<.99],aa_outside_one_percent=[x for x in rows if abs(x['aa']-1)>.01],native_qualified=False,scope='Focused placement counterfactual. GCC variants are byte-identical complete binaries, so not retimed. Clang tests three frozen SIMD panels with all modes and two launch controls. No new iced comparison and no broad qualification.')
(r/'review.json').write_text(json.dumps(report,indent=2)+'\n')
print('rows',len(rows),'losses',len(report['losses']),'AA outliers',len(report['aa_outside_one_percent']))
for x in rows:
    if x['launch']=='same-file-fixed':print(x['host'],x['case'],x['mode'],round(x['gain'],6),round(x['vs_plain'],6),round(x['aa'],6))
