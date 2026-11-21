"""Independently validate every requested product row against the source-build receipts."""
from pathlib import Path
import hashlib
import json
import random
import re
import statistics

r = Path(__file__).resolve().parent
def read(path):
    return json.loads(path.read_text())
inputs = read(r/'product-check/inputs.json')
run = read(r/'product-run.json')
assert run['status']=='completed' and run['head_sha']==(r/'product-check/revision.txt').read_text().strip()
d, = (r/'product').iterdir()
assert re.fullmatch(r'sha256:[0-9a-f]{64}',read(d/'download.json')['digest'])
assert read(d/'inputs.json')==inputs and read(d/'cleanup.json')['removed']
variants = inputs['variants']
is_combined = 'batch' not in variants
cases = {'jpeg-avx2-i386','libzstd1-i386','libssl3t64-amd64','arm-cp','mips64el-ls','putty-32-0.85','putty-64-0.85'}
if is_combined:
    cases.add('libmvec-amd64')
launches = {'images','same-file-fixed'}
planned = {(case,mode,launch) for case in cases for mode in range(3 if case in {'arm-cp','mips64el-ls'} else 4) for launch in launches}
rows = read(d/'timings.json')
assert len(rows)==len(planned) and {(x['case'],x['mode'],x['launch']) for x in rows}==planned
if run['conclusion']=='success':
    done=read(d/'complete.json')
    assert done['cases']==len(planned) and done['active'] and set(done['variants'])==set(variants)
else:
    assert not is_combined and run['conclusion']=='failure' and not (d/'complete.json').exists()
    log=(r/'failure-step.log').read_text()
    trace=log[log.rindex('Traceback (most recent call last)'):]
    assert 'len(results)==48*len(launches)' in trace and 'AssertionError' in trace
    assert len(planned)==52 and len(planned)!=48*len(launches)
source=read(d/'sources.json')
llvm=read(d/'llvm_source_build.json')
ref=read(d/'llvm-baseline-identity.json')
assert source['neverd']==inputs['neverd'] and source['capstone']==inputs['capstone']
assert llvm['prebuilt'] is False and llvm['unmodified_latest_fork'] and source['llvm_fork']==llvm['revision']==ref['revision']
assert ref['tracked_diff_sha256']==hashlib.sha256(b'').hexdigest() and ref['untracked']=={}
managed=read(d/'base-managed-source-identity.json')
controls=read(d/'launch-controls.json')
assert set(controls['launches'])==launches and controls['aslr_disable_returncode']==0
assert controls['original_sha256']['base']==controls['original_sha256']['base-copy']
resid=read(d/'residual.json')
assert set(resid)=={'record-difference-'+k for k in ('base-repeat',*variants)} and not any(resid.values())
checks=read(d/'original-probe-equivalence.json')
batch=read(d/'batch-probe-equivalence.json')
assert checks['unchanged'] and len(checks['checks'])>=42 and batch['unchanged'] and batch['capacity']==64 and len(batch['checks'])>=11
tests,states,delta={},{},{}
norm=read(d/'typed-checksums-base.json')['normalized']
for label in ['base',*variants]:
    for fname,actual in [('llvm-identity',ref),('managed-source-identity',managed),('neverd-head',source['neverd'])]:
        assert read(d/(label+'-'+fname+'.json'))==actual
    record=read(d/('record-difference-'+('base-repeat' if label=='base' else label)+'.json'))
    assert record['changed']==0 and record['states']==40068
    states[label]=read(d/(label+'-public-state.json'))
    assert states[label]==states['base'] and states[label].startswith('40068 ')
    a=read(d/('typed-checksums-'+label+'.json'))
    assert a['normalized']==norm and set(a['delta'])==set(norm)
    delta[label]={k:v for k,v in a['delta'].items() if v}
    if label!='base':
        assert not delta[label] and read(d/(label+'-source-tree.json'))['tree']==variants[label]['tree']
    m=re.findall(r'100% tests passed, 0 tests failed out of (\d+)',(d/('tests-'+label+'.log')).read_text())
    assert len(m)==1 and int(m[0])>=257
    tests[label]=int(m[0])
assert len(set(tests.values()))==1
assert read(d/'avx32-corpus.json')['selected_instructions']==7764
def summary(values,seed):
    rng=random.Random(seed)
    boot=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(2500))
    return dict(median=statistics.median(values),ci95=[boot[62],boot[2436]],cycles=values)
review=[]
for x in rows:
    row={k:x[k] for k in ('case','mode','launch','reps','signature')}
    row['comparisons']={}
    per={}
    assert x['reps']>0 and len(x['signature'])==4 and x['signature'][0]>0
    one=norm[x['case']+'/'+str(x['mode'])]
    assert x['signature'][:2]==[n*x['reps'] for n in one[:2]]
    assert set(x['pairs'])=={'base-copy',*variants}
    for label,pair in x['pairs'].items():
        assert len(pair['plans'])==inputs['timing_protocol']['cycles']==7
        per[label]=[sum(v['ticks'][label]) for v in pair['plans']]
        for v in pair['plans']:
            assert set(v['ticks'])=={'base',label} and all(len(vals)==2 and min(vals)>0 for vals in v['ticks'].values())
            assert v['gain']==sum(v['ticks']['base'])/sum(v['ticks'][label])
        out=summary([v['gain'] for v in pair['plans']],repr((row['case'],row['mode'],row['launch'],label)))
        assert out['median']==pair['median']
        row['comparisons'][label]=out
    if not is_combined:
        for a,b in [('family','batch'),('batch','vector_batch')]:
            row['comparisons'][b+' over '+a]=summary([v/z for v,z in zip(per[a],per[b])],repr((row['case'],row['mode'],row['launch'],a,b)))
    review.append(row)
losses={k:[x for x in review if x['comparisons'][k]['median']<.99] for k in review[0]['comparisons']}
report=dict(complete=True,run=run,inputs=inputs,tests=tests,states=states,raw_differences=resid,delta=delta,source=source,
            llvm=llvm,managed=managed,checks=len(checks['checks']),batch_checks=len(batch['checks']),worker_cleanup=read(d/'cleanup.json'),rows=review,
            losses=losses,cases=len(planned),workflow_conclusion=run['conclusion'],digest=read(d/'download.json')['digest'])
(r/'product-review.json').write_text(json.dumps(report,indent=2)+'\n')
print(tests,len(review),'losses', {k:len(v) for k,v in losses.items()})
