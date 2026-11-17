from pathlib import Path
import hashlib
import json
import subprocess as sp

r=Path(__file__).resolve().parent
s=r.parent/'source'
inputs=json.loads((r/'experiment.json').read_text())
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
if git('rev-parse', 'HEAD') == inputs['baseline_commit']:
    assert not git('status', '--porcelain')
    assert git('rev-parse', 'HEAD^{tree}') == inputs['baseline_tree']
    assert sp.check_output(['git', '-C', s, 'cat-file', 'commit', 'HEAD']) == (r / 'baseline.commit').read_bytes()
    print('Verified the exact published baseline commit and tree fetched directly.')
    raise SystemExit(0)
assert git('rev-parse','HEAD')==inputs['source_parent']
assert not git('status','--porcelain')
patch=r/'baseline.patch'
assert hashlib.sha256(patch.read_bytes()).hexdigest()==inputs['baseline_patch_sha256']
git('apply','--index',str(patch))
assert git('write-tree')==inputs['baseline_tree']
assert git('hash-object','-t','commit','-w',str(r/'baseline.commit'))==inputs['baseline_commit']
git('checkout','-q','--detach',inputs['baseline_commit'])
assert git('rev-parse','HEAD^{tree}')==inputs['baseline_tree']
assert not git('status','--porcelain')
print('Exact prepared baseline commit and source tree reconstructed without publishing it.')
