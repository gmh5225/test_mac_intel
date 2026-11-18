from pathlib import Path
import json
import subprocess as sp
r=Path(__file__).resolve().parent
s=r.parent/'source'
inputs=json.loads((r/'inputs.json').read_text())
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
assert inputs['source_parent'] == inputs['baseline_commit']
assert git('rev-parse','HEAD') == inputs['baseline_commit']
assert git('rev-parse','HEAD^{tree}') == inputs['baseline_tree']
assert not git('status','--porcelain')
assert sp.check_output(['git','-C',s,'cat-file','commit','HEAD']) == (r/'baseline.commit').read_bytes()
print('Verified the published baseline fetched directly, including its exact commit contents and tree.')
