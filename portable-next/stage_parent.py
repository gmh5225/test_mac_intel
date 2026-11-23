"""Materialize the verified base commit in this disposable CI checkout."""
from pathlib import Path
import hashlib,json,subprocess as sp
d=Path(__file__).resolve().parent;s=d.parent/'source'
def git(*args,repo=s,data=None):return sp.check_output(['git','-C',repo,*args],input=data).strip().decode()
def blob(f):return sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:'+d.name+'/'+f])
q=json.loads(blob('parent.json'));source=git('rev-parse','HEAD')
assert source==q['parent'] and not git('status','--porcelain')
patch=blob('parent.patch');assert hashlib.sha256(patch).hexdigest()==q['sha256']
git('apply','--index','--binary','-',data=patch);assert git('write-tree')==q['tree']
h=git('hash-object','-w','-t','commit','--stdin',data=blob('parent.commit'));assert h==q['commit'] and git('rev-parse',h+'^')==source and git('rev-parse',h+'^{tree}')==q['tree']
git('reset','--soft',h);assert not git('status','--porcelain')
