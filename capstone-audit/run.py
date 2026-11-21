from pathlib import Path
import hashlib,json,subprocess as sp,zipfile
r=Path(__file__).parent
repo='repos/gmh5225/test_mac_intel/actions/'
def api(path):return json.loads(sp.check_output(['gh','api',repo+path]))
def write(f,v):f.write_text(json.dumps(v,indent=2)+'\n')
run=api('runs/44858282420')
assert run['head_sha']==(r/'product-check/revision.txt').read_text().strip() and run['conclusion']=='failure'
write(r/'product-run.json',{k:run[k] for k in ('id','head_sha','status','conclusion','html_url','run_attempt')})
artifact,=api('runs/44858282420/artifacts')['artifacts']
info={k:artifact[k] for k in ('id','name','digest','size_in_bytes')}
assert info==json.loads((r/'input-artifact.json').read_text())
path=r/'raw.zip'
with path.open('wb') as f:sp.run(['gh','api',repo+'artifacts/'+str(info['id'])+'/zip'],stdout=f,check=True)
assert hashlib.sha256(path.read_bytes()).hexdigest()==info['digest'].split(':')[1]
dest=r/'product'/info['name'];dest.mkdir(parents=True)
with zipfile.ZipFile(path) as f:
    assert all(not Path(x).is_absolute() and '..' not in Path(x).parts for x in f.namelist())
    f.extractall(dest)
write(dest/'download.json',info)
log=sp.check_output(['gh','api','--allow-escape-sequences',repo+'jobs/136705498638/logs'],text=True)
a=log.rindex('Traceback (most recent call last)');z=log.index('##[error]',a)
(r/'failure-step.log').write_text(log[a:z])
sp.run(['python3','-B',r/'review-product.py'],check=True)
out=json.loads((r/'product-review.json').read_text())
assert out['cases']==52 and all(v==257 for v in out['tests'].values()) and not any(out['raw_differences'].values())
path.unlink()
