from pathlib import Path
import json,subprocess as sp,sys
from compare_traces import inspect
r=Path(__file__).resolve().parent;out=r.parent/'evidence'
for k in ('base','candidate'):sp.run([sys.executable,'-B',r/'stage.py',k],check=True)
(out/'delta.json').write_text(json.dumps(inspect(out),indent=2)+chr(10))
receipts=[json.loads((out/k/'cleanup.json').read_text())for k in ('base','candidate')];assert all(v['removed']for v in receipts)
(out/'cleanup.json').write_text(json.dumps(dict(removed=True,bytes=sum(v['bytes']for v in receipts)))+chr(10))
