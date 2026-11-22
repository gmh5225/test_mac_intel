from pathlib import Path
import json,subprocess as sp,sys
p=Path(__file__).resolve().parent;out=p.parent/'evidence';out.mkdir(exist_ok=True)
model=next(l.split(':',1)[1].strip() for l in sp.check_output(['lscpu'],text=True).splitlines() if l.startswith('Model name:'))
selected='EPYC 9V45' in model
(out/'cpu-selection.json').write_text(json.dumps(dict(exact=selected,cpu=model))+'\n')
if selected:sp.run([sys.executable,'-B',p/'native.py'],check=True)
