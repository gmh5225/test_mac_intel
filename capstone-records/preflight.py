from pathlib import Path
import json
import os
import subprocess as sp
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir(exist_ok=True)
installed=sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
assert installed
perf=str(installed[-1]);setting=Path('/proc/sys/kernel/perf_event_paranoid');original=setting.read_text().strip()
permission=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid=-1'],capture_output=True,text=True)
audit=dict(original_setting=original,permission_returncode=permission.returncode,
 cpu=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')))
try:
 result=sp.run([perf,'stat','-x,','-e','{cycles:u,instructions:u,branches:u,branch-misses:u}','--','/bin/true'],capture_output=True,text=True)
 events={line.split(',')[2]:line.split(',')[0] for line in result.stderr.splitlines() if len(line.split(','))>=5}
 required={'cycles:u','instructions:u','branches:u','branch-misses:u'}
 audit.update(supported=result.returncode==0 and set(events)>=required and all(events[k].isdigit() for k in required),returncode=result.returncode,stderr=result.stderr,events=events)
finally:
 if permission.returncode==0:
  restore=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid='+original],capture_output=True,text=True)
  audit['restore_returncode']=restore.returncode
 audit['final_setting']=setting.read_text().strip();audit['setting_restored']=audit['final_setting']==original
 (e/'preflight.json').write_text(json.dumps(audit,indent=2)+'\n');assert audit['setting_restored']
with Path(os.environ['GITHUB_OUTPUT']).open('a') as out:out.write('supported='+str(audit['supported']).lower()+'\n')
print(json.dumps(audit))
