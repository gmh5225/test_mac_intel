#!/usr/bin/env python3
"""Boot an ARM32 Debian kernel under QEMU TCG and audit the complete report."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

out=Path('emulated32-evidence'); out.mkdir(exist_ok=True)
root=Path('guest')
kernel=list((root/'boot').glob('vmlinuz-*')); initrd=list((root/'boot').glob('initrd.img-*'))
assert len(kernel)==len(initrd)==1
cmd=['qemu-system-arm','-accel','tcg','-M','virt','-cpu','cortex-a15','-m','1024','-smp','2',
     '-kernel',str(kernel[0]),'-initrd',str(initrd[0]),'-append','root=/dev/vda rw console=ttyAMA0 init=/neverd-init',
     '-drive','file=guest.ext4,if=none,format=raw,id=root','-device','virtio-blk-device,drive=root',
     '-net','none','-display','none','-serial','stdio','-no-reboot']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
meta={'schema':'neverd.emulated32.host.v1','run_id':os.environ['GITHUB_RUN_ID'],'run_attempt':os.environ['GITHUB_RUN_ATTEMPT'],
      'harness_commit':os.environ['GITHUB_SHA'],'host_machine':platform.machine(),'command':cmd,
      'qemu_version':subprocess.check_output(['qemu-system-arm','--version'],text=True),
      'kernel':{p.name:sha(p) for p in kernel+initrd},'complete':False}
try:
    with (out/'console.log').open('wb') as log:
        result=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=420)
    meta['qemu_exit']=result.returncode
    console=(out/'console.log').read_text(errors='replace')
    rows=re.findall(r'^NEVERD_GUEST_REPORT:([A-Za-z0-9+/=]+)\r?$',console,re.M)
    assert len(rows)==1, 'missing or duplicate guest report'
    raw=base64.b64decode(rows[0],validate=True)
    (out/'runtime.json').write_bytes(raw+b'\n')
    report=json.loads(raw)
    assert report['complete'] and len(report['observations'])==126,report.get('error')
    assert len({(r['profile'],r['case'],r['repeat']) for r in report['observations']})==126
    assert all(r.get('actual')==r['expected'] for r in report['observations'])
    assert report['guest']['pointer_bits']==32 and report['guest']['machine'].startswith('armv7')
    assert report['execution_kind']=='qemu-system-tcg' and not report['native_qualification']
    assert result.returncode==0
    meta['complete']=True
    print('Verified 96 Linux and 30 Wine ARM32 observations inside a complete emulated ARM32 kernel.')
finally:
    (out/'host.json').write_text(json.dumps(meta,indent=2)+'\n')
