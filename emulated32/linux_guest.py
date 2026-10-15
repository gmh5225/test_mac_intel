#!/usr/bin/env python3
"""Run authenticated patch images inside a complete 32-bit Linux guest."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import zipfile

ROOT = Path('/work')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
report = {'schema':'neverd.emulated32.linux-system.v1','execution_kind':'qemu-system-tcg',
          'native_qualification':False,'guest':{'machine':platform.machine(),'kernel':platform.release(),
          'pointer_bits':struct.calcsize('P')*8,'cpuinfo':Path('/proc/cpuinfo').read_text()},
          'observations':[],'complete':False}
try:
    assert struct.calcsize('P')==4 and platform.machine().startswith('armv7')
    report['packages'] = subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version} ${Architecture}\n','libc6','python3','wine32','libwine'],text=True)
    archive=ROOT/'qualified-images.zip'
    assert sha(archive)=='ad7cdad1ebab507ff99a64b913ddf2c03d9503e1a54deae715981bfa1805e6ce'
    expected={mode+'-original':9 for mode in ['arm','thumb']}
    expected.update({mode+'-'+case+'-'+route:code for mode in ['arm','thumb']
                     for case,code in [('nonleaf',87),('writable-pointer',92),('floating-stack',93)]
                     for route in ['ir','object','supplied-object','gcc-source','gcc-object']})
    dst=ROOT/'linux-images'; dst.mkdir()
    with zipfile.ZipFile(archive) as z:
        manifest=json.loads(z.read('manifest.json'))
        assert manifest['commit']=='fcee81c9a5e2f20a71090ade23ae833175f64c59'
        assert len(manifest['images'])==32 and {r['case'] for r in manifest['images']}==set(expected)
        for row in manifest['images']:
            name=row['path']; assert Path(name).name==name
            (dst/name).write_bytes(z.read(name)); (dst/name).chmod(0o755)
    report['image_commit']=manifest['commit']
    report['engine_source_digest']=manifest['engine_source_digest']
    report['loader']={'path':'/lib/ld-linux-armhf.so.3','sha256':sha(Path('/lib/ld-linux-armhf.so.3'))}
    def run_image(row,kind,cmd,code):
        path=(dst/row['path']) if kind=='linux-arm32' else (ROOT/'pe-arm32'/row['path'])
        assert sha(path)==row['sha256']
        for repeat in range(3):
            obs={'profile':kind,'case':row['case'],'sha256':row['sha256'],'repeat':repeat,
                 'expected':code,'command':cmd}
            try:
                r=subprocess.run(cmd,capture_output=True,timeout=20,env=dict(os.environ,WINEDEBUG='-all',WINEPREFIX='/root/wine32',WINEARCH='win32'))
                obs.update(actual=r.returncode,stdout=r.stdout.decode(errors='replace'),stderr=r.stderr.decode(errors='replace'))
            except (OSError,subprocess.TimeoutExpired) as e: obs['error']=str(e)
            report['observations'].append(obs)
        assert sha(path)==row['sha256']
    for row in manifest['images']:
        run_image(row,'linux-arm32',[str(dst/row['path'])],expected[row['case']])
    pe=json.loads((ROOT/'pe-arm32/manifest.json').read_text())
    expected_pe={'original':9, **{case+'-'+route:code for case,code in [('nonleaf',87),('writable-pointer',92),('floating-stack',93)] for route in ['ir','object','supplied-object']}}
    assert len(pe['images'])==10 and pe['cpu']==0x1c4 and pe['platform']=='windows-arm32'
    assert {r['case'] for r in pe['images']}==set(expected_pe)
    for row in pe['images']:
        assert Path(row['path']).name==row['path'] and row['expected']==expected_pe[row['case']]
        image=ROOT/'pe-arm32'/row['path']; assert sha(image)==row['sha256']
        data=image.read_bytes(); assert data[:2]==b'MZ'
        offset=struct.unpack_from('<I',data,0x3c)[0]
        assert data[offset:offset+4]==b'PE\0\0' and struct.unpack_from('<H',data,offset+4)[0]==0x1c4
        if row['case']!='original':
            assert Path(row['receipt']).name==row['receipt']
            receipt=ROOT/'pe-arm32'/row['receipt'];assert sha(receipt)==row['receipt_sha256']
            obj=json.loads(receipt.read_text());assert obj['schema']=='neverd.source-patch.v1' and obj['success'] and len(obj['installed'])==1
    report['pe_manifest']=pe
    report['pe_manifest_sha256']=sha(ROOT/'pe-arm32/manifest.json')
    # Initialize the real Wine ARM32 loader before any measured patch launch.
    init=subprocess.run(['/usr/lib/wine/wine','wineboot','-u'],capture_output=True,timeout=90,
        env=dict(os.environ,WINEDEBUG='-all',WINEPREFIX='/root/wine32',WINEARCH='win32'))
    report['wine_initialization']={'actual':init.returncode,'stdout':init.stdout.decode(errors='replace'),'stderr':init.stderr.decode(errors='replace')}
    assert init.returncode==0
    for row in pe['images']:
        run_image(row,'pe-arm32-wine',['/usr/lib/wine/wine',str(ROOT/'pe-arm32'/row['path'])],expected_pe[row['case']])
    assert len(report['observations'])==126
    assert all(x.get('actual')==x['expected'] for x in report['observations'])
    report['complete']=True
except Exception as e:
    report['error']=repr(e)
finally:
    raw=json.dumps(report,sort_keys=True).encode()
    print('NEVERD_GUEST_REPORT:'+base64.b64encode(raw).decode(),flush=True)
    print('NEVERD_GUEST_DONE:'+str(report['complete']),flush=True)
