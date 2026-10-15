#!/usr/bin/env python3
"""Record limited legacy Mach-O compatibility/HLE execution, never native OS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import struct
import subprocess

EXPECTED={'original':9, **{case+'-'+route:code for case,code in [('nonleaf',87),('writable-pointer',92),('floating-stack',93)] for route in ['ir','object','supplied-object']}}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def load_images(directory, profile):
    manifest=json.loads((directory/'manifest.json').read_text())
    cpu, subtype={'macos-i386':(7,3),'ios-armv7':(12,9),'watchos-armv7k':(12,12)}[profile]
    assert manifest['platform']==profile and len(manifest['images'])==10
    assert (manifest['cpu'],manifest['cpu_subtype'])==(cpu,subtype)
    assert {r['case'] for r in manifest['images']}==set(EXPECTED)
    for row in manifest['images']:
        assert row['expected']==EXPECTED[row['case']] and Path(row['path']).name==row['path']
        image=directory/row['path']; assert sha(image)==row['sha256']
        data=image.read_bytes()
        assert struct.unpack_from('<III',data)==(0xfeedface,manifest['cpu'],manifest['cpu_subtype'])
        if row['case']!='original':
            assert Path(row['receipt']).name==row['receipt']
            receipt=directory/row['receipt'];assert sha(receipt)==row['receipt_sha256']
            obj=json.loads(receipt.read_text());assert obj['schema']=='neverd.source-patch.v1' and obj['success'] and len(obj['installed'])==1
            assert obj['requested']==[{'original_va':obj['installed'][0]['original_va'],'symbol':obj['installed'][0]['symbol']}]
    return manifest

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['darling','touchhle'],required=True)
    p.add_argument('--executable',type=Path,required=True)
    p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();exe=a.executable.absolute();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    profiles=['macos-i386'] if a.mode=='darling' else ['ios-armv7','watchos-armv7k']
    report={'schema':'neverd.emulated32.apple.v1','execution_kind':a.mode,'native_qualification':False,
            'apple_os_qualification':False,'watchos_runtime_qualification':False,
            'host':{'system':platform.system(),'machine':platform.machine(),'kernel':platform.release()},
            'harness_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
            'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'executor_sha256':sha(exe),
            'inputs':{},'observations':[],'complete':False}
    def save(): (out/'runtime.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        if a.mode=='darling':
            assert platform.system()=='Linux' and platform.machine()=='x86_64'
            env=dict(os.environ,DPREFIX=str(out/'darling-prefix'))
            init=subprocess.run([str(exe),'shell','uname','-a'],capture_output=True,timeout=60,env=env)
            report['initialization']={'actual':init.returncode,'stdout':init.stdout.decode(errors='replace'),'stderr':init.stderr.decode(errors='replace')}
            assert init.returncode==0
        else:env=dict(os.environ)
        for profile in profiles:
            directory=(a.inputs/profile).resolve();manifest=load_images(directory,profile)
            report['inputs'][profile]={'manifest_sha256':sha(directory/'manifest.json'),'manifest':manifest}
            for row in manifest['images']:
                path=directory/row['path'];path.chmod(0o755)
                if a.mode=='darling':
                    cmd=[str(exe),'shell','/Volumes/SystemRoot'+str(path)]
                else:
                    app=out/(profile+'-'+row['case']+'.app');app.mkdir()
                    shutil.copy2(path,app/'Probe')
                    (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'Probe','CFBundleIdentifier':'org.neverd.'+profile+'.'+row['case'],
                        'CFBundleName':'Probe','CFBundleVersion':'1','MinimumOSVersion':'5.0','CFBundleSupportedPlatforms':['iPhoneOS']}))
                    assert sha(app/'Probe')==row['sha256']
                    cmd=[str(exe),str(app),'--headless']
                for repeat in range(3):
                    obs={'profile':profile,'case':row['case'],'repeat':repeat,'expected':EXPECTED[row['case']],
                         'sha256':row['sha256'],'command':cmd}
                    try:
                        run=subprocess.run(cmd,capture_output=True,timeout=20,env=env,cwd=exe.parent if a.mode=='touchhle' else None)
                        obs.update(actual=run.returncode,stdout=run.stdout.decode(errors='replace'),stderr=run.stderr.decode(errors='replace'))
                    except (OSError,subprocess.TimeoutExpired) as e:obs['error']=repr(e)
                    report['observations'].append(obs);save()
                assert sha(path)==row['sha256']
        assert len(report['observations'])==30*len(profiles)
        assert all(row.get('actual')==row['expected'] for row in report['observations'])
        report['complete']=True
        print(a.mode,':',len(report['observations']),'complete expected exits; no Apple OS qualification.')
    finally:save()

if __name__=='__main__':main()
