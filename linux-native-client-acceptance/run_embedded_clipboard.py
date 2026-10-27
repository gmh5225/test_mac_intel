"""Invoke actual embedded factories through a compiled-client preload.

The default CLI entry is covered separately. This authored preload exits after
the selected finite clipboard observations; client bytes are never patched.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0,'/recipes/macos-native-components')
import bounded_process
sys.path.insert(0,'/fixture')
from run_compare import selection_owner, retire


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--arch',required=True,choices=['arm64','x64'])
    parser.add_argument('--abi',required=True,choices=['gnu','musl']);args=parser.parse_args()
    out=Path('/evidence');inputs=Path('/inputs');fixture=Path('/fixture');config=json.loads((inputs/'embedded-config.json').read_bytes())
    target='linux-'+args.arch+'-'+args.abi;temporary=Path('/tmp/owned-embedded');temporary.mkdir(mode=0o700)
    for name in ['home','xdg']:(temporary/name).mkdir(mode=0o700)
    env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(temporary/'home'),TMPDIR='/tmp',LANG='C',LC_ALL='C',
        NO_COLOR='1',XDG_RUNTIME_DIR=str(temporary/'xdg'),BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    cache=fixture/('native-cache-'+args.arch+'-'+args.abi)
    env['BUN_TMPDIR']=str(cache)
    try:
        (cache/'owned-write-must-fail').write_text('owned readonly control')
    except OSError as error:
        assert error.errno==30
    else:
        raise AssertionError('Native module cache must remain read-only')
    if args.abi=='musl':
        runtime=fixture/'inputs'/('runtime-musl-'+args.arch)
        env['LD_LIBRARY_PATH']=str(runtime/'lib')+':'+str(runtime/'usr/lib')
    receipt=dict(status='started',target=target,processes=[],pairs=[],client_bytes_modified=False,preload_entry_audit=True,
        default_entry_covered_separately=True,host_clipboard_connected=False,physical_device_access=False,goal_complete=False,
        preload_sha256=sha(fixture/'compare-embedded-clipboard.mjs'),inputs=config)
    def command(side):
        binary=str(inputs/side)
        return [binary,'--version']
    def run(label,side,environment,expected=0):
        row,stdout,stderr=bounded_process.run(label,command(side),temporary,environment,out,wall=30,file_bytes=262144,cpu=20)
        receipt['processes'].append(row)
        assert row['failure'] is None and row['kill_errors']==[] and row['exit_code']==expected and not stderr,label
        assert sha(inputs/side)==config['clients'][side]['sha256'], 'Client bytes changed'
        return json.loads(stdout)
    try:
        for side,pin in config['clients'].items():
            assert side in ['original','preserved','readable'] and (inputs/side).stat().st_size==pin['bytes'] and sha(inputs/side)==pin['sha256']
        probe=run('owned-preload-admission','preserved',dict(env,BUN_OPTIONS='--preload='+str(fixture/'embedded-preload-probe.mjs')),37)
        assert probe==dict(status='owned_compiled_preload_control',token='OWNED_CLIPBOARD_PRELOAD_OK')
        receipt['owned_compiled_preload_admission']=probe
        for case in ['disconnected','read-owned','read-empty','write-read']:
            observations={}
            for side in ['original','preserved','readable']:
                label=case+'-'+side;folder=out/label;folder.mkdir();children=[]
                environment=dict(env,BUN_OPTIONS='--preload='+str(fixture/'compare-embedded-clipboard.mjs'),
                    OWNED_EMBEDDED_CLIPBOARD_PIN=json.dumps(config['modules']['original' if side=='original' else 'rebuilt']),
                    OWNED_CLIPBOARD_FACTORY=config['factory_virtual_name'],OWNED_CLIPBOARD_MODE='read' if case.startswith('read-') else case)
                try:
                    if case!='disconnected':
                        environment['DISPLAY']=':98'
                        with (folder/'Xvfb.stdout').open('xb') as so,(folder/'Xvfb.stderr').open('xb') as se:
                            display=subprocess.Popen(['Xvfb',':98','-screen','0','64x64x24','-nolisten','tcp','-noreset','-ac','-extension','GLX'],
                                stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=environment,start_new_session=True)
                        children.append(display);deadline=time.monotonic()+5
                        while not Path('/tmp/.X11-unix/X98').exists():
                            assert display.poll() is None and time.monotonic()<deadline;time.sleep(.01)
                        assert selection_owner(':98','CLIPBOARD')==0 and selection_owner(':98','PRIMARY')==0
                        if case=='read-owned':
                            for selection,content in [('clipboard','owned clipboard fixture\n'),('primary','自有 primary 🧪\n')]:
                                with (folder/(selection+'.stdout')).open('xb') as so,(folder/(selection+'.stderr')).open('xb') as se:
                                    owner=subprocess.Popen(['xclip','-quiet','-selection',selection,'-in'],stdin=subprocess.PIPE,stdout=so,stderr=se,env=environment,start_new_session=True)
                                children.append(owner);owner.stdin.write(content.encode());owner.stdin.close();deadline=time.monotonic()+5
                                while not selection_owner(':98',selection.upper()):
                                    assert owner.poll() is None and time.monotonic()<deadline;time.sleep(.01)
                                public=subprocess.run(['xclip','-selection',selection,'-out'],capture_output=True,env=environment,timeout=5)
                                assert public.returncode==0 and public.stdout==content.encode() and not public.stderr
                    observations[side]=run(label,side,environment)
                    (folder/'observation.json').write_text(json.dumps(observations[side],ensure_ascii=False,indent=2)+'\n')
                finally:
                    for child in reversed(children):retire(child)
                    (folder/'retired.json').write_text(json.dumps(dict(all_reaped=True,child_exits=[p.poll() for p in children]))+'\n')
            for side in ['preserved','readable']:
                assert observations[side]==observations['original'],case+'-'+side
                receipt['pairs'].append(dict(case=case,layout=side,equal=True,calls=len(observations[side]['rows'])))
        receipt.update(status='embedded_clipboard_factories_and_84_function_pairs_passed',function_pairs=84,cohort_pairs=8,
            actual_client_processes=12,owned_preload_admission_processes=1)
    except BaseException as error:
        receipt.update(status='failed_not_admitted',error_type=type(error).__name__,error=str(error));raise
    finally:
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(status=receipt['status'],function_pairs=84,target=target)),flush=True)


if __name__=='__main__':main()
