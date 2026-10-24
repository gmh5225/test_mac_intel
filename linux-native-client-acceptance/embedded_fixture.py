"""Stage exact readonly native-loader cache for finite compiled-client probes."""
from pathlib import Path
import json
import os
import shutil


def accept(root, private, abi, inputs, clients, extracted, mapping, expected, engine, sdk, image, run):
    fixture = private/'embedded-fixture'
    if not fixture.exists():
        fixture.mkdir(); (fixture/'inputs').mkdir()
        for name in ['run_embedded_clipboard.py','compare-embedded-clipboard.mjs','embedded-preload-probe.mjs']:
            shutil.copyfile(root/name,fixture/name)
        public = root.parent/'linux-clipboard-addon-acceptance'
        for name in ['run_compare.py','owned_blocked_display.py','owned_wayland_display.py','owned_large_x11.py']:
            shutil.copyfile(public/name,fixture/name)
        run('embedded-public-musl-runtime', ['python3','-B','-c',
            'import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from runtime_sdk import prepare;prepare("x64",Path(sys.argv[2]),Path(sys.argv[3]))',
            private/'recipes/musl-native-components',sdk,fixture/'inputs/runtime-musl-x64'])
        loader = fixture/'inputs/owned-musl-loader-x64'
        shutil.copyfile(fixture/'inputs/runtime-musl-x64/lib/ld-musl-x86_64.so.1',loader); loader.chmod(0o500)
    runtime = private/('runtime-'+abi)/'embedded'; runtime.mkdir()
    stage = runtime/'inputs'; stage.mkdir()
    originals = extracted/'input'/mapping[2346][5]
    replacements = private/'module-replacements'/('clipboard-'+abi+'.node')
    source_engine = private/'admitted-gnu/bun'
    common = ['docker','run','--rm','--init','--platform','linux/amd64','--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}','--cpus','2','--memory','3g',
        '--pids-limit','128','--ulimit','core=0','--tmpfs','/tmp:rw,nosuid,nodev,size=512m']
    hashes = json.loads(run('embedded-hash-'+abi,[*common,'--mount',f'type=bind,src={originals},dst=/data/original,readonly',
        '--mount',f'type=bind,src={replacements},dst=/data/rebuilt,readonly','--mount',f'type=bind,src={source_engine},dst=/runtime/bun,readonly',
        image,'/runtime/bun','-e',"const rows=[];for(const side of ['original','rebuilt']){const b=await Bun.file('/data/'+side).arrayBuffer();rows.push({side,bytes:b.byteLength,wyhash:Bun.hash.wyhash(b).toString(16)});}console.log(JSON.stringify(rows));"],60))
    cache = fixture/('native-cache-x64-'+abi); cache.mkdir()
    config = dict(target='linux-x64-'+abi,clients={},modules={},factory_virtual_name=expected['rows'][10]['virtual_name'])
    from hashlib import file_digest
    def pin(path):
        with path.open('rb') as stream: digest=file_digest(stream,'sha256').hexdigest()
        return dict(bytes=path.stat().st_size,sha256=digest)
    for row in hashes:
        source = originals if row['side']=='original' else replacements
        assert row['bytes']==source.stat().st_size and len(row['wyhash'])<=16 and all(c in '0123456789abcdef' for c in row['wyhash'])
        path = cache/('.bun-'+str(os.getuid())+'-'+row['wyhash']+'.node')
        shutil.copyfile(source,path); path.chmod(0o400); config['modules'][row['side']] = pin(path)
    assert set(config['modules'])=={'original','rebuilt'}
    for side in ['original','preserved','readable']:
        source = inputs/'original' if side=='original' else clients/side/'client-final'
        os.link(source,stage/side); config['clients'][side] = pin(source)
    (stage/'embedded-config.json').write_text(json.dumps(config,indent=2)+'\n')
    records = runtime/'execution-records'; records.mkdir()
    command = [*common,'--mount',f'type=bind,src={fixture},dst=/fixture,readonly',
        '--mount',f'type=bind,src={private}/recipes,dst=/recipes,readonly','--mount',f'type=bind,src={stage},dst=/inputs,readonly']
    if abi=='musl':
        command += ['--mount',f'type=bind,src={fixture}/inputs/owned-musl-loader-x64,dst=/lib/ld-musl-x86_64.so.1,readonly']
    command += ['--mount',f'type=bind,src={records},dst=/evidence',image,'python3','-B','/fixture/run_embedded_clipboard.py','--arch','x64','--abi',abi]
    run('embedded-'+abi,command,240)
    proof = json.loads((records/'receipt.json').read_bytes())
    assert proof['status']=='embedded_clipboard_factories_and_84_function_pairs_passed' and proof['function_pairs']==84
    assert proof['client_bytes_modified'] is False and proof['host_clipboard_connected'] is False
    # The sealer retains all sources through the build-logs namespace.
    sources = private/'build-logs'/('embedded-'+abi); sources.mkdir()
    for name in ['run_embedded_clipboard.py','compare-embedded-clipboard.mjs','embedded-preload-probe.mjs']:
        shutil.copyfile(root/name,sources/name)
    return dict(function_pairs=84,cohort_pairs=8,actual_client_processes=12,owned_preload_admission_processes=1,
        inputs=config,receipt_sha256=pin(records/'receipt.json')['sha256'],readonly_cache=True,noexec_tmp_retained=True)
