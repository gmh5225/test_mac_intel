"""Prepared follow-up: read new allocator bodies and raw re-export context."""
from collections import deque
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import traceback

BASE = Path(__file__).resolve().parents[1] / 'wmf-swiftcore-static'
sys.path.insert(0, str(BASE))
spec = importlib.util.spec_from_file_location('saved_core_collector', BASE / 'collect.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
OUT = Path('wmf-allocator-backend-static-records')


def only_load_commands(data):
    """Retain a re-export-only dylib even when it has no function-start table."""
    original_digest = hashlib.sha256(data).hexdigest()
    selected_offset = 0
    magic = int.from_bytes(data[:4], 'big')
    if magic in (0xcafebabe, 0xcafebabf):
        count = struct.unpack_from('>I', shared.bounds(data, 4, 4))[0]
        stride = 20 if magic == 0xcafebabe else 32
        choices = []
        for index in range(count):
            raw = shared.bounds(data, 8 + stride * index, stride)
            if stride == 20:
                cpu, subtype, offset, size, _ = struct.unpack('>5I', raw)
            else:
                cpu, subtype, offset, size, _, _ = struct.unpack('>IIQQII', raw)
            shared.bounds(data, offset, size)
            if cpu == 0x100000c and subtype == 0:
                choices.append((offset, size))
        assert len(choices) == 1
        selected_offset, size = choices[0]
        data = shared.bounds(data, selected_offset, size)
    header = struct.unpack('<8I', shared.bounds(data, 0, 32))
    assert header[:4] == (0xfeedfacf, 0x100000c, 0, 6)
    commands, payloads, position = [], [], 32
    shared.bounds(data, 32, header[5])
    for number in range(header[4]):
        command, size = struct.unpack('<II', shared.bounds(data, position, 8))
        assert size >= 8 and position + size <= 32 + header[5]
        raw = shared.bounds(data, position, size)
        commands.append(dict(index=number, offset=position, cmd=command, cmdsize=size, bytes_hex=raw.hex()))
        if command in (0x80000033, 0x80000034):
            assert size == 16
            _, _, offset, length = struct.unpack('<4I', raw)
            blob = shared.bounds(data, offset, length)
            payloads.append(dict(command_index=number, offset=offset, bytes=length,
                                 sha256=hashlib.sha256(blob).hexdigest(), data_hex=blob.hex()))
        elif command in (0x22, 0x80000022):
            assert size == 48
            values = struct.unpack('<12I', raw)
            for index, kind in enumerate(('rebase','bind','weak_bind','lazy_bind','export')):
                offset, length = values[2 + index*2:4 + index*2]
                blob = shared.bounds(data, offset, length)
                payloads.append(dict(command_index=number,kind=kind,offset=offset,bytes=length,
                    sha256=hashlib.sha256(blob).hexdigest(),data_hex=blob.hex()))
        position += size
    assert position == 32 + header[5]
    return dict(whole_file_sha256=original_digest,selected_slice_offset=selected_offset,
        selected_slice_sha256=hashlib.sha256(data).hexdigest(),selected_slice_bytes=len(data),
        complete_header_words=list(header),complete_load_commands=commands,
        complete_raw_linkedit_payloads=payloads,
        reexport_resolution_or_runtime_availability_inferred=False)


def select_new(image, names, closed):
    pending, seeds, selected, deferred, reused = deque(), [], {}, [], []
    for name in names:
        found = [row for row in image.symbols if row['name']==name and row['type']&0x0e==0x0e and not row['type']&0xe0]
        assert len(found)==1 and found[0]['value'] in image.function_starts, name
        seeds.append(found[0]);pending.append((found[0]['value'],0))
    while pending:
        address,depth=pending.popleft()
        if address in closed:
            reused.append(dict(complete_prior_function=closed[address],old_body_recollected=False))
            continue
        if address in selected:continue
        assert len(selected)<128,'Explicit new-function collection cap reached'
        body=image.function(address);body['collection_depth']=depth;selected[address]=body
        for edge in body['direct_branches']:
            if edge['internal']:continue
            identity=edge['target_identity']
            if identity['kind']=='text_function_interval' and depth<2:
                pending.append((int(identity['function_start'],16),depth+1))
            else:
                deferred.append(dict(from_function=hex(address),edge=edge))
    return dict(seeds=seeds,complete_new_functions=[row for _,row in sorted(selected.items())],
        closed_prior_function_hash_references=reused,deferred_direct_edges=deferred,
        complete_call_closure_or_effect_or_lifetime_qualified=False)


def main():
    shared.OUT=OUT;OUT.mkdir()
    assert os.environ.get('RUNNER_ARCH')=='ARM64'
    assert os.environ.get('DEVELOPER_DIR')==str(shared.DEVELOPER)
    assert shutil.disk_usage(OUT).free>=512*1024*1024
    pins=json.loads((Path(__file__).parent/'pins.json').read_text())
    raw=shared.run('actual-current-runtime-path',['xcrun','simctl','list','runtimes','--json'])
    runtimes=json.loads(raw)['runtimes']
    matches=[row for row in runtimes if row.get('identifier')=='com.apple.CoreSimulator.SimRuntime.iOS-26-5']
    assert len(matches)==1
    runtime=matches[0];shared.save('actual-current-runtime-record.json',runtime)
    assert runtime['version']=='26.5' and runtime['buildversion']=='23F77' and runtime['isAvailable'] is True
    root=Path(runtime['runtimeRoot']);assert root.is_absolute()
    version=plistlib.loads((root/'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion']=='26.5' and version['ProductBuildVersion']=='23F77'
    shared.save('actual-current-runtime-version.json',version)
    relative='usr/lib/libSystem.B.dylib'
    shared.save('LibSystem-complete-raw-reexport-context.json',dict(path=str(root/relative),
        **only_load_commands((root/relative).read_bytes())))
    providers=[
        ('Core','usr/lib/swift/libswiftCore.dylib',['__ZN5swift11fatalErrorvEjPKcPc','_OUTLINED_FUNCTION_0']),
        ('malloc','usr/lib/system/libsystem_malloc.dylib',['_malloc_type_malloc','_malloc_type_posix_memalign']),
        ('objc','usr/lib/libobjc.A.dylib',['_class_createInstance','_objc_release'])]
    summaries=[]
    with tempfile.TemporaryDirectory(prefix='wmf-new-backend-static-',dir=os.environ['RUNNER_TEMP']) as temporary:
        for name,relative,seeds in providers:
            image=shared.MachO((root/relative).read_bytes())
            assert image.header['filetype']==6 and image.versions and all(row['platform']==7 for row in image.versions)
            closed={}
            if name=='Core':
                assert image.uuid==pins['Core']['uuid'] and image.whole_sha256==pins['Core']['whole_file_sha256']
                assert image.slice_sha256==pins['Core']['selected_slice_sha256']
                closed={int(row['start'],16):row for row in pins['Core']['closed_functions']}
                shared.save('Core-same-file-hash-and-closed-reference.json',dict(pins=pins['Core'],
                    current_uuid=image.uuid,current_whole_sha256=image.whole_sha256,
                    old_complete_metadata_and_raw_context_not_recollected=True))
            else:
                if name=='objc':assert image.uuid==pins['objc_UUID']
                shared.save(name+'-complete-new-MachO-metadata.json',dict(path=str(root/relative),**image.manifest()))
                shared.save(name+'-complete-new-import-fixup-unwind-context.json',shared.raw_context(image))
            domain=select_new(image,seeds,closed)
            shared.save(name+'-complete-new-function-domain.json',domain)
            thin=Path(temporary)/(name+'-arm64.dylib');thin.write_bytes(image.data)
            for body in domain['complete_new_functions']:
                shared.run(name+'-function-'+body['start'][2:]+'-complete-disassembly',
                    ['xcrun','llvm-objdump','--disassemble','--start-address='+body['start'],
                     '--stop-address='+body['end'],str(thin)])
            summaries.append(dict(provider=name,uuid=image.uuid,whole_file_sha256=image.whole_sha256,
                slice_sha256=image.slice_sha256,seeds=seeds,new_functions=len(domain['complete_new_functions']),
                closed_Core_functions_recollected=0))
    shared.save('complete-new-backend-static-result.json',dict(status='PASS',run_id=os.environ['GITHUB_RUN_ID'],
        commit=os.environ['GITHUB_SHA'],summaries=summaries,
        original_provider_match_or_reexport_resolution_or_valid_region_or_call_effect_permission=False,
        old_eight_Core_function_disassemblies_reexecuted=0,
        Simulator_boot_provider_execution_original_WMF_loading_execution=0))


if __name__=='__main__':
    try:main()
    except BaseException:
        if OUT.is_dir():shared.save('failure.json',dict(traceback=traceback.format_exc()))
        raise
