from pathlib import Path
import datetime
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import traceback

from macho import MachO

OUT = Path('wmf-block-provider-records')
ROOT = Path('/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot')
DEVELOPER = Path('/Applications/Xcode_26.5.app/Contents/Developer')
SDK = DEVELOPER / 'Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk'
EXPECTED = {
    'dispatch': ('usr/lib/system/libdispatch.dylib', '42B50931-38D5-3A5D-90EF-0FD7239C408D'),
    'Blocks': ('usr/lib/system/libsystem_blocks.dylib', 'A5FDF1FF-B793-3574-8903-D24571EACD25'),
}
SEEDS = {
    'dispatch': ['_dispatch_source_set_event_handler', '_dispatch_source_set_cancel_handler',
                 '_dispatch_source_cancel', '_dispatch_source_set_timer'],
    'Blocks': ['__Block_copy', '__Block_release', '__Block_object_assign', '__Block_object_dispose'],
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(name, value):
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def run(label, argv):
    record = dict(argv=[str(value) for value in argv], started=now(), developer_dir=os.environ.get('DEVELOPER_DIR'))
    with (OUT / (label + '.stdout')).open('xb') as stdout, (OUT / (label + '.stderr')).open('xb') as stderr:
        try:
            process = subprocess.run(record['argv'], stdout=stdout, stderr=stderr, timeout=55)
            record['returncode'] = process.returncode
        except subprocess.TimeoutExpired:
            record['returncode'] = None
            record['timed_out'] = True
    record['ended'] = now()
    for name in ('stdout', 'stderr'):
        data = (OUT / (label + '.' + name)).read_bytes()
        record[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    save(label + '-command.json', record)
    assert record['returncode'] == 0, label
    return record


def collect_provider(name, relative, expected, temporary):
    path = ROOT / relative
    image = MachO(path.read_bytes())
    assert image.uuid == expected
    assert image.header['filetype'] == 6
    assert image.versions and all(version['platform'] == 7 for version in image.versions)
    save(name + '-complete-static-MachO-metadata.json', dict(path=str(path), **image.manifest()))
    thin = temporary / (name + '-arm64.dylib')
    with thin.open('xb') as stream:
        stream.write(image.data)
    seed_rows = []
    pending = []
    for symbol_name in SEEDS[name]:
        symbols = [item for item in image.symbols if item['name'] == symbol_name and item['type'] & 0x0e == 0x0e and not item['type'] & 0xe0]
        assert len(symbols) == 1, symbol_name
        address = symbols[0]['value']
        assert address in image.function_starts
        seed_rows.append(dict(requested_name=symbol_name, symbol=symbols[0], function_start=hex(address)))
        pending.append((address, 0))
    selected = {}
    deferred = []
    while pending:
        address, depth = pending.pop(0)
        if address in selected:
            continue
        assert len(selected) < 128, 'Explicit static collection cap; not a source qualification'
        function = image.function(address)
        function['collection_depth'] = depth
        selected[address] = function
        for edge in function['direct_branches']:
            if edge['internal']:
                continue
            identity = edge['target_identity']
            if identity['kind'] == 'text_function_interval':
                start = int(identity['function_start'], 16)
                if start not in selected:
                    if depth < 2:
                        pending.append((start, depth + 1))
                    else:
                        deferred.append(dict(from_function=hex(address), edge=edge, reason='outside_two_direct_callee_layers'))
    for address, function in sorted(selected.items()):
        label = name + '-function-' + format(address, 'x')
        save(label + '-complete-bits.json', function)
        run(label + '-disassembly', ['xcrun', 'llvm-objdump', '--disassemble',
            '--start-address=' + function['start'], '--stop-address=' + function['end'], str(thin)])
    scope = dict(provider=name, source_path=str(path), expected_previously_loaded_UUID=expected,
                 current_static_file_UUID=image.uuid, static_file_matches_previously_loaded_identity=True,
                 current_runtime_loading_not_queried=True, whole_file_sha256=image.whole_sha256,
                 selected_arm64_sha256=image.slice_sha256, seeds=seed_rows,
                 selected_functions=[dict(start=body['start'], end=body['end'], sha256=body['code_sha256'], depth=body['collection_depth'])
                                     for _, body in sorted(selected.items())],
                 deferred_direct_targets=deferred, indirect_branch_count=sum(len(body['indirect_branches']) for body in selected.values()),
                 function_bodies_complete=True, two_direct_callee_layers_only=True,
                 complete_call_closure_or_effect_or_lifetime_qualification=False,
                 SDK_or_original_Options_or_ABI_changed=False, original_WMF_loaded_or_executed=False)
    save(name + '-selected-function-scope.json', scope)
    return scope


def resolve_current_target_runtime():
    run('actual-target26_5-runtime-resolution', ['xcrun', 'simctl', 'list', 'runtimes', '--json'])
    result = json.loads((OUT / 'actual-target26_5-runtime-resolution.stdout').read_bytes())
    candidates = [runtime for runtime in result['runtimes']
                  if runtime.get('identifier') == 'com.apple.CoreSimulator.SimRuntime.iOS-26-5']
    assert len(candidates) == 1
    runtime = candidates[0]
    assert runtime['version'] == '26.5' and runtime['buildversion'] == '23F77'
    assert runtime['isAvailable'] is True and 'arm64' in runtime['supportedArchitectures']
    root = runtime['runtimeRoot']
    assert isinstance(root, str) and Path(root).is_absolute()
    save('actual-current-target26_5-runtime-record.json', runtime)
    return Path(root)


def main():
    global ROOT
    OUT.mkdir()
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(DEVELOPER)
    assert shutil.disk_usage(OUT).free > 512 * 1024 * 1024
    run('actual-Xcode26_5-version', ['xcodebuild', '-version'])
    settings = (SDK / 'SDKSettings.json').read_bytes()
    decoded = json.loads(settings)
    assert decoded['Version'] == '26.5'
    assert decoded['SupportedTargets']['iphonesimulator']['BuildVersionPlatformID'] == '7'
    assert '17.6' in decoded['SupportedTargets']['iphonesimulator']['ValidDeploymentTargets']
    (OUT / 'actual-SDK26_5-Settings.json').write_bytes(settings)
    ROOT = resolve_current_target_runtime()
    version = plistlib.loads((ROOT / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion'] == '26.5' and version['ProductBuildVersion'] == '23F77'
    save('actual-runtime26_5-version.json', version)
    headers = []
    for relative in ('usr/include/dispatch/source.h', 'usr/include/dispatch/block.h', 'usr/include/Block.h'):
        source = SDK / relative
        data = source.read_bytes()
        target = OUT / ('SDK26_5-' + relative.replace('/', '-'))
        with target.open('xb') as stream:
            stream.write(data)
        headers.append(dict(source=str(source), artifact=target.name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    save('actual-complete-three-SDK-headers.json', headers)
    temporary = Path(os.environ['RUNNER_TEMP']) / ('wmf-static-block-provider-' + os.environ['GITHUB_RUN_ID'])
    temporary.mkdir()
    scopes = []
    for name, (relative, expected) in EXPECTED.items():
        scopes.append(collect_provider(name, relative, expected, temporary))
    manifest = dict(timestamp=now(), scope='new_static_platform7_provider_function_implementation_domain',
        run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'], runner_image=os.environ.get('ImageVersion'),
        SDK='26.5', runtime='26.5', runtime_build='23F77', developer=str(DEVELOPER),
        scopes=scopes, no_original_WMF_or_generated_C_upload_loading_or_execution=True,
        original_provider_match_or_complete_call_closure_or_source_effect_or_lifetime_qualified=False,
        no_previous_inventory_or_runtime_probe_rerun=True, Apple_provider_binaries_uploaded=False,
        SDK_NeverD_or_original_pipeline_or_Options_or_ABI_or_permission_changed=False)
    save('complete-static-provider-function-domain.json', manifest)
    print(json.dumps(dict(passed=True, providers=2, functions=sum(len(scope['selected_functions']) for scope in scopes),
                          complete_call_closure_or_source_effect_or_lifetime_qualified=False)))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            save('failure.json', dict(timestamp=now(), traceback=traceback.format_exc(), original_execution=False))
        raise
