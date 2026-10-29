from pathlib import Path
import datetime
import glob
import hashlib
import json
import os
import platform
import plistlib
import shutil
import subprocess
import traceback

OUT = Path('wmf-provider-records')
OUT.mkdir(exist_ok=False)
COMMANDS = []


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def run(label, argv, developer=None, timeout=55):
    env = os.environ.copy()
    if developer:
        env['DEVELOPER_DIR'] = str(developer)
    record = dict(label=label, argv=[str(x) for x in argv], started=now(),
                  developer_dir=str(developer) if developer else None)
    with (OUT / (label + '.stdout')).open('xb') as stdout, (OUT / (label + '.stderr')).open('xb') as stderr:
        try:
            process = subprocess.run(record['argv'], env=env, stdout=stdout, stderr=stderr, timeout=timeout)
            record['returncode'] = process.returncode
        except subprocess.TimeoutExpired:
            record['returncode'] = None
            record['timed_out'] = True
    record['ended'] = now()
    for kind in ('stdout', 'stderr'):
        data = (OUT / (label + '.' + kind)).read_bytes()
        record[kind] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    COMMANDS.append(record)
    write(label + '-command.json', record)
    return record, (OUT / (label + '.stdout')).read_text(errors='replace')


def normalized(value):
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, bytes):
        return {'plist_data_hex': value.hex()}
    if isinstance(value, datetime.datetime):
        return {'plist_date_iso': value.isoformat()}
    return value


def plist(path):
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                value=normalized(plistlib.loads(data)))


def capture_sdks(developer):
    items = []
    for sdk in sorted(developer.glob('Platforms/iPhoneSimulator.platform/Developer/SDKs/*.sdk')):
        resolved = sdk.resolve()
        entry = dict(path=str(sdk), resolved=str(resolved), settings=[], system_versions=[])
        for name in ('SDKSettings.json', 'SDKSettings.plist'):
            source = resolved / name
            if source.is_file():
                data = source.read_bytes()
                target = 'sdk-' + hashlib.sha256(str(source).encode()).hexdigest()[:16] + '-' + name
                destination = OUT / target
                if destination.exists():
                    assert destination.read_bytes() == data
                else:
                    with destination.open('xb') as stream:
                        stream.write(data)
                entry['settings'].append(dict(path=str(source), artifact=target,
                                               sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
        version = resolved / 'System/Library/CoreServices/SystemVersion.plist'
        if version.is_file():
            entry['system_versions'].append(plist(version))
        items.append(entry)
    return items


def runtime_files(runtime):
    root = runtime.get('runtimeRoot')
    bundle = runtime.get('bundlePath')
    if not root and bundle:
        root = str(Path(bundle) / 'Contents/Resources/RuntimeRoot')
    result = dict(runtime=runtime, runtime_root=root, plists=[], loose_providers=[], shared_cache_files=[])
    if not root:
        return result
    root = Path(root)
    for candidate in [root / 'System/Library/CoreServices/SystemVersion.plist',
                      Path(bundle) / 'Contents/Info.plist' if bundle else root / '__absent_info__']:
        if candidate.is_file():
            result['plists'].append(plist(candidate))
    for relative in ('usr/lib/swift/libswiftCore.dylib', 'System/Library/Frameworks/Foundation.framework/Foundation',
                     'usr/lib/libobjc.A.dylib', 'usr/lib/system/libdispatch.dylib', 'usr/lib/system/libsystem_blocks.dylib'):
        candidate = root / relative
        entry = dict(path=str(candidate), exists=candidate.exists(), is_file=candidate.is_file())
        if candidate.is_file():
            entry['size'] = candidate.stat().st_size
        result['loose_providers'].append(entry)
    cache_dirs = [root / 'System/Library/dyld', root / 'System/Library/Caches/com.apple.dyld']
    if bundle:
        cache_dirs.append(Path(bundle) / 'Contents/Resources')
    for directory in cache_dirs:
        for candidate in sorted(directory.glob('dyld_shared_cache_*')):
            if candidate.is_file():
                with candidate.open('rb') as stream:
                    prefix = stream.read(65536)
                result['shared_cache_files'].append(dict(path=str(candidate), size=candidate.stat().st_size,
                    first_65536_bytes_sha256=hashlib.sha256(prefix).hexdigest(),
                    prefix_size=len(prefix), magic_first16_hex=prefix[:16].hex(), whole_file_hash_not_queried=True))
    return result


def probe(developer, runtime):
    result = dict(status='preparing', runtime=runtime, developer_dir=str(developer), original_application_loaded=False)
    sdk_record, sdk_text = run('probe-sdk-path', ['xcrun', '--sdk', 'iphonesimulator', '--show-sdk-path'], developer)
    assert sdk_record['returncode'] == 0, 'No simulator SDK for authored probe'
    sdk = sdk_text.strip()
    binary = OUT / 'AuthoredProviderProbe'
    command = ['xcrun', '--sdk', 'iphonesimulator', 'clang', '-target', 'arm64-apple-ios17.6-simulator',
               '-isysroot', sdk, '-O0', '-g', '-fobjc-arc', '-framework', 'Foundation',
               'wmf-provider-inventory/ProviderProbe.m', '-o', str(binary)]
    record, _ = run('probe-authored-compile-link', command, developer)
    assert record['returncode'] == 0, 'Authored provider probe compilation failed'
    run('probe-authored-load-commands', ['xcrun', 'otool', '-l', str(binary)], developer)
    run('probe-authored-linked-libraries', ['xcrun', 'otool', '-L', str(binary)], developer)
    record, text = run('probe-device-types', ['xcrun', 'simctl', 'list', 'devicetypes', '--json'], developer)
    assert record['returncode'] == 0
    devices = json.loads(text)['devicetypes']
    candidates = [item for item in devices if item.get('productFamily') == 'iPhone']
    assert candidates, 'No iPhone device type available'
    chosen = next((item for item in candidates if item['name'] == 'iPhone 16'), candidates[-1])
    record, text = run('probe-create-owned-device', ['xcrun', 'simctl', 'create', 'Authored Provider Inventory',
                      chosen['identifier'], runtime['identifier']], developer)
    assert record['returncode'] == 0, 'Creating independently owned simulator failed'
    device = text.strip()
    result['owned_device'] = device
    try:
        record, _ = run('probe-boot-owned-device', ['xcrun', 'simctl', 'boot', device], developer)
        assert record['returncode'] == 0
        record, _ = run('probe-await-owned-device', ['xcrun', 'simctl', 'bootstatus', device, '-b'], developer, timeout=300)
        assert record['returncode'] == 0, 'Simulator boot did not complete'
        record, text = run('probe-runtime-provider-identity', ['xcrun', 'simctl', 'spawn', device,
                           str(binary.resolve())], developer, timeout=90)
        result['actual_returncode'] = record['returncode']
        if text.strip():
            result['observation'] = json.loads(text)
        assert record['returncode'] == 0, 'Authored simulator provider probe failed'
        result['status'] = 'observed'
    finally:
        run('probe-shutdown-owned-device', ['xcrun', 'simctl', 'shutdown', device], developer)
        run('probe-delete-owned-device', ['xcrun', 'simctl', 'delete', device], developer)
        write('authored-probe.json', result)
    return result


def main():
    manifest = dict(schema=1, started=now(), scope='installed_SDK_runtime_and_authored_provider_identity',
                    runner={key: os.environ.get(key) for key in ('WMF_INVENTORY_RUNNER', 'RUNNER_ARCH',
                        'RUNNER_OS', 'ImageOS', 'ImageVersion', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
                    architecture=platform.machine(), original_application_uploaded_or_executed=False,
                    source_lifetime_or_effect_qualification=False, xcodes=[])
    assert manifest['architecture'] == 'arm64', 'This scope requires native ARM64'
    assert shutil.disk_usage(OUT).free > 512 * 1024 * 1024, '512 MiB reserve'
    for label, argv in [('host-version', ['sw_vers']), ('host-kernel', ['uname', '-a']),
                        ('selected-developer', ['xcode-select', '-p']), ('disk-free', ['df', '-k', '.'])]:
        run(label, argv)
    developers = sorted({Path(path).resolve() / 'Contents/Developer' for path in glob.glob('/Applications/Xcode*.app')})
    available = []
    for index, developer in enumerate(developers):
        prefix = 'xcode-' + str(index)
        item = dict(developer=str(developer), sdk=capture_sdks(developer), runtime_query=prefix + '-runtimes')
        version = developer.parent / 'version.plist'
        if version.is_file():
            item['version'] = plist(version)
        run(prefix + '-version', ['xcodebuild', '-version'], developer)
        run(prefix + '-sdks', ['xcodebuild', '-showsdks', '-json'], developer)
        record, text = run(prefix + '-runtimes', ['xcrun', 'simctl', 'list', 'runtimes', '--json'], developer)
        item['runtime_query_returncode'] = record['returncode']
        if record['returncode'] == 0:
            runtimes = json.loads(text)['runtimes']
            item['runtimes'] = [runtime_files(runtime) for runtime in runtimes]
            for runtime in runtimes:
                if runtime.get('isAvailable') and '.SimRuntime.iOS-' in runtime.get('identifier', ''):
                    available.append((developer, runtime))
        manifest['xcodes'].append(item)
    write('installed-inventory.json', manifest)
    if available:
        developer, runtime = max(available, key=lambda pair: tuple(int(n) for n in pair[1]['version'].split('.')))
        manifest['probe'] = probe(developer, runtime)
    else:
        manifest['probe'] = dict(status='not_queried_no_available_iOS_runtime')
    manifest['ended'] = now()
    manifest['command_count'] = len(COMMANDS)
    write('complete-inventory.json', manifest)
    print(json.dumps(dict(status='inventory_complete', xcodes=len(developers), available_iOS_choices=len(available),
                          probe_status=manifest['probe']['status'], command_count=len(COMMANDS))))


try:
    main()
except BaseException:
    write('failure.json', dict(at=now(), traceback=traceback.format_exc()))
    raise
finally:
    write('all-command-receipts.json', COMMANDS)
