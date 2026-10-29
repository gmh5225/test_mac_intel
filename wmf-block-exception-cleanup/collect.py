from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parents[1]
HELPERS = {'wmf-block-provider-functions/macho.py': 'f6410fa931f51adbdc63bff2cd54ffcb898344fd50832a19ccbd0ba9eb8a0554', 'wmf-block-provider-functions/collect.py': '0f84b8d20b68aa1e3157646ea67891c19afb4008d3abb5eb6a3b847f4d00f9c3', 'wmf-provider-contexts/collect.py': 'ac7c508c4ab0f23d0588867e7a68c291d4acfef99b90daf7c710d66ff6cf3e93'}
for relative, digest in HELPERS.items():
    assert hashlib.sha256((REPO / relative).read_bytes()).hexdigest() == digest
sys.path.insert(0, str(REPO / 'wmf-block-provider-functions'))
spec = importlib.util.spec_from_file_location('wmf_existing_context_reader', REPO / 'wmf-provider-contexts/collect.py')
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)
parent = context.parent
OUT = Path('wmf-block-exception-cleanup-records')
COMMANDS = []
EXPECTED_NEW = {
    'compiler_rt': dict(relative='usr/lib/system/libcompiler_rt.dylib', uuid='5539B26B-6FA7-341F-9C21-25F04BC8138B',
        whole_sha256='fc7836649755bea42a0b6362594ce413d846c25ed9cded65f3351736e07f4d79',
        slice_sha256='585c42e52006c93a59ad017f95b23d491e230f6a1456fbb4557c1dd515772d13'),
    'unwind': dict(relative='usr/lib/system/libunwind.dylib', uuid='C4187425-764F-3506-A411-5102B50AE804',
        whole_sha256='bc71daceb4bb2970750aae8aea74ddcc22495a885635a8e3d72848d21f1407fb',
        slice_sha256='9d2ba24091898fb07eb78c453f9fc1ec0b21269c27e6c9ef1e9674dea020c81d'),
}


def run(label, argv, timeout=55, check=True):
    argv = [str(x) for x in argv]
    record = dict(label=label, argv=argv, started=parent.now(), timeout_seconds=timeout,
                  developer_dir=os.environ.get('DEVELOPER_DIR'))
    with (OUT / (label + '.stdout')).open('xb') as stdout, (OUT / (label + '.stderr')).open('xb') as stderr:
        try:
            process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
            record['returncode'] = process.returncode
        except subprocess.TimeoutExpired:
            record['returncode'] = None
            record['timed_out'] = True
    record['ended'] = parent.now()
    for field in ['stdout', 'stderr']:
        data = (OUT / (label + '.' + field)).read_bytes()
        record[field] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    parent.save(label + '-command.json', record)
    COMMANDS.append(record)
    if check:
        assert record['returncode'] == 0, label
    return record


def main():
    OUT.mkdir()
    parent.OUT = OUT
    context.OUT = OUT
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(parent.DEVELOPER)
    assert shutil.disk_usage(OUT).free > 512 * 1024 * 1024
    run('actual-Xcode26_5-version', ['xcodebuild', '-version'])
    assert (OUT / 'actual-Xcode26_5-version.stdout').read_text().strip() == 'Xcode 26.5\nBuild version 17F42'
    settings = (parent.SDK / 'SDKSettings.json').read_bytes()
    decoded = json.loads(settings)
    assert decoded['Version'] == '26.5'
    assert decoded['SupportedTargets']['iphonesimulator']['BuildVersionPlatformID'] == '7'
    assert '17.6' in decoded['SupportedTargets']['iphonesimulator']['ValidDeploymentTargets']
    with (OUT / 'actual-explicit-SDK26_5-Settings.json').open('xb') as f:
        f.write(settings)
    root = context.resolve_context_runtime_with_cold_start_deadline()
    version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion'] == '26.5' and version['ProductBuildVersion'] == '23F77'
    parent.save('actual-runtime-version.json', version)
    providers = []
    for name, expected in {**context.EXPECTED, **EXPECTED_NEW}.items():
        path = root / expected['relative']
        image = context.MachO(path.read_bytes())
        assert image.uuid == expected['uuid'] and image.whole_sha256 == expected['whole_sha256']
        assert image.slice_sha256 == expected['slice_sha256']
        assert image.versions and all(v['platform'] == 7 for v in image.versions)
        providers.append(dict(provider=name, path=str(path), expected=expected, actual_uuid=image.uuid,
            actual_whole_sha256=image.whole_sha256, actual_slice_sha256=image.slice_sha256, versions=image.versions))
    parent.save('actual-four-provider-whole-slice-UUID-prerequisites.json', providers)
    cxx_path = root / 'usr/lib/libc++abi.dylib'
    cxx = context.MachO(cxx_path.read_bytes())
    assert cxx.versions and all(v['platform'] == 7 for v in cxx.versions)
    parent.save('actual-new-current-static-CxxABI-MachO-identity.json', dict(
        first_static_observation_in_this_scope=True, new_source_ABI_or_original_provider_qualification=False,
        **cxx.manifest()))
    source = REPO / 'wmf-block-exception-cleanup/BlockExceptionCleanup.cpp'
    (OUT / 'BlockExceptionCleanup.cpp').write_bytes(source.read_bytes())
    compiler = parent.DEVELOPER / 'Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++'
    run('actual-explicit-compiler-version', [compiler, '--version'])
    base = [compiler, '-x', 'c++', '-std=c++20', '-fblocks', '-fexceptions', '-fcxx-exceptions',
            '-O0', '-g0', '-target', 'arm64-apple-ios17.6-simulator', '-isysroot', parent.SDK]
    run('new-authored-SDK26_5-IR', base + ['-S', '-emit-llvm', source, '-o', OUT / 'authored-exception-platform7.ll'])
    run('new-authored-SDK26_5-assembly', base + ['-S', source, '-o', OUT / 'authored-exception-platform7.s'])
    binary = OUT / 'WMFAuthoredBlockExceptionCleanup'
    run('new-authored-SDK26_5-compile-link', base + [source, '-MD', '-MF', OUT / 'authored-exception-platform7.d', '-o', binary])
    image = context.MachO(binary.read_bytes())
    assert image.header['filetype'] == 2 and image.versions
    assert all(v['platform'] == 7 and v['minos_bits'] == 0x110600 and v['sdk_bits'] == 0x1a0500 for v in image.versions)
    parent.save('actual-new-authored-binary-before-execution.json', dict(path=str(binary), **image.manifest()))
    text = (OUT / 'authored-exception-platform7.d').read_text()
    deps = shlex.split(text.replace('\\\n', ' ').split(':', 1)[1])
    bindings = {}
    rows = []
    for name in deps:
        lexical = Path(name)
        canonical = lexical.resolve(strict=True)
        digest = hashlib.sha256(canonical.read_bytes()).hexdigest()
        assert hashlib.sha256(lexical.read_bytes()).hexdigest() == digest
        bindings[str(canonical)] = digest
        links = []
        cursor = Path(lexical.anchor)
        for part in lexical.parts[1:]:
            cursor = cursor / part
            if cursor.is_symlink():
                links.append(dict(path=str(cursor), target=os.readlink(cursor), resolved=str(cursor.resolve(strict=True))))
        rows.append(dict(lexical=name, canonical=str(canonical), sha256=digest, bytes=canonical.stat().st_size, symlinks=links))
    parent.save('actual-complete-new-compile-canonical-dependencies.json', bindings)
    parent.save('actual-complete-new-compile-lexical-dependency-identities.json', rows)
    run('actual-new-exception-device-types', ['xcrun', 'simctl', 'list', 'devicetypes', '--json'])
    types = json.loads((OUT / 'actual-new-exception-device-types.stdout').read_bytes())['devicetypes']
    choices = [item for item in types if item.get('productFamily') == 'iPhone'
               and item.get('name', '').startswith('iPhone')
               and item['minRuntimeVersion'] <= 0x1a0500 <= item['maxRuntimeVersion']]
    assert choices
    choice = max(choices, key=lambda item: (item['minRuntimeVersion'], item['identifier']))
    run('create-only-owned-exception-device', ['xcrun', 'simctl', 'create', 'Authored Block Exceptions ' + os.environ['GITHUB_RUN_ID'],
        choice['identifier'], 'com.apple.CoreSimulator.SimRuntime.iOS-26-5'])
    device = (OUT / 'create-only-owned-exception-device.stdout').read_text().strip()
    assert device and '\n' not in device
    parent.save('actual-owned-exception-device.json', dict(UDID=device, device_type=choice, runtime='com.apple.CoreSimulator.SimRuntime.iOS-26-5'))
    try:
        run('boot-only-owned-exception-device', ['xcrun', 'simctl', 'boot', device])
        run('wait-only-owned-exception-device', ['xcrun', 'simctl', 'bootstatus', device, '-b'], timeout=300)
        run('execute-only-new-authored-exception-fixture', ['xcrun', 'simctl', 'spawn', device, str(binary.resolve()), cxx.uuid], timeout=180)
    finally:
        run('shutdown-only-owned-exception-device', ['xcrun', 'simctl', 'shutdown', device], check=False)
        run('delete-only-owned-exception-device', ['xcrun', 'simctl', 'delete', device], check=False)
    records = [json.loads(line) for line in (OUT / 'execute-only-new-authored-exception-fixture.stdout').read_text().splitlines() if line.strip()]
    complete = [r for r in records if r.get('type') == 'complete_new_authored_exception_domain']
    assert len(complete) == 1 and complete[0]['cases'] == 6
    parent.save('complete-new-authored-platform7-exception-cleanup-domain.json', dict(
        at=parent.now(), run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'],
        actual_runtime='26.5/23F77', explicit_compilation_SDK='26.5', explicit_target='arm64-apple-ios17.6-simulator',
        authored_binary_sha256=image.whole_sha256, authored_binary_UUID=image.uuid,
        actual_new_case_count=6, records=records, command_count=len(COMMANDS) + 1,
        no_original_WMF_generated_C_or_NeverD_code_uploaded_loaded_or_executed=True,
        no_prior_successful_compiler_fixture_inventory_or_query_rerun=True,
        finite_authored_exceptions_only_not_original_provider_capture_ABI_value_permission_lifetime_effect_or_source_qualification=True))
    print(json.dumps(dict(passed=True, new_authored_cases=6, actual_SDK='26.5')))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            parent.OUT = OUT
            parent.save('failure.json', dict(at=parent.now(), traceback=traceback.format_exc(), original_WMF_executed=False))
        raise
    finally:
        if OUT.is_dir():
            parent.OUT = OUT
            parent.save('all-new-exception-driver-command-receipts.json', COMMANDS)
