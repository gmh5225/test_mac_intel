"""Read fixed Simulator SwiftCore function bytes; never load target code."""

from collections import deque
from pathlib import Path
import datetime
import hashlib
import json
import os
import plistlib
import shutil
import struct
import subprocess
import tempfile
import traceback

from macho import MachO, bounds


OUT = Path('wmf-swiftcore-static-records')
DEVELOPER = Path('/Applications/Xcode_26.5.app/Contents/Developer')
EXPECTED_UUID = '278DFF77-40C0-3E59-8FE1-7C91FC72144A'
SEEDS = ('_swift_slowAlloc', '_swift_stdlib_isStackAllocationSafe',
         '_swift_willThrowTypedImpl')
CONTEXT_SECTIONS = {'__stubs', '__objc_stubs', '__auth_stubs', '__got',
                    '__auth_got', '__la_symbol_ptr', '__nl_symbol_ptr',
                    '__unwind_info', '__eh_frame', '__gcc_except_tab'}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def run(label, argv):
    record = dict(argv=[str(value) for value in argv], started_at=now(),
                  cwd=str(Path.cwd()), developer_dir=os.environ.get('DEVELOPER_DIR'))
    with (OUT / (label + '.stdout')).open('xb') as stdout, \
            (OUT / (label + '.stderr')).open('xb') as stderr:
        try:
            result = subprocess.run(record['argv'], stdout=stdout, stderr=stderr,
                                    timeout=120, check=False)
            record['returncode'] = result.returncode
        except subprocess.TimeoutExpired:
            record['returncode'] = None
            record['timed_out'] = True
    record['finished_at'] = now()
    for suffix in ('stdout', 'stderr'):
        data = (OUT / (label + '.' + suffix)).read_bytes()
        record[suffix] = dict(bytes=len(data), sha256=digest(data))
    save(label + '-actual-command-return.json', record)
    assert record['returncode'] == 0, label
    return (OUT / (label + '.stdout')).read_bytes()


def validate_image(image, expected_uuid):
    assert image.uuid == expected_uuid, 'Current file UUID differs from saved candidate'
    assert image.header['filetype'] == 6, 'Expected MH_DYLIB'
    assert image.versions and all(row['platform'] == 7 for row in image.versions)


def select_functions(image, seed_names=SEEDS, depth_limit=2, function_limit=128):
    """Collect whole owning intervals; retain every edge beyond the collection."""
    seeds = []
    pending = deque()
    for name in seed_names:
        matches = [row for row in image.symbols if row['name'] == name
                   and row['type'] & 0x0e == 0x0e and not row['type'] & 0xe0]
        assert len(matches) == 1, 'Expected one exact N_SECT definition: ' + name
        record = matches[0]
        assert record['section'] == image.text['index']
        assert record['value'] in image.function_starts, 'Seed is not an exact function start'
        seeds.append(dict(requested_name=name, complete_nlist_record=record))
        pending.append((record['value'], 0))
    selected = {}
    deferred = []
    while pending:
        address, depth = pending.popleft()
        if address in selected:
            continue
        assert len(selected) < function_limit, 'Static collection cap reached'
        body = image.function(address)
        body['collection_depth'] = depth
        selected[address] = body
        for edge in body['direct_branches']:
            if edge['internal']:
                continue
            identity = edge['target_identity']
            if identity['kind'] == 'text_function_interval':
                owner = int(identity['function_start'], 16)
                if depth < depth_limit:
                    pending.append((owner, depth + 1))
                else:
                    deferred.append(dict(from_function=hex(address), edge=edge,
                                         reason='outside_selected_direct_callee_layers'))
            else:
                deferred.append(dict(from_function=hex(address), edge=edge,
                                     reason='external_stub_or_unresolved_address'))
    return dict(seeds=seeds, functions=[body for _, body in sorted(selected.items())],
                deferred_direct_edges=deferred, direct_callee_layer_limit=depth_limit,
                function_collection_limit=function_limit,
                indirect_branches=[dict(from_function=body['start'], **edge)
                                   for body in selected.values()
                                   for edge in body['indirect_branches']],
                complete_call_closure_or_effect_or_lifetime_qualified=False)


def raw_range(image, offset, size):
    data = bounds(image.data, offset, size)
    return dict(slice_file_offset=offset, bytes=len(data), sha256=digest(data),
                data_hex=data.hex())


def raw_context(image):
    sections = [dict(section=row, raw=raw_range(image, row['offset'], row['size']))
                for row in image.sections if row['name'] in CONTEXT_SECTIONS]
    payloads = []
    fixup_pages = []
    chained_seen = False
    for command in image.commands:
        raw = bytes.fromhex(command['bytes_hex'])
        if command['cmd'] in (0x26, 0x29, 0x80000033, 0x80000034):
            assert len(raw) == 16
            _, _, offset, size = struct.unpack('<4I', raw)
            payload = raw_range(image, offset, size)
            payloads.append(dict(command=command, raw=payload))
            if command['cmd'] != 0x80000034:
                continue
            assert not chained_seen
            chained_seen = True
            chained = bytes.fromhex(payload['data_hex'])
            header = struct.unpack('<7I', bounds(chained, 0, 28))
            assert header[0] == 0
            start = header[1]
            count = struct.unpack('<I', bounds(chained, start, 4))[0]
            assert count <= len(image.segments)
            offsets = struct.unpack('<' + str(count) + 'I', bounds(chained, start + 4, count * 4))
            for index, relative in enumerate(offsets):
                if relative == 0:
                    continue
                record_offset = start + relative
                size, page_size, pointer_format, segment_offset, maximum, pages = struct.unpack(
                    '<IHHQIH', bounds(chained, record_offset, 22))
                record = bounds(chained, record_offset, size)
                assert size >= 22 + pages * 2 and page_size > 0
                starts = struct.unpack('<' + str(pages) + 'H', bounds(record, 22, pages * 2))
                segment = image.segments[index]
                assert segment_offset == segment['vmaddr'] - image.text_base
                raw_pages = []
                for page, word in enumerate(starts):
                    if word == 0xffff:
                        continue
                    within = page * page_size
                    assert within < segment['filesize']
                    raw_pages.append(dict(page_index=page, start_word=word,
                        raw=raw_range(image, segment['fileoff'] + within,
                                      min(page_size, segment['filesize'] - within))))
                fixup_pages.append(dict(segment_index=index, segment=segment,
                    pointer_format=pointer_format, page_size=page_size,
                    max_valid_pointer=maximum, starts_record_hex=record.hex(),
                    page_starts=list(starts), pages=raw_pages))
        elif command['cmd'] in (0x22, 0x80000022):
            assert len(raw) == 48
            values = struct.unpack('<12I', raw)
            for number, kind in enumerate(('rebase', 'bind', 'weak_bind', 'lazy_bind', 'export')):
                offset, size = values[2 + 2 * number:4 + 2 * number]
                payloads.append(dict(command=command, kind=kind,
                                     raw=raw_range(image, offset, size)))
    return dict(sections=sections, linkedit_payloads=payloads,
                declared_fixup_pages=fixup_pages,
                raw_encoded_pointers_are_not_current_runtime_values=True,
                no_chain_import_effect_or_language_semantics_inferred=True)


def main():
    OUT.mkdir()
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(DEVELOPER)
    assert shutil.disk_usage(OUT).free >= 512 * 1024 * 1024
    run('actual-Xcode26_5-version', ['xcodebuild', '-version'])
    sdk = DEVELOPER / 'Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk'
    settings = (sdk / 'SDKSettings.json').read_bytes()
    parsed = json.loads(settings)
    assert parsed['Version'] == '26.5'
    target = parsed['SupportedTargets']['iphonesimulator']
    assert target['BuildVersionPlatformID'] == '7' and '17.6' in target['ValidDeploymentTargets']
    (OUT / 'actual-SDK-Settings.json').write_bytes(settings)
    runtime_list = json.loads(run('actual-current-runtime-path',
        ['xcrun', 'simctl', 'list', 'runtimes', '--json']))
    matches = [row for row in runtime_list['runtimes']
               if row.get('identifier') == 'com.apple.CoreSimulator.SimRuntime.iOS-26-5']
    assert len(matches) == 1
    runtime = matches[0]
    save('actual-current-runtime-record.json', runtime)
    assert runtime['version'] == '26.5' and runtime['buildversion'] == '23F77'
    assert runtime['isAvailable'] is True and 'arm64' in runtime['supportedArchitectures']
    root = Path(runtime['runtimeRoot'])
    assert root.is_absolute()
    version_bytes = (root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes()
    version = plistlib.loads(version_bytes)
    assert version['ProductVersion'] == '26.5' and version['ProductBuildVersion'] == '23F77'
    (OUT / 'actual-runtime-SystemVersion.plist').write_bytes(version_bytes)
    source = root / 'usr/lib/swift/libswiftCore.dylib'
    image = MachO(source.read_bytes())
    save('complete-current-SwiftCore-MachO-metadata.json', dict(source=str(source), **image.manifest()))
    validate_image(image, EXPECTED_UUID)
    domain = select_functions(image)
    save('complete-selected-function-domain.json', domain)
    save('complete-current-import-fixup-and-unwind-raw-context.json', raw_context(image))
    # The temporary provider file is input to the disassembler, never a process.
    with tempfile.TemporaryDirectory(prefix='wmf-swiftcore-static-', dir=os.environ['RUNNER_TEMP']) as temporary:
        thin = Path(temporary) / 'SwiftCore-arm64.dylib'
        thin.write_bytes(image.data)
        for body in domain['functions']:
            label = 'function-' + body['start'][2:]
            run(label + '-complete-disassembly', ['xcrun', 'llvm-objdump', '--disassemble',
                '--start-address=' + body['start'], '--stop-address=' + body['end'], str(thin)])
    files = []
    for path in sorted(OUT.iterdir()):
        data = path.read_bytes()
        files.append(dict(name=path.name, bytes=len(data), sha256=digest(data)))
    save('complete-collection-result.json', dict(status='PASS', collected_at=now(),
        run_id=os.environ['GITHUB_RUN_ID'], run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],
        collector_commit=os.environ['GITHUB_SHA'], image_version=os.environ.get('ImageVersion'),
        candidate_UUID=image.uuid, whole_file_sha256=image.whole_sha256,
        selected_slice_sha256=image.slice_sha256, seed_count=len(domain['seeds']),
        full_function_count=len(domain['functions']), files=files,
        original_provider_match_or_memory_or_call_permission=False,
        source_commit_or_build_macro_binding_proved=False,
        no_Simulator_boot_or_app_or_target_provider_execution=True,
        no_original_WMF_upload_load_pipeline_or_query=True,
        no_complete_Apple_provider_binary_uploaded=True))
    print(json.dumps(dict(status='PASS', seeds=len(domain['seeds']),
                          functions=len(domain['functions']), permission_gain=0)))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            save('failure.json', dict(failed_at=now(), traceback=traceback.format_exc(),
                                     original_or_provider_execution=False))
        raise
