from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil
import struct
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'wmf-block-provider-functions'))
import collect as parent
from macho import MachO, bounds

OUT = Path('wmf-provider-context-records')
EXPECTED = {
    'dispatch': dict(relative='usr/lib/system/libdispatch.dylib', uuid='42B50931-38D5-3A5D-90EF-0FD7239C408D',
        whole_sha256='c8916ca8cc53d106df692b89a087324a6ce0b7b74e0772d95b6f1fbf3351c459',
        slice_sha256='2f1ac552aead3b4b729067d3c6c10533f12b59a89ba77dd6b00c7a641f985603'),
    'Blocks': dict(relative='usr/lib/system/libsystem_blocks.dylib', uuid='A5FDF1FF-B793-3574-8903-D24571EACD25',
        whole_sha256='23abac275e8d1acb3adb737d64336726b6a705cd1f1fba385997fb24172bd29b',
        slice_sha256='e43ad83e3bc66b4c9a353e6be5a638b6b9fcb02e6c8cdcd4e196354f13dce7ed'),
}


def raw_range(image, offset, size):
    data = bounds(image.data, offset, size)
    return dict(slice_file_offset=offset, bytes=size, sha256=hashlib.sha256(data).hexdigest(), data_hex=data.hex())


def contexts(name, expected, root):
    path = root / expected['relative']
    image = MachO(path.read_bytes())
    assert image.uuid == expected['uuid']
    assert image.whole_sha256 == expected['whole_sha256'] and image.slice_sha256 == expected['slice_sha256']
    assert image.versions and all(version['platform'] == 7 for version in image.versions)
    sections = []
    for section in image.sections:
        if section['name'] in ('__stubs', '__objc_stubs', '__got', '__unwind_info', '__eh_frame', '__gcc_except_tab'):
            sections.append(dict(section=section, raw=raw_range(image, section['offset'], section['size'])))
    commands = []
    chained = None
    for command in image.commands:
        if command['cmd'] in (0x80000034, 0x80000033):
            raw_command = bytes.fromhex(command['bytes_hex'])
            assert len(raw_command) == 16
            _, _, offset, size = struct.unpack('<4I', raw_command)
            data = raw_range(image, offset, size)
            commands.append(dict(command=command, raw=data))
            if command['cmd'] == 0x80000034:
                assert chained is None
                chained = bytes.fromhex(data['data_hex'])
    assert chained is not None
    header = struct.unpack('<7I', bounds(chained, 0, 28))
    assert header[0] == 0
    starts_offset = header[1]
    segment_count = struct.unpack('<I', bounds(chained, starts_offset, 4))[0]
    assert segment_count <= len(image.segments)
    offsets = struct.unpack('<' + str(segment_count) + 'I', bounds(chained, starts_offset + 4, segment_count * 4))
    records = []
    for segment_index, relative in enumerate(offsets):
        if relative == 0:
            records.append(dict(segment_index=segment_index, starts_absent=True))
            continue
        offset = starts_offset + relative
        size, page_size, pointer_format, segment_offset, maximum, page_count = struct.unpack('<IHHQIH', bounds(chained, offset, 22))
        raw_record = bounds(chained, offset, size)
        assert size >= 22 + page_count * 2 and page_size > 0
        starts = list(struct.unpack('<' + str(page_count) + 'H', bounds(raw_record, 22, page_count * 2)))
        segment = image.segments[segment_index]
        assert segment_offset == segment['vmaddr'] - image.text_base
        pages = []
        for page, start in enumerate(starts):
            if start == 0xffff:
                continue
            within = page * page_size
            assert within < segment['filesize']
            length = min(page_size, segment['filesize'] - within)
            pages.append(dict(page_index=page, page_start_word=start,
                raw=raw_range(image, segment['fileoff'] + within, length)))
        records.append(dict(segment_index=segment_index, starts_absent=False, segment=segment,
            page_size=page_size, pointer_format=pointer_format, segment_offset_hex=hex(segment_offset),
            max_valid_pointer=maximum, page_count=page_count, page_starts=starts,
            raw_starts_record_hex=raw_record.hex(), pages=pages))
    result = dict(provider=name, path=str(path), header=image.header, uuid=image.uuid, versions=image.versions,
        whole_file_sha256=image.whole_sha256, whole_file_bytes=image.whole_size,
        selected_slice_offset=image.slice_offset, selected_slice_sha256=image.slice_sha256,
        segments=image.segments, sections=sections, linkedit_commands=commands,
        declared_chain_starts=records,
        no_pointer_format_or_import_or_language_effect_decoding_attempted=True,
        no_repeat_function_disassembly_or_old_runtime_probe=True,
        no_original_WMF_provider_or_lifetime_or_source_permission_qualification=True)
    parent.save(name + '-complete-new-raw-context.json', result)
    return dict(provider=name, uuid=image.uuid, whole_file_sha256=image.whole_sha256,
        sections=len(sections), fixup_segments=sum(not record['starts_absent'] for record in records),
        fixup_pages=sum(len(record.get('pages', [])) for record in records),
        pointer_formats=sorted(set(record['pointer_format'] for record in records if not record['starts_absent'])))


def main():
    parent.OUT = OUT
    OUT.mkdir()
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == '/Applications/Xcode_26.5.app/Contents/Developer'
    assert shutil.disk_usage(OUT).free > 512 * 1024 * 1024
    parent.run('actual-context-Xcode26_5-version', ['xcodebuild', '-version'])
    settings = (parent.SDK / 'SDKSettings.json').read_bytes()
    assert json.loads(settings)['Version'] == '26.5'
    with (OUT / 'actual-context-SDK26_5-Settings.json').open('xb') as stream:
        stream.write(settings)
    root = parent.resolve_current_target_runtime()
    summaries = [contexts(name, expected, root) for name, expected in EXPECTED.items()]
    parent.save('complete-new-provider-raw-context-domain.json', dict(
        at=datetime.datetime.now(datetime.timezone.utc).isoformat(), run_id=os.environ['GITHUB_RUN_ID'],
        commit=os.environ['GITHUB_SHA'], image_version=os.environ.get('ImageVersion'),
        summaries=summaries, exact_previous_static_provider_whole_file_and_slice_hashes_required=True,
        raw_stub_fixup_page_and_unwind_context_only=True,
        no_previous_inventory_function_disassembly_or_runtime_probe_reexecution=True,
        no_Simulator_boot_or_target_provider_or_original_WMF_code_execution=True,
        no_provider_binary_uploaded=True, source_lifetime_or_effect_qualification=False))
    print(json.dumps(dict(passed=True, summaries=summaries, raw_context_only=True)))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            parent.OUT = OUT
            parent.save('failure.json', dict(at=datetime.datetime.now(datetime.timezone.utc).isoformat(), traceback=traceback.format_exc()))
        raise
