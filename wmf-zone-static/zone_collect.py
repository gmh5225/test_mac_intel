"""Collect the uncollected allocator module and exact NSError class owner."""

from pathlib import Path
import hashlib
import json
import os
import plistlib
import shutil
import sys
import tempfile
import traceback

BASE = Path(__file__).resolve().parents[1] / 'wmf-swiftcore-static'
sys.path.insert(0, str(BASE))
import collect as shared

OUT = Path('wmf-zone-static-records')


def subtract_intervals(begin, end, covered):
    """Return the ordered gaps in one range, including partial overlaps."""
    assert begin <= end
    cursor = begin
    gaps = []
    for lo, hi in sorted(covered):
        assert lo <= hi
        lo, hi = max(lo, begin), min(hi, end)
        if hi <= cursor or hi <= lo:
            continue
        if cursor < lo:
            gaps.append((cursor, lo))
        cursor = max(cursor, hi)
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def disassembly_ranges(functions):
    ranges = []
    for body in sorted(functions, key=lambda row: int(row['start'], 16)):
        lo, hi = int(body['start'], 16), int(body['end'], 16)
        assert lo < hi and (hi - lo) % 4 == 0
        assert not ranges or ranges[-1][1] <= lo
        if ranges and ranges[-1][1] == lo:
            ranges[-1] = (ranges[-1][0], hi)
        else:
            ranges.append((lo, hi))
    return ranges


def verify_pin(path, pin):
    data = path.read_bytes()
    assert len(data) == pin['bytes']
    assert shared.digest(data) == pin['sha256'], str(path)
    return json.loads(data)


def closed_body_ranges(image, closed):
    ranges = []
    for body in closed:
        lo, hi = int(body['start'], 16), int(body['end'], 16)
        assert lo in image.function_starts and lo < hi
        next_start = next((value for value in image.function_starts if value > lo),
                          image.text['addr'] + image.text['size'])
        assert hi == min(next_start, image.text['addr'] + image.text['size'])
        code = shared.bounds(image.text_bytes, lo - image.text['addr'], hi - lo)
        assert len(code) == body['size'] and shared.digest(code) == body['code_sha256']
        ranges.append((lo, hi))
    assert len({lo for lo, hi in ranges}) == len(ranges)
    return sorted(ranges)


def malloc_remainder(image, closed):
    old_ranges = closed_body_ranges(image, closed)
    old_starts = {lo for lo, hi in old_ranges}
    functions = [image.function(value) for value in image.function_starts
                 if image.text['addr'] <= value < image.text['addr'] + image.text['size']
                 and value not in old_starts]
    ranges = disassembly_ranges(functions)
    for lo, hi in ranges:
        assert all(hi <= old_lo or old_hi <= lo for old_lo, old_hi in old_ranges)
    intervals = sorted(ranges + old_ranges)
    assert intervals[0][0] == image.text['addr']
    assert intervals[-1][1] == image.text['addr'] + image.text['size']
    assert all(left[1] == right[0] for left, right in zip(intervals, intervals[1:]))
    return dict(complete_new_functions=functions,
                complete_prior_function_hash_references=closed,
                new_disassembly_ranges=[dict(start=hex(lo), end=hex(hi)) for lo, hi in ranges],
                full_text_union_with_prior_closed_intervals=True,
                old_functions_recollected_or_redisassembled=0,
                runtime_zone_selection_or_callback_effect_permission=False)


def old_file_ranges(context):
    ranges = []
    records = [entry['raw'] for entry in context['sections']]
    records += [entry['raw'] for entry in context['linkedit_payloads']]
    records += [page['raw'] for segment in context['declared_fixup_pages']
                for page in segment['pages']]
    for row in records:
        raw = bytes.fromhex(row['data_hex'])
        assert len(raw) == row['bytes'] and shared.digest(raw) == row['sha256']
        ranges.append((row['slice_file_offset'], row['slice_file_offset'] + row['bytes']))
    return ranges


def new_noncode_sections(image, previous_context):
    covered = old_file_ranges(previous_context)
    sections = []
    for section in image.sections:
        if section['flags'] & 0xff in (1, 0xc, 0x12):
            sections.append(dict(section=section, zero_fill_declaration_only=True))
            continue
        if section['name'] == '__text':
            continue
        lo = section['offset']
        gaps = subtract_intervals(lo, lo + section['size'], covered)
        sections.append(dict(section=section, complete_prior_overlap_reused=True,
                             new_raw_ranges=[shared.raw_range(image, begin, end - begin)
                                             for begin, end in gaps]))
    return dict(sections=sections, previously_captured_bytes_recollected=0,
                raw_initializers_are_not_current_runtime_values=True)


def run_disassembly(name, image, ranges, temporary):
    thin = Path(temporary) / (name + '-arm64.dylib')
    thin.write_bytes(image.data)
    for lo, hi in ranges:
        shared.run(name + '-new-range-' + hex(lo)[2:] + '-' + hex(hi)[2:],
                   ['xcrun', 'llvm-objdump', '--disassemble',
                    '--start-address=' + hex(lo), '--stop-address=' + hex(hi), str(thin)])


def main():
    shared.OUT = OUT
    OUT.mkdir()
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(shared.DEVELOPER)
    assert shutil.disk_usage(OUT).free >= 512 * 1024 * 1024
    pins = json.loads((Path(__file__).parent / 'pins.json').read_text())
    previous = Path('prior-backend')
    malloc_pin = pins['malloc']
    old_metadata = verify_pin(previous / malloc_pin['metadata']['file'], malloc_pin['metadata'])
    old_context = verify_pin(previous / malloc_pin['raw_context']['file'], malloc_pin['raw_context'])
    old_domain = verify_pin(previous / malloc_pin['closed_domain']['file'], malloc_pin['closed_domain'])
    assert malloc_pin['closed_functions'] == [dict(start=row['start'], end=row['end'],
        size=row['size'], code_sha256=row['code_sha256']) for row in old_domain['complete_new_functions']]
    outline_domain = verify_pin(previous / pins['Core']['prior_outline']['file'],
                                pins['Core']['prior_outline'])
    outline = next(row for row in outline_domain['complete_new_functions']
                   if row['start'] == pins['Core']['source_outline'])
    words = {row['address']: row['word_hex'] for row in outline['words']}
    for row in pins['Core']['callback_argument_words']:
        assert words[row['pc']] == row['word']
    adrp, add = [int(row['word'], 16) for row in pins['Core']['callback_argument_words']]
    pc = int(pins['Core']['callback_argument_words'][0]['pc'], 16)
    assert adrp & 0x9f00001f == 0x90000002 and add & 0xffc003ff == 0x91000042
    displacement = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
    if displacement & (1 << 20):
        displacement -= 1 << 21
    callback = (pc & ~0xfff) + displacement * 4096 + (add >> 10 & 0xfff)
    assert callback == int(pins['Core']['new_callback'], 16)
    raw = shared.run('actual-runtime-path', ['xcrun', 'simctl', 'list', 'runtimes', '--json'])
    matches = [row for row in json.loads(raw)['runtimes']
               if row.get('identifier') == 'com.apple.CoreSimulator.SimRuntime.iOS-26-5']
    assert len(matches) == 1
    runtime = matches[0]
    assert runtime['version'] == '26.5' and runtime['buildversion'] == '23F77' and runtime['isAvailable']
    root = Path(runtime['runtimeRoot'])
    assert root.is_absolute()
    version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion'] == '26.5' and version['ProductBuildVersion'] == '23F77'
    shared.save('actual-runtime-record.json', runtime)
    shared.save('actual-runtime-version.json', version)
    summaries = []
    with tempfile.TemporaryDirectory(prefix='wmf-zone-static-', dir=os.environ['RUNNER_TEMP']) as temporary:
        for name, relative in [('malloc', 'usr/lib/system/libsystem_malloc.dylib'),
                               ('Core', 'usr/lib/swift/libswiftCore.dylib')]:
            image = shared.MachO((root / relative).read_bytes())
            pin = pins[name]
            shared.validate_image(image, pin['uuid'])
            assert image.whole_sha256 == pin['whole_file_sha256']
            assert image.slice_sha256 == pin['selected_slice_sha256']
            shared.save(name + '-same-image-and-prior-prefix-pins.json', dict(pins=pin,
                current_whole_sha256=image.whole_sha256, current_slice_sha256=image.slice_sha256,
                old_metadata_context_and_function_disassemblies_recollected=0))
            if name == 'malloc':
                assert image.function_starts == [int(value, 16) for value in old_metadata['function_starts']]
                domain = malloc_remainder(image, pin['closed_functions'])
                shared.save('malloc-new-section-remainder.json', new_noncode_sections(image, old_context))
                ranges = [(int(row['start'], 16), int(row['end'], 16))
                          for row in domain['new_disassembly_ranges']]
            else:
                bodies = [image.function(int(row['start'], 16)) for row in pin['new_class_owner_functions']]
                for body, expected in zip(bodies, pin['new_class_owner_functions']):
                    assert body['end'] == expected['end'] and body['symbol_records'] == expected['symbols']
                assert callback in [int(row['start'], 16) for row in bodies]
                domain = dict(complete_new_functions=bodies, complete_prior_outline=pin['prior_outline'],
                              callback_source_actual_words=pin['callback_argument_words'],
                              original_Error_value_lifetime_or_once_effect_permission=False)
                ranges = disassembly_ranges(bodies)
            shared.save(name + '-complete-new-function-domain.json', domain)
            run_disassembly(name, image, ranges, temporary)
            summaries.append(dict(provider=name, functions=len(domain['complete_new_functions']),
                bytes=sum(row['size'] for row in domain['complete_new_functions']),
                complete_new_disassembly_ranges=[dict(start=hex(lo), end=hex(hi)) for lo, hi in ranges]))
    shared.save('complete-new-zone-static-result.json', dict(status='PASS', summaries=summaries,
        run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'],
        original_provider_identity_region_effect_cell_stability_or_formal_gain=False,
        Simulator_boot_original_WMF_generatedC_or_provider_execution=0))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            shared.save('failure.json', dict(traceback=traceback.format_exc()))
        raise
