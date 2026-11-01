"""Read only the uncollected intervals of the selected SwiftCore file."""

from pathlib import Path
import hashlib
import json
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'wmf-swiftcore-static'))
import collect as shared
sys.path.insert(0, str(ROOT / 'wmf-zone-static'))
import zone_collect as prior

OUT = Path('wmf-Core-module-static-records')


def interval_digest(intervals):
    return hashlib.sha256(b''.join(struct.pack('<QQ', lo, hi)
                                   for lo, hi in intervals)).hexdigest()


def closed_metadata_ranges(image, closed):
    """Reuse old body hashes; never call function() or read old body bytes."""
    starts = image.function_starts
    assert starts == sorted(set(starts))
    begin, end = image.text['addr'], image.text['addr'] + image.text['size']
    assert starts and starts[0] == begin and starts[-1] < end
    ends = dict(zip(starts, starts[1:] + [end]))
    old = []
    for row in closed:
        lo, hi = int(row['start'], 16), int(row['end'], 16)
        assert lo in ends and ends[lo] == hi and hi - lo == row['size']
        assert len(row['code_sha256']) == 64
        old.append((lo, hi))
    assert len(set(old)) == len(old)
    return sorted(old)


def disassembly_chunks(functions, target_bytes):
    """Bound output at function boundaries, retaining an oversized body whole."""
    assert target_bytes > 0 and target_bytes % 4 == 0
    chunks = []
    for body in sorted(functions, key=lambda row: int(row['start'], 16)):
        lo, hi = int(body['start'], 16), int(body['end'], 16)
        assert lo < hi and (hi - lo) % 4 == 0
        assert not chunks or chunks[-1][1] <= lo
        if chunks and chunks[-1][1] == lo and hi - chunks[-1][0] <= target_bytes:
            chunks[-1] = (chunks[-1][0], hi)
        else:
            chunks.append((lo, hi))
    return chunks


def module_remainder(image, closed, target_bytes):
    old = closed_metadata_ranges(image, closed)
    old_starts = {lo for lo, _ in old}
    functions = [image.function(start) for start in image.function_starts
                 if start not in old_starts]
    intervals = [(int(row['start'], 16), int(row['end'], 16)) for row in functions]
    union = sorted(old + intervals)
    assert union[0][0] == image.text['addr']
    assert union[-1][1] == image.text['addr'] + image.text['size']
    assert all(a[1] == b[0] for a, b in zip(union, union[1:]))
    chunks = disassembly_chunks(functions, target_bytes)
    assert all(hi <= a or b <= lo for lo, hi in chunks for a, b in old)
    return dict(complete_new_functions=functions,
                complete_prior_function_hash_references=closed,
                new_interval_u64le_pair_sha256=interval_digest(intervals),
                new_disassembly_ranges=[dict(start=hex(lo), end=hex(hi))
                                        for lo, hi in chunks],
                full_text_union_with_prior_closed_intervals=True,
                old_body_function_reads_or_disassemblies=0,
                provider_callback_effects_value_validity_or_source_permission=False)


def verify_new_plan(domain, pin):
    bodies = domain['complete_new_functions']
    assert len(bodies) == pin['new_function_count']
    assert sum(row['size'] for row in bodies) == pin['new_bytes']
    actual = interval_digest([(int(r['start'], 16), int(r['end'], 16)) for r in bodies])
    assert actual == pin['new_interval_u64le_pair_sha256']
    assert actual == domain['new_interval_u64le_pair_sha256']


def noncode_remainder(image, closed_raw_ranges):
    covered = [(r['slice_file_offset'], r['slice_file_offset'] + r['bytes'])
               for r in closed_raw_ranges]
    result = []
    for section in image.sections:
        if section['flags'] & 0xff in (1, 0xc, 0x12):
            result.append(dict(section=section, zero_fill_declaration_only=True))
        elif section['name'] != '__text':
            lo, hi = section['offset'], section['offset'] + section['size']
            result.append(dict(section=section, old_overlap_hash_reused=True,
                new_raw_ranges=[shared.raw_range(image, a, b - a)
                                for a, b in prior.subtract_intervals(lo, hi, covered)]))
    return dict(sections=result, old_raw_ranges_recollected=0,
                initial_file_bytes_are_not_live_runtime_values=True)


def main():
    shared.OUT = OUT
    OUT.mkdir()
    pins = json.loads((Path(__file__).parent / 'pins.json').read_text())
    pin = pins['Core']
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(shared.DEVELOPER)
    assert shutil.disk_usage(OUT).free >= 512 * 1024 * 1024 + 128 * pin['new_bytes']
    raw = shared.run('actual-runtime-list', ['xcrun', 'simctl', 'list', 'runtimes', '--json'])
    matches = [r for r in json.loads(raw)['runtimes']
               if r.get('identifier') == pins['runtime']['identifier']]
    assert len(matches) == 1
    runtime = matches[0]
    assert runtime['isAvailable'] and runtime['version'] == pins['runtime']['version']
    assert runtime['buildversion'] == pins['runtime']['build']
    root = Path(runtime['runtimeRoot'])
    assert root.is_absolute()
    version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion'] == pins['runtime']['version']
    assert version['ProductBuildVersion'] == pins['runtime']['build']
    shared.save('actual-runtime-record.json', runtime)
    shared.save('actual-runtime-version.json', version)
    image = shared.MachO((root / pin['relative_path']).read_bytes())
    shared.validate_image(image, pin['uuid'])
    assert image.whole_sha256 == pin['whole_file_sha256']
    assert image.slice_sha256 == pin['selected_slice_sha256']
    assert image.text == pin['text']
    assert len(image.function_starts) == pin['function_starts_count']
    assert hashlib.sha256(b''.join(struct.pack('<Q', n) for n in image.function_starts)).hexdigest() == pin['function_starts_u64le_sha256']
    shared.save('same-selected-file-and-old-prefix-hash-references.json', dict(
        uuid=image.uuid, whole_file_sha256=image.whole_sha256,
        selected_slice_sha256=image.slice_sha256, pins=pins,
        old_metadata_raw_context_body_bytes_or_disassemblies_recollected=0,
        loaded_cache_byte_equivalence_not_asserted=True))
    domain = module_remainder(image, pin['closed_functions'], pins['new_disassembly_byte_target'])
    verify_new_plan(domain, pin)
    shared.save('Core-complete-new-module-function-domain.json', domain)
    shared.save('Core-complete-new-noncode-section-remainder.json',
                noncode_remainder(image, pin['prior_raw_ranges']))
    with tempfile.TemporaryDirectory(prefix='wmf-Core-new-static-', dir=os.environ['RUNNER_TEMP']) as temporary:
        thin = Path(temporary) / 'selected-Core-arm64.dylib'
        thin.write_bytes(image.data)
        for row in domain['new_disassembly_ranges']:
            shared.run('Core-new-range-' + row['start'][2:] + '-' + row['end'][2:],
                ['xcrun', 'llvm-objdump', '--disassemble',
                 '--start-address=' + row['start'], '--stop-address=' + row['end'], str(thin)])
    shared.save('complete-new-Core-module-static-result.json', dict(
        status='PASS', run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'],
        complete_new_functions=len(domain['complete_new_functions']),
        complete_new_words=pin['new_bytes'] // 4,
        prior_functions_hash_reused=len(pin['closed_functions']),
        complete_new_disassembly_ranges=domain['new_disassembly_ranges'],
        old_collector_tests_reexecuted=0,
        original_WMF_load_execution_generatedC_provider_execution_or_Simulator_boot=0,
        original_region_validity_callback_effect_value_lifetime_or_formal_permission=False))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        if OUT.exists():
            shared.save('failure.json', dict(traceback=traceback.format_exc()))
        raise
