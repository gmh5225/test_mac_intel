"""Read only the uncollected intervals of the selected ObjC module."""

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
sys.path.insert(0, str(ROOT / 'wmf-Core-module-static'))
import core_module_collect as module

shared = module.shared
OUT = Path('wmf-objc-module-static-records')


def verify_selected_module(image, pin):
    """Verify this new provider frontier before reading any new function."""
    assert image.uuid == pin['uuid']
    assert image.whole_sha256 == pin['whole_file_sha256']
    assert image.slice_sha256 == pin['selected_slice_sha256']
    assert image.text == pin['text']
    starts = image.function_starts
    assert starts == sorted(set(starts))
    assert len(starts) == pin['function_starts_count']
    assert hashlib.sha256(b''.join(struct.pack('<Q', n) for n in starts)).hexdigest() == pin['function_starts_u64le_sha256']
    closed = {int(row['start'], 16) for row in pin['closed_functions']}
    for row in pin['required_new_exact_nlist_records']:
        assert [s for s in image.symbols if s['name'] == row['name']] == [row]
        assert row['value'] in starts and row['value'] not in closed


def main():
    shared.OUT = OUT
    OUT.mkdir()
    pins = json.loads((Path(__file__).parent / 'pins.json').read_text())
    pin = pins['objc']
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(shared.DEVELOPER)
    assert shutil.disk_usage(OUT).free >= 512 * 1024 * 1024 + 128 * pin['new_bytes']
    raw = shared.run('actual-runtime-list', ['xcrun', 'simctl', 'list', 'runtimes', '--json'])
    matches = [r for r in json.loads(raw)['runtimes'] if r.get('identifier') == pins['runtime']['identifier']]
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
    verify_selected_module(image, pin)
    shared.save('same-selected-objc-file-and-old-prefix-hash-references.json', dict(
        uuid=image.uuid, whole_file_sha256=image.whole_sha256, selected_slice_sha256=image.slice_sha256,
        pins=pins, old_metadata_raw_context_body_bytes_or_disassemblies_recollected=0,
        loaded_cache_byte_equivalence_not_asserted=True))
    domain = module.module_remainder(image, pin['closed_functions'], pins['new_disassembly_byte_target'])
    module.verify_new_plan(domain, pin)
    shared.save('objc-complete-new-module-function-domain.json', domain)
    shared.save('objc-complete-new-noncode-section-remainder.json', module.noncode_remainder(image, pin['prior_raw_ranges']))
    with tempfile.TemporaryDirectory(prefix='wmf-objc-new-static-', dir=os.environ['RUNNER_TEMP']) as temporary:
        thin = Path(temporary) / 'selected-objc-arm64.dylib'
        thin.write_bytes(image.data)
        for row in domain['new_disassembly_ranges']:
            shared.run('objc-new-range-' + row['start'][2:] + '-' + row['end'][2:],
                ['xcrun', 'llvm-objdump', '--disassemble', '--start-address=' + row['start'],
                 '--stop-address=' + row['end'], str(thin)])
    shared.save('complete-new-objc-module-static-result.json', dict(
        status='PASS', run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'],
        complete_new_functions=len(domain['complete_new_functions']), complete_new_words=pin['new_bytes'] // 4,
        prior_functions_hash_reused=len(pin['closed_functions']),
        complete_new_disassembly_ranges=domain['new_disassembly_ranges'], old_collector_tests_reexecuted=0,
        original_WMF_load_execution_generatedC_provider_execution_or_Simulator_boot=0,
        original_cell_region_validity_callback_effect_value_lifetime_or_formal_permission=False))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        if OUT.exists():
            shared.save('failure.json', dict(traceback=traceback.format_exc()))
        raise
