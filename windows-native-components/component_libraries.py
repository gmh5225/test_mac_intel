"""Admit pinned Windows source components before any private graph mutation."""
from pathlib import Path
import json
import sys
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest

ARCHIVES = ['recovered_ugrep.lib', 'owned_viiz.lib', 'pcre2-8-static.lib', 'zlibstatic.lib',
    'owned_bzip2.lib', 'libzstd_static.lib', 'brotlidec.lib', 'brotlicommon.lib']


def qualify_candidate(arch, package):
    pins = json.loads((ROOT / 'source-component-pins.json').read_bytes())
    assert pins['schema_version'] == 1 and set(pins['profiles']) == {'arm64', 'x64'}
    assert not pins['full_engine_integrated'] and not pins['private_namespace_qualified']
    expected = pins['profiles'][arch]; check_manifest(package, expected['manifest_sha256'])
    assert sha(package / 'receipt.json') == expected['receipt_sha256']
    receipt = json.loads((package / 'receipt.json').read_bytes())
    assert receipt['arch'] == arch and receipt['native_CPU'] and receipt['public_sources_only']
    assert receipt['status'] == 'native_public_Windows_ugrep_source_candidate_and_owned_cases_passed'
    assert not receipt['original_executed'] and not receipt['full_engine_integrated']
    assert sha(package / 'ugrep-source-host.exe') == expected['binary_sha256']
    assert receipt['upstream_test_counts'] == {'pcre2': 4, 'brotli': 14, 'zlib': 1}
    assert receipt['raw_UG_objects'] == 28 and len(receipt['owned_controls']) == 8
    for name, digest in expected['dependency_archives'].items():
        assert sha(package / 'raw-dependency-archives' / name) == digest
    return dict(status='pinned_native_Windows_public_source_component_admitted', arch=arch,
        producer_run=pins['producer_run'], producer_head=pins['producer_head'],
        manifest_sha256=expected['manifest_sha256'], receipt_sha256=expected['receipt_sha256'],
        independent_qualification_sha256=pins['independent_qualification_sha256'])


def qualify_library(arch, package):
    path = ROOT / 'ugrep-library-pins.json'
    assert path.is_file(), 'Independently admitted native Windows private source library required'
    pins = json.loads(path.read_bytes()); assert pins['schema_version'] == 1 and set(pins['profiles']) == {'arm64', 'x64'}
    expected = pins['profiles'][arch]; check_manifest(package, expected['manifest_sha256'])
    assert sha(package / 'receipt.json') == expected['receipt_sha256']
    r = json.loads((package / 'receipt.json').read_bytes())
    assert r['status'] == 'native_Windows_private_COFF_library_and_nine_standalone_host_pairs_passed' and r['arch'] == arch
    assert not r['original_executed'] and not r['full_engine_integrated']
    assert r['object_count'] == expected['objects'] == 146 and len(r['standalone_host_pairs']) == 9
    assert r['private_C_symbols']['symbols'] == expected['private_C_symbols']
    assert sha(package / 'native-library/ugrep-library-host.exe') == expected['host_sha256']
    assert sha(package / 'native-library/recovered_ugrep.lib') == expected['library_sha256']
    assert r['private_C_symbols']['SDK_CRT_ABI_names_preserved'] == ([] if arch == 'arm64' else ['_Avx2WmemEnabledWeakValue'])
    for name, digest in expected['archives'].items():
        assert name in ARCHIVES and sha(package / 'native-library' / name) == digest
    assert set(expected['archives']) == set(ARCHIVES)
    return dict(status='pinned_native_Windows_private_source_library_admitted', arch=arch,
        producer_run=pins['producer_run'], producer_head=pins['producer_head'],
        manifest_sha256=expected['manifest_sha256'], receipt_sha256=expected['receipt_sha256'],
        independent_qualification_sha256=pins['independent_qualification_sha256'])
