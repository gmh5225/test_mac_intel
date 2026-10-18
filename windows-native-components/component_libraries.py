"""Admit pinned Windows source components before any private graph mutation."""
from pathlib import Path
import json
import sys
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest


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
