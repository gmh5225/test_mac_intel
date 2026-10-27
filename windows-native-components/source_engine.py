"""Exact Windows engine identities; complete-role admission has no fallback."""
from pathlib import Path
import json
from coff_admission import sha
from pe_runtime import qualify as qualify_pe

ROOT = Path(__file__).resolve().parent


def pin(arch, binary, *, baseline_control=False):
    binary = Path(binary); assert binary.is_file() and not binary.is_symlink()
    if baseline_control:
        path = ROOT.parent / 'platform-runtime/windows-baseline-candidates.json'
        pins = json.loads(path.read_bytes()); expected = pins['profiles'][arch]
        assert sha(binary) == expected['binary_sha256']
        return dict(status='public_baseline_only_compiler_control_not_a_complete_role_engine', arch=arch,
            binary_sha256=sha(binary), producer_run=expected['producer_run'], producer_head=expected['producer_head'],
            native_owned_controls_producer_run=39032390145, complete_native_source_engine_admitted=False)
    path = ROOT / 'source-engine-pins.json'
    assert path.is_file(), 'An independently admitted complete Windows source engine is required'
    pins = json.loads(path.read_bytes()); assert pins['schema_version'] == 1 and set(pins['profiles']) == {'arm64', 'x64'}
    assert pins['status'] == 'both_native_Windows_complete_source_engines_independently_qualified'
    expected = pins['profiles'][arch]
    assert sha(binary) == expected['binary_sha256'] and binary.stat().st_size == expected['bytes']
    observed = qualify_pe(binary, arch)
    assert observed['exception_records'] == expected['exception_records'] and expected['duplicate_strong_symbols'] == 0
    return dict(status='complete_native_Windows_source_engine_admitted', arch=arch,
        binary_sha256=sha(binary), bytes=binary.stat().st_size, producer_run=pins['producer_run'],
        producer_head=pins['producer_head'], independent_qualification_sha256=pins['independent_qualification_sha256'],
        pin_file_sha256=sha(path), complete_native_source_engine_admitted=True)


def critical_sections(path, arch):
    observed = qualify_pe(path, arch)
    selected = [s for s in observed['sections'] if s['name'] in ['.text', '.rdata', '.pdata', '.tls']]
    assert {s['name'] for s in selected} >= {'.text', '.rdata', '.pdata'}
    return [{k: s[k] for k in ['index', 'name', 'rva', 'virtual', 'raw_bytes', 'attrs', 'sha256']} for s in selected]
