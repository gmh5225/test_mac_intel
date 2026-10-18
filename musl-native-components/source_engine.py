"""Admit an exact independently qualified complete musl source engine."""
from pathlib import Path
import json
import re
import struct
import sys
from sdk import ROOT, profile, sha
from elf_client_layout import core_sections
from musl_allocator import SYMBOLS
from musl_rust_lock import LOCK_SHA256
from verify_musl_graph import verify
from component_libraries import qualify as qualify_components
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest


def pins():
    path = ROOT / 'source-engine-pins.json'
    assert path.is_file(), 'An independently admitted complete musl source engine is required'
    data = json.loads(path.read_bytes())
    assert data['schema_version'] == 1 and data['target_abi'] == 'musl'
    assert data['status'] == 'complete_source_engine_ELF_single_Rust_graph_and_owned_controls_independently_qualified'
    assert data['public_bun_commit'] == 'c6da4a4d3010e5553438c60f6bd76d981976867c'
    assert type(data['producer_run']) is int and data['producer_run'] > 0 and re.fullmatch('[0-9a-f]{40}', data['producer_head'])
    assert re.fullmatch('[0-9a-f]{64}', data['independent_qualification_sha256'])
    assert set(data['profiles']) == {'arm64', 'x64'}
    for arch, row in data['profiles'].items():
        assert row['needed_libraries'] == [profile(arch)['libc']]
        assert row['musl_allocator_exports'] == 29 and row['duplicate_strong_symbols'] == 0
        assert row['single_Rust_std_libraries'] == 1 and row['standalone_jemalloc_units'] == 0
        assert row['native_owned_roles'] == 19 and row['native_filename_controls'] == 768
    return data


def pin(arch, binary):
    data = pins(); expected = data['profiles'][arch]
    assert binary.is_file() and not binary.is_symlink() and sha(binary) == expected['binary_sha256'] and binary.stat().st_size == expected['bytes']
    with binary.open('rb') as stream: header = stream.read(64)
    assert header[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', header, 18)[0] == {'arm64': 183, 'x64': 62}[arch]
    assert core_sections(binary) == expected['critical_sections']
    return dict(expected, producer_run=data['producer_run'], producer_head=data['producer_head'],
        public_bun_commit=data['public_bun_commit'], pin_file_sha256=sha(ROOT / 'source-engine-pins.json'),
        independent_qualification_sha256=data['independent_qualification_sha256'], complete_native_source_engine_admitted=True)


def qualify(arch, package):
    data = pins(); expected = data['profiles'][arch]
    check_manifest(package, expected['manifest_sha256'])
    assert sha(package / 'receipt.json') == expected['receipt_sha256']
    r = json.loads((package / 'receipt.json').read_bytes())
    assert r['status'] == 'public_musl_complete_native_source_engine_and_owned_controls_passed' and r['arch'] == arch
    assert not r['captured_client_executed'] and not r['original_prefix_reused'] and not r['compiled_rust_archive_used']
    assert r['public_bun_commit'] == data['public_bun_commit'] and r['needed_libraries'] == expected['needed_libraries']
    assert sha(package / 'Cargo.lock') == r['locked_musl_graph_sha256'] == LOCK_SHA256
    graph = verify(package / 'rust-plan.json'); assert graph == r['single_rust_graph'] and graph['plan_sha256'] == expected['rust_plan_sha256']
    assert qualify_components(arch, package / 'C-source-component-inputs') == r['components'] == expected['component_provenance']
    assert r['allocator_exports']['symbols'] == sorted(SYMBOLS) and not r['allocator_exports']['GNU_allocator_versions_used']
    assert r['duplicate_strong_symbols'] == 0 and r['native_controls']['cases'] == 19 and r['native_controls']['native_rg_filename_controls']['cases'] == 768
    return pin(arch, package / 'bun')
