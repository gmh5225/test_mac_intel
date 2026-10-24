"""Admit an independently retained native musl C component producer."""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest, sha
from patch_musl import ARCHIVES
from sdk import profile


def qualify(arch, package):
    pins = json.loads((ROOT / 'component-library-pins.json').read_bytes())
    assert pins['schema_version'] == 1 and pins['target_abi'] == 'musl' and not pins['core_engine_integrated']
    assert type(pins['producer_run']) is int and pins['producer_run'] > 0 and re.fullmatch('[0-9a-f]{40}', pins['producer_head'])
    pin = pins['profiles'][arch]; check_manifest(package, pin['manifest_sha256'])
    assert sha(package / 'receipt.json') == pin['receipt_sha256']
    r = json.loads((package / 'receipt.json').read_bytes())
    assert r['status'] == 'musl_source_component_graphs_hosts_and_upstream_checks_passed' and r['arch'] == arch
    assert r['target_profile'] == profile(arch) and not r['captured_client_executed'] and not r['core_engine_integrated']
    for role, names in ARCHIVES.items():
        graph = r['components'][role]
        assert graph['private_c_symbols']['status'] == 'elf_component_c_namespace_and_every_object_reference_verified'
        assert graph['private_c_symbols']['private_prefix'] == 'neverd_' + role + '_native_'
        assert graph['private_c_symbols']['all_typed_symbols_and_relocations_verified']
        assert not graph['private_c_symbols']['cxx_runtime_renamed'] and not graph['private_c_symbols']['entry_renamed']
        assert len(graph['private_c_symbols']['object_proofs']) == pin['private_objects'][role]
        assert graph['private_c_symbols']['allocated_and_debug_section_bytes_unchanged']
        assert graph['needed_libraries'] == [profile(arch)['libc']] and not graph['GNU_symbol_versions_imported']
        folder = package / 'native-libraries' / role
        assert set(graph['archives']) == set(names) and graph['archives'] == pin['archives'][role]
        assert len(graph['controls']) == (5 if role == 'ugrep' else 4)
        assert sha(folder / (role + '-library-host')) == graph['host_sha256']
        for name in names:
            assert (folder / name).read_bytes().startswith(b'!<arch>\n') and sha(folder / name) == graph['archives'][name]
    pc = package / 'native-libraries/rg-pcre2/libpcre2-8.a'
    assert sha(pc) == r['source_graph']['rg_pcre2_archive_sha256'] == pin['rg_pcre2_archive_sha256']
    return dict(arch=arch, producer_run=pins['producer_run'], producer_head=pins['producer_head'],
        manifest_sha256=pin['manifest_sha256'], receipt_sha256=pin['receipt_sha256'],
        independent_qualification_sha256=pin['independent_qualification_sha256'], compiled_rust_archive_used=False,
        exact_original_transitive_versions_proven=False)
