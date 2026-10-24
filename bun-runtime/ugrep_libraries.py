"""Admit exact source-built Ugrep archives before direct engine linking."""
from pathlib import Path
import json,re
from native_libraries import check_manifest,sha
ROOT=Path(__file__).resolve().parent
ARCHIVES=['librecovered_ugrep.a','libreflex.a','libviiz.a','libpcre2-8.a','libz.a','libbz2.a','libzstd.a','libbrotlidec.a','libbrotlicommon.a']
def qualify(arch,package,compiler_image):
    pins=json.loads((ROOT/'ugrep-library-pins.json').read_bytes())
    assert pins['schema_version']==1 and type(pins['producer_run']) is int and pins['producer_run']>0
    assert re.fullmatch('[0-9a-f]{40}',pins['producer_head']) and re.fullmatch('[0-9a-f]{64}',pins['independent_qualification_sha256'])
    expected=pins['profiles'][arch];check_manifest(package,expected['manifest_sha256'])
    receipt=json.loads((package/'receipt.json').read_bytes());lib=receipt['native_library'];library=package/'native-library'
    assert receipt['status']=='portable_ugrep_source_library_host_and_original_version_controls_passed' and receipt['arch']==arch
    assert receipt['compiler_image']==compiler_image and receipt['maximum_glibc_requirement']=='2.17'
    assert sha(package/'glibc-sysroot-pins.json')==sha(ROOT/'glibc-sysroot-pins.json')
    assert not receipt['captured_client_executed'] and not receipt['original_binary_reused']
    assert lib['status']=='ugrep_source_library_host_and_upstream_checks_passed' and lib['source_objects']==9
    assert lib['entry_symbol']=='neverd_recovered_ugrep_main' and lib['main_text_unchanged']
    assert lib['static_pthread_condition_variable_control_passed'] and lib['public_bun_compatibility_controls_passed']
    private=lib['private_c_symbols']
    assert private['status']=='component_c_definitions_privately_namespaced' and private['private_prefix']=='neverd_ugrep_native_'
    assert private['symbols']==expected['private_symbol_count']>100
    assert private['mapping_sha256']==expected['private_symbol_mapping_sha256']==sha(library/'private-symbols.txt')
    assert not private['cxx_runtime_renamed'] and not private['entry_renamed']
    assert (library/'main-text-private.bin').read_bytes()==(library/'main-text-before.bin').read_bytes()
    assert len(lib['controls'])==4 and all(c['exit_code']==0 and c['rlimit_fsize']==0 for c in lib['controls'])
    assert sha(library/'ugrep-library-host')==lib['host_sha256']==expected['host_sha256']
    assert (library/'main-text-before.bin').read_bytes()==(library/'main-text-after.bin').read_bytes()
    assert sha(library/'main-text-before.bin')==lib['main_text_sha256']==expected['main_text_sha256']
    assert (library/'version.stdout').read_bytes()==(package/'expected-original-version.txt').read_bytes()
    assert sha(package/'expected-original-version.txt')==expected['expected_version_sha256']
    for name in ARCHIVES:
        path=library/name;assert path.read_bytes().startswith(b'!<arch>\n') and sha(path)==expected['archives'][name]
    return dict(producer_run=pins['producer_run'],producer_head=pins['producer_head'],manifest_sha256=expected['manifest_sha256'],
        archive_sha256=expected['archives'],compiler_image=compiler_image,main_text_sha256=expected['main_text_sha256'],original_binary_reused=False,
        private_symbol_mapping_sha256=private['mapping_sha256'],private_symbol_count=private['symbols'])
