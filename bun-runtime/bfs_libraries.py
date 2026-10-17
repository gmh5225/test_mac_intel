"""Admit only the native C archives independently rebuilt from Bfs sources."""
from pathlib import Path
import json,re
from native_libraries import check_manifest,sha
ROOT=Path(__file__).resolve().parent
def qualify(arch,package,compiler_image):
    pins=json.loads((ROOT/'bfs-library-pins.json').read_bytes());assert pins['schema_version']==1 and pins['producer_run']>0 and re.fullmatch('[0-9a-f]{40}',pins['producer_head'])
    expected=pins['profiles'][arch];check_manifest(package,expected['manifest_sha256'])
    receipt=json.loads((package/'receipt.json').read_bytes());lib=receipt['native_library']
    assert receipt['status']=='public_bfs_original_compatibility_flags_pass_portability_and_native_controls' and receipt['arch']==arch
    assert receipt['compiler_image']==compiler_image and receipt['maximum_glibc_requirement']=='2.17'
    assert sha(package/'glibc-sysroot-pins.json')==sha(ROOT/'glibc-sysroot-pins.json')
    assert not receipt['captured_client_executed'] and lib['status']=='fresh_bfs_library_host_passes_zero_file_budget_controls' and not lib['original_binary_reused']
    assert lib['entry_symbol']=='neverd_recovered_bfs_main' and len(lib['objects'])==29
    assert len(lib['controls'])==4 and all(row['exit_code']==0 and row['rlimit_fsize']==0 for row in lib['controls'])
    for name,key in [('librecovered_bfs.a','native_library_archive_sha256'),('libonig.a','oniguruma_archive_sha256')]:
        p=package/'native-library'/name;assert p.read_bytes().startswith(b'!<arch>\n') and sha(p)==expected[key]
    assert (package/'native-library/main-text-before').read_bytes()==(package/'native-library/main-text-after').read_bytes()
    assert sha(package/'native-library/main-text-before')==lib['main_text_unchanged_sha256']
    assert sha(package/'bfs')==expected['binary_sha256']==lib['host_sha256']
    return dict(producer_run=pins['producer_run'],producer_head=pins['producer_head'],manifest_sha256=expected['manifest_sha256'],bfs_archive_sha256=expected['native_library_archive_sha256'],oniguruma_archive_sha256=expected['oniguruma_archive_sha256'],compiler_image=compiler_image,original_binary_reused=False)
