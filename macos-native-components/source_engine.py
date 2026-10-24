"""Require an independently admitted public source engine, never a captured prefix."""
from pathlib import Path
import json
from component_libraries import sha
from macho_runtime import qualify as qualify_macho

ROOT = Path(__file__).resolve().parent


def qualify(arch, binary):
    pins = json.loads((ROOT / 'source-engine-pins.json').read_bytes())
    assert pins['schema_version'] == 1 and pins['target_os'] == 'darwin'
    assert arch in pins['profiles'], 'Full native source engine is not independently admitted for ' + arch
    profile = pins['profiles'][arch]; binary = Path(binary)
    assert binary.is_file() and not binary.is_symlink() and sha(binary) == profile['binary_sha256']
    assert type(pins['producer_run']) is int and pins['producer_run'] > 0 and len(pins['producer_head']) == 40
    assert profile['single_target_std_libraries'] == 1 and profile['duplicate_strong_symbols'] == 0
    assert set(profile['native_qualified_os']) == {'15', '26'}
    final = qualify_macho(binary, arch)
    return dict(arch=arch, binary_sha256=sha(binary), producer_run=pins['producer_run'], producer_head=pins['producer_head'],
        independent_qualification_sha256=profile['independent_qualification_sha256'], final_macho=final,
        compiled_rust_archive_used=False, original_prefix_used=False)
