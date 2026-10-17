"""Admit pinned native macOS source graphs before changing the engine."""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest, sha

ARCHIVES = {
    'bfs': ['librecovered_bfs.a', 'libonig.a'],
    'ugrep': ['librecovered_ugrep.a', 'libreflex.a', 'libpcre2-8.a', 'libz.a', 'libbz2.a',
              'libzstd.a', 'libbrotlidec.a', 'libbrotlicommon.a', 'libviiz.a'],
}


def qualify(role, arch, package):
    pins = json.loads((ROOT / (role + '-library-pins.json')).read_bytes())
    assert pins['schema_version'] == 1 and type(pins['producer_run']) is int and pins['producer_run'] > 0
    assert re.fullmatch('[0-9a-f]{40}', pins['producer_head']) and pins['target_os'] == 'darwin' and pins['component'] == role
    assert set(pins['profiles']) == {'arm64', 'x64'} and not pins['core_engine_integrated']
    expected = pins['profiles'][arch]; check_manifest(package, expected['manifest_sha256'])
    assert sha(package / 'receipt.json') == expected['receipt_sha256']
    outer = json.loads((package / 'receipt.json').read_bytes()); assert outer['arch'] == arch and not outer['captured_client_executed']
    r = outer if role == 'ugrep' else outer['native_library']
    assert sha(package / 'native-library' / (role + '-library-host')) == expected['host_sha256'] == r['host_sha256']
    assert sha(package / 'native-library' / ('librecovered_' + role + '.a')) == expected['library_sha256'] == r['library_sha256']
    assert r['private_c_symbols']['symbols'] == expected['private_C_symbols']
    assert len(r['private_c_symbols']['object_proofs']) == expected['objects']
    assert not r['original_binary_reused']
    libraries = []
    for name in ARCHIVES[role]:
        path = package / 'native-library' / name
        assert path.read_bytes().startswith(b'!<arch>\n'); libraries.append(dict(file=name, bytes=path.stat().st_size, sha256=sha(path)))
    return dict(role=role, arch=arch, producer_run=pins['producer_run'], producer_head=pins['producer_head'],
        manifest_sha256=expected['manifest_sha256'], receipt_sha256=expected['receipt_sha256'],
        independent_qualification_sha256=expected['independent_qualification_sha256'], libraries=libraries,
        original_transitive_versions_proven=False, compiled_rust_archive_used=False)
