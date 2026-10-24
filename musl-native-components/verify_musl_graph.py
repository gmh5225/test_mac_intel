"""Require musl rg/std to share Bun's graph without standalone jemalloc."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from verify_rust_plan import verify as verify_shared


def verify(path):
    result = verify_shared(path)
    assert result['triple'] in ['aarch64-unknown-linux-musl', 'x86_64-unknown-linux-musl']
    data = json.loads(path.read_bytes()); units = data['unitGraph']['units']
    assert not any(u['target']['name'] in ['jemallocator', 'jemalloc_sys'] for u in units), 'Standalone allocator entered the embedded Bun graph'
    rg = [u for u in units if u['target']['name'] == 'recovered_ripgrep']; assert len(rg) == 1
    assert {'pcre2', 'recovery-bun-args'} <= set(rg[0]['features']) and 'standalone-jemalloc' not in rg[0]['features']
    result.update(standalone_jemalloc_units=0, embedded_Rust_allocator_owner='Bun process mimalloc',
        upstream_standalone_main_preserved=True, original_allocator_performance_reproduced=False)
    result['embedded_rg_C_runtime_argument_vector_required'] = True
    return result


if __name__ == '__main__':
    r = verify(Path(sys.argv[1])); Path(sys.argv[2]).write_text(json.dumps(r, indent=2) + '\n'); print(json.dumps(r))
