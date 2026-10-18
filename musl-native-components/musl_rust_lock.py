"""Pin the allocator-free embedded musl graph without changing shared locks."""
from pathlib import Path
import copy
import hashlib
import sys
import tomllib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from rust_source_graph import RESOLVED_LOCK_SHA256 as SHARED_LOCK_SHA256

LOCK_SHA256 = '687f8d5292ab189581c8d1a253ca03bae545dbc3df579a95e7965f05d01551b3'


def verify_delta(before, after):
    expected = copy.deepcopy(before)
    removed = [p for p in expected['package'] if p['name'] in ['jemalloc-sys', 'jemallocator']]
    assert {(p['name'], p['version']) for p in removed} == {('jemalloc-sys', '0.5.4+5.3.0-patched'), ('jemallocator', '0.5.4')}
    assert len(removed) == 2
    expected['package'] = [p for p in expected['package'] if p not in removed]
    rg = [p for p in expected['package'] if p['name'] == 'ripgrep']; assert len(rg) == 1 and rg[0]['version'] == '14.1.1'
    assert rg[0]['dependencies'].count('jemallocator') == 1
    rg[0]['dependencies'].remove('jemallocator')
    assert after == expected, 'Musl lock changed more than the unused standalone allocator closure'


def qualified_text():
    before = (ROOT.parent / 'bun-runtime/resolved-Cargo.lock').read_bytes()
    after = (ROOT / 'resolved-Cargo.lock').read_bytes()
    assert hashlib.sha256(before).hexdigest() == SHARED_LOCK_SHA256
    assert hashlib.sha256(after).hexdigest() == LOCK_SHA256
    verify_delta(tomllib.loads(before.decode()), tomllib.loads(after.decode()))
    return after.decode()
