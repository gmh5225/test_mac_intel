"""Reject version/checksum/edge drift outside the measured allocator closure."""
import copy
from pathlib import Path
import tomllib
import unittest
from musl_rust_lock import qualified_text, verify_delta


class MuslLock(unittest.TestCase):
    def test_pinned_graph_and_unrelated_mutations(self):
        root = Path(__file__).resolve().parent
        before = tomllib.loads((root.parent / 'bun-runtime/resolved-Cargo.lock').read_text())
        after = tomllib.loads(qualified_text()); verify_delta(before, after)
        for field, value in [('version', '0.0.0'), ('checksum', '0' * 64)]:
            changed = copy.deepcopy(after)
            package = next(p for p in changed['package'] if p['name'] == 'libc')
            package[field] = value
            with self.assertRaises(AssertionError): verify_delta(before, changed)
        changed = copy.deepcopy(after)
        next(p for p in changed['package'] if p['name'] == 'ripgrep')['dependencies'].remove('grep')
        with self.assertRaises(AssertionError): verify_delta(before, changed)
        changed = copy.deepcopy(after); changed['package'].pop()
        with self.assertRaises(AssertionError): verify_delta(before, changed)


if __name__ == '__main__': unittest.main()
