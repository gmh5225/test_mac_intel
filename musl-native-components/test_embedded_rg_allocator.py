"""Preserve the standalone main while the embedding process owns allocation."""
from pathlib import Path
import hashlib
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from embedded_rg_allocator import plan, ALLOCATOR


class EmbeddedAllocator(unittest.TestCase):
    def test_library_only_adaptation_preserves_default_binary_dependency(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / 'crates/core').mkdir(parents=True)
            manifest = '''[package]
name = "owned"
version = "0.0.0"
[target.'cfg(all(target_env = "musl", target_pointer_width = "64"))'.dependencies.jemallocator]
version = "0.5.0"
[features]
pcre2 = []
[lib]
path = "crates/core/recovery_lib.rs"
'''
            main = ALLOCATOR + '\nfn main() -> ExitCode { ExitCode::SUCCESS }\n'
            wrapper = '#![feature(exitcode_exit_method)]\n' + main
            for rel, body in [('Cargo.toml', manifest), ('crates/core/main.rs', main), ('crates/core/recovery_lib.rs', wrapper)]: (root / rel).write_text(body)
            hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
            with self.assertRaises(AssertionError): plan(root)
            with patch('embedded_rg_allocator.HASHES', hashes): changes = plan(root)
            self.assertEqual((root / 'crates/core/main.rs').read_text(), main)
            self.assertEqual((root / 'Cargo.toml').read_text(), manifest)
            self.assertEqual(len(changes), 2)
            parsed = tomllib.loads(changes[0][3])
            self.assertEqual(parsed['features']['default'], ['standalone-jemalloc'])
            self.assertEqual(parsed['features']['standalone-jemalloc'], ['dep:jemallocator'])
            self.assertTrue(next(iter(parsed['target'].values()))['dependencies']['jemallocator']['optional'])
            self.assertNotIn('#[global_allocator]', changes[1][3])
            self.assertEqual(changes[1][3].split('fn main()', 1)[1], wrapper.split('fn main()', 1)[1])


if __name__ == '__main__': unittest.main()
