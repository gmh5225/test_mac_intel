"""Preserve the standalone main while the embedding process owns allocation."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from embedded_rg_allocator import plan, ALLOCATOR, ARGUMENTS


class EmbeddedAllocator(unittest.TestCase):
    def test_library_only_adaptation_preserves_default_binary_dependency(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / 'crates/core/flags').mkdir(parents=True)
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
            wrapper = '#![feature(exitcode_exit_method)]\n' + main + '\n#[unsafe(no_mangle)]\npub extern "C" fn neverd_recovered_rg_main() -> ! { main().exit_process() }\n'
            parse = 'use std::{borrow::Cow, collections::BTreeSet, ffi::OsString};\nfirst(std::env::args_os());\nconfig.extend(std::env::args_os());\n'
            for rel, body in [('Cargo.toml', manifest), ('crates/core/main.rs', main), ('crates/core/recovery_lib.rs', wrapper), ('crates/core/flags/parse.rs', parse)]: (root / rel).write_text(body)
            hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
            with self.assertRaises(AssertionError): plan(root)
            with patch('embedded_rg_allocator.HASHES', hashes): changes = plan(root)
            self.assertEqual((root / 'crates/core/main.rs').read_text(), main)
            self.assertEqual((root / 'Cargo.toml').read_text(), manifest)
            self.assertEqual(len(changes), 3)
            parsed = tomllib.loads(changes[0][3])
            self.assertEqual(parsed['features']['default'], ['standalone-jemalloc'])
            self.assertEqual(parsed['features']['standalone-jemalloc'], ['dep:jemallocator'])
            self.assertTrue(next(iter(parsed['target'].values()))['dependencies']['jemallocator']['optional'])
            self.assertEqual(parsed['features']['recovery-bun-args'], [])
            self.assertNotIn('#[global_allocator]', changes[1][3])
            self.assertEqual(changes[1][3].split('fn main()', 1)[1].split('\n#[unsafe(no_mangle)]')[0], wrapper.split('fn main()', 1)[1].split('\n#[unsafe(no_mangle)]')[0])
            self.assertEqual(changes[2][3].count('recovery_args_os()'), 2)
            self.assertIn('#[cfg(not(feature = "recovery-bun-args"))]\nuse std::env::args_os as recovery_args_os;', changes[2][3])

    @unittest.skipUnless(shutil.which('rustc'), 'A native Rust compiler is required for the authored argument control')
    def test_raw_C_argument_vector_keeps_empty_unicode_and_non_UTF8_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / 'owned.rs'; binary = root / 'owned'
            body = ARGUMENTS + r'''
fn main() {
    use std::os::unix::ffi::OsStrExt;
    let bytes: Vec<&[u8]> = vec![b"rg", b"space \xe9\x9b\xaa\nname", b"", b"invalid-\xff"];
    let strings: Vec<_> = bytes.iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
    let mut pointers: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let middle_null = std::env::args().any(|a| a == "middle-null");
    if middle_null { pointers[2] = std::ptr::null(); }
    unsafe { initialize_recovery_args(4, pointers.as_ptr()) };
    for _ in 0..2 {
        let actual: Vec<_> = recovery_args_os().map(|s| s.as_bytes().to_vec()).collect();
        let expected = if middle_null { &bytes[..2] } else { &bytes[..] };
        assert_eq!(actual, expected);
    }
    println!("owned raw argv preserved");
}
'''
            source.write_text(body)
            subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(binary)], check=True, capture_output=True, timeout=60)
            for args in [[], ['middle-null']]:
                result = subprocess.run([str(binary), *args], check=True, capture_output=True, timeout=10)
                self.assertEqual(result.stdout, b'owned raw argv preserved\n'); self.assertEqual(result.stderr, b'')


if __name__ == '__main__': unittest.main()
