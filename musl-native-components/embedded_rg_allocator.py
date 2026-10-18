"""Keep the embedded Rust library's allocator owned by its Bun process."""
from pathlib import Path
import hashlib

HASHES = {
    'Cargo.toml': '1a91f226eef02adaf01896e8c03400efc5e31bd630141b6d87e6e59b04f32a99',
    'crates/core/main.rs': 'dc3f8c2e868d3b852b5cf34a16ff6fbf181b30f6bb7b67ba3051400152d59136',
    'crates/core/recovery_lib.rs': '86fd6a2a45fed65b04a4564009d160c5895c9066f1f82f3341a8e679af64c5a8',
    'crates/core/flags/parse.rs': '731c57fe9984e5d4aa08699a5e6f93a16eb28051d428376a005d6c4dccba7147',
}
ALLOCATOR = '''#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;
'''

ARGUMENTS = '''
// The C-runtime argv is authoritative on musl; std's glibc-only constructor
// does not run there. Keep raw Unix bytes, including empty/non-UTF8 values.
static RECOVERY_ARGS: std::sync::OnceLock<Vec<std::ffi::OsString>> = std::sync::OnceLock::new();

unsafe fn initialize_recovery_args(argc: core::ffi::c_int, argv: *const *const core::ffi::c_char) {
    use std::os::unix::ffi::OsStringExt;
    assert!(argc >= 0 && (argc == 0 || !argv.is_null()), "invalid embedded rg argument vector");
    let mut owned = Vec::with_capacity(argc as usize);
    for index in 0..argc as usize {
        let pointer = unsafe { *argv.add(index) };
        if pointer.is_null() { break; }
        let bytes = unsafe { std::ffi::CStr::from_ptr(pointer) }.to_bytes();
        owned.push(std::ffi::OsString::from_vec(bytes.to_vec()));
    }
    assert!(RECOVERY_ARGS.set(owned).is_ok(), "embedded rg argument vector initialized twice");
}

pub(crate) fn recovery_args_os() -> std::vec::IntoIter<std::ffi::OsString> {
    RECOVERY_ARGS.get().expect("embedded rg argument vector was not initialized").clone().into_iter()
}
'''


def plan(root):
    for name, digest in HASHES.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, 'Unqualified rg allocator input: ' + name
    manifest = (root / 'Cargo.toml').read_text()
    dependency = '''[target.'cfg(all(target_env = "musl", target_pointer_width = "64"))'.dependencies.jemallocator]
version = "0.5.0"
'''
    assert manifest.count(dependency) == manifest.count('[features]\n') == 1 and 'standalone-jemalloc' not in manifest
    after = manifest.replace(dependency, dependency + 'optional = true\n')
    after = after.replace('[features]\n', '[features]\ndefault = ["standalone-jemalloc"]\nstandalone-jemalloc = ["dep:jemallocator"]\nrecovery-bun-args = []\n')
    wrapper = (root / 'crates/core/recovery_lib.rs').read_text(); assert wrapper.count(ALLOCATOR) == 1
    replacement = '// The embedding Bun process owns the one Rust global allocator.\n// The archived standalone main and its default jemalloc choice remain unchanged.\n'
    after_wrapper = wrapper.replace(ALLOCATOR, replacement)
    old_entry = 'pub extern "C" fn neverd_recovered_rg_main() -> ! { main().exit_process() }'
    new_entry = '''pub unsafe extern "C" fn neverd_recovered_rg_main(argc: core::ffi::c_int, argv: *const *const core::ffi::c_char) -> ! {
    unsafe { initialize_recovery_args(argc, argv) };
    main().exit_process()
}'''
    assert after_wrapper.count(old_entry) == 1
    after_wrapper = after_wrapper.replace(old_entry, new_entry) + ARGUMENTS
    assert after_wrapper.split('fn main() -> ExitCode {', 1)[1].split('\n#[unsafe(no_mangle)]')[0] == wrapper.split('fn main() -> ExitCode {', 1)[1].split('\n#[unsafe(no_mangle)]')[0]
    assert '#[global_allocator]' not in after_wrapper
    before_parse = (root / 'crates/core/flags/parse.rs').read_text()
    assert before_parse.count('std::env::args_os()') == 2
    anchor = 'use std::{borrow::Cow, collections::BTreeSet, ffi::OsString};\n'
    assert before_parse.count(anchor) == 1
    after_parse = before_parse.replace(anchor, anchor + '''
#[cfg(feature = "recovery-bun-args")]
use crate::recovery_args_os;
#[cfg(not(feature = "recovery-bun-args"))]
use std::env::args_os as recovery_args_os;
''').replace('std::env::args_os()', 'recovery_args_os()')
    return [('embedded-rg-manifest', 'recovery-native/ripgrep/Cargo.toml', manifest, after),
        ('embedded-rg-host-allocator', 'recovery-native/ripgrep/crates/core/recovery_lib.rs', wrapper, after_wrapper),
        ('embedded-rg-argument-reader', 'recovery-native/ripgrep/crates/core/flags/parse.rs', before_parse, after_parse)]
