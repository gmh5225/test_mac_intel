"""Keep the embedded Rust library's allocator owned by its Bun process."""
from pathlib import Path
import hashlib

HASHES = {
    'Cargo.toml': '1a91f226eef02adaf01896e8c03400efc5e31bd630141b6d87e6e59b04f32a99',
    'crates/core/main.rs': 'dc3f8c2e868d3b852b5cf34a16ff6fbf181b30f6bb7b67ba3051400152d59136',
    'crates/core/recovery_lib.rs': '86fd6a2a45fed65b04a4564009d160c5895c9066f1f82f3341a8e679af64c5a8',
}
ALLOCATOR = '''#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;
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
    after = after.replace('[features]\n', '[features]\ndefault = ["standalone-jemalloc"]\nstandalone-jemalloc = ["dep:jemallocator"]\n')
    wrapper = (root / 'crates/core/recovery_lib.rs').read_text(); assert wrapper.count(ALLOCATOR) == 1
    replacement = '// The embedding Bun process owns the one Rust global allocator.\n// The archived standalone main and its default jemalloc choice remain unchanged.\n'
    after_wrapper = wrapper.replace(ALLOCATOR, replacement)
    assert after_wrapper.split('fn main() -> ExitCode {', 1)[1] == wrapper.split('fn main() -> ExitCode {', 1)[1]
    assert '#[global_allocator]' not in after_wrapper
    return [('embedded-rg-manifest', 'recovery-native/ripgrep/Cargo.toml', manifest, after),
        ('embedded-rg-host-allocator', 'recovery-native/ripgrep/crates/core/recovery_lib.rs', wrapper, after_wrapper)]
